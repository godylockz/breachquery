#!/usr/bin/env python3
"""Query the HackNotice Research API for a domain, conservatively.

A companion to dehashquery.py. It writes the same per-domain output files, but
sources them from HackNotice's research8 phrase search and only over a recent
window (default: the last 90 days).

Access to the HackNotice API is for approved accounts only and requires a prior
consultation with HackNotice. Endpoints and request shapes follow HackNotice's
own n8n node (github.com/HackNotice/n8n-nodes-hacknotice).

Conservative by design:
  * A count query runs first; you confirm the estimated page count before any
    record pages are fetched (skip with -y).
  * --max-pages hard-caps retrieval per domain (default 10 pages, ~500 rows).
  * Requests are throttled below HackNotice's documented 1 req/s governor.
  * Results are cached; a domain is not re-queried unless you pass --refresh.

HackNotice does not publish per-request billing. Confirm how count and page
requests are metered on your contract before raising the caps.

Credentials resolve in order: CLI flag -> environment -> a .env file.
  HACKNOTICE_INTEGRATION_KEY                        (preferred, single header)
  HACKNOTICE_API_KEY + HACKNOTICE_EMAIL + HACKNOTICE_PASSWORD  (JWT sign-in)
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import argparse
import json
import logging
import os
import sys
import time

from dehashquery import Colors, DumpProcessor, load_domains, parse_env_file

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write("[-] Missing dependency 'requests'. Install with: pip install -r requirements.txt\n")
    sys.exit(1)


API_BASE_URL = "https://extensionapi.hacknotice.com"
SIGN_IN_PATH = "/auth/sign_in"
SIGN_OUT_PATH = "/auth/sign_out"
COUNT_TERM_PATH = "/research8/count/term"
SEARCH_TERM_PATH = "/research8/search/term/page/{page}"   # page is zero-based

PAGE_SIZE = 50            # rows per research page (fixed server-side)
DEFAULT_DAYS = 90
DEFAULT_MAX_PAGES = 10
MIN_INTERVAL = 1.1        # seconds between requests (governor: 1 req/s)
REQUEST_TIMEOUT = 60

SEARCH_TYPES = ("wildcard_pre", "wildcard_both", "wildcard_post", "match_phrase")

log = logging.getLogger("hacknoticequery")


# --------------------------------------------------------------------------- #
# Credential resolution
# --------------------------------------------------------------------------- #
ENV_NAMES = {
    "integration_key": "HACKNOTICE_INTEGRATION_KEY",
    "api_key": "HACKNOTICE_API_KEY",
    "email": "HACKNOTICE_EMAIL",
    "password": "HACKNOTICE_PASSWORD",
}


def resolve_credentials(args: argparse.Namespace) -> Dict[str, str]:
    """Resolve credentials: CLI flag -> environment variable -> .env file."""
    dotenv: Dict[str, str] = {}
    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"):
        if candidate.is_file():
            for key, val in parse_env_file(candidate).items():
                dotenv.setdefault(key, val)

    creds: Dict[str, str] = {}
    for field, env_name in ENV_NAMES.items():
        value = getattr(args, field, None) or os.environ.get(env_name) or dotenv.get(env_name)
        if value:
            creds[field] = value.strip()

    if creds.get("integration_key"):
        return {"integration_key": creds["integration_key"]}
    if all(creds.get(k) for k in ("api_key", "email", "password")):
        return creds
    raise SystemExit(
        f"{Colors.RED}[-] No HackNotice credentials found.{Colors.NOCOLOR} Set "
        "HACKNOTICE_INTEGRATION_KEY, or HACKNOTICE_API_KEY + HACKNOTICE_EMAIL + "
        "HACKNOTICE_PASSWORD, in the environment or a .env file."
    )


class ApiError(RuntimeError):
    """A non-200 response ({"message": "..."} body) from the HackNotice API."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message


def extract_count(response: Any) -> Optional[int]:
    """Pull an integer count out of the response shapes the API returns."""
    if isinstance(response, bool):
        return None
    if isinstance(response, (int, float)):
        return int(response)
    if isinstance(response, str):
        try:
            return extract_count(json.loads(response))
        except ValueError:
            return None
    if isinstance(response, dict):
        for key in ("count", "total"):
            if key in response:
                return extract_count(response[key])
    return None


def extract_items(response: Any) -> List[Dict[str, Any]]:
    """Pull the record list out of a page response (array or wrapped array)."""
    if isinstance(response, list):
        return [r for r in response if isinstance(r, dict)]
    if isinstance(response, dict):
        for key in ("data", "results", "items", "hits"):
            if isinstance(response.get(key), list):
                return [r for r in response[key] if isinstance(r, dict)]
    return []


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class HackNoticeClient:
    """Thin wrapper over the HackNotice extension API, throttled to <1 req/s."""

    def __init__(self, creds: Dict[str, str], min_interval: float = MIN_INTERVAL) -> None:
        self.min_interval = max(1.0, min_interval)
        self._last_call = 0.0
        self.requests_made = 0
        self._signed_in = False
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "hacknoticequery/1.0",
        })
        # Retry transport errors and 5xx only. A 429 is not retried: the governor
        # sends no Retry-After, and blind retries would just spend more requests.
        retry = Retry(
            total=3, connect=3, read=2, backoff_factor=2.0,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

        if "integration_key" in creds:
            self.session.headers["X-HackNotice-Integration-Key"] = creds["integration_key"]
        else:
            self._sign_in(creds["api_key"], creds["email"], creds["password"])

    def _throttle(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        self._throttle()
        url = f"{API_BASE_URL}{path}"
        try:
            resp = self.session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"Request to {url} failed: {exc}") from exc
        self.requests_made += 1
        log.debug("%s %s -> %d", method, path, resp.status_code)

        try:
            data = resp.json()
        except ValueError:
            data = {"message": resp.text.strip()[:200] or f"HTTP {resp.status_code}"}

        if resp.status_code != 200:
            msg = data.get("message", "Unknown error") if isinstance(data, dict) else str(data)
            if resp.status_code == 403 and "challenge" in str(msg).lower():
                msg = "blocked by Cloudflare bot protection"
            raise ApiError(resp.status_code, str(msg))
        return data

    def _sign_in(self, api_key: str, email: str, password: str) -> None:
        """Exchange apikey + email + password for a JWT (form-encoded, per docs)."""
        self.session.headers["apikey"] = api_key
        data = self._request(
            "POST", SIGN_IN_PATH,
            data={"email": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise RuntimeError("HackNotice sign-in returned no token "
                               "(2FA accounts should use an integration key).")
        # HackNotice's scheme uses the literal "JWT " prefix, not "Bearer ".
        self.session.headers["Authorization"] = f"JWT {token}"
        self._signed_in = True

    def sign_out(self) -> None:
        """End the JWT session we opened (this session only, never sign_out_all)."""
        if not self._signed_in:
            return
        try:
            self._request("GET", SIGN_OUT_PATH)
        except (ApiError, RuntimeError) as exc:
            log.debug("Sign-out failed (ignored): %s", exc)
        self._signed_in = False

    def count_term(self, body: Dict[str, Any]) -> int:
        count = extract_count(self._request("POST", COUNT_TERM_PATH, json=body))
        if count is None:
            raise RuntimeError("Count response did not include a numeric count.")
        return count

    def search_term(self, body: Dict[str, Any], page: int) -> List[Dict[str, Any]]:
        return extract_items(self._request("POST", SEARCH_TERM_PATH.format(page=page), json=body))


# --------------------------------------------------------------------------- #
# Query building and record mapping
# --------------------------------------------------------------------------- #
# HackNotice research records use different key names than DeHashed. We map each
# record into the entry schema DumpProcessor (from dehashquery) already knows, so
# both tools emit identical output files. Candidate keys, most specific first --
# the research response schema is not published, so we probe the keys seen across
# HackNotice's docs, n8n node, and MCP tool summaries.
FIELD_KEY_CANDIDATES: Dict[str, tuple] = {
    "email": ("email", "emails", "hit_value"),
    "username": ("username", "user", "login"),
    "password": ("password", "pass"),
    "hashed_password": ("hashed_password", "passwordHash", "hash"),
    "ip_address": ("ip", "ip_address"),
    "url": ("url", "link"),
    "database_name": ("name", "hackname", "breach", "sourcetype", "filename"),
}


def _first(record: Dict[str, Any], keys: tuple) -> str:
    for key in keys:
        val = record.get(key)
        if isinstance(val, list):
            val = next((v for v in val if v), "")
        if val:
            return str(val)
    return ""


def map_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Map a HackNotice research record onto the DeHashed entry schema."""
    entry = {field: _first(record, keys) for field, keys in FIELD_KEY_CANDIDATES.items()}
    # HackNotice tags credential type (plaintext / MD5 / SHA1). A hashed value in
    # the password field belongs in hashed_password so it isn't treated as plaintext.
    ptype = str(_first(record, ("passwordType", "password_type", "passwordtype"))).lower()
    if ptype and ptype not in ("plaintext", "plain", "cleartext") and entry["password"]:
        entry.setdefault("hashed_password", "")
        if not entry["hashed_password"]:
            entry["hashed_password"] = entry["password"]
        entry["password"] = ""
    return entry


def date_window(days: int, end: Optional[date] = None) -> Dict[str, str]:
    end = end or date.today()
    return {"startdate": (end - timedelta(days=days)).isoformat(), "enddate": end.isoformat()}


def build_body(domain: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Request body for research8 phrase search, limited to credential hits."""
    body: Dict[str, Any] = {
        "term": domain,
        "searchtype": args.searchtype,
        "domainfilter": True,   # server-side boundary check drops loose substring hits
        "creds": True,          # include extracted email/password fields
        "credsonly": True,      # only results carrying credentials
        "fullrecords": False,   # 1000-char previews, not full leak text
        "order": "desc",        # newest first, so a page cap keeps the most recent
    }
    body.update(date_window(args.days))
    return body


def fetch_entries(client: HackNoticeClient, body: Dict[str, Any], pages: int) -> List[Dict[str, Any]]:
    """Fetch up to `pages` zero-based pages, stopping on a short or empty page."""
    entries: List[Dict[str, Any]] = []
    for page in range(pages):
        try:
            items = client.search_term(body, page)
        except ApiError as exc:
            # The research8 family enforces an upper page cap; treat a refusal past
            # page 0 as the end rather than an error, and keep what we have.
            if page > 0 and exc.status_code in (400, 404, 416, 422):
                log.warning("Server stopped pagination at page %d (%s); keeping %d records.",
                            page, exc.message, len(entries))
                break
            raise
        if not items:
            break
        entries.extend(map_record(r) for r in items)
        log.info("  page %d: %d records (%d total)", page, len(items), len(entries))
        if len(items) < PAGE_SIZE:
            break
    return entries


# --------------------------------------------------------------------------- #
# Subcommand handlers
# --------------------------------------------------------------------------- #
def confirm_pages(domain: str, count: int, pages: int, assume_yes: bool) -> bool:
    """Show the count and how many pages will be fetched; ask before spending."""
    est_pages = (count + PAGE_SIZE - 1) // PAGE_SIZE if count else 0
    fetch = min(est_pages, pages)
    print(f"{Colors.CYAN}[*] {domain}: {count} credential hit(s) in window "
          f"(~{est_pages} page(s)); will fetch up to {fetch} page(s).{Colors.NOCOLOR}")
    if count == 0:
        return False
    if est_pages > pages:
        print(f"{Colors.YELLOW}[!] Result set exceeds --max-pages ({pages}); "
              f"output will be truncated to the {pages * PAGE_SIZE} most recent rows."
              f"{Colors.NOCOLOR}")
    if assume_yes:
        return True
    while True:
        ans = input("Fetch these pages? (y/n): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            print(f"{Colors.CYAN}[*] Skipping {domain}.{Colors.NOCOLOR}")
            return False
        print("Please enter 'y' or 'n'.")


def cmd_count(args: argparse.Namespace) -> int:
    creds = resolve_credentials(args)
    domains = load_domains(args)
    if not domains:
        raise SystemExit(f"{Colors.RED}[-] No valid domains supplied.{Colors.NOCOLOR}")
    client = HackNoticeClient(creds, min_interval=args.min_interval)
    try:
        for domain in domains:
            count = client.count_term(build_body(domain, args))
            est_pages = (count + PAGE_SIZE - 1) // PAGE_SIZE if count else 0
            print(f"{Colors.CYAN}[*] {domain}: {count} credential hit(s) in the last "
                  f"{args.days} day(s) (~{est_pages} page(s)).{Colors.NOCOLOR}")
    finally:
        client.sign_out()
    print(f"{Colors.CYAN}[*] Requests used: {client.requests_made}{Colors.NOCOLOR}")
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    creds = resolve_credentials(args)
    domains = load_domains(args)
    if not domains:
        raise SystemExit(f"{Colors.RED}[-] No valid domains supplied.{Colors.NOCOLOR}")
    base_dir = Path(args.output_dir)

    need_query = any(
        not (base_dir / d / "allData.json").is_file() or args.refresh for d in domains
    )
    client = HackNoticeClient(creds, min_interval=args.min_interval) if need_query else None
    try:
        for domain in domains:
            out_dir = base_dir / domain
            cache = out_dir / "allData.json"
            print(f"{Colors.CYAN}[*] Target: {domain}  ->  {out_dir}{Colors.NOCOLOR}")

            if cache.is_file() and not args.refresh:
                print(f"{Colors.CYAN}[*] Using cached data ({cache}). Use --refresh to re-query."
                      f"{Colors.NOCOLOR}")
                data = json.loads(cache.read_text(encoding="utf-8"))
                entries = data.get("entries", []) if isinstance(data, dict) else data
            else:
                assert client is not None
                body = build_body(domain, args)
                count = client.count_term(body)
                if not confirm_pages(domain, count, args.max_pages, args.yes):
                    continue
                entries = fetch_entries(client, body, args.max_pages)
                out_dir.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(
                    {"count": count, "window_days": args.days,
                     "startdate": body["startdate"], "enddate": body["enddate"],
                     "entries": entries}, indent=2), encoding="utf-8")
                print(f"{Colors.CYAN}[*] Cached {len(entries)} records to {cache}{Colors.NOCOLOR}")

            DumpProcessor(domain, out_dir, wells=None).process(entries)
    finally:
        if client is not None:
            client.sign_out()
            print(f"{Colors.CYAN}[*] Requests used: {client.requests_made}{Colors.NOCOLOR}")

    print(f"{Colors.GREEN}[*] Done{Colors.NOCOLOR}")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hacknoticequery.py",
        description="Query the HackNotice Research API for a domain (last N days, conservative).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    def add_common(p: argparse.ArgumentParser) -> None:
        grp = p.add_mutually_exclusive_group(required=True)
        grp.add_argument("-d", "--domain", help="Single domain to query")
        grp.add_argument("--domains", help="File with newline-separated domains")
        p.add_argument("--days", type=int, default=DEFAULT_DAYS,
                       help=f"Look-back window in days (default {DEFAULT_DAYS})")
        p.add_argument("--searchtype", choices=SEARCH_TYPES, default="wildcard_pre",
                       help="Phrase match mode (default wildcard_pre: emails ending in the term)")
        p.add_argument("--min-interval", type=float, default=MIN_INTERVAL,
                       help=f"Min seconds between requests (default {MIN_INTERVAL}, governor is 1/s)")
        p.add_argument("--integration-key", dest="integration_key",
                       help="HackNotice integration key (else $HACKNOTICE_INTEGRATION_KEY or .env)")
        p.add_argument("--api-key", dest="api_key", help="API key for JWT sign-in")
        p.add_argument("--email", dest="email", help="Account email for JWT sign-in")
        p.add_argument("--password", dest="password", help="Account password for JWT sign-in")
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
        p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    sub = parser.add_subparsers(dest="command")

    dump = sub.add_parser("dump", help="Count, confirm, then fetch credential hits")
    add_common(dump)
    dump.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES,
                      help=f"Max pages fetched per domain (default {DEFAULT_MAX_PAGES}, "
                           f"{PAGE_SIZE} rows/page)")
    dump.add_argument("-o", "--output-dir", default="output", help="Base output directory")
    dump.add_argument("--refresh", action="store_true", help="Ignore cache and re-query")
    dump.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt")
    dump.set_defaults(func=cmd_dump)

    cnt = sub.add_parser("count", help="Count-only; fetches no records")
    add_common(cnt)
    cnt.set_defaults(func=cmd_count)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Default to the `dump` subcommand when none is given.
    subcommands = {"dump", "count"}
    if argv and not any(h in argv for h in ("-h", "--help")):
        first_positional = next((a for a in argv if not a.startswith("-")), None)
        if first_positional not in subcommands:
            argv.insert(0, "dump")

    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(message)s",
    )
    if getattr(args, "no_color", False) or not sys.stdout.isatty():
        Colors.disable()

    if not getattr(args, "func", None):
        build_parser().print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        return 130
    except (RuntimeError, ApiError) as exc:
        print(f"{Colors.RED}[-] Error: {exc}{Colors.NOCOLOR}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
