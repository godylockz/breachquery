#!/usr/bin/env python3
"""Query the DeHashed API v2 to dump and parse breach data for a domain.

Reference: https://app.dehashed.com/documentation/api

Subcommands:
  dump             Dump breach data for one or more domains (default).
  password-check   Free SHA-256 password-appearance lookup (no credits used).
  credits          Show your search / WHOIS credit balances.

The API key is resolved from $DEHASHED_API_KEY or a .env file
(DEHASHED_API_KEY=...) in the current directory or next to this script. Secrets
are not accepted as command-line arguments because those can be exposed in the
process list and shell history.
"""

from __future__ import annotations

from itertools import product
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import argparse
import csv
import getpass
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import deque
from urllib.parse import urlsplit

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write("[-] Missing dependency 'requests'. Install with: pip install -r requirements.txt\n")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
SEARCH_URL = "https://api.dehashed.com/v2/search"
HASH_LOOKUP_URL = "https://api.dehashed.com/v2/search-password"
USER_INFO_URL = "https://api.dehashed.com/v2/info/user"
DATA_WELLS_URL = "https://api.dehashed.com/data-wells"

MAX_SIZE = 10_000          # API hard cap for `size`
MAX_TOTAL = 50_000         # API hard cap for page*size (total results per query)
DEFAULT_RATE = 15          # client-side requests/second (API limit is 20/s)
REQUEST_TIMEOUT = 60       # seconds
DEHASHED_CACHE_SOURCE = "dehashed-v2"

# Entry fields exposed by the current v2 API, in CSV column order.
ENTRY_FIELDS = [
    "email", "ip_address", "username", "password", "hashed_password",
    "name", "dob", "license_plate", "address", "phone", "company",
    "url", "social", "cryptocurrency_address", "database_name",
]
CSV_HEADER = [
    "Email", "IP Address", "Username", "Password", "Hash", "Name", "DOB",
    "License Plate", "Address", "Phone", "Company", "URL", "Social",
    "Cryptocurrency Address", "Database",
]
FULL_EXTRA_HEADER = ["Breach Date", "Breach Records", "Sensitive", "Breach Description"]


log = logging.getLogger("dehashquery")


class Colors:
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    NOCOLOR = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        cls.GREEN = cls.CYAN = cls.YELLOW = cls.RED = cls.NOCOLOR = ""


# --------------------------------------------------------------------------- #
# API key resolution
# --------------------------------------------------------------------------- #
def parse_env_file(path: Path) -> Dict[str, str]:
    """Minimal .env parser (KEY=VALUE, ignores blanks/comments/quotes)."""
    values: Dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            val = val.strip().strip('"').strip("'")
            values[key] = val
    except OSError as exc:
        log.debug("Could not read %s: %s", path, exc)
    return values


def resolve_api_key() -> str:
    """Resolve the API key from the environment or a .env file."""
    env_key = os.environ.get("DEHASHED_API_KEY")
    if env_key:
        return env_key.strip()

    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"):
        if candidate.is_file():
            key = parse_env_file(candidate).get("DEHASHED_API_KEY")
            if key:
                log.debug("Loaded API key from %s", candidate)
                return key.strip()

    raise SystemExit(
        f"{Colors.RED}[-] No API key found.{Colors.NOCOLOR} Set the "
        "DEHASHED_API_KEY environment variable or use a .env file "
        "(cp .env.example .env and edit it)."
    )


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Simple sliding-window limiter to stay under `rate` requests/second."""

    def __init__(self, rate: int = DEFAULT_RATE) -> None:
        self.rate = max(1, rate)
        self._calls: deque[float] = deque()

    def wait(self) -> None:
        now = time.monotonic()
        while self._calls and now - self._calls[0] >= 1.0:
            self._calls.popleft()
        if len(self._calls) >= self.rate:
            sleep_for = 1.0 - (now - self._calls[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._calls.append(time.monotonic())


class ApiError(RuntimeError):
    """A non-200 response from the DeHashed API, carrying status and message."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message

    def is_pagination_limit(self) -> bool:
        """True when the server refused a page for a depth/pagination reason."""
        m = self.message.lower()
        return self.status_code == 400 and (
            "pagination" in m or "paginate" in m
        )


class DehashedClient:
    """Thin, resilient wrapper over the DeHashed v2 REST API."""

    def __init__(self, api_key: str, rate: int = DEFAULT_RATE) -> None:
        self.limiter = RateLimiter(rate)
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Dehashed-Api-Key": api_key,
            "User-Agent": "dehashquery/2.0 (+https://github.com/)",
        })
        retry = Retry(
            total=5,
            connect=3,
            read=3,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _request(self, method: str, url: str, **kwargs: Any) -> Dict[str, Any]:
        self.limiter.wait()
        try:
            resp = self.session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"Request to {url} failed: {exc}") from exc

        try:
            data = resp.json()
        except ValueError:
            data = {"error": resp.text.strip() or f"HTTP {resp.status_code}"}

        if resp.status_code != 200:
            msg = data.get("error", "Unknown error") if isinstance(data, dict) else str(data)
            raise ApiError(resp.status_code, str(msg))
        return data

    def user_info(self) -> Dict[str, Any]:
        return self._request("GET", USER_INFO_URL)

    def search(self, query: str, page: int, size: int,
               regex: bool = False, wildcard: bool = False,
               de_dupe: bool = False) -> Dict[str, Any]:
        payload = {
            "query": query, "page": page, "size": size,
            "regex": regex, "wildcard": wildcard, "de_dupe": de_dupe,
        }
        return self._request("POST", SEARCH_URL, json=payload)

    def search_password(self, sha256_hash: str) -> Dict[str, Any]:
        return self._request("POST", HASH_LOOKUP_URL,
                             json={"sha256_hashed_password": sha256_hash})

    def data_wells_page(self, page: int, count: int = 50,
                        sort: str = "name-ASC") -> Dict[str, Any]:
        return self._request("GET", DATA_WELLS_URL,
                             params={"page": page, "count": count, "sort": sort})


# --------------------------------------------------------------------------- #
# Search / pagination
# --------------------------------------------------------------------------- #
# Entry fields that identify a record's content, ignoring which breach it came
# from. Used to collapse the same record seen across multiple datasets, which is
# what the server's de_dupe did before we moved de-duplication client-side.
_SIGNATURE_FIELDS = [f for f in ENTRY_FIELDS if f != "database_name"]


def entry_signature(entry: Dict[str, Any]) -> tuple:
    """A content fingerprint for an entry, independent of its source database."""
    return tuple(
        tuple(sorted(normalize_field(entry.get(f, ""), f)))
        for f in _SIGNATURE_FIELDS
    )


def fetch_all_entries(client: DehashedClient, query: str, size: int,
                      de_dupe: bool = True) -> Dict[str, Any]:
    """Fetch every page for `query` and de-duplicate results.

    Pages are always requested with the server's own ``de_dupe`` OFF. Confirmed
    against the live API:
      * de_dupe=true with a large ``size`` returns HTTP 400 "issue with search"
        (it only works up to size~1000), which would force ~10x more requests.
      * Billing is 1 credit per request regardless of ``size``, so the largest
        page size (fewest requests) is also the cheapest.
      * Raw pages overlap (the same record recurs across pages), so client-side
        de-duplication on entry content is required, not optional.
    We therefore fetch raw at the largest page size and de-duplicate client-side.
    Deep pagination past the 10k offset works (the 50k page*size cap is the real
    limit), but the loop still stops cleanly if the server ever refuses a page.
    """
    size = max(1, min(size, MAX_SIZE))
    log.info("Query: %s", query)
    first = client.search(query, page=1, size=size)
    total = int(first.get("total", 0) or 0)
    balance = first.get("balance")

    seen: set = set()
    entries: List[Dict[str, Any]] = []

    def collect(page_entries: List[Dict[str, Any]]) -> int:
        added = 0
        for e in page_entries:
            if de_dupe:
                sig = entry_signature(e)
                if sig in seen:
                    continue
                seen.add(sig)
            entries.append(e)
            added += 1
        return added

    collect(first.get("entries", []) or [])

    reachable = min(total, MAX_TOTAL)
    if total > MAX_TOTAL:
        log.warning("total=%d exceeds the API cap of %d; results will be truncated.",
                    total, MAX_TOTAL)

    last_page = min(reachable // size + (1 if reachable % size else 0), MAX_TOTAL // size)
    log.info("total=%d  fetching up to %d page(s) at size=%d", total, max(last_page, 1), size)

    # Deep pagination beyond 10k must be sequential; a simple ascending loop
    # satisfies that. The server is the source of truth for the real depth cap:
    # stop and keep what we have if it rejects a page.
    for page in range(2, last_page + 1):
        try:
            result = client.search(query, page=page, size=size)
        except ApiError as exc:
            if exc.is_pagination_limit():
                log.warning("Server stopped pagination at page %d (%s); "
                            "keeping %d entries fetched so far.",
                            page, exc.message, len(entries))
                break
            raise
        page_entries = result.get("entries", []) or []
        if not page_entries:
            break
        collect(page_entries)
        log.info("  page %d/%d (%d unique entries so far)", page, last_page, len(entries))

    return {
        "source": DEHASHED_CACHE_SOURCE,
        "balance": balance,
        "total": total,
        "entries": entries,
    }


# --------------------------------------------------------------------------- #
# Data-wells breach enrichment (free feed)
# --------------------------------------------------------------------------- #
def load_data_wells(client: DehashedClient, cache_file: Path,
                    refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """Return {lowercased breach name: metadata}, cached to disk."""
    if cache_file.is_file() and not refresh:
        log.info("Reading data wells from %s", cache_file)
        wells = json.loads(cache_file.read_text(encoding="utf-8"))
    else:
        log.info("Downloading breach metadata (data-wells)...")
        wells = []
        page = 1
        while True:
            result = client.data_wells_page(page=page, count=50)
            batch = result.get("data_wells", []) or []
            wells.extend(batch)
            if not result.get("next_page") or not batch:
                break
            page += 1
            if page % 20 == 0:
                log.info("  ...%d breaches", len(wells))
        cache_file.write_text(json.dumps(wells, indent=2), encoding="utf-8")
        log.info("Cached %d breaches to %s", len(wells), cache_file)

    return {str(w.get("name", "")).lower(): w for w in wells if w.get("name")}


# --------------------------------------------------------------------------- #
# Output processing
# --------------------------------------------------------------------------- #
def normalize_field(value: Any, field_name: str) -> List[str]:
    """Normalize and filter a single entry field into a clean list of strings."""
    values = value if isinstance(value, list) else [value]
    result: List[str] = []
    for v in values:
        if v is None or v == "":
            continue
        v = str(v)
        if field_name == "name":
            if "@" in v:
                continue  # skip emails mislabeled as names
            v = " ".join(word.capitalize() for word in v.split())
        elif field_name == "email":
            v = v.lower()
        elif field_name == "hashed_password":
            if ":None||" in v:
                continue
            if ":||" in v:
                v = v.split(":||")[0]
        v = v.strip()
        if v:
            result.append(v)
    return result


class DumpProcessor:
    """Turn raw entries into the emails / passwords / hashes / CSV output files."""

    def __init__(self, domain: str, out_dir: Path,
                 wells: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.domain = domain
        self.out_dir = out_dir
        self.wells = wells or {}
        self.full = wells is not None

    def process(self, entries: List[Dict[str, Any]]) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._write_emails(entries)
        self._write_users(entries)
        self._write_email_passwords(entries)
        self._write_passwords(entries)
        self._write_email_hashes(entries)
        self._write_csv(entries)

    def _write_emails(self, entries: List[Dict]) -> None:
        rows = set()
        for e in entries:
            rows.update(normalize_field(e.get("email", ""), "email"))
        self._write_lines("emails.txt", sorted(rows))

    def _write_users(self, entries: List[Dict]) -> None:
        rows = set()
        for e in entries:
            rows.update(normalize_field(e.get("email", ""), "email"))
            rows.update(normalize_field(e.get("username", ""), "username"))
        self._write_lines("users.lst", sorted(rows))

    def _write_passwords(self, entries: List[Dict]) -> None:
        rows = set()
        for e in entries:
            rows.update(normalize_field(e.get("password", ""), "password"))
        self._write_lines("passwords.lst", sorted(rows))

    def _write_email_passwords(self, entries: List[Dict]) -> None:
        rows = set()
        for e in entries:
            emails = normalize_field(e.get("email", ""), "email")
            passwords = normalize_field(e.get("password", ""), "password")
            rows.update(f"{a}:{b}" for a, b in product(emails, passwords))
        self._write_lines("emailAndPassword.txt", sorted(rows))

    def _write_email_hashes(self, entries: List[Dict]) -> None:
        rows = set()
        for e in entries:
            emails = normalize_field(e.get("email", ""), "email")
            hashes = normalize_field(e.get("hashed_password", ""), "hashed_password")
            rows.update(f"{a}:{b}" for a, b in product(emails, hashes))
        self._write_lines("emailAndHash.txt", sorted(rows))

    def _write_csv(self, entries: List[Dict]) -> None:
        header = CSV_HEADER + (FULL_EXTRA_HEADER if self.full else [])
        path = self.out_dir / "outData.csv"
        count = 0
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for e in entries:
                row = ["; ".join(normalize_field(e.get(fld, ""), fld)) for fld in ENTRY_FIELDS]
                if self.full:
                    row.extend(self._breach_columns(e.get("database_name", "")))
                writer.writerow(row)
                count += 1
        print(f"{Colors.GREEN}[*] outData.csv created, {count} rows.{Colors.NOCOLOR}")

    def _breach_columns(self, database_name: Any) -> List[str]:
        meta = self.wells.get(str(database_name).lower(), {})
        return [
            str(meta.get("date", "")),
            str(meta.get("records", "")),
            str(meta.get("is_sensitive", "")),
            str(meta.get("description", "")),
        ]

    def _write_lines(self, filename: str, rows: Iterable[str]) -> None:
        rows = list(rows)
        path = self.out_dir / filename
        path.write_text(("\n".join(rows) + "\n") if rows else "", encoding="utf-8")
        print(f"{Colors.GREEN}[*] {filename} created, {len(rows)} entries.{Colors.NOCOLOR}")


# --------------------------------------------------------------------------- #
# Credit pre-flight & confirmation
# --------------------------------------------------------------------------- #
def preflight(client: DehashedClient, assume_yes: bool) -> None:
    """Verify search access and credits before spending anything."""
    info = client.user_info()
    if not info.get("search_access", False):
        raise SystemExit(f"{Colors.RED}[-] This API key has no search access. "
                         f"Purchase a search subscription to continue.{Colors.NOCOLOR}")
    credits = int(info.get("search_credits", 0) or 0)
    print(f"{Colors.CYAN}[*] Search credits available: {credits}{Colors.NOCOLOR}")
    if credits <= 0:
        raise SystemExit(f"{Colors.RED}[-] No search credits remaining.{Colors.NOCOLOR}")
    if assume_yes:
        return
    while True:
        ans = input("Run new API queries and consume credits? (y/n): ").strip().lower()
        if ans in ("y", "yes"):
            return
        if ans in ("n", "no"):
            raise SystemExit("[*] Aborted by user.")
        print("Please enter 'y' or 'n'.")


# --------------------------------------------------------------------------- #
# Subcommand handlers
# --------------------------------------------------------------------------- #
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(raw: str) -> str:
    """Return a canonical DNS name, rejecting unsafe or malformed input."""
    value = raw.strip()
    if not value:
        raise ValueError("domain is empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("domain contains control characters")

    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("only http and https URLs are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo is not allowed in a domain")
    try:
        host = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("domain has an invalid port") from exc
    if not host or ":" in host:
        raise ValueError("a DNS hostname is required")

    host = host.rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc

    if len(host) > 253 or not all(_DOMAIN_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("domain is not a valid DNS hostname")
    return host


def load_domains(args: argparse.Namespace) -> List[str]:
    domains: List[str] = []
    domain_file = getattr(args, "domains", None)
    single_domain = getattr(args, "domain", None)
    if domain_file:
        try:
            domains = Path(domain_file).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise SystemExit(f"[-] Could not read domain file {domain_file!r}: {exc}") from exc
    elif single_domain:
        domains = [single_domain]

    cleaned: List[str] = []
    for raw in domains:
        if not raw.strip():
            continue
        try:
            cleaned.append(normalize_domain(raw))
        except ValueError as exc:
            log.error("Rejected invalid domain input %r: %s", raw[:200], exc)
            raise SystemExit(f"[-] Invalid domain {raw!r}: {exc}") from exc
    return list(dict.fromkeys(cleaned))


def load_cached_data(cache: Path) -> Any:
    """Load a DeHashed cache and reject foreign or malformed data."""
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        log.error("Rejected unreadable cache %s: %s", cache, exc)
        raise RuntimeError(f"Could not read cache {cache}; use --refresh to replace it.") from exc

    if isinstance(data, dict):
        source = data.get("source")
        if source not in (None, DEHASHED_CACHE_SOURCE):
            log.error("Rejected cache with unexpected source marker %r: %s", source, cache)
            raise RuntimeError(
                f"Cache {cache} is not a DeHashed cache; choose another "
                "--output-dir or use --refresh to replace it."
            )
        entries = data.get("entries")
    else:
        entries = data

    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        log.error("Rejected cache with invalid entries: %s", cache)
        raise RuntimeError(f"Cache {cache} has invalid entries; use --refresh to replace it.")
    return data


def cmd_dump(args: argparse.Namespace) -> int:
    domains = load_domains(args)
    if not domains:
        raise SystemExit(f"{Colors.RED}[-] No valid domains supplied.{Colors.NOCOLOR}")

    api_key = resolve_api_key()
    client = DehashedClient(api_key, rate=args.rate)
    base_dir = Path(args.output_dir)

    wells: Optional[Dict[str, Dict[str, Any]]] = None
    need_query = any(
        not (base_dir / d / "allData.json").is_file() or args.refresh for d in domains
    )
    if need_query:
        preflight(client, args.yes)
    if args.full:
        wells = load_data_wells(client, base_dir / "data-wells.json", refresh=args.refresh)

    for domain in domains:
        out_dir = base_dir / domain
        cache = out_dir / "allData.json"
        print(f"{Colors.CYAN}[*] Target: {domain}  ->  {out_dir}{Colors.NOCOLOR}")

        if cache.is_file() and not args.refresh:
            print(f"{Colors.CYAN}[*] Using cached data ({cache}). Use --refresh to re-query.{Colors.NOCOLOR}")
            data = load_cached_data(cache)
        else:
            query = args.query or f"domain:{domain}"
            data = fetch_all_entries(client, query, size=args.size,
                                     de_dupe=not args.no_dedupe)
            out_dir.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"{Colors.CYAN}[*] Cached {len(data.get('entries', []))} entries "
                  f"to {cache}{Colors.NOCOLOR}")

        entries = data.get("entries", data) if isinstance(data, dict) else data
        DumpProcessor(domain, out_dir, wells=wells).process(entries)
        if isinstance(data, dict) and data.get("balance") is not None:
            print(f"{Colors.CYAN}[*] Remaining balance: {data['balance']}{Colors.NOCOLOR}")

    print(f"{Colors.GREEN}[*] Done{Colors.NOCOLOR}")
    return 0


def cmd_password_check(args: argparse.Namespace) -> int:
    api_key = resolve_api_key()
    client = DehashedClient(api_key, rate=args.rate)
    password = getpass.getpass("Password to check: ")
    if not password:
        raise SystemExit(f"{Colors.RED}[-] Password cannot be empty.{Colors.NOCOLOR}")
    sha256_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    result = client.search_password(sha256_hash)
    found = result.get("results_found", 0)
    color = Colors.RED if found else Colors.GREEN
    print(f"{color}[*] Password appears in {found} record(s). (sha256={sha256_hash}){Colors.NOCOLOR}")
    return 0


def cmd_credits(args: argparse.Namespace) -> int:
    api_key = resolve_api_key()
    client = DehashedClient(api_key, rate=args.rate)
    info = client.user_info()
    print(f"{Colors.CYAN}[*] Search access : {info.get('search_access')}{Colors.NOCOLOR}")
    print(f"{Colors.CYAN}[*] Search credits: {info.get('search_credits')}{Colors.NOCOLOR}")
    print(f"{Colors.CYAN}[*] WHOIS credits : {info.get('whois_credits')}{Colors.NOCOLOR}")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dehashquery.py",
        description="Query the DeHashed API v2 and parse breach data.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--rate", type=int, default=DEFAULT_RATE,
                       help=f"Max requests/second (default {DEFAULT_RATE}, API limit 20)")
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
        p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    sub = parser.add_subparsers(dest="command")

    dump = sub.add_parser("dump", help="Dump breach data for domain(s)")
    add_common(dump)
    grp = dump.add_mutually_exclusive_group(required=True)
    grp.add_argument("-d", "--domain", help="Single domain to query")
    grp.add_argument("--domains", help="File with newline-separated domains")
    dump.add_argument("-q", "--query", help="Raw DeHashed query (overrides domain:<domain>)")
    dump.add_argument("-s", "--size", type=int, default=MAX_SIZE,
                      help=f"Results per page 1-{MAX_SIZE} (default {MAX_SIZE})")
    dump.add_argument("--no-dedupe", action="store_true",
                      help="Keep raw entries; skip client-side de-duplication")
    dump.add_argument("-o", "--output-dir", default="output", help="Base output directory")
    dump.add_argument("--full", action="store_true",
                      help="Add breach metadata columns to the CSV (free data-wells feed)")
    dump.add_argument("--refresh", action="store_true", help="Ignore cache and re-query")
    dump.add_argument("-y", "--yes", action="store_true", help="Skip the credit confirmation prompt")
    dump.set_defaults(func=cmd_dump)

    pw = sub.add_parser("password-check", help="Free SHA-256 password appearance lookup")
    add_common(pw)
    pw.set_defaults(func=cmd_password_check)

    cr = sub.add_parser("credits", help="Show credit balances")
    add_common(cr)
    cr.set_defaults(func=cmd_credits)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backward compatibility: default to the `dump` subcommand when none is given.
    subcommands = {"dump", "password-check", "credits"}
    if argv and not any(h in argv for h in ("-h", "--help")):
        first_positional = next((a for a in argv if not a.startswith("-")), None)
        if first_positional not in subcommands:
            argv.insert(0, "dump")

    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(message)s",
    )
    if getattr(args, "no_color", False) or not sys.stdout.isatty():
        Colors.disable()

    if not getattr(args, "func", None):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        return 130
    except (RuntimeError, SystemExit) as exc:
        if isinstance(exc, SystemExit):
            raise
        print(f"{Colors.RED}[-] Error: {exc}{Colors.NOCOLOR}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
