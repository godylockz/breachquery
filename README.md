# DeHashed v2 Query Tool

`dehashquery.py` queries the [DeHashed API v2](https://app.dehashed.com/documentation/api)
to dump and parse breach data (emails, usernames, passwords, and password hashes)
for one or more domains, with optional breach-metadata enrichment.

> **Note:** The legacy v1 API is fully deprecated. You must use a v2 API key — if
> you generated yours before the v2 migration, refresh it once from your
> [DeHashed profile](https://app.dehashed.com/profile).

## Features

- **Correct, current v2 schema** — emits every field the API returns today
  (email, username, password, hashed_password, name, dob, license_plate, address,
  phone, company, url, social, cryptocurrency_address, database_name).
- **Full pagination** — automatically pages through results up to the API's
  50,000-per-query cap (deep pages fetched sequentially, as the API requires).
- **Rate-limit aware** — client-side throttle (default 15 req/s, under the 20 req/s
  limit) plus automatic retry/back-off on `429`/`5xx`.
- **Credit-safe** — checks search access and credit balance *before* querying, and
  prompts for confirmation (skippable with `-y`). Cached results are reused so you
  never pay twice for the same domain.
- **Secret-safe key handling** — the key is read from `.env` or an environment
  variable, never required on the command line.
- **Multi-domain** — pass a single `--domain` or a `--domains` file.
- **Breach enrichment** (`--full`) — joins each record against DeHashed's free
  `data-wells` feed to add breach date, record count, sensitivity, and description.
- **Free password check** — SHA-256 password-appearance lookup that costs no credits.

## Install

```sh
pip install -r requirements.txt
cp .env.example .env      # then edit .env and paste your API key
```

## API key

Resolved in this order:

1. `--api-key <key>` (or `-k`)
2. `DEHASHED_API_KEY` environment variable
3. a `.env` file (`DEHASHED_API_KEY=...`) in the current dir or next to the script

`.env` is git-ignored.

## Usage

```text
dehashquery.py [-v] [--no-color] {dump,password-check,credits} ...
```

### Dump a domain

```sh
# `dump` is the default subcommand, so this also works: dehashquery.py -d example.com
python3 dehashquery.py dump -d example.com
python3 dehashquery.py dump --domains domains.txt --full -y
```

Key `dump` options:

| Option | Description |
| --- | --- |
| `-d, --domain` | Single domain to query |
| `--domains` | File with newline-separated domains |
| `-q, --query` | Raw DeHashed query (overrides `domain:<domain>`) |
| `-s, --size` | Results per page, 1–10000 (default 10000) |
| `-o, --output-dir` | Base output directory (default `output/`) |
| `--full` | Add breach-metadata columns to the CSV (free) |
| `--refresh` | Ignore cached results and re-query |
| `-y, --yes` | Skip the credit-confirmation prompt |

### Check a password (free, no credits)

```sh
python3 dehashquery.py password-check 'Password12345'
```

The password is SHA-256 hashed locally and only the hash is sent.

### Show credit balances

```sh
python3 dehashquery.py credits
```

## Output

Written to `output/<domain>/`:

| File | Contents |
| --- | --- |
| `emails.txt` | Unique email addresses |
| `users.lst` | Unique emails + usernames (spraying candidates) |
| `passwords.lst` | Unique plaintext passwords |
| `emailAndPassword.txt` | `email:password` pairs |
| `emailAndHash.txt` | `email:hash` pairs |
| `outData.csv` | Full per-record table (+ breach metadata with `--full`) |
| `allData.json` | Cached raw API response for the domain |

All generated output and `.env` are git-ignored.

## Notes & limits

- 1 search = 1 credit. Cached domains are not re-queried unless you pass `--refresh`.
- The API returns at most 50,000 results per query; larger result sets are truncated
  (a warning is printed).
- WHOIS and monitoring endpoints exist in the v2 API but are out of scope for this tool.

---

# HackNotice Research Query Tool

`hacknoticequery.py` is a conservative companion to `dehashquery.py`. It queries
the [HackNotice](https://hacknotice.com/) Research API (`research8` phrase search)
for credential exposures on a domain and writes the **same output files** as the
DeHashed tool, but limited to a recent window (default: the last 90 days).

> **Access:** the HackNotice API is for approved accounts only and requires a
> prior consultation with HackNotice. This tool cannot get you access — it only
> uses credentials you already have.

## Conservative by design

- **Count first.** A count query runs before anything is fetched, and you confirm
  the estimated page count before spending on record pages (skip with `-y`).
- **Hard page cap.** `--max-pages` bounds retrieval per domain (default 10 pages,
  50 rows/page). Larger result sets are truncated to the most recent rows.
- **Recent window only.** Defaults to the last 90 days (`--days`); results are
  ordered newest-first so a page cap keeps the most recent exposures.
- **Rate-limit safe.** Requests are throttled below HackNotice's documented
  1 request/second governor (`--min-interval`).
- **Cached.** A domain is not re-queried unless you pass `--refresh`.

> **Billing:** HackNotice does not publish per-request billing for count and page
> queries. Confirm how they are metered on your contract before raising the caps.

## Testing access without spending credits

`hacknoticequery.py verify` authenticates and calls HackNotice's own credential-test
endpoint (`POST /auth/verify`). It never touches the research/search surface, so it
consumes no search credits — use it to confirm a key, a sign-in, or connectivity
before running any real query:

```sh
python3 hacknoticequery.py verify                 # uses .env / environment creds
python3 hacknoticequery.py verify --integration-key hn_ik_...
```

If you use HackNotice's MCP server instead, its `hacknotice_verify_credentials`
tool serves the same purpose. (The `count` subcommand returns totals without
fetching records, but whether *count* queries are metered is not published — treat
`verify` as the guaranteed no-cost check.)

## Credentials

Resolved in order — CLI flag → environment variable → `.env` file:

1. `HACKNOTICE_INTEGRATION_KEY` (preferred; a single `X-HackNotice-Integration-Key` header), **or**
2. `HACKNOTICE_API_KEY` + `HACKNOTICE_EMAIL` + `HACKNOTICE_PASSWORD` (JWT sign-in).

`.env` is git-ignored. See `.env.example`.

## Usage

```sh
# Verify credentials + connectivity — spends no search credits
python3 hacknoticequery.py verify

# Count only — fetches no records
python3 hacknoticequery.py count -d example.com

# Dump last 90 days (count, confirm, then fetch — capped at 10 pages)
python3 hacknoticequery.py dump -d example.com

# Wider window, higher cap, no prompt
python3 hacknoticequery.py dump -d example.com --days 30 --max-pages 20 -y
```

Key `dump` options:

| Option | Description |
| --- | --- |
| `-d, --domain` | Single domain to query |
| `--domains` | File with newline-separated domains |
| `--days` | Look-back window in days (default 90) |
| `--searchtype` | Phrase match: `wildcard_pre` (default), `wildcard_both`, `wildcard_post`, `match_phrase` |
| `--max-pages` | Max pages fetched per domain (default 10, 50 rows/page) |
| `--min-interval` | Min seconds between requests (default 1.1) |
| `-o, --output-dir` | Base output directory (default `output/`) |
| `--refresh` | Ignore cache and re-query |
| `-y, --yes` | Skip the confirmation prompt |

## Output

Identical layout to `dehashquery.py` (written to `output/<domain>/`): `emails.txt`,
`users.lst`, `passwords.lst`, `emailAndPassword.txt`, `emailAndHash.txt`,
`outData.csv`, and a cached `allData.json`. HackNotice records are mapped onto the
same entry schema, so both tools' outputs can be diffed or merged directly.
