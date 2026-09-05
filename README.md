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
