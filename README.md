# BreachQuery

BreachQuery provides two Python command-line tools for querying authorized
credential-exposure data from [DeHashed](https://www.dehashed.com/) and
[HackNotice](https://hacknotice.com/). Both tools normalize results into the same
set of files, making provider output easier to review, compare, or merge.

Use these tools only with accounts, domains, and data you are authorized to
access. Generated files can contain sensitive information and should be handled
accordingly.

## Tools

| Tool | Provider | Default scope | Built-in safeguards |
| --- | --- | --- | --- |
| `dehashquery.py` | DeHashed API v2 | Domain search across available breach data | Credit preflight, confirmation prompt, 100-query budget, caching, and rate limiting |
| `hacknoticequery.py` | HackNotice Research API | Credential hits from the last 90 days | Count-before-fetch, confirmation prompt, 10-page cap, 300-query budget, caching, and request throttling |

The DeHashed tool also supports raw queries, breach-metadata enrichment, credit
checks, and a free password-appearance check. The HackNotice tool supports a
no-cost credential check before any research query is made.

## Requirements

- Python 3.9 or newer
- A DeHashed v2 API key, HackNotice API access, or both
- HackNotice Research access must already be approved for your account

Install the dependency in a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
```

Add only the credentials for the provider you plan to use. The tools check the
process environment first, then `.env` in the current directory or beside the
scripts.

| Provider | Credentials |
| --- | --- |
| DeHashed | `DEHASHED_API_KEY` |
| HackNotice, preferred | `HACKNOTICE_INTEGRATION_KEY` |
| HackNotice, existing session | `HACKNOTICE_API_KEY` and `HACKNOTICE_JWT_TOKEN` |
| HackNotice, automatic sign-in | `HACKNOTICE_API_KEY`, `HACKNOTICE_EMAIL`, and `HACKNOTICE_PASSWORD` |

Credentials are never accepted as command-line arguments, where they could be
exposed through shell history or process listings. `.env` and generated output
are excluded from Git.

## Quick start

```sh
# Check DeHashed access and balances without running a search
python3 dehashquery.py credits

# Query one domain with DeHashed
python3 dehashquery.py dump -d example.com

# Verify HackNotice credentials without using the research API
python3 hacknoticequery.py verify

# Count recent HackNotice hits without fetching records
python3 hacknoticequery.py count -d example.com

# Count, confirm, and fetch recent HackNotice hits
python3 hacknoticequery.py dump -d example.com
```

## DeHashed usage

`dehashquery.py` uses the current [DeHashed API v2](https://app.dehashed.com/documentation/api).
Legacy v1 keys are not supported; refresh an older key from your
[DeHashed profile](https://app.dehashed.com/profile) before use.

```sh
# `dump` is the default subcommand, so `-d example.com` also works
python3 dehashquery.py dump -d example.com

# Query several newline-separated domains and enrich the CSV with breach metadata
python3 dehashquery.py dump --domains domains.txt --full -y

# Check a password without spending search credits
python3 dehashquery.py password-check

# Show search and WHOIS credit balances
python3 dehashquery.py credits
```

The password check reads from a hidden prompt, hashes the value locally with
SHA-256, and never sends the plaintext password.

Key `dump` options:

| Option | Description |
| --- | --- |
| `-d, --domain` | Query one domain |
| `--domains` | Read newline-separated domains from a file |
| `-q, --query` | Use a raw DeHashed query instead of `domain:<domain>` |
| `-s, --size` | Set results per page from 1 to 10,000 (default: 10,000) |
| `--no-dedupe` | Keep raw entries instead of deduplicating them locally |
| `--rate` | Set requests per second (default: 15; API limit: 20) |
| `--max-queries` | Set the run's billed-search limit (default: 100) |
| `--infinite` | Remove the local query budget; provider limits still apply |
| `--full` | Add free data-wells breach metadata to `outData.csv` |
| `-o, --output-dir` | Change the base directory (default: `output/dehashed/`) |
| `--refresh` | Ignore cached results and query again |
| `-y, --yes` | Skip the credit-use confirmation prompt |

Each search request uses one DeHashed credit. Before a new search, the tool checks
search access and the available balance. Results are cached by domain so repeated
runs do not spend credits unless `--refresh` is supplied. DeHashed returns at most
50,000 results per query; larger result sets are truncated with a warning.

## HackNotice usage

`hacknoticequery.py` queries the HackNotice `research8` phrase-search API. It is
for approved HackNotice accounts and does not provide or bypass API access.

```sh
# Authentication and connectivity only; no research query
python3 hacknoticequery.py verify

# Count hits in the default 90-day window
python3 hacknoticequery.py count -d example.com

# Fetch up to 10 pages after showing the count and asking for confirmation
python3 hacknoticequery.py dump -d example.com

# Search a 30-day window, raise the page cap, and skip confirmation
python3 hacknoticequery.py dump -d example.com --days 30 --max-pages 20 -y

# Process several newline-separated domains
python3 hacknoticequery.py dump --domains domains.txt
```

Key query options:

| Option | Description |
| --- | --- |
| `-d, --domain` | Query one domain |
| `--domains` | Read newline-separated domains from a file |
| `--days` | Set the look-back window (default: 90) |
| `--searchtype` | Use `wildcard_pre` (default), `wildcard_both`, `wildcard_post`, or `match_phrase` |
| `--max-pages` | Set pages fetched per domain (default: 10 at 50 rows per page; `dump` only) |
| `--max-queries` | Set the run's count/page request budget (default: 300) |
| `--infinite` | Remove the query budget; the page cap and provider limits still apply |
| `--min-interval` | Set seconds between requests (default: 1.1; minimum: 1) |
| `-o, --output-dir` | Change the base directory (default: `output/hacknotice/`; `dump` only) |
| `--refresh` | Ignore cached results and query again (`dump` only) |
| `-y, --yes` | Skip the fetch confirmation prompt (`dump` only) |

`verify` calls HackNotice's credential-test endpoint and does not touch the
research API. A `count` request fetches no records, but HackNotice does not publish
whether count or page requests are billed. The local budget therefore counts both
as research queries. Confirm the billing terms for your account before raising or
removing the limit.

When an existing JWT is supplied, the tool sends the API key and token on each
request but does not sign out that session. Replace the token after it expires.
Sessions created by the automatic sign-in flow are signed out when the command
finishes.

## Output

Results are written under `output/dehashed/<domain>/` or
`output/hacknotice/<domain>/`:

| File | Contents |
| --- | --- |
| `emails.txt` | Unique email addresses |
| `users.lst` | Unique email addresses and usernames |
| `passwords.lst` | Unique plaintext passwords |
| `emailAndPassword.txt` | Unique `email:password` pairs |
| `emailAndHash.txt` | Unique `email:hash` pairs |
| `outData.csv` | Normalized records; DeHashed can add breach metadata with `--full` |
| `allData.json` | Provider-specific raw-data cache and query metadata |

Separate provider directories prevent one tool from reading or overwriting the
other tool's cache. Treat the entire output directory as sensitive. Do not commit,
email, or upload it to an untrusted system.

## Tests

```sh
python3 -m unittest discover -s tests -v
python3 dehashquery.py --help
python3 hacknoticequery.py --help
```

## License

[MIT](LICENSE)
