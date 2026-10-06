# ScriptLens

Find JavaScript requests and useful security-review clues from domains, URLs or
local files. ScriptLens downloads pages and their scripts, parses JavaScript and
TypeScript, and automatically saves a JSON report with endpoint data, curl
templates and source evidence.

Terminal output stays short: no banners, emojis, random path dumps or repeated
failure rows. Help is always plain. Only result labels can have color.

## Install

Requires Python 3.11 or newer. No Node.js or browser installation is needed.

```bash
git clone https://github.com/obsec07/scriptlens.git
cd scriptlens
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
scriptlens --help
```

Run `pip install .` from the directory containing `pyproject.toml`, not your home
or `docs` directory. On Windows, activate with `.venv\Scripts\activate` instead.

To update an existing clone:

```bash
cd scriptlens
git pull --ff-only
source .venv/bin/activate
python -m pip install --upgrade .
scriptlens --version
```

## Run it

Use only assets you are authorized to inspect. Domains default to HTTPS. Supply
an explicit `http://` URL for HTTP. TLS certificates are verified by default;
`-k`, `--insecure`, and `--no-ssl-verify` disable this check.

```bash
# Single domain, URL, or several targets
scriptlens scan example.com
scriptlens scan example.com https://app.example.com/dashboard

# One hostname/URL per line; duplicate targets are removed
scriptlens scan hosts.txt
scriptlens scan -l domains.txt -l urls.txt -o results.json
cat urls.txt | scriptlens scan -

# Equivalent explicit flags
scriptlens scan -d example.com -u https://app.example.com/

# Plain output with curl templates; JSON is still saved automatically
scriptlens scan -l urls.txt --raw --show-curl -o requests.json

# Direct JS input: supply the page URL to resolve relative fetch URLs correctly
scriptlens scan https://cdn.example.com/app.js --base-url https://app.example.com/

# Authorized sibling hosts and CDN assets
scriptlens scan https://app.example.com/ --scope example.com --asset-host cdn.example.net

# Analyze downloaded code without any network requests
scriptlens analyze bundle.js original.ts app.js.map --base-url https://app.example.com/ -o local.json

# Offline example included in the repository
scriptlens analyze tests/fixtures/demo.js --base-url https://demo.example.test/ --show-curl
```

`--base-url` is the **document URL**, not the script directory. A script served
from a CDN can make relative API calls against the page's origin. When this
context is unknown, ScriptLens uses `{{BASE_URL}}` rather than inventing a host.

## What you get

```text
[GET] https://demo.example.test/api/orders/{{orderId}}
[POST] https://demo.example.test/api/v2/users; body: email, role
Done: 4 sources, 2 endpoints, 0 review items, 0 incomplete.
Saved: scriptlens-results/20261006-120000-a1b2c3.json
```

Every run saves JSON, including runs with incomplete downloads or syntax errors.
The default location is a unique file under `scriptlens-results/`. Use `-o FILE`
to choose it. Existing files are never overwritten. New reports use mode `0600`
on platforms that support Unix permissions.

Each endpoint includes:

- Method, resolved URL or URL template, request library and source file/line/column.
- Recoverable headers, query parameters (including duplicates), body data and body completeness.
- A shell-quoted curl template, or `null` when the method/protocol cannot be represented reliably.
- Explicit unknowns such as `{{user.email}}`, request-specific caveats and review suggestions.
- All matching source locations after deduplication; different request bodies remain separate.

For example, an Axios POST may produce this curl template:

```bash
curl --globoff --request POST --url https://demo.example.test/api/v2/users \
  --header 'Content-Type: application/json' \
  --data-raw '{"email":"{{user.email}}","role":"member"}'
```

Fill placeholders and add your authorized session details before using a curl
example. These are source-derived templates, not captured browser requests.
ScriptLens never executes them or sends the extracted GET/POST/PUT/DELETE requests.
Multipart templates use text fields; choose actual file-upload fields manually.

The report also contains `findings`, `graphql_operations`, `sources` with hashes,
`unresolved_requests`, `diagnostics`, `summary`, settings and timestamps. Likely
credentials and sensitive request values are redacted by default; credential
findings include a fingerprint for correlation. Raw downloaded source is not
written to disk. Redaction is best-effort: unusual formats can escape detection.

## Coverage

| Area | Supported evidence |
| --- | --- |
| Discovery | HTML scripts, inline JavaScript, module/script preloads, static imports/exports, literal dynamic imports, Worker/importScripts references, bounded page links |
| Source maps | Declared `sourceMappingURL`, `SourceMap`/`X-SourceMap` headers, inline data maps and embedded `sourcesContent`; JS, TS and TSX originals |
| Requests | Global Fetch, `new Request`, common `new URL` construction, Axios calls/aliases/instances, jQuery AJAX/get/post/getJSON, linear XHR open/header/send sequences |
| Request data | Literal/constant URL construction, template placeholders, simple Axios base URLs/headers/params, JSON bodies, URLSearchParams and simple FormData append/set sequences |
| Other network APIs | Beacon POSTs, WebSocket and EventSource URLs; streaming protocols do not get misleading HTTP curl examples |
| GraphQL | Query text, named operations and declared variable names from request bodies or `gql`/`graphql` tagged templates; no introspection is sent |
| Credential clues | GitHub/Stripe secret-token formats, private-key blocks, sensitive hardcoded values with length/entropy controls; no credential validation |
| Browser security | Short local flows from URL/referrer/message data to HTML, eval, redirects or Fetch URLs; sensitive storage writes; sensitive fields in wildcard postMessage calls |
| Endpoint review | Suggestions for object/tenant authorization, admin access and state-changing requests, based on the observed request shape |

Security findings are **review clues**, never confirmed vulnerabilities. Priority
means review order, not proven impact. Ordinary Firebase client configuration,
OAuth client IDs, static HTML assignments, theme storage, harmless message
handlers and arbitrary strings that resemble paths are not automatically flagged.

A static tool cannot find every endpoint or guarantee zero false positives.
Runtime webpack chunk loaders, obfuscation, authentication-only pages, framework
wrappers, imported values, alias-heavy code, interceptors, object mutation and
cross-function data flow may be missed. The analyzer resolves simple local
bindings, not an entire running application. It does not prove server-side
access control, token validity, dependency CVEs, business-logic flaws or exploitability.

See [the research notes](docs/RESEARCH.md) for the articles, papers, design choices
and the manual checks that remain useful.

## Quiet output and colors

By default, at most 20 useful results appear in the terminal. All results remain
in JSON. `--max-output N` changes the terminal limit; `-v` shows skipped/failed
source details. The summary always counts incomplete checks.

`--color auto|always|never` changes result labels only. `auto` colors a terminal,
not redirected output. `NO_COLOR` overrides forced colors. `--raw` disables all
colors and the summary. Help, saved JSON and status text are always plain.

| Label | Meaning | Color |
| --- | --- | --- |
| `GET`, `HEAD`, `OPTIONS`, streaming labels | Observed request | Plain |
| `POST`, `PUT`, `PATCH`, `DELETE` | Observed state-changing method | Cyan |
| `KEY` | Credential-like value needing review | Yellow |
| `REVIEW` | Browser security clue needing review | Magenta |

There is no automatic critical/high vulnerability label. Unknown URL calls stay
in `unresolved_requests`, and incomplete fetches stay in `diagnostics` rather
than becoming noisy per-host findings.

## Boundaries and limits

Only supplied hostnames are fetched by default. `--scope DOMAIN` adds that domain
and its subdomains. `--asset-host HOST` adds one exact hostname for scripts/maps,
not general page crawling. Out-of-scope redirects are stopped before the next
request. Private and loopback destinations are blocked unless `--allow-private`
is supplied for an authorized lab. DNS resolution is checked in the connector,
so the address actually used must pass the check.

Defaults: 10 HTML pages, link depth 1, 100 script/map contexts, 6 concurrent
fetches, 8 GET starts/second, 12 seconds/request, 4 MB/file and 80 MB downloaded.
Use the corresponding `--max-pages`, `--depth`, `--max-files`, `--concurrency`,
`--rate`, `--timeout`, `--max-bytes` and `--max-total-bytes` options to adjust them.
Embedded source maps, analysis units, syntax nodes and report items also have
bounds. Hitting a bound is recorded as incomplete, not silently reported as success.
Repeated assets may be analyzed in multiple page contexts but are downloaded once
per resource kind. This is a static collector: it does not run a browser, reuse
cookies, read `.netrc`, use environment proxies, guess undeclared `.map` paths,
validate secrets, or send authentication/exploit requests. Unexpected compressed
responses are skipped to keep download-memory limits enforceable.

Exit codes: `0` collection completed; `2` input/output/internal error; `3` one or
more incomplete checks; `130` interrupted with a partial report. Code 0 and
`complete: true` mean the configured collection completed, not that every runtime
endpoint was found or that the application is secure.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check src tests
ruff format --check src tests
pytest -q
python -m build
```

Tests use synthetic JavaScript and a local HTTP fixture, not live bounty targets.
CI covers Python 3.11–3.14, lint, formatting, tests, packaging and the installed CLI.
