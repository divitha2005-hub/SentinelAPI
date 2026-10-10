# SentinelAPI — AI-Driven OpenAPI Contract Tester & Security Fuzzer

Reads an OpenAPI/Swagger spec, ranks endpoints by fuzz-risk, generates hostile inputs
(boundary values, type confusion, SQLi / XSS / path-traversal payloads, plus optional
Claude-generated inputs), fires them concurrently with `httpx`, and classifies the responses.

## Install
    python3 -m venv .venv && . .venv/bin/activate
    pip install -e ".[dev]"          # installs the `sentinelapi` command
    # or: docker build -t sentinelapi . && docker run --rm -v $PWD:/w sentinelapi /w/spec.json --base-url http://host.docker.internal:8000

## Responsible use
On Windows PowerShell:

    python -m venv .venv
    .\.venv\Scripts\python -m pip install -e ".[dev]"
    .\.venv\Scripts\python -m pytest -q

The development extra includes the form parser required by the bundled demo API.

SentinelAPI sends hostile inputs. By default it only runs against localhost / private-network
targets. A remote target is refused (exit code 2) unless you pass `--authorized`, confirming you
own it or have written permission, or list it with `--allow-host`. Use `--rps` and `--max-requests`
to keep load on a target under control.

## Quick start (bundled vulnerable demo API)
    python -c "import json,demo_api;json.dump(demo_api.app.openapi(),open('demo_openapi.json','w'))"

    # 1. in-process (no server) + server-side code coverage
    sentinelapi demo_openapi.json --asgi demo_api:app --cov-source demo_api.py

    # 2. against a live server, with a login flow
    uvicorn demo_api:app --port 8765 &
    sentinelapi demo_openapi.json --base-url http://127.0.0.1:8765 \
        --login-url /login --login-body '{"user":"admin","password":"secret"}'

    # 3. just the risk ranking
    sentinelapi demo_openapi.json --base-url http://x --list

    pytest -q tests

Outputs `report.html`, `report.md`, `findings.json` and `results.sarif` (GitHub code scanning) in `--out` (default `sentinel_out/`).

## Options
| Flag | Purpose |
|---|---|
| `--top N` | fuzz only the N highest-risk endpoints |
| `--llm` | add Claude-generated, field-aware attack inputs (needs `ANTHROPIC_API_KEY`; model via `SENTINEL_MODEL`) |
| `--header "K: V"`, `--bearer T`, `--basic user:pass` | static credentials |
| `--login-url/--login-body/--token-field` | POST credentials, use the returned token |
| `--asgi module:app` + `--cov-source PATH` | in-process fuzzing with line coverage of the server code |
| `--rps N`, `--max-requests N` | rate limit and hard request budget |
| `--authorized`, `--allow-host H` | permit non-local targets (see Responsible use) |
| `--config FILE` | YAML defaults, see `sentinel.example.yaml` |
| `--fail-on SEVERITY` | exit code 1 if a finding that bad exists (CI gate) |

The request budget includes login, baseline, independent anonymous authentication probes and fuzz requests. `--max-requests 0`
sends no requests and still writes reports; a small budget may cover only part of the spec.
Concurrency must be positive, and the request budget and request rate must be nonnegative
(the rate must also be finite). Nested report directories are created automatically.

## What it detects
SERVER_ERROR, SQL_INJECTION (error-based), SQLI_SUSPECTED (response-size heuristic),
XSS_REFLECTION, PATH_TRAVERSAL, VALIDATION_BYPASS, SCHEMA_VIOLATION (response vs spec),
UNDOCUMENTED_STATUS, AUTH_NOT_ENFORCED, CONNECTION_ERROR.

## Coverage metrics
- **Spec coverage** (always): endpoints fuzzed, documented response codes actually observed, undocumented codes seen.
- **Code coverage** (with `--asgi --cov-source`): % of server lines executed by the fuzzing run.

## Modules
`spec.py` parse + `$ref` resolve · `risk.py` priority score · `generators.py` inputs ·
`llm.py` Claude generator · `auth.py` credentials/login · `engine.py` async fuzzer ·
`classifier.py` findings · `report.py` HTML/MD/JSON · `cli.py`

## Limitations
- SQLi detection is error/size based; blind (time-based) detection is intentionally not included.
- Code coverage needs the app importable in-process (Python ASGI apps); for remote targets only spec coverage is reported.
- Request bodies: JSON, form-urlencoded, multipart and text/plain (Swagger 2 `body`/`formData` too). XML bodies and remote `$ref`s are not handled; `oneOf/anyOf` fuzz the first alternative.
- Risk score is a rule-based index from the spec, not an observed test outcome.

## Project layout
`pyproject.toml` (package + `sentinelapi` entry point) · `Dockerfile` · `.github/workflows/ci.yml`
(tests on 3.10/3.12 + SARIF upload) · `safety.py` target guard · `ratelimit.py` · `sarif.py` · `tests/`

## Repository layout
- `sentinelapi/`, `tests/`, `demo_api.py` : the fuzzer, its tests and the demo target
- `analysis/` : the dataset preprocessing, EDA and visualisation assignment (APIs.guru OpenAPI Directory), see `analysis/README.md`

## Team
Gondu Divitha (23mis0166), Devarla Sowmya Rai (23mis0158), K Meghana (23mis0185), Thatavarthi V S S M M Nagasri Kavya (23mis0057)
Vellore Institute of Technology, Software Metrics

## Windows PowerShell: run the local demo

Run these commands from `C:\SentinelAPI`. Activation is optional; these commands use the virtual environment directly.

```powershell
cd C:\SentinelAPI
# First-time setup only:
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"

# Validate the project:
.\.venv\Scripts\python -m pytest -q

# Export the demo contract and scan in-process (no separate server required):
.\.venv\Scripts\python -c "import json,demo_api; from pathlib import Path; Path('demo_openapi.json').write_text(json.dumps(demo_api.app.openapi()), encoding='utf-8')"
.\.venv\Scripts\sentinelapi demo_openapi.json --asgi demo_api:app --cov-source demo_api.py --out sentinel_out

# Open the HTML report:
Start-Process .\sentinel_out\report.html
```

The demo intentionally contains vulnerabilities. The verified deterministic run produces 7 findings; reports include HTML, Markdown, JSON and SARIF. No Claude key is needed. For a live demo, start `.\.venv\Scripts\uvicorn demo_api:app --host 127.0.0.1 --port 8765` in another PowerShell window from the same directory, then run `.\.venv\Scripts\sentinelapi demo_openapi.json --base-url http://127.0.0.1:8765 --out sentinel_live`. Stop the server with Ctrl+C.

## Contract and authentication checks

Secured endpoints receive an independent anonymous probe, even when the scan uses credentials. The probe strips static credential headers, authorization, cookies and declared API-key parameters. Only a 2xx anonymous response generates `AUTH_NOT_ENFORCED`; errors and redirects do not. These probes count toward rate and request limits. Specs that explicitly permit anonymous access are respected.

JSON request bodies support root strings, numbers, booleans, arrays, objects and null. Contract checks cover nullability, enum/const, numeric bounds and multiples, string length/pattern, required/additional object fields and property counts, array sizes/uniqueness and all array items. Default response schemas are checked. Full JSON Schema dialect/composition and format assertions are not implemented; generation uses the first oneOf/anyOf alternative.

YAML configuration must be a mapping with known option names and appropriate value types. Numeric options use YAML numbers, boolean flags use booleans, and `header`/`allow_host` use lists of strings. Explicit CLI flags override valid configuration defaults. Invalid configuration, missing or malformed specs, invalid login JSON, authentication failures and report filesystem errors produce a concise message and exit code 2.

## Browser dashboard

From PowerShell in `C:\SentinelAPI`, run:

```powershell
.\.venv\Scripts\python -m sentinelapi.web
```

Open **http://127.0.0.1:8766** in your browser. Keep PowerShell open while using the dashboard. Stop it with Ctrl+C. If you need another port, use `--port 9000` and open the matching address.

Click **Run security scan** in the Bundled demo tab for your first scan. Results include endpoint counts, findings, requests and coverage. Search/filter findings, expand **View evidence**, or download HTML, Markdown, JSON and SARIF reports. For your API, start its server, switch to **Your API**, enter its base URL, choose its OpenAPI JSON/YAML file, set limits and run. The local dashboard retains at most 20 report sets in server memory; restarting clears reports, and refreshing clears browser session history. Download reports you want to keep. This UI currently uses deterministic testing and does not expose login or AI settings; those remain available in the CLI.

The existing development environment already has dashboard dependencies. On a fresh environment, install `python -m pip install -e ".[dev]"` from the repository. Alternatively, the `ui` extra provides FastAPI and uvicorn for the dashboard; the bundled demo additionally needs the development extra. Dashboard assets are included as package data. The server binds only to localhost, rejects foreign Host/Origin headers, and retains the scanner's local/private-target restrictions.
