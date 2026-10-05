# SentinelAPI — AI-Driven OpenAPI Contract Tester & Security Fuzzer

Reads an OpenAPI/Swagger spec, ranks endpoints by fuzz-risk, generates hostile inputs
(boundary values, type confusion, SQLi / XSS / path-traversal payloads, plus optional
Claude-generated inputs), fires them concurrently with `httpx`, and classifies the responses.

## Install
    python3 -m venv .venv && . .venv/bin/activate
    pip install -e ".[dev]"          # installs the `sentinelapi` command
    # or: docker build -t sentinelapi . && docker run --rm -v $PWD:/w sentinelapi /w/spec.json --base-url http://host.docker.internal:8000

## Responsible use
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
