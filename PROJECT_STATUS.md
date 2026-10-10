# SentinelAPI — Project Status

## Project Goal
Test authorized APIs against OpenAPI contracts using deterministic hostile inputs and optional AI inputs; report suspicious responses and coverage.

## Current Architecture
Existing Python 3.10+ package, setuptools entry point `sentinelapi = sentinelapi.cli:main`. Runtime dependencies: httpx and PyYAML. Development dependencies supply pytest, FastAPI, uvicorn and coverage. The analysis notebook and dataset builder are independent of the CLI; no runtime module is unused.

## Execution Pipeline
`cli.main` loads YAML defaults (explicit CLI flags win), calls `load_spec` and `parse_endpoints`, optionally lists risk scores, checks target authorization, imports an ASGI app and starts optional coverage. `Fuzzer` ranks endpoints, applies static/login credentials, sends baselines, generates field mutations and optional LLM cases, dispatches requests with concurrency/rate controls, classifies and deduplicates findings. CLI writes HTML, Markdown, JSON and SARIF and applies a severity exit gate.

Data models: `Param`, `Endpoint`, `Case`, `Finding`. Optional Claude HTTP requests require `ANTHROPIC_API_KEY`; `SENTINEL_MODEL` overrides the model. Deterministic mode requires neither variable. Login credentials, target and output settings come from CLI/config. No retry mechanism exists; HTTP timeout is 10 seconds.

## Completed Features
- [x] Local browser dashboard: real demo/uploaded-spec scans, limits, metrics, search/severity filters, evidence, session history and four downloadable report formats.
The following implementations have been verified by tests and local demo execution:
- [x] Local demo parsing and risk ranking (existing tests).
- [x] Deterministic SQLi, XSS and traversal detection (existing tests and demo).
- [x] Login, ordinary rate limits, four report formats and spec/code coverage.
- [x] Reproducible editable development installation including form parser.
- [x] Request caps across login, baselines and fuzz cases, including zero/small budgets.
- [x] HTTP client cleanup after successful scans and failed login.
- [x] Live localhost scan with login; nested report destinations and UTF-8 output.

## Partially Completed Features
- [ ] Specification support: OpenAPI 3 and Swagger 2, local references, allOf merging, first oneOf/anyOf alternative. Escaped JSON-pointer decoding, operation parameter overrides and Swagger response schemas are now verified; remote references remain excluded.
- [x] Common contract constraints: types/nullability, enum/const, numeric bounds/exclusive bounds/multiples, string length/pattern, object requirements/additional properties/property counts, array sizes/uniqueness and every array item. Default response schemas and JSON null responses are checked. Full JSON Schema dialect support remains outside this implementation.
- [x] Authentication accuracy: independent anonymous probes strip static credential headers, authorization, session cookies and declared API-key parameters; only 2xx responses indicate missing enforcement. Optional anonymous security alternatives are respected. Probes share the request budget/rate limiter.
- [x] Request bodies: JSON objects, root scalars/arrays/null, URL-encoded forms, multipart and text. Baselines and mutations preserve root JSON values on the wire.
- [x] CLI/configuration: typed YAML defaults, unknown-key/choice validation, positive top/concurrency, numeric limits, login JSON objects, header syntax and ASGI syntax. Missing files, malformed documents, login failures and report destination failures return actionable errors with exit code 2.

## Remaining Features
The four requested core improvements are implemented and locally verified. Further improvements include more complete JSON Schema dialect support and stronger valid-baseline generation for complex constraints. Remote references, XML and blind SQL injection are documented exclusions, not required unfinished features. Live Claude, Docker and GitHub-hosted CI verification remain pending.

## Existing Security Checks
SERVER_ERROR, SQL_INJECTION, SQLI_SUSPECTED, XSS_REFLECTION, PATH_TRAVERSAL, VALIDATION_BYPASS, SCHEMA_VIOLATION, UNDOCUMENTED_STATUS, AUTH_NOT_ENFORCED, CONNECTION_ERROR. Reflection and size-based checks are heuristic evidence, not proof of exploitability.

## Existing Payload Generators
Numeric boundary/overflow values; empty, oversized, NUL and Unicode strings; enum violations; type confusion; empty arrays; SQLi, XSS and traversal strings; optional field-aware Claude values. No raw malformed-JSON generator is present.

## Tests
Initial environment: system Python 3.11.9 has no pytest. Created `.venv` and installed `.[dev]`.

Baseline ` .venv/Scripts/python -m pytest -q`: collection interrupted by missing python-multipart.
Baseline total: 17 existing test functions, zero collected successfully.
Baseline passed: 0. Failed: 0 executed; 1 collection error. Skipped: 0. Warnings: none reported.
Initial demo import failed with the same missing dependency. Editable package build succeeded.

Current `.venv/Scripts/python -m pytest -q`:
Total: 108. Passed: 108. Failed: 0. Skipped: 0. Warnings: one Starlette TestClient/httpx dependency deprecation. Runtime: 2.94 seconds on Python 3.11.9 / Windows (2026-10-10).
Regression tests cover concurrent budgets, login accounting, zero budgets, cleanup on failure, invalid numeric settings and capped CLI report generation.
`pip check` and `git diff --check` passed. Python 3.10/3.12, Docker and hosted CI have not been executed here.

## Known Bugs
- Fixed: development installation omitted python-multipart required by `/feedback`.
- Fixed: baseline request-budget exhaustion was uncaught, zero meant unlimited, and login was uncounted.
- Fixed: authentication detection accepted any status other than 401/403; it now requires 2xx from an independent anonymous probe.
- Fixed: Swagger response schemas were ignored, local reference tokens were not unescaped, and operation parameters did not override shared parameters.
- Fixed: report output directory creation did not create missing parents; reports now explicitly use UTF-8.

## Technical Debt
Broad/silent exceptions in LLM and JSON parsing; optional Claude clients created by the CLI are now closed; tasks are materialized for every payload. Analysis builder hardcodes another developer's absolute paths. Notebook risk formula differs from CLI risk scoring. Analysis artifacts inspected but not regenerated; notebook execution is outside the core test suite.

## Important Files
- `sentinelapi/cli.py`: main, build_parser, _code_cov; configuration and execution entry point.
- `sentinelapi/spec.py`: Param, Endpoint, load_spec, _resolve, parse_endpoints.
- `sentinelapi/risk.py`: fuzz_risk_score, band; 40-point unvalidated ratio, capped input count, mutating/open method and missing 4xx weights.
- `sentinelapi/generators.py`: Case, boundary_values, attack_values, valid_value, cases_for.
- `sentinelapi/engine.py`: Fuzzer, _baseline, _targets, _build; request execution and observed-status coverage.
- `sentinelapi/classifier.py`: Finding, violates, check_schema, classify.
- `sentinelapi/auth.py`: build_headers, parse_headers, login_for_token.
- `sentinelapi/llm.py`: ClaudeGenerator; cached optional Anthropic Messages calls.
- `sentinelapi/safety.py`: check_target; localhost/private target guard and explicit remote authorization.
- `sentinelapi/ratelimit.py`: RateLimiter; serialized request scheduling.
- `sentinelapi/report.py`, `sarif.py`: four report serializers.
- `tests/test_sentinel.py`: 17 demo/parser/auth/safety/report/LLM/budget tests.
- `demo_api.py`: eight local demo operations, including planted vulnerabilities.
- `pyproject.toml`, `Dockerfile`, `.github/workflows/ci.yml`: packaging, container and Python 3.10/3.12 CI with demo SARIF upload.
- `analysis/`: standalone APIs.guru preprocessing, datasets and 34 figures; notebook imports pandas/numpy/matplotlib/seaborn/squarify and includes statsmodels VIF analysis.

## Files Modified
- `PROJECT_STATUS.md`: initial audit and tracking.
- `pyproject.toml`: declared python-multipart in development dependencies.
- `sentinelapi/engine.py`: shared login/fuzz request reservation, clean cap exhaustion, numeric validation and guaranteed HTTP client cleanup.
- `sentinelapi/cli.py`: numeric option errors, nested destinations and explicit UTF-8 report writes.
- `tests/test_budget.py`: 19 regression cases.
- `README.md`: Windows setup and request-budget semantics.

## Design Decisions
Decision: preserve architecture and first repair installation. Reason: demo import blocks every existing test. Alternatives considered: remove form endpoint or install an undocumented dependency manually. Impact: declaring the dependency preserves teammate functionality and makes setup reproducible.

Decision: use a dedicated budget-exhaustion exception and a shared reservation method. Reason: exhaustion is expected scan control, not an invalid request error; login must honor the same rate and cap. Alternatives considered: catch all ValueErrors around run or exclude baselines/login from the cap. Impact: small scans return partial reports; requests counts now include login, zero sends nothing. Run cleanup uses finally so authentication exceptions still propagate while closing the client.

## Development Log
### 2026-10-09 — Repository audit
Goal: understand and verify existing implementation before coding.
Changes made: inspected source, tests, packaging, CI, demo, analysis script/notebook and existing artifacts; searched unfinished-code markers (no explicit stubs found; pass statements are exception handling).
Files modified: PROJECT_STATUS.md.
Tests run: system pytest invocation; editable dev installation; venv pytest; demo import.
Results: editable build succeeded; test collection and demo fail because python-multipart is missing.
Problems encountered: Windows sandbox cannot initialize; approved escalated commands used. Windows console encoding required UTF-8 for notebook inspection.
Resolution: use isolated .venv; declare missing form dependency next.
Next step: restore reproducible installation and validate local demo.

### 2026-10-09 — Reproducible development installation
Goal: restore documented setup and preserve the form demo.
Changes made: added python-multipart to dev dependencies.
Files modified: pyproject.toml, PROJECT_STATUS.md.
Tests run: `.venv/Scripts/python -m pip install -e '.[dev]'`; `.venv/Scripts/python -m pytest -q` (17 passed, 0 failed/skipped, no warnings, 1.99s); generated demo_openapi.json; `.venv/Scripts/sentinelapi demo_openapi.json --asgi demo_api:app --cov-source demo_api.py`.
Results: 8 findings, 137 requests, 95.7% server line coverage; all four report files created in ignored sentinel_out directory.
Problems encountered: `.venv/Scripts/sentinelapi demo_openapi.json --asgi demo_api:app --max-requests 1 --out sentinel_out/budget` crashes with ValueError during baseline gather.
Resolution: dependency omission fixed; baseline failure reproduced and selected for the next milestone.
Next step: enforce budgets consistently and close clients on failures.

### 2026-10-09 — Reliable capped scans
Goal: honor the hard cap for every target request and preserve reports for partial scans.
Existing implementation: fuzz cases caught exhaustion, but baselines crashed and login bypassed the cap.
Changes made: shared reservation counts/rate-limits login and endpoint requests; zero is an actual zero budget; baselines and fuzz cases catch dedicated exhaustion; runs close the client in finally; invalid numeric options are rejected; nested output directories and UTF-8 report writes supported.
Files modified: sentinelapi/engine.py, sentinelapi/cli.py, tests/test_budget.py, README.md, PROJECT_STATUS.md.
Tests run: full pytest suite (36 passed); one-request ASGI scan (0 findings, 1 request, four reports); full ASGI coverage scan (8 findings, 137 requests, 95.7% line coverage); live uvicorn on 127.0.0.1:8765 with login, rps=500 and max_requests=150 (8 findings, 138 requests, 100% endpoint coverage); parsed live JSON/SARIF; pip check; git diff --check.
Results: all checks passed; planted SQL injection, XSS and traversal detected. Live server terminated after verification. Report files are ignored local artifacts in sentinel_out/ and sentinel_live/.
Problems encountered: initial baseline crash confirmed with max_requests=1; Windows requires explicit UTF-8 for portable report output.
Resolution: small budgets now finish normally, count every target request and emit partial reports.
Unresolved issues: parser correctness gaps, incomplete schema validation, authentication false positives, invalid file/config errors, analysis portability and optional LLM lifecycle.
Next step: correct parser fidelity with regression tests before expanding detectors.

### 2026-10-10 ? Local browser dashboard
Goal: provide an approachable UI connected to the existing scanner.
Changes made: responsive navy-sidebar/light-workspace dashboard; demo/custom API modes; specification file loading; numeric controls; real scan results; search/severity filters; expandable evidence; session history and report downloads. FastAPI backend binds to localhost, checks Host/Origin, preserves target restrictions, serializes scan access and retains at most 20 report sets in memory. Added ui dependencies and packaged static assets.
Files modified: sentinelapi/web.py, sentinelapi/static/index.html, pyproject.toml, tests/test_web.py, README.md, PROJECT_STATUS.md.
Tests run: full suite 108 passed in 2.94s, one upstream TestClient deprecation warning; real demo via dashboard integration test; all report downloads; access/validation tests; live GET / returned 200; node --check passed; git diff --check.
Results: dashboard starts at http://127.0.0.1:8766 via python -m sentinelapi.web; configurable --port. Scans run the real engine and show actual results rather than seeded dashboard data.
Problems encountered: Windows blocked port 8080; changed default to 8766. Corrected a Windows BOM encoding issue before final verification.
Verification limit: browser automation unavailable; layout has not been visually checked in a browser. Local HTTP serving, JavaScript syntax, backend functionality and full tests are verified. Temporary verification server stopped after checks.
Design decision: extend the existing Python repository using a local web server and dependency-free browser assets. Preserve CLI authentication/AI options; those are not exposed by this first UI. No hosted deployment is needed to use the local Python scanner.
Next step: improve valid baseline generation for constrained strings and numeric schemas.

### 2026-10-10 ? Uploadable example specification
Goal: give the user a concrete file for testing the Your API dashboard flow.
Files added: examples/demo-openapi.json, examples/README.md.
Changes made: exported the actual bundled FastAPI contract as formatted JSON; documented separate API/dashboard commands and upload settings.
Validation: parsed the saved example and scanned the demo through ASGI using a 150-request cap; 8 endpoints, 107 requests, 7 findings. SQL injection, reflection and traversal findings verified. Live two-server browser flow not repeated for this documentation/example task.
Next step: improve valid baseline generation for constrained strings and numeric schemas.

### 2026-10-10 ? GitHub SARIF upload permissions
Goal: resolve the failed branch-push CI check shown in pull request #1.
Evidence: push run 38032937786 passed installation, pytest and demo scan on Python 3.12; upload-sarif failed with Resource not accessible by integration. Pull-request run 38033012737 completed successfully.
Changes made: explicitly grant the test job contents: read, actions: read and security-events: write for SARIF uploads.
Files modified: .github/workflows/ci.yml, PROJECT_STATUS.md.
Validation: workflow YAML parsed locally and permission mapping asserted. Hosted rerun verification follows the push.
Next step: improve valid baseline generation for constrained strings and numeric schemas.

## Current Next Step
Improve parser fidelity for escaped local JSON pointers, operation-level parameter overrides and Swagger 2 response schemas, with focused regression tests.
