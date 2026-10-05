import asyncio, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import httpx
from demo_api import app
from sentinelapi.engine import Fuzzer
from sentinelapi.risk import fuzz_risk_score
from sentinelapi.spec import parse_endpoints


def run_demo():
    eps = parse_endpoints(app.openapi())
    fz = Fuzzer(eps, transport=httpx.ASGITransport(app=app, raise_app_exceptions=False))
    return eps, asyncio.run(fz.run())


def test_parses_endpoints():
    eps, _ = run_demo()
    assert {e.key for e in eps} >= {"GET /users/search", "POST /orders", "GET /safe/{item_id}"}


def test_finds_planted_vulns():
    _, fs = run_demo()
    kinds = {(f.kind, f.endpoint) for f in fs}
    assert ("SQL_INJECTION", "GET /users/search") in kinds
    assert ("XSS_REFLECTION", "GET /greet") in kinds
    assert ("PATH_TRAVERSAL", "GET /files") in kinds


def test_safe_endpoint_has_no_critical():
    _, fs = run_demo()
    assert not [f for f in fs if f.endpoint == "GET /safe/{item_id}" and f.severity in ("critical", "high")]


def test_risk_prioritises_unvalidated_mutations():
    eps = {e.key: e for e in parse_endpoints(app.openapi())}
    assert fuzz_risk_score(eps["POST /orders"]) > fuzz_risk_score(eps["GET /safe/{item_id}"])


def test_auth_login_flow_and_spec_coverage():
    eps = parse_endpoints(app.openapi())
    fz = Fuzzer(eps, transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                login={"url": "/login", "body": {"user": "admin", "password": "secret"}})
    asyncio.run(fz.run())
    assert fz.baseline_status["GET /me"] == 200       # login token was applied to the baseline
    cov = fz.spec_coverage()
    assert cov["endpoint_coverage_pct"] == 100.0


def test_unauthenticated_secured_endpoint_gets_401():
    eps = parse_endpoints(app.openapi())
    fz = Fuzzer(eps, transport=httpx.ASGITransport(app=app, raise_app_exceptions=False))
    asyncio.run(fz.run())
    assert 401 in fz.observed["GET /me"]


def test_llm_hook_cases_are_used():
    eps = [e for e in parse_endpoints(app.openapi()) if e.key == "GET /files"]
    seen = []
    def fake(endpoint, field, schema):
        seen.append(field); return ["../../../../etc/passwd"]
    fz = Fuzzer(eps, transport=httpx.ASGITransport(app=app), llm=fake)
    asyncio.run(fz.run())
    assert seen == ["path"]


def test_claude_generator_parses_response():
    from sentinelapi.llm import ClaudeGenerator
    def handler(req):
        return httpx.Response(200, json={"content": [{"type": "text", "text": 'Sure: ["a", -1, "\' OR 1=1"]'}]})
    g = ClaudeGenerator(api_key="k", transport=httpx.MockTransport(handler))
    assert g("GET /x", "q", {"type": "string"}) == ["a", -1, "' OR 1=1"]


def test_noise_reduction_no_type_confusion_bypass_on_string_query():
    _, fs = run_demo()
    assert not [f for f in fs if f.kind == "VALIDATION_BYPASS" and f.endpoint == "GET /greet"
                and f.payload in (12345, None)]


def test_safety_blocks_remote_without_authorization():
    import pytest
    from sentinelapi.safety import UnauthorizedTarget, check_target
    check_target("http://127.0.0.1:8000"); check_target("http://localhost"); check_target("http://192.168.1.5")
    with pytest.raises(UnauthorizedTarget):
        check_target("http://8.8.8.8")
    check_target("http://8.8.8.8", authorized=True)
    check_target("http://8.8.8.8", allow_hosts=["8.8.8.8"])


def test_cli_refuses_remote_target(tmp_path):
    from sentinelapi.cli import main
    import json
    (tmp_path / "s.json").write_text(json.dumps(app.openapi()))
    assert main([str(tmp_path / "s.json"), "--base-url", "http://8.8.8.8"]) == 2


def test_request_budget_and_rate_limit():
    import time
    eps = parse_endpoints(app.openapi())
    fz = Fuzzer(eps, transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), max_requests=25)
    asyncio.run(fz.run())
    assert fz.requests <= 25 and fz.truncated
    fz = Fuzzer(eps[:1], transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), rps=200, max_requests=20)
    t = time.time(); asyncio.run(fz.run())
    assert time.time() - t >= 0.05


def test_sarif_output_valid():
    import json
    from sentinelapi.sarif import to_sarif
    _, fs = run_demo()
    doc = json.loads(to_sarif(fs, "spec.json", "1.0.0"))
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]
    assert any(r["level"] == "error" for r in doc["runs"][0]["results"])


def test_cli_end_to_end_writes_all_reports(tmp_path):
    from sentinelapi.cli import main
    import json
    (tmp_path / "s.json").write_text(json.dumps(app.openapi()))
    rc = main([str(tmp_path / "s.json"), "--asgi", "demo_api:app", "--out", str(tmp_path / "o"), "--fail-on", "critical"])
    assert rc == 1
    for n in ("report.html", "report.md", "findings.json", "results.sarif"):
        assert (tmp_path / "o" / n).exists()


def test_form_body_endpoint_is_fuzzed():
    eps = {e.key: e for e in parse_endpoints(app.openapi())}
    assert eps["POST /feedback"].content_type == "form"
    fz = Fuzzer([eps["POST /feedback"]], transport=httpx.ASGITransport(app=app, raise_app_exceptions=False))
    fs = asyncio.run(fz.run())
    assert fz.baseline_status["POST /feedback"] == 200
    assert any(f.kind == "XSS_REFLECTION" for f in fs)


def test_swagger2_body_and_formdata_parsed():
    spec = {"swagger": "2.0", "paths": {
        "/a": {"post": {"consumes": ["application/json"], "parameters": [
            {"in": "body", "name": "b", "schema": {"type": "object", "properties": {"x": {"type": "integer"}}}}],
            "responses": {"200": {"description": "ok"}}}},
        "/b": {"post": {"consumes": ["multipart/form-data"], "parameters": [
            {"in": "formData", "name": "f", "type": "string"}], "responses": {"200": {"description": "ok"}}}}}}
    eps = {e.key: e for e in parse_endpoints(spec)}
    assert eps["POST /a"].body_schema["properties"]["x"]["type"] == "integer"
    assert eps["POST /b"].content_type == "multipart" and "f" in eps["POST /b"].body_schema["properties"]


def test_parser_handles_allof_oneof_recursive_refs_and_path_params():
    spec = {"openapi": "3.0.0", "components": {"schemas": {
        "Base": {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}},
        "Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}, "n": {"type": "string"}}},
        "Pet": {"allOf": [{"$ref": "#/components/schemas/Base"}, {"properties": {"name": {"type": "string", "maxLength": 5}}}]},
        "Either": {"oneOf": [{"type": "string"}, {"type": "integer"}]}}},
        "paths": {"/p/{id}": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}},
                     "responses": {"200": {"description": "ok"}}},
            "put": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}},
                    "responses": {"200": {"description": "ok"}}}}}}
    eps = {e.key: e for e in parse_endpoints(spec)}
    pet = eps["POST /p/{id}"]
    assert set(pet.body_schema["properties"]) == {"id", "name"} and pet.params[0].name == "id"
    assert "n" in eps["PUT /p/{id}"].body_schema["properties"]     # recursion terminates
