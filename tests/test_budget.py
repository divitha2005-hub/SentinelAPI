"""Regression tests for request caps and cleanup using local mock transports."""
import asyncio
import json

import httpx
import pytest

from sentinelapi.cli import main
from sentinelapi.engine import Fuzzer
from sentinelapi.spec import Endpoint, Param


def endpoints():
    return [Endpoint("GET", f"/items/{i}", params=[Param("q", "query", {"type": "string"})])
            for i in range(4)]


@pytest.mark.parametrize("budget", [0, 1, 3, 4, 9])
def test_cap_applies_to_baselines_and_concurrent_cases(budget):
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={})

    fuzzer = Fuzzer(endpoints(), transport=httpx.MockTransport(handler), max_requests=budget)
    asyncio.run(fuzzer.run())
    assert len(sent) == fuzzer.requests == budget
    assert fuzzer.truncated
    assert fuzzer.client.is_closed
    assert fuzzer.spec_coverage()["endpoints_fuzzed"] == min(budget, 4)


@pytest.mark.parametrize("budget", [0, 1, 2])
def test_login_consumes_the_same_budget(budget):
    sent = []

    def handler(request):
        sent.append(request.url.path)
        return httpx.Response(200, json={"access_token": "demo"})

    fuzzer = Fuzzer(endpoints(), transport=httpx.MockTransport(handler), max_requests=budget,
                    login={"url": "/login", "body": {}})
    asyncio.run(fuzzer.run())
    assert len(sent) == fuzzer.requests == budget
    assert sent == (["/login", "/items/0"][:budget])
    assert fuzzer.client.is_closed


def test_login_failure_closes_client():
    fuzzer = Fuzzer(endpoints(), transport=httpx.MockTransport(
        lambda request: httpx.Response(401)), login={"url": "/login", "body": {}})
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(fuzzer.run())
    assert fuzzer.requests == 1
    assert fuzzer.client.is_closed


@pytest.mark.parametrize("settings", [
    {"concurrency": 0}, {"max_requests": -1}, {"rps": -1},
    {"rps": float("nan")}, {"rps": float("inf")},
])
def test_engine_rejects_invalid_execution_settings(settings):
    with pytest.raises(ValueError):
        Fuzzer(endpoints(), **settings)


@pytest.mark.parametrize("args", [
    ["--concurrency", "0"], ["--max-requests", "-1"], ["--rps", "nan"],
])
def test_cli_rejects_invalid_settings_before_reading_spec(args):
    with pytest.raises(SystemExit) as error:
        main(["missing.json", *args])
    assert error.value.code == 2


@pytest.mark.parametrize("budget", [0, 1])
def test_cli_small_budget_still_writes_reports(tmp_path, budget):
    from demo_api import app

    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(app.openapi()), encoding="utf-8")
    output = tmp_path / "nested" / "reports"
    assert main([str(spec), "--asgi", "demo_api:app", "--max-requests", str(budget),
                 "--out", str(output)]) == 0
    for name in ("report.md", "report.html", "findings.json", "results.sarif"):
        assert (output / name).read_text(encoding="utf-8")
    report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert report["spec_coverage"]["endpoints_fuzzed"] == budget
