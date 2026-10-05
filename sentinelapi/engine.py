"""Async fuzzing engine."""
from __future__ import annotations
import asyncio, logging, re, time
from collections import defaultdict
from typing import Any

import httpx

from .classifier import Finding, classify
from .ratelimit import RateLimiter
from .generators import Case, cases_for, valid_value
from .risk import fuzz_risk_score
from .spec import Endpoint


def _baseline(ep: Endpoint) -> dict[tuple, Any]:
    base = {(p.location, p.name): valid_value(p.schema) for p in ep.params}
    if ep.body_schema:
        for k, s in ep.body_schema.get("properties", {}).items():
            base[("body", k)] = valid_value(s)
    return base


def _targets(ep: Endpoint):
    for p in ep.params:
        yield (p.location, p.name), p.schema
    for k, s in (ep.body_schema or {}).get("properties", {}).items():
        yield ("body", k), s
    if ep.body_schema is not None and not ep.body_schema.get("properties"):
        yield ("body", "payload"), {"type": "string"}      # free-form body: fuzz a generic field


def _build(ep: Endpoint, values: dict):
    path, query, headers, cookies, body = ep.path, {}, {}, {}, None
    for (loc, name), v in values.items():
        if loc == "path":
            path = path.replace("{" + name + "}", str(v))
        elif loc == "query":
            query[name] = v
        elif loc == "header":
            headers[name] = str(v)
        elif loc == "cookie":
            cookies[name] = str(v)
        elif loc == "body":
            body = body or {}
            body[name] = v
    return re.sub(r"\{[^}]+\}", "1", path), query, headers, cookies, body


log = logging.getLogger("sentinelapi")


class Fuzzer:
    def __init__(self, endpoints: list[Endpoint], base_url: str = "http://test",
                 transport: httpx.AsyncBaseTransport | None = None, concurrency: int = 20,
                 llm=None, top_n: int | None = None, headers: dict | None = None,
                 login: dict | None = None, rps: float = 0, max_requests: int | None = None):
        ranked = sorted(endpoints, key=fuzz_risk_score, reverse=True)
        self.all_endpoints = endpoints
        self.endpoints = ranked[:top_n] if top_n else ranked
        self.client = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=10,
                                        headers=headers or {})
        self.login = login          # {"url":..., "body":{...}, "token_field": "access_token"}
        self.sem = asyncio.Semaphore(concurrency)
        self.llm = llm
        self.limiter = RateLimiter(rps)
        self.max_requests = max_requests
        self.truncated = False
        self.findings: list[Finding] = []
        self.requests = 0
        self.elapsed = 0.0
        self.observed: dict[str, set[int]] = defaultdict(set)
        self.baseline_len: dict[str, int] = {}
        self.baseline_status: dict[str, int] = {}

    def _base(self, ep):
        base = _baseline(ep)
        for (loc, name) in list(base):
            if loc == "header" and name.lower() in self.client.headers:
                base[(loc, name)] = self.client.headers[name]      # keep real credentials in baseline
        return base

    async def _request(self, ep, values):
        path, query, headers, cookies, body = _build(ep, values)
        if self.max_requests and self.requests >= self.max_requests:
            self.truncated = True
            raise ValueError("request budget exhausted")
        self.requests += 1                      # reserve a slot before awaiting (tasks run concurrently)
        await self.limiter.wait()
        kw: dict = {}
        if ep.body_schema is not None:
            b = body or {}
            if ep.content_type == "json":
                kw["json"] = body if body is not None else {}
            elif ep.content_type == "form":
                kw["data"] = {k: ("" if v is None else v) for k, v in b.items()}
            elif ep.content_type == "multipart":
                kw["files"] = {k: (None, str("" if v is None else v)) for k, v in b.items()}
            else:
                kw["content"] = str(next(iter(b.values()), ""))
                headers = {**headers, "Content-Type": "text/plain"}
        async with self.sem:
            r = await self.client.request(ep.method, path, params=query, headers=headers,
                                          cookies=cookies or None, **kw)
        self.observed[ep.key].add(r.status_code)
        return r

    async def _do_baseline(self, ep):
        try:
            r = await self._request(ep, self._base(ep))
            self.baseline_len[ep.key] = len(r.text)
            self.baseline_status[ep.key] = r.status_code
            if ep.secured and r.status_code not in (401, 403) and not self.client.headers.get("authorization"):
                self.findings.append(Finding("AUTH_NOT_ENFORCED", "high", ep.key, "-", None,
                                             r.status_code, "spec says secured but request without credentials succeeded"))
        except httpx.HTTPError:
            pass

    async def _send(self, ep, values, target, case, schema):
        if target[0] in ("header", "cookie") and (not isinstance(case.value, str) or not case.value.isascii()
                                                   or "\x00" in case.value or "\n" in case.value):
            return      # cannot be put on the wire in a header/cookie
        try:
            r = await self._request(ep, values)
        except (UnicodeError, ValueError):
            return
        except httpx.HTTPError as e:
            self.findings.append(Finding("CONNECTION_ERROR", "medium", ep.key, str(target[1]),
                                         case.value, 0, type(e).__name__))
            return
        try:
            jb = r.json()
        except Exception:
            jb = None
        self.findings += classify(ep, target[1], case, schema, r.status_code, r.text, jb,
                                  loc=target[0], baseline_len=self.baseline_len.get(ep.key))

    async def _llm_cases(self, ep, target, schema) -> list[Case]:
        if not self.llm:
            return []
        try:
            vals = await asyncio.to_thread(self.llm, ep.key, target[1], schema)
            return [Case("llm", v) for v in vals]
        except Exception:
            return []

    async def run(self) -> list[Finding]:
        t0 = time.time()
        if self.login:
            from .auth import login_for_token
            self.client.headers.update(await login_for_token(
                self.client, self.login["url"], self.login["body"], self.login.get("token_field", "access_token")))
        await asyncio.gather(*[self._do_baseline(ep) for ep in self.endpoints])
        jobs = []
        for ep in self.endpoints:
            for target, schema in _targets(ep):
                jobs.append((ep, target, schema))
        llm_results = await asyncio.gather(*[self._llm_cases(*j) for j in jobs])
        tasks = []
        base_cache = {ep.key: self._base(ep) for ep in self.endpoints}
        for (ep, target, schema), extra in zip(jobs, llm_results):
            for case in cases_for(ep.key, target[1], schema) + extra:
                vals = dict(base_cache[ep.key]); vals[target] = case.value
                tasks.append(self._send(ep, vals, target, case, schema))
        log.info("fuzzing %d endpoints, %d cases", len(self.endpoints), len(tasks))
        await asyncio.gather(*tasks)
        if self.truncated:
            log.warning("stopped early: --max-requests budget reached")
        self.elapsed = time.time() - t0
        await self.client.aclose()
        return self._dedupe(self.findings)

    def spec_coverage(self) -> dict:
        tested = [e for e in self.endpoints if e.key in self.observed]
        documented = sum(len([s for s in e.responses if s.isdigit()]) for e in self.endpoints)
        seen = sum(len({str(s) for s in self.observed[e.key]} & set(e.responses)) for e in tested)
        return {"endpoints_in_spec": len(self.all_endpoints), "endpoints_fuzzed": len(tested),
                "endpoint_coverage_pct": round(100 * len(tested) / max(len(self.all_endpoints), 1), 1),
                "documented_statuses": documented, "documented_statuses_observed": seen,
                "status_coverage_pct": round(100 * seen / max(documented, 1), 1),
                "undocumented_statuses_seen": sorted({(e.key, s) for e in tested for s in self.observed[e.key]
                                                      if str(s) not in e.responses and "default" not in e.responses})}

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.kind, f.endpoint, f.target)
            if k not in seen:
                seen.add(k); out.append(f)
        return out
