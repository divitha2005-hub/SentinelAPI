"""Local browser interface. Run with python -m sentinelapi.web."""
from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
import asyncio
import json

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from .engine import Fuzzer
from .report import to_html, to_json, to_markdown
from .sarif import to_sarif
from .safety import check_target, UnauthorizedTarget
from .spec import parse_endpoints
from . import __version__

app = FastAPI(title="SentinelAPI local dashboard", docs_url=None, redoc_url=None)
reports: OrderedDict = OrderedDict()
scan_lock = asyncio.Lock()


@app.middleware('http')
async def local_only(request: Request, call_next):
    host = request.url.hostname
    origin = request.headers.get('origin')
    if host not in ('127.0.0.1', 'localhost', '::1'):
        return Response('Use the local dashboard address.', status_code=403)
    if origin and origin != f'{request.url.scheme}://{request.url.netloc}':
        return Response('Cross-origin requests are not allowed.', status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"
    return response


class Scan(BaseModel):
    mode: str = 'demo'
    spec_text: str = Field(default='', max_length=2_000_000)
    base_url: str = Field(default='http://127.0.0.1:8000', max_length=2048)
    max_requests: int = Field(default=150, ge=0, le=2000)
    rps: float = Field(default=20, ge=1, le=100)


@app.get('/')
async def dashboard():
    return FileResponse(Path(__file__).parent / 'static' / 'index.html')


@app.post('/api/scan')
async def scan(options: Scan):
    if scan_lock.locked():
        raise HTTPException(409, 'A scan is already running. Please wait for it to finish.')
    async with scan_lock:
        try:
            if options.mode == 'demo':
                from demo_api import app as demo
                spec = demo.openapi()
                base = 'http://test'
                transport = httpx.ASGITransport(app=demo, raise_app_exceptions=False)
            elif options.mode == 'live':
                if not options.spec_text.strip():
                    raise ValueError('Choose an OpenAPI JSON or YAML file first.')
                spec = yaml.safe_load(options.spec_text)
                parsed = urlparse(options.base_url)
                if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                    raise ValueError('Enter a valid http:// or https:// API address.')
                check_target(options.base_url)
                base, transport = options.base_url, None
            else:
                raise ValueError('Choose demo or live scan mode.')
            eps = parse_endpoints(spec)
            if not eps:
                raise ValueError('The specification has no supported API operations.')
            if len(eps) > 200:
                raise ValueError('Use a specification with at most 200 operations in this local UI.')
            fz = Fuzzer(eps, base, transport=transport, max_requests=options.max_requests,
                rps=options.rps, concurrency=10)
            findings = await fz.run()
        except (ValueError, yaml.YAMLError, UnauthorizedTarget, OSError, ImportError, AttributeError, TypeError, KeyError) as error:
            raise HTTPException(400, str(error)) from error
        cov = fz.spec_coverage()
        args = (findings, cov['endpoints_fuzzed'], fz.requests, fz.elapsed, cov)
        scan_id = uuid4().hex
        reports[scan_id] = {
            'html': to_html(*args), 'md': to_markdown(*args),
            'json': to_json(findings, cov), 'sarif': to_sarif(findings, 'uploaded-spec', __version__)}
        while len(reports) > 20:
            reports.popitem(last=False)

        from collections import Counter
        from .risk import fuzz_risk_score

        severities = Counter(f.severity for f in findings)
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        dsi = round(sum(severities[s] * weights.get(s, 1) for s in severities) / max(len(findings), 1), 2) if findings else 0.0
        vulnerable_eps = len({f.endpoint for f in findings})
        fuzzed_count = max(cov['endpoints_fuzzed'], 1)
        defect_density = round(len(findings) / fuzzed_count, 2)
        vulnerable_pct = round(100 * vulnerable_eps / fuzzed_count, 1)

        type_counts = dict(Counter(f.kind for f in findings).most_common())
        method_counts = dict(Counter(ep.method.upper() for ep in eps))
        risk_scores = [fuzz_risk_score(ep) for ep in eps]
        risk_breakdown = {
            "High": sum(1 for r in risk_scores if r >= 6),
            "Medium": sum(1 for r in risk_scores if 3 <= r < 6),
            "Low": sum(1 for r in risk_scores if r < 3),
        }

        status_counts = Counter()
        for f in findings:
            if f.status:
                status_counts[str(f.status)] += 1
        for codes in fz.observed.values():
            for c in codes:
                status_counts[str(c)] = max(status_counts[str(c)], 1)

        # In-depth architectural & attack surface metrics
        total_params = sum(len(ep.params) for ep in eps)
        body_fields = sum(len(ep.body_schema.get("properties", {})) if isinstance(ep.body_schema, dict) else (1 if ep.body_schema else 0) for ep in eps)
        attack_surface_points = total_params + body_fields
        avg_param_density = round(attack_surface_points / max(len(eps), 1), 2)
        unsecured_eps = sum(1 for ep in eps if not ep.secured)
        unauthenticated_ratio = round(100 * unsecured_eps / max(len(eps), 1), 1)
        test_generation_density = round(fz.requests / fuzzed_count, 1)

        # In-depth fault resilience & contract compliance
        count_4xx = sum(status_counts.get(str(c), 0) for c in range(400, 500))
        count_5xx = sum(status_counts.get(str(c), 0) for c in range(500, 600)) + sum(1 for f in findings if f.kind == "SERVER_ERROR")
        error_resilience = round(100 * count_4xx / max(count_4xx + count_5xx, 1), 1) if (count_4xx + count_5xx) > 0 else 100.0
        schema_violations = sum(1 for f in findings if f.kind == "SCHEMA_VIOLATION")
        schema_conformance = round(max(0, 100 - (100 * schema_violations / max(fz.requests, 1))), 1)

        # Composite API Quality & Security Health Score (SHS) (0 - 100)
        penalty = (severities.get("critical", 0) * 12 +
                   severities.get("high", 0) * 6 +
                   severities.get("medium", 0) * 3 +
                   severities.get("low", 0) * 1 +
                   min(count_5xx * 3, 15))
        health_score = max(5, min(100, round(100 - penalty)))
        if health_score >= 90:
            grade, grade_label = "A", "Excellent (Secure & Robust)"
        elif health_score >= 80:
            grade, grade_label = "B", "Good (Minor Vulnerabilities)"
        elif health_score >= 70:
            grade, grade_label = "C", "Fair (Moderate Risk Flaws)"
        elif health_score >= 55:
            grade, grade_label = "D", "Needs Attention (High Risk)"
        else:
            grade, grade_label = "F", "Critical Risk (Severe Exposure)"

        metrics = {
            "health_score": health_score,
            "grade": grade,
            "grade_label": grade_label,
            "defect_density": defect_density,
            "defect_severity_index": dsi,
            "vulnerable_endpoints_pct": vulnerable_pct,
            "vulnerable_endpoints_count": vulnerable_eps,
            "throughput_rps": round(fz.requests / max(fz.elapsed, 0.001), 1),
            "avg_latency_ms": round((fz.elapsed / max(fz.requests, 1)) * 1000, 1),
            "attack_surface_points": attack_surface_points,
            "avg_param_density": avg_param_density,
            "unauthenticated_ratio": unauthenticated_ratio,
            "test_generation_density": test_generation_density,
            "error_resilience_ratio": error_resilience,
            "schema_conformance_rate": schema_conformance,
            "severities": {s: severities.get(s, 0) for s in ("critical", "high", "medium", "low")},
            "vulnerability_types": type_counts,
            "methods": method_counts,
            "risk_breakdown": risk_breakdown,
            "status_codes": dict(status_counts.most_common(8))
        }

        endpoint_catalog = [
            {
                "key": ep.key,
                "method": ep.method.upper(),
                "path": ep.path,
                "params_count": len(ep.params),
                "has_body": bool(ep.body_schema),
                "secured": ep.secured,
                "risk_score": fuzz_risk_score(ep),
                "findings_count": len([f for f in findings if f.endpoint == ep.key])
            }
            for ep in eps
        ]

        return {'id': scan_id, 'findings': [f.to_dict() for f in findings],
            'coverage': cov, 'requests': fz.requests, 'elapsed': round(fz.elapsed, 2),
            'truncated': fz.truncated, 'mode': options.mode, 'metrics': metrics,
            'catalog': endpoint_catalog}


@app.get('/api/reports/{scan_id}/{format}')
async def download(scan_id: str, format: str):
    if scan_id not in reports or format not in reports[scan_id]:
        raise HTTPException(404, 'Report is no longer available. Run a new scan.')
    filename = 'results.sarif' if format == 'sarif' else f'report.{format}'
    return Response(reports[scan_id][format], media_type='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'})


if __name__ == '__main__':
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser(description="Open the local SentinelAPI dashboard")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    uvicorn.run(app, host='127.0.0.1', port=args.port)
