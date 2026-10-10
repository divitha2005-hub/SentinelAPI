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
        return {'id': scan_id, 'findings': [f.to_dict() for f in findings],
            'coverage': cov, 'requests': fz.requests, 'elapsed': round(fz.elapsed, 2),
            'truncated': fz.truncated, 'mode': options.mode}


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
