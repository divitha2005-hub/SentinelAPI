"""SentinelAPI CLI.

  python -m sentinelapi.cli SPEC --base-url URL [--top N] [--llm] [--bearer T] [--out DIR]
  python -m sentinelapi.cli SPEC --asgi demo_api:app --cov-source .     # in-process + code coverage
"""
from __future__ import annotations
import argparse, asyncio, importlib, json, logging, math, sys
from pathlib import Path

import httpx
import yaml

from .auth import build_headers
from .engine import Fuzzer
from .llm import ClaudeGenerator
from . import __version__
from .safety import UnauthorizedTarget, check_target
from .sarif import to_sarif
from .report import to_html, to_json, to_markdown
from .risk import band, fuzz_risk_score
from .spec import load_spec, parse_endpoints


def _code_cov(cov) -> dict:
    cov.stop()
    total = covered = 0
    files = {}
    for fn in cov.get_data().measured_files():
        _, stmts, _, missing, _ = cov.analysis2(fn)
        t = len(stmts); c = t - len(missing)
        total += t; covered += c
        files[Path(fn).name] = round(100 * c / t, 1) if t else 100.0
    return {"percent": round(100 * covered / max(total, 1), 1), "covered": covered, "total": total, "files": files}


def build_parser():
    ap = argparse.ArgumentParser(prog="sentinelapi")
    ap.add_argument("spec")
    ap.add_argument("--base-url", help="live API root")
    ap.add_argument("--asgi", help="module:app to fuzz in-process (no server needed)")
    ap.add_argument("--cov-source", help="file or directory to measure server code coverage in (with --asgi)")
    ap.add_argument("--top", type=int, help="only fuzz the N highest-risk endpoints")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--llm", action="store_true", help="use Claude to generate extra inputs (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--header", action="append", help="'Name: value' (repeatable)")
    ap.add_argument("--bearer"); ap.add_argument("--basic", help="user:pass")
    ap.add_argument("--login-url"); ap.add_argument("--login-body", help="JSON string")
    ap.add_argument("--token-field", default="access_token")
    ap.add_argument("--out", default="sentinel_out")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you own the (remote) target or have written permission to test it")
    ap.add_argument("--allow-host", action="append", default=[], help="extra host allowed without --authorized")
    ap.add_argument("--rps", type=float, default=0, help="max requests per second (0 = unlimited)")
    ap.add_argument("--max-requests", type=int, help="hard cap on total requests sent")
    ap.add_argument("--config", help="YAML file with defaults for any option (CLI flags win)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=f"sentinelapi {__version__}")
    ap.add_argument("--list", action="store_true", help="only print the risk ranking")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                    help="exit 1 if a finding of this severity or worse exists (CI gate)")
    return ap


def main(argv=None) -> int:
    try:
        return _main(argv)
    except (OSError, ValueError, yaml.YAMLError, httpx.HTTPError, ImportError, AttributeError, KeyError) as error:
        print(f"sentinelapi: {error}", file=sys.stderr)
        return 2


def _config_defaults(ap, filename):
    cfg = yaml.safe_load(Path(filename).read_text(encoding="utf-8-sig"))
    if cfg is None:
        return {}
    if not isinstance(cfg, dict):
        raise ValueError("configuration must be a YAML mapping of option names to values")
    actions = {action.dest: action for action in ap._actions}
    result = {}
    for key, value in cfg.items():
        if not isinstance(key, str):
            raise ValueError("configuration option names must be strings")
        name = key.replace("-", "_")
        if name not in actions or name in ("help", "version", "spec", "config"):
            raise ValueError(f"unknown configuration option: {key}")
        action = actions[name]
        if isinstance(action, argparse._StoreTrueAction):
            valid = isinstance(value, bool)
        elif isinstance(action, argparse._AppendAction):
            valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
        elif action.type is int:
            valid = type(value) is int
        elif action.type is float:
            valid = type(value) in (int, float)
        else:
            valid = isinstance(value, str)
        if not valid:
            raise ValueError(f"invalid type for configuration option: {key}")
        if action.choices and value not in action.choices:
            raise ValueError(f"invalid value for configuration option: {key}")
        result[name] = value
    return result


def _main(argv=None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    if a.config:
        ap.set_defaults(**_config_defaults(ap, a.config))
        a = ap.parse_args(argv)
    if a.top is not None and a.top < 1:
        ap.error("--top must be at least 1")
    if a.concurrency < 1:
        ap.error("--concurrency must be at least 1")
    if not math.isfinite(a.rps) or a.rps < 0:
        ap.error("--rps must be a finite nonnegative number")
    if a.max_requests is not None and a.max_requests < 0:
        ap.error("--max-requests must be nonnegative")
    logging.basicConfig(level=logging.INFO if a.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    eps = parse_endpoints(load_spec(a.spec))
    if a.list:
        for e in sorted(eps, key=fuzz_risk_score, reverse=True):
            s = fuzz_risk_score(e); print(f"{s:5.1f} {band(s):6} {e.key}")
        return 0
    if not (a.base_url or a.asgi):
        sys.exit("need --base-url or --asgi")

    headers = build_headers(a.header, a.bearer, a.basic)
    if a.login_body and not a.login_url:
        raise ValueError("--login-body requires --login-url")
    login_body = json.loads(a.login_body or "{}")
    if not isinstance(login_body, dict):
        raise ValueError("--login-body must be a JSON object")
    if a.asgi and (":" not in a.asgi or not all(a.asgi.split(":", 1))):
        raise ValueError("--asgi must use module:app syntax")
    cov = None; transport = None; base = a.base_url or "http://test"
    try:
        check_target(base, a.authorized, a.allow_host)
    except UnauthorizedTarget as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if a.asgi:
        if a.cov_source:
            import coverage
            src = Path(a.cov_source).resolve()
            cov = coverage.Coverage(data_file=None, include=[str(src)] if src.is_file() else None,
                                    source=[str(src)] if src.is_dir() else None)
            cov.start()
        sys.path.insert(0, ".")
        mod, _, attr = a.asgi.partition(":")
        app = getattr(importlib.import_module(mod), attr)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)

    llm = ClaudeGenerator() if a.llm else None
    if llm and not llm.available:
        print("warning: --llm set but ANTHROPIC_API_KEY missing; using heuristics only", file=sys.stderr); llm.client.close(); llm = None
    login = {"url": a.login_url, "body": login_body, "token_field": a.token_field} if a.login_url else None
    fz = Fuzzer(eps, base, transport=transport, concurrency=a.concurrency, llm=llm, top_n=a.top,
                headers=headers, login=login,
                rps=a.rps, max_requests=a.max_requests)
    try:
        findings = asyncio.run(fz.run())
    finally:
        if llm:
            llm.client.close()
        if cov:
            cov.stop()
    spec_cov = fz.spec_coverage()
    code_cov = _code_cov(cov) if cov else None

    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    args = (findings, len(fz.endpoints), fz.requests, fz.elapsed, spec_cov, code_cov)
    (out / "report.md").write_text(to_markdown(*args), encoding="utf-8")
    (out / "report.html").write_text(to_html(*args), encoding="utf-8")
    (out / "findings.json").write_text(to_json(findings, spec_cov, code_cov), encoding="utf-8")
    (out / "results.sarif").write_text(to_sarif(findings, a.spec, __version__), encoding="utf-8")
    print(f"{len(findings)} findings, {fz.requests} requests in {fz.elapsed:.2f}s -> {out}/report.html")
    if code_cov: print(f"server code coverage: {code_cov['percent']}%")
    if a.fail_on:
        order = ["critical", "high", "medium", "low"]
        if any(order.index(f.severity) <= order.index(a.fail_on) for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
