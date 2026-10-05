from __future__ import annotations
import html, json
from collections import Counter

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb"}


def _sorted(findings):
    return sorted(findings, key=lambda f: (ORDER[f.severity], f.endpoint))


def _cov_lines(cov: dict | None, code_cov: dict | None):
    L = []
    if cov:
        L += [f"- Endpoints fuzzed: {cov['endpoints_fuzzed']}/{cov['endpoints_in_spec']} ({cov['endpoint_coverage_pct']}%)",
              f"- Documented response codes observed: {cov['documented_statuses_observed']}/{cov['documented_statuses']} ({cov['status_coverage_pct']}%)",
              f"- Undocumented status codes seen: {len(cov['undocumented_statuses_seen'])}"]
    if code_cov:
        L.append(f"- Server code coverage: {code_cov['percent']}% ({code_cov['covered']}/{code_cov['total']} lines)")
        for f, pct in code_cov.get("files", {}).items():
            L.append(f"  - {f}: {pct}%")
    return L


def to_markdown(findings, endpoints_tested, requests, elapsed, cov=None, code_cov=None) -> str:
    fs = _sorted(findings)
    c = Counter(f.severity for f in fs)
    lines = ["# SentinelAPI Report", "",
             f"Endpoints tested: **{endpoints_tested}** | Requests sent: **{requests}** | Time: **{elapsed:.2f}s**", "",
             "| Severity | Count |", "|---|---|"] + [f"| {s} | {c.get(s, 0)} |" for s in ORDER]
    cl = _cov_lines(cov, code_cov)
    if cl:
        lines += ["", "## Coverage", ""] + cl
    lines += ["", "## Findings", "", "| Severity | Type | Endpoint | Field | Payload | Detail |", "|---|---|---|---|---|---|"]
    for f in fs:
        p = repr(f.payload)[:40].replace("|", "/")
        lines.append(f"| {f.severity} | {f.kind} | `{f.endpoint}` | {f.target} | `{p}` | {f.detail} |")
    return "\n".join(lines) + "\n"


def to_html(findings, endpoints_tested, requests, elapsed, cov=None, code_cov=None) -> str:
    fs = _sorted(findings)
    c = Counter(f.severity for f in fs)
    cards = "".join(f'<div class="c" style="border-top:4px solid {COLOR[s]}"><b>{c.get(s,0)}</b><br>{s}</div>' for s in ORDER)
    rows = "".join(
        f'<tr><td style="color:{COLOR[f.severity]};font-weight:600">{f.severity}</td><td>{f.kind}</td>'
        f'<td><code>{html.escape(f.endpoint)}</code></td><td>{html.escape(str(f.target))}</td>'
        f'<td><code>{html.escape(repr(f.payload)[:50])}</code></td><td>{html.escape(f.detail)}</td></tr>' for f in fs)
    cl = "".join(f"<li>{html.escape(x.strip('- '))}</li>" for x in _cov_lines(cov, code_cov))
    return f"""<!doctype html><meta charset=utf-8><title>SentinelAPI Report</title>
<style>body{{font:15px system-ui;margin:2rem auto;max-width:1000px;padding:0 1rem}}
.g{{display:flex;gap:12px}}.c{{flex:1;padding:12px;background:#f5f5f5;border-radius:6px;text-align:center}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left;font-size:13px}}</style>
<h1>SentinelAPI Report</h1><p>{endpoints_tested} endpoints, {requests} requests, {elapsed:.2f}s</p>
<div class=g>{cards}</div><h2>Coverage</h2><ul>{cl}</ul>
<h2>Findings</h2><table><tr><th>Severity<th>Type<th>Endpoint<th>Field<th>Payload<th>Detail</tr>{rows}</table>"""


def to_json(findings, cov=None, code_cov=None) -> str:
    return json.dumps({"findings": [f.to_dict() for f in _sorted(findings)],
                       "spec_coverage": cov, "code_coverage": code_cov}, indent=2, default=list)
