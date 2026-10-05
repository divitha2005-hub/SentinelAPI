"""SARIF 2.1.0 output so results show up in GitHub code scanning and other CI tools."""
from __future__ import annotations
import json

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(findings, spec_path: str, version: str) -> str:
    rules = {}
    for f in findings:
        rules.setdefault(f.kind, {"id": f.kind, "name": f.kind,
                                  "shortDescription": {"text": f.kind.replace("_", " ").title()}})
    results = [{
        "ruleId": f.kind,
        "level": LEVEL[f.severity],
        "message": {"text": f"{f.endpoint} [{f.target}]: {f.detail}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": spec_path}},
                       "logicalLocations": [{"name": f.endpoint, "kind": "function"}]}],
    } for f in findings]
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "SentinelAPI", "version": version,
                                      "rules": list(rules.values())}}, "results": results}]}, indent=2)
