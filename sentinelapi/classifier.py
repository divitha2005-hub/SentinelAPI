"""Turn (case, response) pairs into findings."""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from typing import Any

SQL_ERRORS = re.compile(r"(sql syntax|sqlite3?\.|unrecognized token|incomplete input|sqlite error|psycopg|ora-\d{5}|mysql|unterminated quoted|"
                        r"near \"|SQLSTATE|syntax error at or near)", re.I)
TYPES = {"integer": int, "number": (int, float), "string": str, "boolean": bool,
         "array": list, "object": dict}


@dataclass
class Finding:
    kind: str
    severity: str
    endpoint: str
    target: str
    payload: Any
    status: int
    detail: str

    def to_dict(self):
        d = asdict(self)
        d["payload"] = repr(self.payload)[:120]
        return d


def violates(schema: dict, value: Any) -> bool:
    """True if value breaks the declared contract (so a 2xx means validation is missing)."""
    t = schema.get("type", "string")
    exp = TYPES.get(t)
    if value is None or (exp and (not isinstance(value, exp) or (t != "boolean" and isinstance(value, bool)))):
        return True
    if "enum" in schema and value not in schema["enum"]:
        return True
    if isinstance(value, (int, float)):
        if "minimum" in schema and value < schema["minimum"]:
            return True
        if "maximum" in schema and value > schema["maximum"]:
            return True
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return True
        if "minLength" in schema and len(value) < schema["minLength"]:
            return True
    return False


def check_schema(schema: dict, data: Any, path: str = "$") -> list[str]:
    """Minimal response-body check against a declared JSON schema."""
    errs: list[str] = []
    t = schema.get("type")
    exp = TYPES.get(t)
    if exp and (not isinstance(data, exp) or (t != "boolean" and isinstance(data, bool))):
        return [f"{path}: expected {t}, got {type(data).__name__}"]
    if t == "object" and isinstance(data, dict):
        for r in schema.get("required", []):
            if r not in data:
                errs.append(f"{path}.{r}: required field missing")
        for k, sub in schema.get("properties", {}).items():
            if k in data:
                errs += check_schema(sub, data[k], f"{path}.{k}")
    if t == "array" and isinstance(data, list) and "items" in schema:
        for i, item in enumerate(data[:5]):
            errs += check_schema(schema["items"], item, f"{path}[{i}]")
    return errs


def classify(ep, target: str, case, schema: dict, status: int, body: str, json_body: Any,
             loc: str = "body", baseline_len: int | None = None) -> list[Finding]:
    f: list[Finding] = []
    mk = lambda kind, sev, detail: Finding(kind, sev, ep.key, target, case.value, status, detail)

    if status >= 500:
        f.append(mk("SERVER_ERROR", "high", f"{status} returned for {case.label} input"))
    if case.label == "sqli" and SQL_ERRORS.search(body):
        f.append(mk("SQL_INJECTION", "critical", "database error text leaked in response"))
    if case.label == "xss" and isinstance(case.value, str) and case.value in body:
        f.append(mk("XSS_REFLECTION", "high", "payload reflected unescaped"))
    if case.label == "traversal" and re.search(r"root:.*:0:0:", body):
        f.append(mk("PATH_TRAVERSAL", "critical", "file contents (/etc/passwd) returned"))
    if (case.label == "sqli" and 200 <= status < 300 and baseline_len is not None
            and len(body) > baseline_len * 1.5 + 20):
        f.append(mk("SQLI_SUSPECTED", "medium", "response grew sharply vs baseline (boolean-based SQLi?)"))
    wire_string = loc != "body" and schema.get("type", "string") == "string"
    skip_bypass = wire_string and case.label == "type_confusion"   # strings on the wire: not a violation
    if not skip_bypass and case.label in ("boundary", "type_confusion", "llm") and 200 <= status < 300 and violates(schema, case.value):
        f.append(mk("VALIDATION_BYPASS", "medium", "input violating the declared schema was accepted"))

    declared = ep.responses
    if declared and str(status) not in declared and "default" not in declared and status < 500:
        f.append(mk("UNDOCUMENTED_STATUS", "low", f"{status} is not declared in the spec"))
    resp_schema = declared.get(str(status))
    if resp_schema and json_body is not None:
        for e in check_schema(resp_schema, json_body)[:3]:
            f.append(mk("SCHEMA_VIOLATION", "medium", e))
    return f
