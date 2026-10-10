"""Turn (case, response) pairs into findings."""
from __future__ import annotations
import json, math, re
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
    """Use the same contract constraints for input and response validation."""
    return bool(check_schema(schema, value))


def check_schema(schema: dict, data: Any, path: str = "$") -> list[str]:
    """Check common OpenAPI JSON constraints recursively, including every array item."""
    if data is None and (schema.get("nullable") or schema.get("type") == "null"):
        return []
    errors = []
    def fail(message):
        errors.append(f"{path}: {message}")
    t = schema.get("type")
    types = t if isinstance(t, list) else [t]
    def matches(kind):
        if kind == "null":
            return data is None
        expected = TYPES.get(kind)
        return expected is None or (isinstance(data, expected)
            and not (kind in ("integer", "number") and isinstance(data, bool)))
    if not any(matches(kind) for kind in types):
        return [f"{path}: expected {t}, got {type(data).__name__}"]
    if "enum" in schema and not any(type(data) is type(v) and data == v for v in schema["enum"]):
        fail("value is outside enum")
    if "const" in schema and data != schema["const"]:
        fail("value differs from const")
    if isinstance(data, (int, float)) and not isinstance(data, bool):
        for key, comparison in (("minimum", lambda a,b: a < b), ("maximum", lambda a,b: a > b)):
            if key in schema and comparison(data, schema[key]):
                fail(f"violates {key}")
        for key, bound, comparison in (("exclusiveMinimum", "minimum", lambda a,b: a <= b),
                                       ("exclusiveMaximum", "maximum", lambda a,b: a >= b)):
            limit = schema.get(key)
            if isinstance(limit, bool):
                limit = schema.get(bound) if limit else None
            if limit is not None and comparison(data, limit):
                fail(f"violates {key}")
        multiple = schema.get("multipleOf")
        if multiple and not math.isclose(data / multiple, round(data / multiple), rel_tol=1e-9, abs_tol=1e-9):
            fail("violates multipleOf")
    if isinstance(data, str):
        if len(data) < schema.get("minLength", 0):
            fail("violates minLength")
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            fail("violates maxLength")
        if "pattern" in schema and re.search(schema["pattern"], data) is None:
            fail("does not match pattern")
    if isinstance(data, dict):
        for key in schema.get("required", []):
            if key not in data:
                errors.append(f"{path}.{key}: required field missing")
        properties = schema.get("properties", {})
        for key, value in data.items():
            sub = properties.get(key, schema.get("additionalProperties", {}))
            if sub is False:
                errors.append(f"{path}.{key}: additional property forbidden")
            elif isinstance(sub, dict):
                errors.extend(check_schema(sub, value, f"{path}.{key}"))
        if len(data) < schema.get("minProperties", 0):
            fail("violates minProperties")
        if "maxProperties" in schema and len(data) > schema["maxProperties"]:
            fail("violates maxProperties")
    if isinstance(data, list):
        if len(data) < schema.get("minItems", 0):
            fail("violates minItems")
        if "maxItems" in schema and len(data) > schema["maxItems"]:
            fail("violates maxItems")
        if schema.get("uniqueItems"):
            keys = [json.dumps(item, sort_keys=True) for item in data]
            if len(set(keys)) != len(keys):
                fail("violates uniqueItems")
        if isinstance(schema.get("items"), dict):
            for i, item in enumerate(data):
                errors.extend(check_schema(schema["items"], item, f"{path}[{i}]"))
    return errors


def classify(ep, target: str, case, schema: dict, status: int, body: str, json_body: Any,
             loc: str = "body", baseline_len: int | None = None, json_parsed: bool = False) -> list[Finding]:
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
    resp_schema = declared.get(str(status), declared.get("default"))
    if resp_schema and (json_body is not None or json_parsed):
        for e in check_schema(resp_schema, json_body)[:3]:
            f.append(mk("SCHEMA_VIOLATION", "medium", e))
    return f
