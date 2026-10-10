"""Hostile / edge-case input generation: boundary-value heuristics + attack payloads
+ an optional LLM hook (any callable: (endpoint_key, param_name, schema) -> list[str])."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable

SQLI = ["'", "\"", "' OR '1'='1", "1; DROP TABLE users;--", "' UNION SELECT NULL,NULL--", "admin'--"]
XSS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)"]
TRAVERSAL = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]
LLMHook = Callable[[str, str, dict], list[Any]]


@dataclass
class Case:
    label: str        # boundary | sqli | xss | traversal | type_confusion | llm
    value: Any


def boundary_values(schema: dict) -> list[Case]:
    t = schema.get("type", "string")
    cases: list[Case] = []
    if t in ("integer", "number"):
        lo, hi = schema.get("minimum"), schema.get("maximum")
        vals = [0, -1, 2**31, -(2**31), 2**63]
        if lo is not None:
            vals += [lo - 1, lo]
        if hi is not None:
            vals += [hi, hi + 1]
        cases += [Case("boundary", v) for v in vals]
        cases += [Case("type_confusion", "not_a_number"), Case("type_confusion", None)]
    elif t == "boolean":
        cases += [Case("type_confusion", "maybe"), Case("type_confusion", 2)]
    elif t == "array":
        cases += [Case("boundary", []), Case("type_confusion", "scalar")]
        if "maxItems" in schema:
            cases.append(Case("boundary", [valid_value(schema.get("items", {}))] * (schema["maxItems"] + 1)))
        if "items" in schema:
            cases.append(Case("boundary", [None]))
    elif t == "object":
        cases += [Case("boundary", {}), Case("type_confusion", "scalar"), Case("type_confusion", None)]
    else:
        mx, mn = schema.get("maxLength"), schema.get("minLength")
        cases += [Case("boundary", ""), Case("boundary", "A" * 10000), Case("boundary", "\x00"),
                  Case("boundary", "Ã©ðŸ’¥")]
        if mx is not None:
            cases.append(Case("boundary", "A" * (mx + 1)))
        if mn:
            cases.append(Case("boundary", "A" * (mn - 1)))
        if "enum" in schema:
            cases.append(Case("boundary", "__not_in_enum__"))
        cases += [Case("type_confusion", 12345), Case("type_confusion", None)]
    return cases


def attack_values(schema: dict) -> list[Case]:
    if schema.get("type", "string") not in ("string", None):
        return []
    return ([Case("sqli", p) for p in SQLI] + [Case("xss", p) for p in XSS]
            + [Case("traversal", p) for p in TRAVERSAL])


def cases_for(endpoint_key: str, name: str, schema: dict, llm: LLMHook | None = None) -> list[Case]:
    cases = boundary_values(schema) + attack_values(schema)
    if llm:
        try:
            cases += [Case("llm", v) for v in llm(endpoint_key, name, schema)]
        except Exception:
            pass
    return cases


def valid_value(schema: dict) -> Any:
    """A well-formed baseline value, used for the fields we are NOT currently fuzzing."""
    if "enum" in schema:
        return schema["enum"][0]
    t = schema.get("type", "string")
    if t == "integer":
        return int(schema.get("minimum", 1))
    if t == "number":
        return float(schema.get("minimum", 1))
    if t == "boolean":
        return True
    if t == "array":
        return [valid_value(schema.get("items", {})) for _ in range(schema.get("minItems", 0))]
    if t == "object":
        return {k: valid_value(v) for k, v in schema.get("properties", {}).items()}
    return "test"
