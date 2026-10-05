"""Rule-based fuzz-risk score (same idea as FUZZ_RISK in the EDA notebook):
more unvalidated input surface, mutating verbs and missing auth/error docs => test first."""
from .spec import Endpoint

_VALIDATION_KEYS = ("enum", "minimum", "maximum", "minLength", "maxLength", "pattern", "format")


def _validated(schema: dict) -> bool:
    return any(k in schema for k in _VALIDATION_KEYS)


def fuzz_risk_score(ep: Endpoint) -> float:
    params = list(ep.params)
    n_props = len((ep.body_schema or {}).get("properties", {}))
    if ep.body_schema is not None and not n_props:
        n_props = 1          # free-form body: one wide-open input
    total = len(params) + n_props
    validated = sum(_validated(p.schema) for p in params)
    validated += sum(_validated(s) for s in (ep.body_schema or {}).get("properties", {}).values())
    unvalidated = (total - validated) / total if total else 0.0
    score = 40 * unvalidated + min(total, 10) * 2
    if ep.method in ("POST", "PUT", "PATCH", "DELETE"):
        score += 15
        if not ep.secured:
            score += 15
    if not any(s.startswith("4") for s in ep.responses):
        score += 10
    return round(min(score, 100.0), 1)


def band(score: float) -> str:
    return "High" if score >= 60 else "Medium" if score >= 30 else "Low"
