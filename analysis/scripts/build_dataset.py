#!/usr/bin/env python3
"""
SentinelAPI - Dataset Builder
=============================
Parses the APIs.guru OpenAPI Directory (~4,100 real-world REST API
specifications) into a flat, endpoint-level dataset.

Each row = one API endpoint (one path + one HTTP method).

The columns describe the "attack surface" that SentinelAPI would see when it
parses a spec: how many parameters exist, how many are validated, whether
authentication is required, which error responses are declared, and so on.

Output: data/raw_api_endpoints.csv.gz  (gzipped CSV, read directly by pandas)
"""

import os
import sys
import csv
import gzip
import glob
import warnings
from multiprocessing import Pool, cpu_count

import yaml

warnings.filterwarnings("ignore")

try:
    from yaml import CSafeLoader as Loader
except ImportError:
    from yaml import SafeLoader as Loader

REPO = "/home/claude/openapi-directory/APIs"
OUT = "/home/claude/visualization/data/raw_api_endpoints.csv.gz"

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
STATE_CHANGING = {"post", "put", "patch", "delete"}

# Keywords that constitute an actual input-validation rule on a parameter.
CONSTRAINT_KEYS = {
    "maxLength", "minLength", "pattern", "enum", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "maxItems", "minItems", "uniqueItems", "format",
}

FIELDS = [
    # --- identity -------------------------------------------------------
    "api_provider", "api_title", "api_version", "spec_version", "category",
    "path", "http_method",
    # --- structure ------------------------------------------------------
    "path_depth", "path_length_chars", "has_description", "is_deprecated",
    "is_state_changing",
    # --- parameter surface ---------------------------------------------
    "num_path_params", "num_query_params", "num_header_params",
    "num_cookie_params", "total_params", "num_required_params",
    "num_optional_params",
    # --- validation coverage -------------------------------------------
    "num_constrained_params", "num_unconstrained_params",
    "num_string_params", "num_unconstrained_string_params",
    "num_enum_params", "num_pattern_params", "num_length_bounded_params",
    "num_numeric_range_params",
    # --- request body ---------------------------------------------------
    "has_request_body", "body_required",
    # --- responses ------------------------------------------------------
    "num_response_codes", "num_2xx_responses", "num_4xx_responses",
    "num_5xx_responses", "has_default_response",
    # --- security -------------------------------------------------------
    "requires_auth", "num_security_schemes",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def deref(node, root, depth=0):
    """Resolve a local $ref (e.g. '#/components/parameters/PageSize')."""
    if depth > 6 or not isinstance(node, dict):
        return node if isinstance(node, dict) else {}
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    target = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(target, dict) and part in target:
            target = target[part]
        else:
            return {}
    return deref(target, root, depth + 1)


def param_schema(p):
    """Return the schema dict of a parameter, for Swagger 2 and OpenAPI 3."""
    if isinstance(p.get("schema"), dict):
        return p["schema"]
    # Swagger 2.0 puts type/format/enum directly on the parameter
    return p


def has_constraint(p):
    """True if the parameter declares at least one validation rule."""
    sch = param_schema(p)
    if not isinstance(sch, dict):
        return False
    return any(k in sch for k in CONSTRAINT_KEYS)


def is_string_param(p):
    sch = param_schema(p)
    return isinstance(sch, dict) and sch.get("type") == "string"


def collect_params(op, path_item, root):
    """Merge path-level and operation-level parameters, resolving $refs."""
    raw = []
    for src in (path_item.get("parameters"), op.get("parameters")):
        if isinstance(src, list):
            raw.extend(src)
    out, seen = [], set()
    for p in raw:
        p = deref(p, root)
        if not isinstance(p, dict):
            continue
        key = (p.get("name"), p.get("in"))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def count_responses(op):
    resp = op.get("responses")
    if not isinstance(resp, dict):
        return 0, 0, 0, 0, 0
    codes = [str(c) for c in resp.keys()]
    n2 = sum(1 for c in codes if c.startswith("2"))
    n4 = sum(1 for c in codes if c.startswith("4"))
    n5 = sum(1 for c in codes if c.startswith("5"))
    has_default = int("default" in codes)
    return len(codes), n2, n4, n5, has_default


# ---------------------------------------------------------------------------
# per-file parsing
# ---------------------------------------------------------------------------

def parse_spec(filepath):
    rows = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            spec = yaml.load(fh, Loader=Loader)
    except Exception:
        return rows
    if not isinstance(spec, dict):
        return rows

    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        return rows

    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    spec_version = "OpenAPI 3.x" if "openapi" in spec else "Swagger 2.0"

    cats = info.get("x-apisguru-categories")
    category = cats[0] if isinstance(cats, list) and cats else "uncategorised"

    # provider folder name, e.g. APIs/stripe.com/2022-11-15/openapi.yaml
    rel = os.path.relpath(filepath, REPO).split(os.sep)
    provider = rel[0] if rel else "unknown"

    global_security = spec.get("security")
    global_secure = bool(isinstance(global_security, list) and global_security)

    if "components" in spec and isinstance(spec.get("components"), dict):
        schemes = spec["components"].get("securitySchemes")
    else:
        schemes = spec.get("securityDefinitions")
    n_schemes = len(schemes) if isinstance(schemes, dict) else 0

    for path, path_item in paths.items():
        if not isinstance(path_item, dict) or not isinstance(path, str):
            continue
        for method, op in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            m = method.lower()
            params = collect_params(op, path_item, spec)

            n_path = sum(1 for p in params if p.get("in") == "path")
            n_query = sum(1 for p in params if p.get("in") == "query")
            n_header = sum(1 for p in params if p.get("in") == "header")
            n_cookie = sum(1 for p in params if p.get("in") == "cookie")
            n_required = sum(1 for p in params if p.get("required") is True)

            n_constrained = sum(1 for p in params if has_constraint(p))
            strings = [p for p in params if is_string_param(p)]
            n_unconstrained_str = sum(1 for p in strings if not has_constraint(p))

            def cnt(keys):
                return sum(
                    1 for p in params
                    if isinstance(param_schema(p), dict)
                    and any(k in param_schema(p) for k in keys)
                )

            n_enum = cnt({"enum"})
            n_pattern = cnt({"pattern"})
            n_len = cnt({"maxLength", "minLength"})
            n_range = cnt({"minimum", "maximum",
                           "exclusiveMinimum", "exclusiveMaximum"})

            # request body (OpenAPI 3) or body parameter (Swagger 2)
            rb = op.get("requestBody")
            body_params = [p for p in params if p.get("in") == "body"]
            has_body = int(bool(isinstance(rb, dict) and rb) or bool(body_params))
            if isinstance(rb, dict):
                body_req = int(rb.get("required") is True)
            elif body_params:
                body_req = int(any(p.get("required") is True for p in body_params))
            else:
                body_req = 0

            n_codes, n2, n4, n5, has_def = count_responses(op)

            op_sec = op.get("security")
            if isinstance(op_sec, list):
                secure = bool(op_sec)          # [] explicitly disables auth
            else:
                secure = global_secure

            desc = op.get("description") or op.get("summary")

            rows.append({
                "api_provider": provider,
                "api_title": (info.get("title") or "")[:120],
                "api_version": str(info.get("version") or ""),
                "spec_version": spec_version,
                "category": category,
                "path": path[:200],
                "http_method": m.upper(),
                "path_depth": len([s for s in path.split("/") if s]),
                "path_length_chars": len(path),
                "has_description": int(bool(desc and str(desc).strip())),
                "is_deprecated": int(op.get("deprecated") is True),
                "is_state_changing": int(m in STATE_CHANGING),
                "num_path_params": n_path,
                "num_query_params": n_query,
                "num_header_params": n_header,
                "num_cookie_params": n_cookie,
                "total_params": len(params),
                "num_required_params": n_required,
                "num_optional_params": len(params) - n_required,
                "num_constrained_params": n_constrained,
                "num_unconstrained_params": len(params) - n_constrained,
                "num_string_params": len(strings),
                "num_unconstrained_string_params": n_unconstrained_str,
                "num_enum_params": n_enum,
                "num_pattern_params": n_pattern,
                "num_length_bounded_params": n_len,
                "num_numeric_range_params": n_range,
                "has_request_body": has_body,
                "body_required": body_req,
                "num_response_codes": n_codes,
                "num_2xx_responses": n2,
                "num_4xx_responses": n4,
                "num_5xx_responses": n5,
                "has_default_response": has_def,
                "requires_auth": int(secure),
                "num_security_schemes": n_schemes,
            })
    return rows


# ---------------------------------------------------------------------------

def main():
    files = sorted(
        glob.glob(os.path.join(REPO, "**", "openapi.yaml"), recursive=True)
        + glob.glob(os.path.join(REPO, "**", "swagger.yaml"), recursive=True)
    )
    print(f"Specification files found: {len(files)}")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)

    n_rows = 0
    with gzip.open(OUT, "wt", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        with Pool(processes=max(2, cpu_count())) as pool:
            for i, rows in enumerate(pool.imap_unordered(parse_spec, files,
                                                         chunksize=8), 1):
                for r in rows:
                    writer.writerow(r)
                n_rows += len(rows)
                if i % 400 == 0:
                    print(f"  parsed {i}/{len(files)} specs -> {n_rows} endpoints",
                          flush=True)

    print(f"\nDone. {n_rows} endpoint rows written to {OUT}")


if __name__ == "__main__":
    main()
