"""Load an OpenAPI 3 / Swagger 2 spec and flatten it into Endpoint objects."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


@dataclass
class Param:
    name: str
    location: str            # path | query | header | cookie | body
    schema: dict
    required: bool = False


@dataclass
class Endpoint:
    method: str
    path: str
    params: list[Param] = field(default_factory=list)
    body_schema: dict | None = None
    responses: dict[str, dict] = field(default_factory=dict)   # status -> schema
    secured: bool = False
    auth_params: list[tuple[str, str]] = field(default_factory=list)
    content_type: str = "json"      # json | form | multipart | text

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


def load_spec(source: str | Path | dict) -> dict:
    if isinstance(source, dict):
        return source
    text = Path(source).read_text(encoding="utf-8-sig")
    return json.loads(text) if str(source).endswith(".json") else yaml.safe_load(text)


def _resolve(spec: dict, node: Any, depth: int = 0) -> Any:
    """Resolve local $ref pointers (depth-limited so recursive schemas terminate)."""
    if depth > 8:
        return {}
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("#/"):
            target: Any = spec
            for part in node["$ref"][2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                target = target.get(part, {}) if isinstance(target, dict) else {}
            return _resolve(spec, target, depth + 1)
        out = {k: _resolve(spec, v, depth) for k, v in node.items()}
        if isinstance(out.get("allOf"), list):             # merge allOf into one object schema
            merged: dict = {"type": "object", "properties": {}, "required": []}
            for part in out.pop("allOf"):
                if isinstance(part, dict):
                    merged["properties"].update(part.get("properties", {}))
                    merged["required"] += part.get("required", [])
                    for k, v in part.items():
                        if k not in ("properties", "required"):
                            merged.setdefault(k, v)
            out = {**merged, **{k: v for k, v in out.items() if k not in ("properties", "required")}}
        for key in ("oneOf", "anyOf"):                      # fuzz the first alternative
            if isinstance(out.get(key), list) and out[key] and isinstance(out[key][0], dict):
                first = out.pop(key)[0]
                out = {**first, **out}
        return out
    if isinstance(node, list):
        return [_resolve(spec, v, depth) for v in node]
    return node


def _validate_structure(spec):
    """Validate operation containers without interpreting user-defined field names."""
    def security(value, where):
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError(f"{where}: security must be a list of mappings")
    def parameters(value, where):
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError(f"{where}: parameters must be a list of mappings")
    security(spec.get("security", []), "spec")
    for path, item in spec["paths"].items():
        if not isinstance(item, dict):
            raise ValueError(f"path {path} must contain an operation mapping")
        parameters(item.get("parameters", []), path)
        for method, operation in item.items():
            if method.lower() not in METHODS:
                continue
            where = f"{method.upper()} {path}"
            if not isinstance(operation, dict):
                raise ValueError(f"{where} must contain an operation mapping")
            parameters(operation.get("parameters", []), where)
            security(operation.get("security", []), where)
            responses = operation.get("responses", {})
            if not isinstance(responses, dict) or not all(isinstance(r, dict) for r in responses.values()):
                raise ValueError(f"{where}: responses must be a mapping of response objects")
            if "requestBody" in operation and not isinstance(operation["requestBody"], dict):
                raise ValueError(f"{where}: requestBody must be a mapping")


def parse_endpoints(spec: dict) -> list[Endpoint]:
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("OpenAPI document must contain a paths mapping")
    _validate_structure(spec)
    global_security = spec.get("security", [])
    schemes = spec.get("components", {}).get("securitySchemes", spec.get("securityDefinitions", {}))
    out: list[Endpoint] = []
    for path, item in (spec.get("paths") or {}).items():
        item = _resolve(spec, item)
        shared = item.get("parameters", [])
        for method, op in item.items():
            if method.lower() not in METHODS or not isinstance(op, dict):
                continue
            ep = Endpoint(method=method.upper(), path=path,
                          secured=bool(op.get("security", global_security)))
            security = op.get("security", global_security)
            ep.secured = bool(security) and all(bool(requirement) for requirement in security)
            for requirement in security:
                for name in requirement:
                    scheme = schemes.get(name, {})
                    if scheme.get("type") == "apiKey":
                        ep.auth_params.append((scheme.get("in", "header"), scheme.get("name", name)))
            consumes = op.get("consumes") or spec.get("consumes") or []
            form_props: dict = {}
            # Operation parameters override path parameters by name and location.
            parameters = {}
            for p in shared + op.get("parameters", []):
                p = _resolve(spec, p)
                parameters[(p.get("name"), p.get("in"))] = p
            for p in parameters.values():
                if p.get("in") == "body":                       # Swagger 2 body parameter
                    ep.body_schema = p.get("schema", {})
                    continue
                if p.get("in") == "formData":                   # Swagger 2 form field
                    form_props[p.get("name", "f")] = {k: v for k, v in p.items() if k in (
                        "type", "enum", "minimum", "maximum", "minLength", "maxLength", "pattern", "format")} or {"type": "string"}
                    continue
                schema = p.get("schema") or {k: v for k, v in p.items()
                                             if k in ("type", "enum", "minimum", "maximum",
                                                      "minLength", "maxLength", "pattern", "format")}
                ep.params.append(Param(p.get("name", "p"), p.get("in", "query"),
                                       schema or {"type": "string"}, bool(p.get("required"))))
            if form_props:
                ep.body_schema = {"type": "object", "properties": form_props}
                ep.content_type = "multipart" if "multipart/form-data" in consumes else "form"
            body = op.get("requestBody")
            if body:
                content = _resolve(spec, body).get("content", {})
                for ctype, kind in (("application/json", "json"), ("application/x-www-form-urlencoded", "form"),
                                    ("multipart/form-data", "multipart"), ("text/plain", "text")):
                    media = next((m for k, m in content.items()
                                  if k == ctype or (kind == "json" and k.endswith("+json"))), None)
                    if media is not None:
                        ep.body_schema = media.get("schema", {})
                        ep.content_type = kind
                        break
            for status, resp in (op.get("responses") or {}).items():
                resp = _resolve(spec, resp)
                media = (resp.get("content") or {}).get("application/json", {})
                ep.responses[str(status)] = media.get("schema", resp.get("schema", {}))
            out.append(ep)
    return out
