"""Authentication helpers: static headers, bearer, basic, or login-flow token fetch."""
from __future__ import annotations
import base64
import httpx


def parse_headers(items: list[str] | None) -> dict:
    out = {}
    for it in items or []:
        k, _, v = it.partition(":")
        out[k.strip()] = v.strip()
    return out


def build_headers(headers=None, bearer=None, basic=None) -> dict:
    h = parse_headers(headers)
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    if basic:
        h["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
    return h


async def login_for_token(client: httpx.AsyncClient, url: str, body: dict, token_field: str = "access_token") -> dict:
    """POST credentials to a login endpoint and return an Authorization header."""
    r = await client.post(url, json=body)
    r.raise_for_status()
    data = r.json()
    for part in token_field.split("."):
        data = data[part]
    return {"Authorization": f"Bearer {data}"}
