"""LLM-driven hostile input generation via the Anthropic Messages API (optional).
Needs ANTHROPIC_API_KEY. Falls back silently to heuristics if unavailable."""
from __future__ import annotations
import json, os, re
import httpx

PROMPT = """You are a security tester. For the API endpoint below, propose {n} hostile or edge-case
values for the field "{field}" (schema: {schema}). Think about business-logic abuse (negative
quantities, huge ids, other users' ids, mass-assignment strings), injection (SQL, NoSQL, command,
template, XSS, path traversal) and parser edge cases that fit THIS field's meaning.
Reply with ONLY a JSON array of values.
Endpoint: {endpoint}"""


class ClaudeGenerator:
    def __init__(self, api_key: str | None = None, model: str | None = None, n: int = 8,
                 transport: httpx.BaseTransport | None = None):
        self.key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("SENTINEL_MODEL", "claude-sonnet-4-5")
        self.n = n
        self.client = httpx.Client(timeout=60, transport=transport)
        self.cache: dict = {}

    @property
    def available(self) -> bool:
        return bool(self.key)

    def __call__(self, endpoint: str, field: str, schema: dict) -> list:
        ck = (endpoint, field, json.dumps(schema, sort_keys=True))
        if ck in self.cache:
            return self.cache[ck]
        if not self.available:
            return []
        r = self.client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.key, "anthropic-version": "2023-06-01"},
            json={"model": self.model, "max_tokens": 1024, "messages": [{"role": "user", "content":
                  PROMPT.format(n=self.n, field=field, schema=json.dumps(schema), endpoint=endpoint)}]})
        r.raise_for_status()
        text = "".join(b.get("text", "") for b in r.json().get("content", []))
        m = re.search(r"\[.*\]", text, re.S)
        vals = json.loads(m.group(0)) if m else []
        self.cache[ck] = vals[: self.n]
        return self.cache[ck]
