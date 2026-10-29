"""Sanitize every output channel, including non-secret findings and reviews."""
from __future__ import annotations

import re

SECRET_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9]+[_-])*(api[_-]?key|access[_-]?token|secret|password|bearer[_-]?token|auth[_-]?token|token)\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;}]{8,})"
)
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|secret|password|bearer[_-]?token|auth[_-]?token|token)\b[\"']?\s*[:=]\s*)(?:([\"'])(.*?)(\2)|([^\s,;}]+))"
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]+)")
_URL_AUTH = re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@", re.I)
_QUERY = re.compile(r"(?i)([?&](?:token|key|api_key|access_token|secret|password)=)[^&#\s\"']+")


def secret_values(text: str) -> set[str]:
    values = {m.group(3) or m.group(5) for m in _ASSIGNMENT.finditer(text)}
    values.update(m.group(2) for m in _BEARER.finditer(text))
    return {v for v in values if v and len(v) >= 8 and v != "<REDACTED>"}


def redact_text(text: str, known_secrets: set[str] | None = None) -> str:
    for value in sorted(known_secrets or (), key=len, reverse=True):
        text = text.replace(value, "<REDACTED>")
    text = _ASSIGNMENT.sub(
        lambda m: m.group(1) + (m.group(2) or "") + "<REDACTED>" + (m.group(4) or ""), text
    )
    text = _BEARER.sub(r"\1<REDACTED>", text)
    text = _URL_AUTH.sub(r"\1<REDACTED>@", text)
    return _QUERY.sub(r"\1<REDACTED>", text)


def redact_data(value, known_secrets: set[str] | None = None):
    if isinstance(value, str):
        return redact_text(value, known_secrets)
    if isinstance(value, list):
        return [redact_data(item, known_secrets) for item in value]
    if isinstance(value, dict):
        return {redact_text(str(key), known_secrets): redact_data(item, known_secrets) for key, item in value.items()}
    return value
