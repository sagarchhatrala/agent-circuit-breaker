"""Deterministic redaction helpers for persisted local records."""

import os
import re
from typing import Any


REDACTION_MARKER = "[REDACTED]"
RAW_RETENTION_ENV = "ACB_RETAIN_RAW_RECORDS"

SECRET_PATTERNS = (
    re.compile(r"(?i)\b([a-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|pwd)[a-z0-9_.-]*)\s*=\s*([^\s;&|]+)"),
    re.compile(r"(?i)\b(authorization:\s*bearer)\s+([a-z0-9._~+/=-]+)"),
    re.compile(r"(?i)([?&](?:api[_-]?key|token|secret|password)=)([^&\s]+)"),
    re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)@"),
    re.compile(r"(?i)(\s-u\s+[^:\s]+:)([^\s]+)"),
    re.compile(r"(?i)(\s-p)([^\s]+)"),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{12,})\b"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{8,})\b"),
)


def raw_retention_enabled() -> bool:
    """Return true when callers explicitly opt into raw persisted records."""
    return os.environ.get(RAW_RETENTION_ENV) in {"1", "true", "TRUE", "yes", "YES"}


def redact_text(value: str) -> str:
    """Redact common secret-like values from a string."""
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(_redact_match, redacted)
    return redacted


def _redact_match(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 2:
        return match.group(0)[: match.start(match.lastindex) - match.start(0)] + REDACTION_MARKER
    return REDACTION_MARKER


def redact_record(value: Any) -> Any:
    """Recursively redact strings in JSON-like data."""
    if raw_retention_enabled():
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        original = value
        redacted = [redact_record(item) for item in value]
        for index, item in enumerate(redacted):
            if not isinstance(item, str):
                continue
            previous = str(original[index - 1]).lower() if index >= 1 else ""
            previous_previous = str(original[index - 2]).lower() if index >= 2 else ""
            if _looks_like_secret_key(previous) or (previous == "=" and _looks_like_secret_key(previous_previous)):
                redacted[index] = REDACTION_MARKER
            elif previous in {"-u", "--user"} and ":" in item:
                username, _, _password = item.partition(":")
                redacted[index] = f"{username}:{REDACTION_MARKER}"
            elif re.fullmatch(r"(?i)-p\S+", item):
                redacted[index] = "-p" + REDACTION_MARKER
        return redacted
    if isinstance(value, dict):
        return {key: redact_record(child) for key, child in value.items()}
    return value


def _looks_like_secret_key(value: str) -> bool:
    return any(
        marker in value
        for marker in ("token", "secret", "password", "passwd", "pwd", "api_key", "apikey")
    )


def redaction_metadata() -> dict:
    """Return metadata describing persisted-record redaction behavior."""
    return {
        "enabled": not raw_retention_enabled(),
        "raw_retention_env": RAW_RETENTION_ENV,
    }
