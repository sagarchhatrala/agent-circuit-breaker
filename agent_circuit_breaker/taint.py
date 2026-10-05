"""Hash-only cross-tool secret taint tracking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


DEFAULT_TAINT_FILE = ".agent-circuit-breaker/taint-ledger.jsonl"
DEFAULT_TTL_SECONDS = 600

SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|ghp|gho|github_pat|pypi|xox[baprs])[-_A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9_]{20,}\.[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}\b"),
)


def default_taint_path() -> Path:
    configured = os.environ.get("ACB_TAINT_LEDGER")
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_TAINT_FILE


class TaintLedger:
    """Append-only hash ledger for credential-shaped values.

    Raw secret values are never written to disk. The ledger stores only
    SHA-256 hashes plus source metadata and expires entries by age.
    """

    def __init__(self, path: Optional[str] = None, *, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.path = Path(path) if path else default_taint_path()
        self.ttl_seconds = ttl_seconds

    def tag_text(self, text: str, *, source: str, tool: Optional[str] = None) -> int:
        count = 0
        for secret in secret_candidates(text):
            self._append(secret, source=source, tool=tool)
            count += 1
        return count

    def tag_value(self, value: Any, *, source: str, tool: Optional[str] = None) -> int:
        return sum(self.tag_text(text, source=source, tool=tool) for text in _strings(value))

    def check_value(self, value: Any, *, different_tool: Optional[str] = None) -> Optional[Dict[str, Any]]:
        active = self.entries()
        if not active:
            return None
        hashes = {entry.get("hash"): entry for entry in active}
        for secret in secret_candidates(" ".join(_strings(value))):
            digest = _hash(secret)
            entry = hashes.get(digest)
            if entry is None:
                continue
            if different_tool and entry.get("tool") == different_tool:
                continue
            return {
                "hash": digest,
                "source": entry.get("source"),
                "tool": entry.get("tool"),
                "age_seconds": max(0, int(time.time() - float(entry.get("timestamp", 0)))),
            }
        return None

    def entries(self) -> List[Dict[str, Any]]:
        now = time.time()
        out: List[Dict[str, Any]] = []
        if not self.path.exists():
            return out
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = float(entry.get("timestamp", 0))
                if now - ts <= self.ttl_seconds:
                    out.append(entry)
        return out

    def flush(self) -> int:
        existing = len(self.entries())
        if self.path.exists():
            self.path.unlink()
        return existing

    def _append(self, secret: str, *, source: str, tool: Optional[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "schema_version": 1,
            "timestamp": time.time(),
            "hash": _hash(secret),
            "source": source,
            "tool": tool,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def secret_candidates(text: str) -> Iterable[str]:
    if not isinstance(text, str):
        return []
    matches: List[str] = []
    for pattern in SECRET_PATTERNS:
        matches.extend(match.group(0) for match in pattern.finditer(text))
    return matches


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
