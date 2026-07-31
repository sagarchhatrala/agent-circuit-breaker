"""Tamper-evident local audit logging."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker.redaction import redact_record, redaction_metadata


DEFAULT_AUDIT_DIR = ".agent-circuit-breaker"
DEFAULT_AUDIT_FILE = "audit.jsonl"


def default_audit_path() -> Path:
    """Return the user-level audit log path."""
    configured = os.environ.get("ACB_AUDIT_LOG")
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_AUDIT_DIR / DEFAULT_AUDIT_FILE


class AuditLog:
    """Append-only JSONL audit log with hash chaining."""

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else default_audit_path()

    def append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append an event and return the stored entry."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        previous_hash = self._last_hash()
        entry = {
            "schema_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": previous_hash,
            "event": event,
        }
        entry["entry_hash"] = self._hash_entry(entry)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def tail(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return the last audit entries."""
        if not self.path.exists():
            return []
        entries = list(read_entries(self.path))
        return entries[-limit:]

    def verify(self) -> Dict[str, Any]:
        """Verify hash-chain integrity."""
        previous_hash = None
        count = 0
        for entry in read_entries(self.path):
            count += 1
            expected_previous = entry.get("previous_hash")
            if expected_previous != previous_hash:
                return {"is_valid": False, "entries": count, "error": "previous_hash mismatch"}
            entry_hash = entry.get("entry_hash")
            if entry_hash != self._hash_entry(entry):
                return {"is_valid": False, "entries": count, "error": "entry_hash mismatch"}
            previous_hash = entry_hash
        return {"is_valid": True, "entries": count, "error": None}

    def _last_hash(self) -> Optional[str]:
        last_hash = None
        if not self.path.exists():
            return None
        for entry in read_entries(self.path):
            last_hash = entry.get("entry_hash")
        return last_hash

    @staticmethod
    def _hash_entry(entry: Dict[str, Any]) -> str:
        material = {key: value for key, value in entry.items() if key != "entry_hash"}
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def read_entries(path: Path) -> Iterable[Dict[str, Any]]:
    """Read JSONL audit entries, skipping blank lines."""
    if not path.exists():
        return []
    entries: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def audit_event_from_result(result: Dict[str, Any], source: str = "cli") -> Dict[str, Any]:
    """Build a compact audit event from an evaluation result."""
    event = {
        "source": source,
        "command": result.get("command"),
        "verdict": result.get("verdict"),
        "decision": result.get("decision"),
        "risk_score": result.get("risk_score"),
        "matched_rule": result.get("matched_rule"),
        "policy": result.get("policy"),
        "redaction": redaction_metadata(),
    }
    return redact_record(event)
