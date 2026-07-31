"""Replayable local run ledger for trajectory results."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker.redaction import redact_record, redaction_metadata


DEFAULT_LEDGER_DIR = ".agent-circuit-breaker"
DEFAULT_LEDGER_FILE = "run-ledger.jsonl"


def default_ledger_path() -> Path:
    """Return the user-level run ledger path."""
    configured = os.environ.get("ACB_RUN_LEDGER")
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_LEDGER_DIR / DEFAULT_LEDGER_FILE


class RunLedger:
    """Append-only JSONL run ledger with hash chaining."""

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else default_ledger_path()

    def append(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Append a trajectory result and return the stored ledger entry."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        previous_hash = self._last_hash()
        entry = {
            "schema_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": previous_hash,
            "run_id": result.get("run_id"),
            "redaction": redaction_metadata(),
            "result": redact_record(result),
        }
        entry["entry_hash"] = self._hash_entry(entry)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def tail(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent ledger entries."""
        entries = list(read_ledger_entries(self.path))
        return entries[-limit:]

    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Return the latest ledger entry for a run id."""
        match = None
        for entry in read_ledger_entries(self.path):
            if entry.get("run_id") == run_id:
                match = entry
        return match

    def replay(self, run_id: str) -> Dict[str, Any]:
        """Return replayable action history for a stored trajectory run."""
        entry = self.get(run_id)
        if entry is None:
            raise FileNotFoundError(f"run not found: {run_id}")
        result = entry.get("result") or {}
        return {
            "run_id": run_id,
            "verdict": result.get("verdict"),
            "summary": result.get("summary"),
            "contract": result.get("contract"),
            "trajectory_findings": result.get("trajectory_findings", []),
            "actions": [
                {
                    "trajectory_index": action.get("trajectory_index"),
                    "command": action.get("command"),
                    "verdict": action.get("verdict"),
                    "decision": action.get("decision"),
                    "matched_rule": action.get("matched_rule"),
                    "risk_score": action.get("risk_score"),
                }
                for action in result.get("actions", [])
            ],
        }

    def verify(self) -> Dict[str, Any]:
        """Verify ledger hash-chain integrity."""
        previous_hash = None
        count = 0
        for entry in read_ledger_entries(self.path):
            count += 1
            if entry.get("previous_hash") != previous_hash:
                return {"is_valid": False, "entries": count, "error": "previous_hash mismatch"}
            entry_hash = entry.get("entry_hash")
            if entry_hash != self._hash_entry(entry):
                return {"is_valid": False, "entries": count, "error": "entry_hash mismatch"}
            previous_hash = entry_hash
        return {"is_valid": True, "entries": count, "error": None}

    def _last_hash(self) -> Optional[str]:
        last_hash = None
        for entry in read_ledger_entries(self.path):
            last_hash = entry.get("entry_hash")
        return last_hash

    @staticmethod
    def _hash_entry(entry: Dict[str, Any]) -> str:
        material = {key: value for key, value in entry.items() if key != "entry_hash"}
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def read_ledger_entries(path: Path) -> Iterable[Dict[str, Any]]:
    """Read JSONL ledger entries, skipping blank lines."""
    if not path.exists():
        return []
    entries: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries
