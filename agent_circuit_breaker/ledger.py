"""Replayable local run ledger for trajectory results."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker.decision import from_legacy_result
from agent_circuit_breaker.redaction import redact_record, redaction_metadata
from agent_circuit_breaker.audit import AuditLog, AUDIT_HMAC_ENV, _audit_hmac_key
from agent_circuit_breaker.log_lock import locked_log


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

    @locked_log
    def append(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Append a trajectory result and return the stored ledger entry."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        verification = self.verify()
        if not verification["is_valid"]:
            raise ValueError(f"cannot append to invalid run ledger: {verification['error']}")
        key = _audit_hmac_key()
        previous_hash = self._last_hash()
        entry = {
            "schema_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": previous_hash,
            "run_id": result.get("run_id"),
            "redaction": redaction_metadata(),
            "result": redact_record(result),
            "integrity": {
                "hash_algorithm": "sha256",
                "signature_algorithm": "hmac-sha256" if key else None,
                "signature_key_source": AUDIT_HMAC_ENV if key else None,
            },
        }
        entry["entry_hash"] = self._hash_entry(entry)
        if key:
            entry["entry_signature"] = AuditLog._sign_entry(entry, key)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return entry

    @locked_log
    def tail(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent ledger entries."""
        entries = list(read_ledger_entries(self.path))
        return entries[-limit:]

    @locked_log
    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Return the latest ledger entry for a run id."""
        match = None
        for entry in read_ledger_entries(self.path):
            if entry.get("run_id") == run_id:
                match = entry
        return match

    @locked_log
    def replay(self, run_id: str) -> Dict[str, Any]:
        """Return replayable action history for a stored trajectory run."""
        verification = self.verify()
        if not verification["is_valid"]:
            raise ValueError(f"cannot replay invalid run ledger: {verification['error']}")
        entry = self.get(run_id)
        if entry is None:
            raise FileNotFoundError(f"run not found: {run_id}")
        result = entry.get("result") or {}
        return {
            "run_id": run_id,
            "run_fingerprint": result.get("run_fingerprint"),
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
                    "engine_version": action.get("engine_version"),
                    "policy": action.get("policy"),
                    "policy_source": action.get("policy_source"),
                    "policy_trust": action.get("policy_trust"),
                    "policy_signature": action.get("policy_signature"),
                    "inspection_coverage": action.get("inspection_coverage"),
                    "decision_validation": action.get("decision_validation"),
                    "canonical_decision": action.get("canonical_decision")
                    or _canonical_action_summary(action),
                    "error": action.get("error"),
                }
                for action in result.get("actions", [])
            ],
        }

    def verify(self, *, require_signature: bool = False) -> Dict[str, Any]:
        """Verify the chain and, when configured, every protected-key signature."""
        result = AuditLog(str(self.path)).verify()
        if require_signature and not result.get("signature_checked"):
            return {**result, "is_valid": False, "error": "authenticated ledger required"}
        return result

    def checkpoint(self) -> Dict[str, Any]:
        """Create a checkpoint in the shared audit format for independent retention."""
        return AuditLog(str(self.path)).checkpoint()

    def verify_checkpoint(self, checkpoint: Dict[str, Any]) -> Dict[str, Any]:
        return AuditLog(str(self.path)).verify_checkpoint(checkpoint)

    def _last_hash(self) -> Optional[str]:
        last_hash = None
        for entry in read_ledger_entries(self.path):
            last_hash = entry.get("entry_hash")
        return last_hash

    @staticmethod
    def _hash_entry(entry: Dict[str, Any]) -> str:
        material = {key: value for key, value in entry.items() if key not in {"entry_hash", "entry_signature"}}
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


def _canonical_action_summary(action: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return from_legacy_result(action).to_summary()
    except Exception:
        return {}
