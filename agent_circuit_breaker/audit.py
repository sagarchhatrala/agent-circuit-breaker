"""Tamper-evident local audit logging."""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker.decision import from_legacy_result
from agent_circuit_breaker.redaction import redact_record, redaction_metadata


DEFAULT_AUDIT_DIR = ".agent-circuit-breaker"
DEFAULT_AUDIT_FILE = "audit.jsonl"
AUDIT_HMAC_ENV = "ACB_AUDIT_HMAC_KEY"
MIN_AUDIT_HMAC_KEY_BYTES = 16


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
        key = _audit_hmac_key()
        entry = {
            "schema_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": previous_hash,
            "event": event,
            "integrity": {
                "hash_algorithm": "sha256",
                "signature_algorithm": "hmac-sha256" if key else None,
                "signature_key_source": AUDIT_HMAC_ENV if key else None,
            },
        }
        entry["entry_hash"] = self._hash_entry(entry)
        if key:
            entry["entry_signature"] = self._sign_entry(entry, key)
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
        key = _audit_hmac_key()
        for entry in read_entries(self.path):
            count += 1
            integrity = entry.get("integrity") if isinstance(entry.get("integrity"), dict) else {}
            hash_algorithm = integrity.get("hash_algorithm", "sha256")
            if hash_algorithm != "sha256":
                return {"is_valid": False, "entries": count, "error": "unsupported hash algorithm", "signature_checked": bool(key)}
            expected_previous = entry.get("previous_hash")
            if expected_previous != previous_hash:
                return {"is_valid": False, "entries": count, "error": "previous_hash mismatch", "signature_checked": bool(key)}
            entry_hash = entry.get("entry_hash")
            if entry_hash != self._hash_entry(entry):
                return {"is_valid": False, "entries": count, "error": "entry_hash mismatch", "signature_checked": bool(key)}
            signature_algorithm = integrity.get("signature_algorithm")
            has_signature = "entry_signature" in entry
            if not key and (signature_algorithm or has_signature):
                return {
                    "is_valid": False,
                    "entries": count,
                    "error": "entry_signature present but verification key unavailable",
                    "signature_checked": False,
                }
            if key:
                if signature_algorithm != "hmac-sha256":
                    return {"is_valid": False, "entries": count, "error": "unsupported signature algorithm", "signature_checked": True}
                signature = entry.get("entry_signature")
                if not isinstance(signature, str):
                    return {"is_valid": False, "entries": count, "error": "entry_signature missing", "signature_checked": True}
                if not hmac.compare_digest(signature, self._sign_entry(entry, key)):
                    return {"is_valid": False, "entries": count, "error": "entry_signature mismatch", "signature_checked": True}
            previous_hash = entry_hash
        return {"is_valid": True, "entries": count, "error": None, "signature_checked": bool(key)}

    def checkpoint(self) -> Dict[str, Any]:
        """Return a signed checkpoint for external retention."""
        verification = self.verify()
        if not verification["is_valid"]:
            raise ValueError(f"cannot checkpoint invalid audit log: {verification['error']}")
        entries = list(read_entries(self.path))
        key = _audit_hmac_key()
        checkpoint = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_path": str(self.path),
            "entry_count": len(entries),
            "last_entry_hash": entries[-1].get("entry_hash") if entries else None,
            "integrity": {
                "hash_algorithm": "sha256",
                "signature_algorithm": "hmac-sha256" if key else None,
                "signature_key_source": AUDIT_HMAC_ENV if key else None,
            },
        }
        checkpoint["checkpoint_hash"] = self._hash_checkpoint(checkpoint)
        if key:
            checkpoint["checkpoint_signature"] = self._sign_checkpoint(checkpoint, key)
        return checkpoint

    def verify_checkpoint(self, checkpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Verify that the current audit log still contains a retained checkpoint."""
        if not isinstance(checkpoint, dict):
            return {"is_valid": False, "error": "checkpoint must be an object"}
        if checkpoint.get("schema_version") != 1:
            return {"is_valid": False, "error": "unsupported checkpoint schema"}
        if checkpoint.get("checkpoint_hash") != self._hash_checkpoint(checkpoint):
            return {"is_valid": False, "error": "checkpoint_hash mismatch"}

        key = _audit_hmac_key()
        signature_algorithm = (checkpoint.get("integrity") or {}).get("signature_algorithm")
        if signature_algorithm or checkpoint.get("checkpoint_signature"):
            if not key:
                return {"is_valid": False, "error": "checkpoint_signature present but verification key unavailable"}
            if signature_algorithm != "hmac-sha256":
                return {"is_valid": False, "error": "unsupported checkpoint signature algorithm"}
            if not hmac.compare_digest(
                checkpoint.get("checkpoint_signature") or "",
                self._sign_checkpoint(checkpoint, key),
            ):
                return {"is_valid": False, "error": "checkpoint_signature mismatch"}

        verification = self.verify()
        if not verification["is_valid"]:
            return {"is_valid": False, "error": verification["error"], "audit_verification": verification}

        entries = list(read_entries(self.path))
        entry_count = checkpoint.get("entry_count")
        if not isinstance(entry_count, int) or entry_count < 0:
            return {"is_valid": False, "error": "checkpoint entry_count invalid"}
        if len(entries) < entry_count:
            return {
                "is_valid": False,
                "error": "audit log is shorter than checkpoint",
                "checkpoint_entries": entry_count,
                "current_entries": len(entries),
            }
        expected_hash = checkpoint.get("last_entry_hash")
        actual_hash = entries[entry_count - 1].get("entry_hash") if entry_count else None
        if actual_hash != expected_hash:
            return {"is_valid": False, "error": "checkpoint last_entry_hash mismatch"}
        return {
            "is_valid": True,
            "error": None,
            "checkpoint_entries": entry_count,
            "current_entries": len(entries),
            "signature_checked": bool(key and signature_algorithm),
        }

    def _last_hash(self) -> Optional[str]:
        last_hash = None
        if not self.path.exists():
            return None
        for entry in read_entries(self.path):
            last_hash = entry.get("entry_hash")
        return last_hash

    @staticmethod
    def _hash_entry(entry: Dict[str, Any]) -> str:
        material = {key: value for key, value in entry.items() if key not in {"entry_hash", "entry_signature"}}
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _sign_entry(entry: Dict[str, Any], key: str) -> str:
        material = {field: value for field, value in entry.items() if field != "entry_signature"}
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(key.encode("utf-8"), encoded, hashlib.sha256).hexdigest()

    @staticmethod
    def _hash_checkpoint(checkpoint: Dict[str, Any]) -> str:
        material = {
            key: value
            for key, value in checkpoint.items()
            if key not in {"checkpoint_hash", "checkpoint_signature"}
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _sign_checkpoint(checkpoint: Dict[str, Any], key: str) -> str:
        material = {field: value for field, value in checkpoint.items() if field != "checkpoint_signature"}
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(key.encode("utf-8"), encoded, hashlib.sha256).hexdigest()


def _audit_hmac_key() -> Optional[str]:
    key = os.environ.get(AUDIT_HMAC_ENV)
    if key is None:
        return None
    if not key:
        raise ValueError(f"{AUDIT_HMAC_ENV} is set but empty")
    if len(key.encode("utf-8")) < MIN_AUDIT_HMAC_KEY_BYTES:
        raise ValueError(f"{AUDIT_HMAC_ENV} must be at least {MIN_AUDIT_HMAC_KEY_BYTES} bytes")
    return key


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
    coverage = result.get("inspection_coverage") or {}
    validation = result.get("decision_validation") or {}
    canonical = from_legacy_result(result)
    event = {
        "source": source,
        "command": result.get("command"),
        "verdict": result.get("verdict"),
        "decision": result.get("decision"),
        "risk_score": result.get("risk_score"),
        "matched_rule": result.get("matched_rule"),
        "policy": result.get("policy"),
        "policy_source": result.get("policy_source"),
        "policy_trust": result.get("policy_trust"),
        "policy_signature": result.get("policy_signature"),
        "inspection_coverage": {
            "schema_version": coverage.get("schema_version"),
            "status": coverage.get("status"),
            "mandatory_complete": coverage.get("mandatory_complete"),
            "allow_eligible": coverage.get("allow_eligible"),
            "auto_allow_reason": coverage.get("auto_allow_reason"),
            "unknowns": coverage.get("unknowns") or [],
        },
        "decision_validation": {
            "schema_version": validation.get("schema_version"),
            "status": validation.get("status"),
            "allow_source": validation.get("allow_source"),
            "allow_permitted": validation.get("allow_permitted"),
            "reason": validation.get("reason"),
        },
        "canonical_decision": canonical.to_summary(),
        "redaction": redaction_metadata(),
    }
    return redact_record(event)
