"""Local pending-approval store."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


APPROVAL_DIR = ".agent-circuit-breaker/approvals"


def default_approval_dir() -> Path:
    """Return the default user-level approval directory."""
    return Path.home() / APPROVAL_DIR


class ApprovalStore:
    """File-backed local approval queue."""

    def __init__(self, directory: Optional[str] = None):
        self.directory = Path(directory) if directory else default_approval_dir()

    def create(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create a pending approval record for a result."""
        self.directory.mkdir(parents=True, exist_ok=True)
        approval_id = self._approval_id(result)
        record = {
            "id": approval_id,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "decided_at": None,
            "result": result,
        }
        self._path(approval_id).write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    def list(self) -> List[Dict[str, Any]]:
        """List approval records."""
        if not self.directory.exists():
            return []
        records = []
        for path in sorted(self.directory.glob("*.json")):
            records.append(json.loads(path.read_text(encoding="utf-8")))
        return records

    def decide(self, approval_id: str, status: str) -> Dict[str, Any]:
        """Approve or deny a pending record."""
        if status not in {"approved", "denied"}:
            raise ValueError("status must be approved or denied")
        path = self._path(approval_id)
        if not path.exists():
            raise FileNotFoundError(f"approval not found: {approval_id}")
        record = json.loads(path.read_text(encoding="utf-8"))
        record["status"] = status
        record["decided_at"] = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    def _path(self, approval_id: str) -> Path:
        return self.directory / f"{approval_id}.json"

    @staticmethod
    def _approval_id(result: Dict[str, Any]) -> str:
        material = {
            "command": result.get("command"),
            "risk_score": result.get("risk_score"),
            "matched_rule": result.get("matched_rule"),
            "policy": result.get("policy"),
        }
        digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()
        return digest[:16]
