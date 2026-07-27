"""Local pending-approval store."""

import hashlib
import json
import os
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

    def create(self, result: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a pending approval record for a result."""
        self.directory.mkdir(parents=True, exist_ok=True)
        approval_id = self._approval_id(result)
        path = self._path(approval_id)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        record = {
            "id": approval_id,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "decided_at": None,
            "approval_security": approval_security_context(),
            "context": context if context is not None else approval_context(result),
            "result": result,
        }
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
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
            "run_id": result.get("run_id"),
            "risk_score": result.get("risk_score"),
            "matched_rule": result.get("matched_rule"),
            "policy": result.get("policy"),
            "trajectory_findings": [
                finding.get("id")
                for finding in result.get("trajectory_findings", [])
            ],
        }
        digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()
        return digest[:16]


def approval_context(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return compact human-review context for an approval result."""
    if "trajectory_findings" in result:
        return {
            "type": "trajectory",
            "run_id": result.get("run_id"),
            "verdict": result.get("verdict"),
            "summary": result.get("summary"),
            "findings": [
                {
                    "id": finding.get("id"),
                    "severity": finding.get("severity"),
                    "indices": finding.get("indices"),
                    "reason": finding.get("reason"),
                }
                for finding in result.get("trajectory_findings", [])
            ],
            "recent_actions": [
                {
                    "trajectory_index": action.get("trajectory_index"),
                    "command": action.get("command"),
                    "verdict": action.get("verdict"),
                    "matched_rule": action.get("matched_rule"),
                }
                for action in result.get("actions", [])[-5:]
            ],
        }

    return {
        "type": "action",
        "command": result.get("command"),
        "verdict": result.get("verdict"),
        "decision": result.get("decision"),
        "risk_score": result.get("risk_score"),
        "matched_rule": result.get("matched_rule"),
        "policy": result.get("policy"),
    }


def approval_security_context() -> Dict[str, Any]:
    """Return local approval security metadata for review records."""
    token_required = bool(os.environ.get("ACB_APPROVAL_TOKEN"))
    warning = None
    if not token_required:
        warning = (
            "ACB_APPROVAL_TOKEN is not configured; any local actor with shell access "
            "can approve or deny this record."
        )
    return {
        "token_required": token_required,
        "warning": warning,
    }
