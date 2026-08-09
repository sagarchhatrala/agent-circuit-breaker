"""Canonical internal security decision contract.

This module is intentionally small. Public v1.x result dictionaries remain the
compatibility surface; this contract gives adapters a single place to derive
security meaning from those dictionaries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from agent_circuit_breaker import __version__


ALLOW = "ALLOW"
BLOCK = "BLOCK"
UNKNOWN = "UNKNOWN"
ERROR = "ERROR"
PENDING_APPROVAL = "PENDING_APPROVAL"
EXECUTABLE_DECISIONS = {ALLOW}
STOP_DECISIONS = {BLOCK, UNKNOWN, ERROR, PENDING_APPROVAL}


@dataclass(frozen=True)
class CanonicalDecision:
    """Internal, projection-friendly security decision."""

    action: Any
    verdict: str
    decision: str
    risk_score: int = 0
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    error: Optional[str] = None
    policy: Any = None
    policy_source: Optional[str] = None
    policy_trust: Any = None
    policy_signature: Any = None
    inspection_coverage: Any = None
    decision_validation: Any = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    engine_version: str = __version__

    @property
    def executable(self) -> bool:
        """Return true only for a validated ALLOW decision."""
        return self.decision == ALLOW and self.verdict == "allow"

    @property
    def stop_state(self) -> bool:
        """Return true when callers must not execute without another control."""
        return self.decision in STOP_DECISIONS or not self.executable

    @property
    def action_fingerprint(self) -> str:
        """Return a deterministic fingerprint of the evaluated action."""
        return stable_hash(self.action)

    def to_summary(self) -> dict[str, Any]:
        """Return a compact JSON-compatible decision summary."""
        return {
            "schema_version": 1,
            "action_fingerprint": self.action_fingerprint,
            "verdict": self.verdict,
            "decision": self.decision,
            "executable": self.executable,
            "stop_state": self.stop_state,
            "risk_score": self.risk_score,
            "matched_rule": self.matched_rule,
            "reason": self.reason,
            "error": self.error,
            "policy_source": self.policy_source,
            "policy_trust": self.policy_trust,
            "engine_version": self.engine_version,
            "evidence": dict(self.evidence),
        }


def from_legacy_result(result: Mapping[str, Any]) -> CanonicalDecision:
    """Build the canonical contract from the stable v1.x result dictionary."""
    coverage = result.get("inspection_coverage") or {}
    validation = result.get("decision_validation") or {}
    rule_details = result.get("rule_details") or {}
    reason = _reason_from_result(result, rule_details, validation)
    evidence = {
        "rule": {
            "id": result.get("matched_rule"),
            "title": rule_details.get("title"),
            "severity": rule_details.get("severity"),
            "response": rule_details.get("response"),
        },
        "coverage": {
            "schema_version": coverage.get("schema_version"),
            "status": coverage.get("status"),
            "mandatory_complete": coverage.get("mandatory_complete"),
            "allow_eligible": coverage.get("allow_eligible"),
            "auto_allow_reason": coverage.get("auto_allow_reason"),
            "unknowns": coverage.get("unknowns") or [],
        },
        "validation": {
            "schema_version": validation.get("schema_version"),
            "status": validation.get("status"),
            "allow_source": validation.get("allow_source"),
            "allow_permitted": validation.get("allow_permitted"),
            "reason": validation.get("reason"),
        },
        "policy": {
            "policy": result.get("policy"),
            "source": result.get("policy_source"),
            "trust": result.get("policy_trust"),
            "signature": result.get("policy_signature"),
        },
    }
    return CanonicalDecision(
        action=result.get("command"),
        verdict=str(result.get("verdict") or "").lower(),
        decision=str(result.get("decision") or "").upper(),
        risk_score=int(result.get("risk_score") or 0),
        matched_rule=result.get("matched_rule"),
        reason=reason,
        error=result.get("error"),
        policy=result.get("policy"),
        policy_source=result.get("policy_source"),
        policy_trust=result.get("policy_trust"),
        policy_signature=result.get("policy_signature"),
        inspection_coverage=result.get("inspection_coverage"),
        decision_validation=result.get("decision_validation"),
        evidence=evidence,
        engine_version=result.get("engine_version") or __version__,
    )


def legacy_with_canonical_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """Return a legacy result plus additive canonical decision metadata."""
    rendered = dict(result)
    rendered["canonical_decision"] = from_legacy_result(result).to_summary()
    return rendered


def stable_hash(value: Any) -> str:
    """Hash JSON-compatible values deterministically."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reason_from_result(
    result: Mapping[str, Any],
    rule_details: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> Optional[str]:
    if result.get("error"):
        return str(result.get("error"))
    if rule_details.get("title"):
        return str(rule_details.get("title"))
    if validation.get("reason"):
        return str(validation.get("reason"))
    decision = str(result.get("decision") or "").upper()
    if decision == ALLOW:
        return "action passed deterministic allow validation"
    if decision == UNKNOWN:
        return "no deterministic allow or block rule matched"
    if decision == PENDING_APPROVAL:
        return "action requires approval before execution"
    return None
