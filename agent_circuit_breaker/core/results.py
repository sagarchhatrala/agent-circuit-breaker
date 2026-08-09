"""Result DTOs for pipeline and action evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple


ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class EvaluationRequest:
    """Normalized action request used by typed decision results."""

    action_type: str
    subject: Any = None
    arguments: Mapping[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    actor: str | None = None
    workspace: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_action(
        cls,
        action: Any,
        *,
        action_type: str = "command",
        request_id: str | None = None,
        actor: str | None = None,
        workspace: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "EvaluationRequest":
        """Build a normalized request for a single action string."""
        return cls(
            action_type=action_type,
            subject=action,
            arguments={"action": action},
            request_id=request_id,
            actor=actor,
            workspace=workspace,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible request dictionary."""
        return {
            "request_id": self.request_id,
            "action_type": self.action_type,
            "subject": self.subject,
            "arguments": dict(self.arguments),
            "actor": self.actor,
            "workspace": self.workspace,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class Finding:
    """Structured evidence for one safety finding."""

    rule_id: str
    message: str
    severity: str = "LOW"
    domain: str = "unknown"
    pack_id: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    location: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible finding dictionary."""
        return {
            "rule_id": self.rule_id,
            "pack_id": self.pack_id,
            "domain": self.domain,
            "severity": self.severity,
            "message": self.message,
            "evidence": dict(self.evidence),
            "location": self.location,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class DecisionResult:
    """Typed action decision used internally before public dict rendering."""

    decision: str
    verdict: str
    reason: str = ""
    findings: Tuple[Finding, ...] = ()
    request: EvaluationRequest | None = None
    policy_source: str | None = None
    evaluation_id: str | None = None
    elapsed_ms: float | None = None
    fail_secure: bool = False
    risk_score: int = 0
    matched_rule: str | None = None
    error: str | None = None
    legacy_result: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_legacy_result(
        cls,
        result: Mapping[str, Any],
        *,
        request: EvaluationRequest | None = None,
        elapsed_ms: float | None = None,
    ) -> "DecisionResult":
        """Create a typed result from the stable v1.x public result dictionary."""
        decision = str(result.get("decision") or "").upper()
        verdict = str(result.get("verdict") or "").lower()
        matched_rule = result.get("matched_rule")
        error = result.get("error")
        risk_score = int(result.get("risk_score") or 0)
        findings = tuple(_findings_from_legacy_result(result))
        reason = _reason_from_legacy_result(result, findings)
        evaluation_id = _stable_evaluation_id(result, request)

        return cls(
            decision=decision,
            verdict=verdict,
            reason=reason,
            findings=findings,
            request=request,
            policy_source=result.get("policy_source"),
            evaluation_id=evaluation_id,
            elapsed_ms=elapsed_ms,
            fail_secure=verdict in {"block", "error", "pending_approval"},
            risk_score=risk_score,
            matched_rule=matched_rule,
            error=error,
            legacy_result=dict(result),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the typed decision model as a JSON-compatible dictionary."""
        return {
            "evaluation_id": self.evaluation_id,
            "decision": self.decision,
            "verdict": self.verdict,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "matched_rule": self.matched_rule,
            "error": self.error,
            "policy_source": self.policy_source,
            "fail_secure": self.fail_secure,
            "elapsed_ms": self.elapsed_ms,
            "request": self.request.to_dict() if self.request else None,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_legacy_dict(self) -> dict[str, Any]:
        """Return the stable v1.x public result dictionary."""
        if self.legacy_result:
            return dict(self.legacy_result)

        return {
            "command": self.request.subject if self.request else None,
            "verdict": self.verdict,
            "decision": self.decision,
            "matched_rule": self.matched_rule,
            "rule_details": None,
            "operation_analysis": None,
            "command_analysis": None,
            "sql_analysis": None,
            "risk_score": self.risk_score,
            "error": self.error,
        }


@dataclass(frozen=True)
class GuardResult:
    """Result returned by one guard."""

    verdict: str
    guard_id: str
    reason: str = ""
    severity: str = "LOW"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def applicable(self) -> bool:
        """Return false when a guard explicitly reports it did not apply."""
        return bool(self.metadata.get("applicable", True))

    @property
    def coverage_complete(self) -> bool:
        """Return false when a guard explicitly reports incomplete coverage."""
        return bool(self.metadata.get("coverage_complete", True))

    @classmethod
    def allow(cls, guard_id: str, reason: str = "", metadata: Mapping[str, Any] | None = None) -> "GuardResult":
        return cls(ALLOW, guard_id, reason, "LOW", metadata or {})

    @classmethod
    def deny(
        cls,
        guard_id: str,
        reason: str,
        severity: str = "HIGH",
        metadata: Mapping[str, Any] | None = None,
    ) -> "GuardResult":
        return cls(DENY, guard_id, reason, severity, metadata or {})

    @classmethod
    def unknown(cls, guard_id: str, reason: str = "", metadata: Mapping[str, Any] | None = None) -> "GuardResult":
        return cls(UNKNOWN, guard_id, reason, "LOW", metadata or {})

    @classmethod
    def not_applicable(cls, guard_id: str, reason: str = "") -> "GuardResult":
        return cls(UNKNOWN, guard_id, reason, "LOW", {"applicable": False, "coverage_complete": True})


@dataclass(frozen=True)
class PipelineResult:
    """Aggregate result from the concurrent guard pipeline."""

    verdict: str
    request_id: str
    guard_results: Tuple[GuardResult, ...]
    denied_by: str | None = None
    reason: str = ""
    validation: Mapping[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Return true when the pipeline allows execution."""
        return self.verdict == ALLOW


def _findings_from_legacy_result(result: Mapping[str, Any]) -> list[Finding]:
    """Build typed findings from the stable public result dictionary."""
    findings: list[Finding] = []
    matched_rule = result.get("matched_rule")
    rule_details = result.get("rule_details") or {}

    if matched_rule:
        domain = _infer_domain(result)
        evidence: dict[str, Any] = {
            "command": result.get("command"),
            "risk_score": result.get("risk_score"),
        }
        _add_analysis_evidence(evidence, "operation", result.get("operation_analysis"))
        _add_analysis_evidence(evidence, "command", result.get("command_analysis"))
        _add_analysis_evidence(evidence, "sql", result.get("sql_analysis"))

        findings.append(
            Finding(
                rule_id=str(matched_rule),
                pack_id=f"acb.{domain}.core" if domain != "unknown" else None,
                domain=domain,
                severity=str(rule_details.get("severity") or "LOW"),
                message=str(rule_details.get("title") or matched_rule),
                evidence=evidence,
                recommendation=None,
            )
        )

    if result.get("verdict") == "error":
        findings.append(
            Finding(
                rule_id="acb.evaluation_error",
                pack_id="acb.core",
                domain="core",
                severity="CRITICAL",
                message=str(result.get("error") or "Evaluation failed"),
                evidence={
                    "command": result.get("command"),
                    "risk_score": result.get("risk_score"),
                },
            )
        )

    return findings


def _reason_from_legacy_result(result: Mapping[str, Any], findings: Tuple[Finding, ...]) -> str:
    """Return a stable human-readable reason for a typed decision."""
    if result.get("error"):
        return str(result["error"])
    if findings:
        return findings[0].message
    verdict = result.get("verdict")
    if verdict == "allow":
        return "Action allowed by deterministic evaluation"
    if verdict == "unknown":
        return "No deterministic allow or block rule matched"
    if verdict == "pending_approval":
        return "Action requires approval"
    return "Evaluation completed"


def _infer_domain(result: Mapping[str, Any]) -> str:
    """Infer a coarse safety domain from legacy analysis fields."""
    sql_analysis = result.get("sql_analysis") or {}
    if sql_analysis.get("risk_flags") or sql_analysis.get("danger_reason"):
        return "sql"

    operation_analysis = result.get("operation_analysis") or {}
    if operation_analysis.get("operation") not in {None, "unknown"}:
        return "filesystem"

    command_analysis = result.get("command_analysis") or {}
    if command_analysis.get("command") or command_analysis.get("risk_flags"):
        return "shell"

    return "unknown"


def _add_analysis_evidence(evidence: dict[str, Any], prefix: str, analysis: Any) -> None:
    """Copy audit-safe risk evidence from an analysis dictionary."""
    if not isinstance(analysis, Mapping):
        return

    for key in ("risk_flags", "danger_reason", "error"):
        value = analysis.get(key)
        if value:
            evidence[f"{prefix}_{key}"] = value


def _stable_evaluation_id(result: Mapping[str, Any], request: EvaluationRequest | None) -> str:
    """Return a deterministic short ID for a typed decision."""
    payload = {
        "request": request.to_dict() if request else None,
        "command": result.get("command"),
        "decision": result.get("decision"),
        "verdict": result.get("verdict"),
        "matched_rule": result.get("matched_rule"),
        "error": result.get("error"),
    }
    encoded = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
