"""Local production-readiness checks for supported ACB deployment scopes."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker import __version__
from agent_circuit_breaker.audit import AUDIT_HMAC_ENV, AuditLog


SUPPORTED_TARGETS = ("local-runtime", "general-containment")


@dataclass(frozen=True)
class ProductionCheck:
    """One production-readiness check result."""

    check_id: str
    status: str
    severity: str
    message: str
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.check_id,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


async def evaluate_production_readiness(
    *,
    target: str = "local-runtime",
    runtime_store_path: Optional[str] = None,
    audit_log_path: Optional[str] = None,
    require_audit_hmac: bool = False,
) -> Dict[str, Any]:
    """Evaluate local production-readiness posture without executing tools."""
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported production target: {target}")

    checks: List[ProductionCheck] = [
        _target_scope_check(target),
        _runtime_store_check_missing(runtime_store_path),
        _audit_integrity_check(audit_log_path, require_audit_hmac),
        _audit_hmac_check(require_audit_hmac),
        _local_only_release_check(),
    ]
    if runtime_store_path:
        checks.append(await _runtime_store_health_check(runtime_store_path))

    if target == "general-containment":
        checks.extend(_general_containment_blockers())

    check_dicts = [check.to_dict() for check in checks]
    failures = [
        check
        for check in check_dicts
        if check["status"] == "fail" and check["severity"] in {"critical", "high"}
    ]
    warnings = [check for check in check_dicts if check["status"] == "warn"]
    return {
        "schema_version": 1,
        "package": "agent-circuit-breaker",
        "version": __version__,
        "target": target,
        "is_production_ready": not failures,
        "failure_count": len(failures),
        "warning_count": len(warnings),
        "checks": check_dicts,
    }


def format_production_readiness(result: Dict[str, Any]) -> str:
    """Format production-readiness results for terminal output."""
    verdict = "READY" if result["is_production_ready"] else "NOT READY"
    lines = [
        f"Production target: {result['target']}",
        f"Verdict: {verdict}",
        f"Failures: {result['failure_count']}",
        f"Warnings: {result['warning_count']}",
    ]
    for check in result["checks"]:
        prefix = check["status"].upper()
        lines.append(f"{prefix} {check['id']}: {check['message']}")
    return "\n".join(lines)


def _target_scope_check(target: str) -> ProductionCheck:
    if target == "local-runtime":
        return ProductionCheck(
            "target_scope",
            "pass",
            "info",
            "target is the supported single-host RuntimeGate deployment scope",
            {"unsupported_general_claims": False},
        )
    return ProductionCheck(
        "target_scope",
        "fail",
        "critical",
        "general arbitrary-agent containment is not implemented by this package",
        {"unsupported_general_claims": True},
    )


def _runtime_store_check_missing(runtime_store_path: Optional[str]) -> ProductionCheck:
    if runtime_store_path:
        return ProductionCheck(
            "runtime_store_configured",
            "pass",
            "high",
            "RuntimeGate SQLite store path was provided",
            {"path": runtime_store_path},
        )
    return ProductionCheck(
        "runtime_store_configured",
        "fail",
        "high",
        "production local-runtime deployments must declare a RuntimeGate SQLite store",
        {"path": None},
    )


async def _runtime_store_health_check(runtime_store_path: str) -> ProductionCheck:
    from agent_circuit_breaker.runtime import SQLiteRunStore

    path = Path(runtime_store_path)
    if not path.exists():
        return ProductionCheck(
            "runtime_store_health",
            "fail",
            "critical",
            "runtime store path does not exist",
            {"path": runtime_store_path},
        )

    try:
        health = await SQLiteRunStore(runtime_store_path).health()
    except Exception as exc:
        return ProductionCheck(
            "runtime_store_health",
            "fail",
            "critical",
            f"runtime store failed health validation: {exc}",
            {"path": runtime_store_path, "error": str(exc)},
        )

    unresolved = int(health.get("unresolved_execution_runs") or 0)
    if unresolved:
        return ProductionCheck(
            "runtime_store_health",
            "fail",
            "high",
            "runtime store contains unresolved executions that require reconciliation",
            {"path": runtime_store_path, "health": health},
        )
    return ProductionCheck(
        "runtime_store_health",
        "pass",
        "high",
        "runtime store is readable and has no unresolved executions",
        {"path": runtime_store_path, "health": health},
    )


def _audit_integrity_check(audit_log_path: Optional[str], require_audit_hmac: bool) -> ProductionCheck:
    try:
        audit = AuditLog(audit_log_path)
        verification = audit.verify()
    except Exception as exc:
        return ProductionCheck(
            "audit_integrity",
            "fail",
            "high",
            f"audit log verification failed before integrity result: {exc}",
            {"path": audit_log_path, "error": str(exc), "require_hmac": require_audit_hmac},
        )

    if not verification.get("is_valid"):
        return ProductionCheck(
            "audit_integrity",
            "fail",
            "high",
            "audit log hash/signature verification failed",
            {"path": str(AuditLog(audit_log_path).path), "verification": verification},
        )

    status = "pass" if verification.get("entries") else "warn"
    message = "audit log verifies" if verification.get("entries") else "audit log verifies but contains no entries"
    return ProductionCheck(
        "audit_integrity",
        status,
        "medium",
        message,
        {"path": str(AuditLog(audit_log_path).path), "verification": verification},
    )


def _audit_hmac_check(require_audit_hmac: bool) -> ProductionCheck:
    configured = bool(os.environ.get(AUDIT_HMAC_ENV))
    if require_audit_hmac and not configured:
        return ProductionCheck(
            "audit_hmac",
            "fail",
            "high",
            f"{AUDIT_HMAC_ENV} is required but not configured",
            {"env": AUDIT_HMAC_ENV, "configured": False},
        )
    if configured:
        return ProductionCheck(
            "audit_hmac",
            "pass",
            "high",
            "audit HMAC key is configured for signed local evidence",
            {"env": AUDIT_HMAC_ENV, "configured": True},
        )
    return ProductionCheck(
        "audit_hmac",
        "warn",
        "medium",
        "audit HMAC key is not configured; hash chain is local tamper evidence only",
        {"env": AUDIT_HMAC_ENV, "configured": False},
    )


def _local_only_release_check() -> ProductionCheck:
    return ProductionCheck(
        "local_only_release",
        "pass",
        "info",
        "check is local-only and does not push, publish, tag, or create releases",
        {"network_side_effects": False},
    )


def _general_containment_blockers() -> Iterable[ProductionCheck]:
    blockers = [
        ("os_sandbox", "no OS sandbox, syscall policy, mount isolation, or process kill boundary is implemented"),
        ("distributed_coordination", "no multi-host lock service or consensus-backed runtime store is implemented"),
        ("external_audit_sink", "no independently controlled append-only audit sink is configured by this package"),
        ("unmediated_tool_bypass", "direct subprocess/tool calls outside RuntimeGate remain outside enforcement"),
    ]
    for check_id, message in blockers:
        yield ProductionCheck(check_id, "fail", "critical", message, {"implemented": False})
