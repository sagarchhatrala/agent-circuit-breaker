"""Safe local validation harness for production hardening."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_circuit_breaker.audit import AUDIT_HMAC_ENV, AuditLog
from agent_circuit_breaker.production import evaluate_production_readiness


@dataclass(frozen=True)
class ValidationPaths:
    root: Path
    evidence: Path
    runtime_store: Path
    audit_log: Path
    checkpoint: Path
    side_effects: Path


async def run_safe_environment_validation(root: Optional[str] = None) -> Dict[str, Any]:
    """Run safe end-to-end validation using synthetic local side effects only."""
    from agent_circuit_breaker.runtime import RuntimeGate, RuntimeToolExecutor, SQLiteRunStore

    paths = _validation_paths(root)
    _ensure_managed_artifacts_absent(paths)
    paths.evidence.mkdir(parents=True, exist_ok=True)
    old_audit_log = os.environ.get("ACB_AUDIT_LOG")
    old_hmac = os.environ.get(AUDIT_HMAC_ENV)
    os.environ["ACB_AUDIT_LOG"] = str(paths.audit_log)
    os.environ[AUDIT_HMAC_ENV] = "safe-validation-local-key-32-bytes"
    results: List[Dict[str, Any]] = []

    try:
        gate = RuntimeGate(
            evaluator=_safe_evaluator,
            store=SQLiteRunStore(str(paths.runtime_store)),
        )
        run = await gate.create_run(
            {
                "allowed_actors": ["validator"],
                "require_actor": True,
                "approval_required_targets": ["sandbox:approval-required"],
                "approver_tokens": {"security.validator": "safe-approval-token"},
            },
            run_id="safe-validation-run",
        )
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            actor="validator",
            executor=lambda action: _safe_executor(paths, action),
        )

        allowed = await executor.execute("safe-write allowed.txt")
        results.append(_result("allowed_runtime_execution", allowed.executed, {"executed": allowed.executed}))

        approval_action = {
            "command": "safe-write approved.txt",
            "actor": "validator",
            "target_resource": "sandbox:approval-required",
        }
        before_pending = _side_effect_count(paths)
        pending = await executor.execute(approval_action)
        after_pending = _side_effect_count(paths)
        approval = await gate.grant_approval(
            run.run_id,
            approval_action,
            approver="security.validator",
            approver_token="safe-approval-token",
        )
        approved = await executor.execute(approval_action, approval_id=approval.approval_id)
        try:
            replay = await executor.execute(approval_action, approval_id=approval.approval_id)
            replay_executed = replay.executed
            replay_error = None
        except ValueError as exc:
            replay_executed = False
            replay_error = str(exc)
        results.append(
            _result(
                "approval_required_consumed_once",
                (not pending.executed)
                and before_pending == after_pending
                and approved.executed
                and not replay_executed,
                {
                    "pending_executed": pending.executed,
                    "approved_executed": approved.executed,
                    "replay_executed": replay_executed,
                    "replay_error": replay_error,
                },
            )
        )

        deny_run = await gate.create_run(
            {"allowed_actors": ["validator"], "require_actor": True},
            run_id="safe-validation-deny-run",
        )
        deny_executor = RuntimeToolExecutor(
            gate,
            run_id=deny_run.run_id,
            actor="validator",
            executor=lambda action: _safe_executor(paths, action),
        )
        before_denied = _side_effect_count(paths)
        denied = await deny_executor.execute("rm -rf /")
        after_denied = _side_effect_count(paths)
        results.append(
            _result(
                "denied_runtime_execution_no_side_effect",
                (not denied.executed) and before_denied == after_denied,
                {"executed": denied.executed, "before": before_denied, "after": after_denied},
            )
        )

        audit = AuditLog(str(paths.audit_log))
        audit.append({"source": "safe-validation", "verdict": "allow", "run_id": run.run_id})
        checkpoint = audit.checkpoint()
        paths.checkpoint.write_text(json.dumps(checkpoint, indent=2, sort_keys=True), encoding="utf-8")
        checkpoint_verification = audit.verify_checkpoint(checkpoint)
        results.append(
            _result(
                "audit_checkpoint_verifies",
                bool(checkpoint_verification["is_valid"]),
                checkpoint_verification,
            )
        )

        production = await evaluate_production_readiness(
            runtime_store_path=str(paths.runtime_store),
            audit_log_path=str(paths.audit_log),
            require_audit_hmac=True,
        )
        results.append(
            _result(
                "production_check_passes",
                bool(production["is_production_ready"]),
                {"failure_count": production["failure_count"], "warning_count": production["warning_count"]},
            )
        )
    finally:
        _restore_env("ACB_AUDIT_LOG", old_audit_log)
        _restore_env(AUDIT_HMAC_ENV, old_hmac)

    payload = {
        "schema_version": 1,
        "root": str(paths.root),
        "runtime_store": str(paths.runtime_store),
        "audit_log": str(paths.audit_log),
        "checkpoint": str(paths.checkpoint),
        "side_effects": str(paths.side_effects),
        "result_count": len(results),
        "failures": [result for result in results if not result["passed"]],
        "results": results,
    }
    (paths.evidence / "safe_validation_results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return payload


def format_safe_validation(result: Dict[str, Any]) -> str:
    """Format safe validation results for terminal output."""
    lines = [
        f"Safe validation root: {result['root']}",
        f"Results: {result['result_count']}",
        f"Failures: {len(result['failures'])}",
    ]
    for item in result["results"]:
        lines.append(f"{'PASS' if item['passed'] else 'FAIL'} {item['id']}")
    return "\n".join(lines)


def _validation_paths(root: Optional[str]) -> ValidationPaths:
    root_path = Path(root) if root else Path(tempfile.mkdtemp(prefix="acb-safe-validation-"))
    evidence = root_path / "evidence"
    return ValidationPaths(
        root=root_path,
        evidence=evidence,
        runtime_store=evidence / "runtime.sqlite3",
        audit_log=evidence / "audit.jsonl",
        checkpoint=evidence / "audit.checkpoint.json",
        side_effects=evidence / "side_effects.jsonl",
    )


def _ensure_managed_artifacts_absent(paths: ValidationPaths) -> None:
    managed = [
        paths.runtime_store,
        paths.audit_log,
        paths.checkpoint,
        paths.side_effects,
        paths.evidence / "allowed.txt",
        paths.evidence / "approved.txt",
        paths.evidence / "safe_validation_results.json",
    ]
    existing = [str(path) for path in managed if path.exists()]
    if existing:
        raise FileExistsError(
            "safe validation managed artifact already exists: "
            + ", ".join(existing)
        )


def _safe_evaluator(action: str) -> Dict[str, Any]:
    if action.startswith("safe-write "):
        return {"verdict": "allow", "decision": "ALLOW", "risk_score": 0}
    if action == "rm -rf /":
        return {"verdict": "block", "decision": "BLOCK", "risk_score": 100}
    return {"verdict": "unknown", "decision": "UNKNOWN", "risk_score": 50}


def _safe_executor(paths: ValidationPaths, action: Dict[str, Any]) -> Dict[str, Any]:
    command = action.get("command")
    if not isinstance(command, str) or not command.startswith("safe-write "):
        raise ValueError("safe validation executor only accepts safe-write commands")
    name = command[len("safe-write ") :].strip()
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("safe validation filename must be a simple relative name")
    target = paths.evidence / name
    if paths.evidence.resolve() not in [target.resolve().parent, *target.resolve().parents]:
        raise ValueError("safe validation path escaped evidence directory")
    target.write_text("validated\n", encoding="utf-8")
    record = {"command": command, "target": str(target)}
    with paths.side_effects.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def _side_effect_count(paths: ValidationPaths) -> int:
    if not paths.side_effects.exists():
        return 0
    return len([line for line in paths.side_effects.read_text(encoding="utf-8").splitlines() if line.strip()])


def _result(check_id: str, passed: bool, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": check_id, "passed": bool(passed), "evidence": evidence}


def _restore_env(name: str, value: Optional[str]) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
