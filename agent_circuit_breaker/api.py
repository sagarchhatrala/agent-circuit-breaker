"""Public Python API for Agent Circuit Breaker integrations."""

from typing import Any, Dict, Optional

from agent_circuit_breaker.cli import CircuitBreakerCLI
from agent_circuit_breaker.engine import Decision
from agent_circuit_breaker.rules.loader import RuleFileLoader, RuleSchema
from agent_circuit_breaker.trajectory import evaluate_trajectory as _evaluate_trajectory


def evaluate_action(action: str, rule_file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate an action and return a deterministic result dictionary.

    Args:
        action: Action or command text to evaluate.
        rule_file_path: Optional external JSON rule file to append after built-in rules.

    Returns:
        Evaluation result dictionary. Invalid rule files fail closed with an error verdict.
    """
    cli = CircuitBreakerCLI()
    custom_rules = []
    custom_rule_summary = None

    if rule_file_path is not None:
        custom_rule_result = cli.load_custom_rules(rule_file_path)
        custom_rule_summary = {
            "path": rule_file_path,
            "is_valid": custom_rule_result["is_valid"],
            "errors": custom_rule_result["errors"],
            "rule_count": len(custom_rule_result["rules"]),
        }

        if not custom_rule_result["is_valid"]:
            result = _error_result(action, "Invalid rule file")
            result["custom_rules"] = custom_rule_summary
            return result

        custom_rules = custom_rule_result["rules"]

    result = cli.evaluate_command(action, custom_rules)
    if custom_rule_summary is not None:
        result["custom_rules"] = custom_rule_summary
    return result


def evaluate_trajectory(
    actions: list[str],
    contract: Optional[Dict[str, Any]] = None,
    rule_file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate a sequence of actions for single-action and trajectory-level risk.

    Args:
        actions: Ordered list of action or command strings.
        contract: Optional run contract with goal, allowed_scopes,
            forbidden_targets, allowed_outputs, max_blocked_attempts, and
            max_unknown_actions.
        rule_file_path: Optional external JSON rule file to append after built-in rules.

    Returns:
        Trajectory result dictionary. Invalid inputs or rule files fail closed.
    """
    cli = CircuitBreakerCLI()
    custom_rules = []
    custom_rule_summary = None

    if rule_file_path is not None:
        custom_rule_result = cli.load_custom_rules(rule_file_path)
        custom_rule_summary = {
            "path": rule_file_path,
            "is_valid": custom_rule_result["is_valid"],
            "errors": custom_rule_result["errors"],
            "rule_count": len(custom_rule_result["rules"]),
        }

        if not custom_rule_result["is_valid"]:
            return _trajectory_error_result("Invalid rule file", custom_rule_summary)

        custom_rules = custom_rule_result["rules"]

    try:
        result = _evaluate_trajectory(
            actions,
            lambda action: cli.evaluate_command(action, custom_rules),
            contract=contract,
        )
    except ValueError as exc:
        return _trajectory_error_result(str(exc), custom_rule_summary)

    if custom_rule_summary is not None:
        result["custom_rules"] = custom_rule_summary
    return result


def validate_rule_file(path: str) -> Dict[str, Any]:
    """
    Validate an external JSON rule file.

    Args:
        path: Path to a JSON rule file.

    Returns:
        Dictionary with path, validity, errors, and parsed definition when valid.
    """
    result = RuleFileLoader.load(path)
    return {
        "path": path,
        "is_valid": result["is_valid"],
        "errors": result["errors"],
        "definition": result["definition"],
    }


def rule_schema_metadata() -> Dict[str, Any]:
    """Return deterministic metadata for the supported external rule schema."""
    return RuleSchema.metadata()


def _error_result(action: Any, error: str) -> Dict[str, Any]:
    """Build a public API error result without evaluating the action."""
    return {
        "command": action,
        "verdict": "error",
        "decision": Decision.ERROR.name,
        "matched_rule": None,
        "rule_details": None,
        "operation_analysis": None,
        "command_analysis": None,
        "sql_analysis": None,
        "risk_score": 100,
        "error": error,
    }


def _trajectory_error_result(error: str, custom_rule_summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a public API trajectory error result without action evaluation."""
    result: Dict[str, Any] = {
        "schema_version": 1,
        "run_id": None,
        "verdict": "error",
        "decision": Decision.ERROR.name,
        "summary": {
            "actions": 0,
            "allowed": 0,
            "blocked": 0,
            "unknown": 0,
            "pending_approval": 0,
            "errors": 1,
            "trajectory_findings": 0,
        },
        "contract": None,
        "actions": [],
        "trajectory_findings": [],
        "error": error,
    }
    if custom_rule_summary is not None:
        result["custom_rules"] = custom_rule_summary
    return result
