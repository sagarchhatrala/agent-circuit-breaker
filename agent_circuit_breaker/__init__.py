"""Agent Circuit Breaker - Deterministic safety layer for AI agents."""

__version__ = "1.2.0"
__author__ = "Sagar Chhatrala"

from .engine import Engine, Decision, Rule

__all__ = [
    "Engine",
    "Decision",
    "Rule",
    "evaluate_action",
    "rule_schema_metadata",
    "validate_rule_file",
]


def __getattr__(name):
    """Lazily expose public API helpers without importing the CLI during package init."""
    if name in {"evaluate_action", "rule_schema_metadata", "validate_rule_file"}:
        from .api import evaluate_action, rule_schema_metadata, validate_rule_file

        exports = {
            "evaluate_action": evaluate_action,
            "rule_schema_metadata": rule_schema_metadata,
            "validate_rule_file": validate_rule_file,
        }
        return exports[name]

    raise AttributeError(f"module 'agent_circuit_breaker' has no attribute {name!r}")
