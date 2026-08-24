"""Agent Circuit Breaker - Local-first safety runtime for AI agents."""

__version__ = "1.6.7"
__author__ = "Sagar Chhatrala"

from .engine import Engine, Decision, Rule
from .core import (
    AgentCircuitBreaker,
    AgentContext,
    DecisionResult,
    EvaluationRequest,
    Finding,
    GuardResult,
    PipelineBenchmark,
    PipelineEngine,
    PipelineResult,
    benchmark_pipeline,
)

__all__ = [
    "Engine",
    "Decision",
    "Rule",
    "AgentCircuitBreaker",
    "AgentContext",
    "DecisionResult",
    "EvaluationRequest",
    "Finding",
    "GuardResult",
    "PipelineBenchmark",
    "PipelineEngine",
    "PipelineResult",
    "benchmark_pipeline",
    "evaluate_action",
    "evaluate_trajectory",
    "rule_schema_metadata",
    "validate_rule_file",
]


def __getattr__(name):
    """Lazily expose public API helpers without importing the CLI during package init."""
    if name in {"evaluate_action", "evaluate_trajectory", "rule_schema_metadata", "validate_rule_file"}:
        from .api import evaluate_action, evaluate_trajectory, rule_schema_metadata, validate_rule_file

        exports = {
            "evaluate_action": evaluate_action,
            "evaluate_trajectory": evaluate_trajectory,
            "rule_schema_metadata": rule_schema_metadata,
            "validate_rule_file": validate_rule_file,
        }
        return exports[name]

    raise AttributeError(f"module 'agent_circuit_breaker' has no attribute {name!r}")
