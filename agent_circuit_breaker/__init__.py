"""Agent Circuit Breaker - Local-first safety runtime for AI agents."""

__version__ = "1.6.9"
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
    "evaluate_production_readiness",
    "format_production_readiness",
    "format_safe_validation",
    "run_safe_environment_validation",
    "rule_schema_metadata",
    "validate_rule_file",
    "CapabilityGrant",
    "InMemoryRunStore",
    "RunContract",
    "RuntimeAction",
    "RuntimeApproval",
    "RuntimeDecision",
    "RuntimeEvent",
    "RuntimeExecutionResult",
    "RuntimeGate",
    "RuntimeIntegrityError",
    "RuntimeInvalidRecordError",
    "RuntimeMigrationError",
    "RuntimeMissingStateError",
    "RuntimeSchemaError",
    "RuntimeStateConflictError",
    "RuntimeStoreBusy",
    "RuntimeStoreError",
    "RuntimeStoreUnavailable",
    "SQLiteRunStore",
    "RuntimeState",
    "RuntimeToolCallResult",
    "RuntimeToolExecutor",
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

    if name in {"evaluate_production_readiness", "format_production_readiness"}:
        from .production import evaluate_production_readiness, format_production_readiness

        exports = {
            "evaluate_production_readiness": evaluate_production_readiness,
            "format_production_readiness": format_production_readiness,
        }
        return exports[name]

    if name in {"format_safe_validation", "run_safe_environment_validation"}:
        from .validation import format_safe_validation, run_safe_environment_validation

        exports = {
            "format_safe_validation": format_safe_validation,
            "run_safe_environment_validation": run_safe_environment_validation,
        }
        return exports[name]

    if name in {
        "InMemoryRunStore",
        "CapabilityGrant",
        "RunContract",
        "RuntimeAction",
        "RuntimeApproval",
        "RuntimeDecision",
        "RuntimeEvent",
        "RuntimeExecutionResult",
        "RuntimeGate",
        "RuntimeIntegrityError",
        "RuntimeInvalidRecordError",
        "RuntimeMigrationError",
        "RuntimeMissingStateError",
        "RuntimeSchemaError",
        "RuntimeStateConflictError",
        "RuntimeStoreBusy",
        "RuntimeStoreError",
        "RuntimeStoreUnavailable",
        "SQLiteRunStore",
        "RuntimeState",
        "RuntimeToolCallResult",
        "RuntimeToolExecutor",
    }:
        from .runtime import (
            CapabilityGrant,
            InMemoryRunStore,
            RunContract,
            RuntimeAction,
            RuntimeApproval,
            RuntimeDecision,
            RuntimeEvent,
            RuntimeExecutionResult,
            RuntimeGate,
            RuntimeIntegrityError,
            RuntimeInvalidRecordError,
            RuntimeMigrationError,
            RuntimeMissingStateError,
            RuntimeSchemaError,
            RuntimeStateConflictError,
            RuntimeStoreBusy,
            RuntimeStoreError,
            RuntimeStoreUnavailable,
            SQLiteRunStore,
            RuntimeState,
            RuntimeToolCallResult,
            RuntimeToolExecutor,
        )

        exports = {
            "CapabilityGrant": CapabilityGrant,
            "InMemoryRunStore": InMemoryRunStore,
            "RunContract": RunContract,
            "RuntimeAction": RuntimeAction,
            "RuntimeApproval": RuntimeApproval,
            "RuntimeDecision": RuntimeDecision,
            "RuntimeEvent": RuntimeEvent,
            "RuntimeExecutionResult": RuntimeExecutionResult,
            "RuntimeGate": RuntimeGate,
            "RuntimeIntegrityError": RuntimeIntegrityError,
            "RuntimeInvalidRecordError": RuntimeInvalidRecordError,
            "RuntimeMigrationError": RuntimeMigrationError,
            "RuntimeMissingStateError": RuntimeMissingStateError,
            "RuntimeSchemaError": RuntimeSchemaError,
            "RuntimeStateConflictError": RuntimeStateConflictError,
            "RuntimeStoreBusy": RuntimeStoreBusy,
            "RuntimeStoreError": RuntimeStoreError,
            "RuntimeStoreUnavailable": RuntimeStoreUnavailable,
            "SQLiteRunStore": SQLiteRunStore,
            "RuntimeState": RuntimeState,
            "RuntimeToolCallResult": RuntimeToolCallResult,
            "RuntimeToolExecutor": RuntimeToolExecutor,
        }
        return exports[name]

    raise AttributeError(f"module 'agent_circuit_breaker' has no attribute {name!r}")
