"""Versioned JSON schema artifacts for public ACB contracts."""

from copy import deepcopy
from typing import Any, Dict


SCHEMA_VERSION = "1.6.0"
JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"


RULE_FILE_SCHEMA: Dict[str, Any] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "$id": "https://agent-circuit-breaker.dev/schemas/rule-file.schema.json",
    "title": "Agent Circuit Breaker Rule File",
    "type": "object",
    "additionalProperties": False,
    "required": ["rules"],
    "properties": {
        "version": {"type": "integer", "const": 1},
        "signature": {"type": "object"},
        "rules": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/rule"},
        },
    },
    "$defs": {
        "rule": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "title", "severity", "response", "matcher"],
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "title": {"type": "string", "minLength": 1},
                "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "response": {"enum": ["allow", "block", "approval"]},
                "matcher": {"$ref": "#/$defs/matcher"},
                "metadata": {"type": "object"},
            },
        },
        "matcher": {
            "type": "object",
            "additionalProperties": False,
            "required": ["type"],
            "properties": {
                "type": {"enum": ["contains", "equals", "prefix", "regex", "all_of", "any_of", "not"]},
                "value": {"type": "string", "minLength": 1},
                "matchers": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"$ref": "#/$defs/matcher"},
                },
                "matcher": {"$ref": "#/$defs/matcher"},
            },
        },
    },
}


POLICY_FILE_SCHEMA: Dict[str, Any] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "$id": "https://agent-circuit-breaker.dev/schemas/policy-file.schema.json",
    "title": "Agent Circuit Breaker Policy File",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "profile": {"enum": ["solo", "repo", "team", "prod"]},
        "mode": {"enum": ["strict", "advisory", "approval"]},
        "rules": {
            "oneOf": [
                {"type": "string", "minLength": 1},
                RULE_FILE_SCHEMA,
            ]
        },
        "rule_file": {"type": "string", "minLength": 1},
        "strict": {"type": "boolean"},
        "signature": {"type": "object"},
    },
}


DECISION_OUTPUT_SCHEMA: Dict[str, Any] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "$id": "https://agent-circuit-breaker.dev/schemas/decision-output.schema.json",
    "title": "Agent Circuit Breaker Decision Output",
    "type": "object",
    "required": ["command", "verdict", "decision", "matched_rule", "risk_score", "error"],
    "properties": {
        "command": {},
        "verdict": {"enum": ["allow", "block", "error", "unknown", "pending_approval"]},
        "decision": {"enum": ["ALLOW", "BLOCK", "ERROR", "UNKNOWN", "PENDING_APPROVAL"]},
        "matched_rule": {"type": ["string", "null"]},
        "rule_details": {"type": ["object", "null"]},
        "operation_analysis": {"type": ["object", "null"]},
        "command_analysis": {"type": ["object", "null"]},
        "sql_analysis": {"type": ["object", "null"]},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "error": {"type": ["string", "null"]},
        "policy": {"type": ["object", "null"]},
    },
    "additionalProperties": True,
}


TRAJECTORY_OUTPUT_SCHEMA: Dict[str, Any] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "$id": "https://agent-circuit-breaker.dev/schemas/trajectory-output.schema.json",
    "title": "Agent Circuit Breaker Trajectory Output",
    "type": "object",
    "required": ["schema_version", "run_id", "verdict", "decision", "summary", "actions", "trajectory_findings"],
    "properties": {
        "schema_version": {"type": "integer"},
        "run_id": {"type": ["string", "null"]},
        "verdict": {"enum": ["allow", "block", "error", "unknown", "pending_approval"]},
        "decision": {"enum": ["ALLOW", "BLOCK", "ERROR", "UNKNOWN", "PENDING_APPROVAL"]},
        "summary": {"type": "object"},
        "contract": {"type": ["object", "null"]},
        "actions": {"type": "array"},
        "trajectory_findings": {"type": "array"},
        "error": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}


AUDIT_EVENT_SCHEMA: Dict[str, Any] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "$id": "https://agent-circuit-breaker.dev/schemas/audit-event.schema.json",
    "title": "Agent Circuit Breaker Audit Event",
    "type": "object",
    "required": ["source"],
    "properties": {
        "source": {"type": "string"},
        "command": {"type": ["string", "null"]},
        "verdict": {"type": ["string", "null"]},
        "decision": {"type": ["string", "null"]},
        "risk_score": {"type": ["integer", "null"]},
        "matched_rule": {"type": ["string", "null"]},
        "policy": {"type": ["object", "null"]},
        "redaction": {"type": "object"},
    },
    "additionalProperties": True,
}


SCHEMAS = {
    "rule-file": RULE_FILE_SCHEMA,
    "policy-file": POLICY_FILE_SCHEMA,
    "decision-output": DECISION_OUTPUT_SCHEMA,
    "trajectory-output": TRAJECTORY_OUTPUT_SCHEMA,
    "audit-event": AUDIT_EVENT_SCHEMA,
}


def get_schema(name: str) -> Dict[str, Any]:
    """Return one schema by stable name."""
    if name not in SCHEMAS:
        raise KeyError(f"unknown schema: {name}")
    return deepcopy(SCHEMAS[name])


def all_schemas() -> Dict[str, Dict[str, Any]]:
    """Return all public schema artifacts."""
    return {name: deepcopy(schema) for name, schema in SCHEMAS.items()}
