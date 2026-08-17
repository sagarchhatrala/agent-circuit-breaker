"""Command-line interface for Agent Circuit Breaker."""

import sys
import json
import argparse
import os
from typing import Dict, Any, List, Optional
from pathlib import Path

from agent_circuit_breaker import __version__
from agent_circuit_breaker.engine import Engine, Decision
from agent_circuit_breaker.approvals import ApprovalStore, approval_context
from agent_circuit_breaker.audit import AuditLog, audit_event_from_result
from agent_circuit_breaker.catalog import built_in_rule_catalog, format_catalog_markdown
from agent_circuit_breaker.explain import explain_result, format_explanation
from agent_circuit_breaker.hooks import hook_instructions, write_hook_scaffold
from agent_circuit_breaker.ledger import RunLedger
from agent_circuit_breaker.limits import (
    MAX_COMMAND_BYTES,
    MAX_TRAJECTORY_ACTIONS,
    MAX_TRAJECTORY_FILE_BYTES,
    ensure_file_within_limit,
    ensure_text_within_limit,
)
from agent_circuit_breaker.plugins import discover_plugins, load_rule_plugins
from agent_circuit_breaker.policy import load_policy
from agent_circuit_breaker.profiles import apply_policy_mode, get_profile, profile_metadata
from agent_circuit_breaker.rules.builtin_rules import BUILTIN_RULES
from agent_circuit_breaker.rules.loader import RuleDefinitionBuilder, RuleFileLoader
from agent_circuit_breaker.sarif import scan_to_sarif
from agent_circuit_breaker.scan import format_scan_result, scan_paths
from agent_circuit_breaker.trajectory import evaluate_trajectory
from agent_circuit_breaker.inspectors.filesystem import FilesystemInspector
from agent_circuit_breaker.inspectors.command import CommandInspector
from agent_circuit_breaker.inspectors.sql import SQLInspector


class CircuitBreakerCLI:
    """CLI interface for Agent Circuit Breaker safety evaluation."""

    def __init__(
        self,
        verbose: bool = False,
        output_format: str = "text",
        json_output: bool = False,
    ):
        """
        Initialize the CLI.

        Args:
            verbose: Enable verbose output
            output_format: Output format, either "text" or "json"
            json_output: Compatibility shortcut for JSON output
        """
        self.verbose = verbose
        self.output_format = "json" if json_output else output_format
        self.engine = Engine()
        self.inspector = FilesystemInspector()
        self.command_inspector = CommandInspector()
        self.sql_inspector = SQLInspector()

    def evaluate_command(
        self,
        command: str,
        extra_rules: Optional[List[Any]] = None,
        *,
        profile_name: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate a shell command for safety.

        Args:
            command: Shell command to evaluate

        Returns:
            Dictionary with evaluation results
        """
        result = {
            "command": command,
            "verdict": None,
            "decision": None,
            "matched_rule": None,
            "rule_details": None,
            "operation_analysis": None,
            "command_analysis": None,
            "sql_analysis": None,
            "risk_score": 0,
            "error": None,
            "policy": None,
            "engine_version": __version__,
            "inspection_coverage": None,
            "decision_validation": None,
        }

        try:
            profile = get_profile(profile_name)
            if not isinstance(command, str):
                result["verdict"] = "error"
                result["decision"] = Decision.ERROR.name
                result["risk_score"] = 100
                result["operation_analysis"] = {
                    "operation": "unknown",
                    "targets": [],
                    "flags": [],
                    "is_dangerous": False,
                    "danger_reason": None,
                }
                result["command_analysis"] = {
                    "tokens": [],
                    "command": None,
                    "args": [],
                    "segments": [],
                    "operators": [],
                    "is_valid": False,
                    "error": "Command must be a string",
                    "risk_flags": [],
                    "risk_score": 0,
                    "is_dangerous": False,
                    "danger_reason": None,
                }
                result["sql_analysis"] = {
                    "tokens": [],
                    "statements": [],
                    "is_valid": False,
                    "error": "SQL must be a string",
                    "risk_flags": [],
                    "risk_score": 0,
                    "is_dangerous": False,
                    "danger_reason": None,
                }
                result["error"] = "Command must be a string"
                result["inspection_coverage"] = self._build_inspection_coverage(
                    result["operation_analysis"],
                    result["command_analysis"],
                    result["sql_analysis"],
                    auto_allow_reason=None,
                )
                return self._apply_policy_mode_and_validate(result, mode, profile)

            ensure_text_within_limit(command, MAX_COMMAND_BYTES, "command")

            # Analyze the filesystem operation
            operation_analysis = self.inspector.analyze_operation(command)
            result["operation_analysis"] = {
                "operation": operation_analysis["operation"],
                "targets": operation_analysis["targets"],
                "flags": list(operation_analysis["flags"]),
                "is_dangerous": operation_analysis["is_dangerous"],
                "danger_reason": operation_analysis["danger_reason"],
            }

            command_analysis = self.command_inspector.analyze_command(command)
            result["command_analysis"] = {
                "tokens": command_analysis["tokens"],
                "command": command_analysis["command"],
                "args": command_analysis["args"],
                "segments": command_analysis["segments"],
                "operators": command_analysis["operators"],
                "is_valid": command_analysis["is_valid"],
                "error": command_analysis["error"],
                "risk_flags": command_analysis["risk_flags"],
                "risk_score": command_analysis["risk_score"],
                "is_dangerous": command_analysis["is_dangerous"],
                "danger_reason": command_analysis["danger_reason"],
            }

            sql_analysis = self.sql_inspector.analyze_sql(command)
            result["sql_analysis"] = {
                "tokens": sql_analysis["tokens"],
                "statements": sql_analysis["statements"],
                "is_valid": sql_analysis["is_valid"],
                "error": sql_analysis["error"],
                "risk_flags": sql_analysis["risk_flags"],
                "risk_score": sql_analysis["risk_score"],
                "is_dangerous": sql_analysis["is_dangerous"],
                "danger_reason": sql_analysis["danger_reason"],
            }
            result["inspection_coverage"] = self._build_inspection_coverage(
                result["operation_analysis"],
                result["command_analysis"],
                result["sql_analysis"],
                auto_allow_reason=None,
            )

            if not command_analysis["is_valid"]:
                result["decision"] = Decision.ERROR.name
                result["verdict"] = "error"
                result["risk_score"] = 100
                result["error"] = command_analysis["error"]
                return self._apply_policy_mode_and_validate(result, mode, profile)

            # Evaluate against engine rules
            rules = BUILTIN_RULES + (extra_rules or [])
            decision, matched_rule = self.engine.evaluate(command, rules)
            allow_source = "rule" if matched_rule and decision == Decision.ALLOW else None
            if decision != Decision.BLOCK and not sql_analysis["is_valid"]:
                result["decision"] = Decision.ERROR.name
                result["verdict"] = "error"
                result["risk_score"] = 100
                result["error"] = sql_analysis["error"]
                return self._apply_policy_mode_and_validate(result, mode, profile)

            if decision == Decision.UNKNOWN and self._can_auto_allow_known_safe_operation(
                operation_analysis,
                command_analysis,
                sql_analysis,
            ):
                decision = Decision.ALLOW
                allow_source = "auto_known_safe"
                result["inspection_coverage"] = self._build_inspection_coverage(
                    result["operation_analysis"],
                    result["command_analysis"],
                    result["sql_analysis"],
                    auto_allow_reason="known_safe_single_segment_operation",
                )

            result["decision"] = decision.name

            if matched_rule:
                result["matched_rule"] = matched_rule.id
                result["rule_details"] = {
                    "id": matched_rule.id,
                    "title": matched_rule.title,
                    "severity": matched_rule.severity,
                    "response": matched_rule.response,
                    "metadata": matched_rule.metadata or {},
                }

            # Determine verdict
            if decision == Decision.ALLOW:
                result["verdict"] = "allow"
            elif decision == Decision.BLOCK:
                result["verdict"] = "block"
            elif decision == Decision.PENDING_APPROVAL:
                result["verdict"] = "pending_approval"
            elif decision == Decision.ERROR:
                result["verdict"] = "error"
            else:  # UNKNOWN
                result["verdict"] = "unknown"

            result["risk_score"] = self._risk_score_for_result(
                decision,
                matched_rule,
                command_analysis,
                sql_analysis,
            )
            result = self._apply_policy_mode_and_validate(result, mode, profile, allow_source=allow_source)

        except Exception as e:
            result["verdict"] = "error"
            result["decision"] = Decision.ERROR.name
            result["risk_score"] = 100
            result["error"] = str(e)
            if result.get("inspection_coverage") is None:
                result["inspection_coverage"] = self._error_inspection_coverage(str(e))
            self._validate_decision(result)
            if self.verbose:
                import traceback

                result["traceback"] = traceback.format_exc()

        return result

    @staticmethod
    def _risk_score_for_result(
        decision: Decision,
        matched_rule: Optional[Any],
        command_analysis: Dict[str, Any],
        sql_analysis: Dict[str, Any],
    ) -> int:
        """Return additive 0-100 risk score without changing the decision enum."""
        if decision == Decision.ERROR:
            return 100

        scores = [
            int(command_analysis.get("risk_score") or 0),
            int(sql_analysis.get("risk_score") or 0),
        ]

        if decision in {Decision.BLOCK, Decision.PENDING_APPROVAL} and matched_rule:
            scores.append(
                {
                    "CRITICAL": 100,
                    "HIGH": 85,
                    "MEDIUM": 60,
                    "LOW": 35,
                }.get(matched_rule.severity, 50)
            )

        if decision == Decision.ALLOW:
            scores.append(0)

        return max(scores)

    @staticmethod
    def _is_known_safe_operation(operation_analysis: Dict[str, Any]) -> bool:
        """Return true for recognized operations with no detected danger."""
        if operation_analysis["is_dangerous"]:
            return False

        return operation_analysis["operation"] in {
            "move",
            "copy",
            "chmod",
            "create_dir",
            "create_file",
        }

    @classmethod
    def _can_auto_allow_known_safe_operation(
        cls,
        operation_analysis: Dict[str, Any],
        command_analysis: Dict[str, Any],
        sql_analysis: Dict[str, Any],
    ) -> bool:
        """Return true only when every mandatory inspector supports safe auto-allow."""
        if not cls._is_known_safe_operation(operation_analysis):
            return False
        if not command_analysis.get("is_valid"):
            return False
        if command_analysis.get("is_dangerous"):
            return False
        if command_analysis.get("risk_flags"):
            return False
        if command_analysis.get("operators"):
            return False
        if len(command_analysis.get("segments") or []) != 1:
            return False
        if not sql_analysis.get("is_valid"):
            return False
        if sql_analysis.get("is_dangerous"):
            return False
        if sql_analysis.get("risk_flags"):
            return False
        return True

    def _apply_policy_mode_and_validate(
        self,
        result: Dict[str, Any],
        mode: Optional[str],
        profile: Any,
        *,
        allow_source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Apply compatibility policy mode, then validate final decision semantics."""
        result = apply_policy_mode(result, mode=mode, profile=profile)
        self._validate_decision(result, allow_source=allow_source)
        return result

    @staticmethod
    def _build_inspection_coverage(
        operation_analysis: Optional[Dict[str, Any]],
        command_analysis: Optional[Dict[str, Any]],
        sql_analysis: Optional[Dict[str, Any]],
        *,
        auto_allow_reason: Optional[str],
    ) -> Dict[str, Any]:
        """Build additive evidence showing which mandatory inspectors completed."""
        records = [
            {
                "name": "filesystem",
                "target": "command",
                "mandatory": True,
                "status": "complete" if operation_analysis is not None else "failed",
                "error": None if operation_analysis is not None else "filesystem inspection did not run",
                "limits_reached": False,
                "metadata": {
                    "operation": operation_analysis.get("operation") if operation_analysis else None,
                    "targets": len(operation_analysis.get("targets") or []) if operation_analysis else 0,
                    "dangerous": bool(operation_analysis.get("is_dangerous")) if operation_analysis else False,
                },
            },
            {
                "name": "command",
                "target": "command",
                "mandatory": True,
                "status": "complete" if (command_analysis or {}).get("is_valid") else "failed",
                "error": (command_analysis or {}).get("error"),
                "limits_reached": False,
                "metadata": {
                    "segments": len((command_analysis or {}).get("segments") or []),
                    "operators": list((command_analysis or {}).get("operators") or []),
                    "risk_flags": list((command_analysis or {}).get("risk_flags") or []),
                    "dangerous": bool((command_analysis or {}).get("is_dangerous")),
                },
            },
            {
                "name": "sql",
                "target": "command",
                "mandatory": True,
                "status": "complete" if (sql_analysis or {}).get("is_valid") else "failed",
                "error": (sql_analysis or {}).get("error"),
                "limits_reached": False,
                "metadata": {
                    "statements": len((sql_analysis or {}).get("statements") or []),
                    "risk_flags": list((sql_analysis or {}).get("risk_flags") or []),
                    "dangerous": bool((sql_analysis or {}).get("is_dangerous")),
                },
            },
        ]
        mandatory_complete = all(record["status"] == "complete" for record in records if record["mandatory"])
        command_metadata = records[1]["metadata"]
        sql_metadata = records[2]["metadata"]
        allow_eligible = (
            mandatory_complete
            and bool(operation_analysis)
            and CircuitBreakerCLI._is_known_safe_operation(operation_analysis)
            and command_metadata["segments"] == 1
            and not command_metadata["operators"]
            and not command_metadata["risk_flags"]
            and not command_metadata["dangerous"]
            and not sql_metadata["risk_flags"]
            and not sql_metadata["dangerous"]
        )
        unknowns = [
            record["name"]
            for record in records
            if record["mandatory"] and record["status"] != "complete"
        ]
        status = "complete" if mandatory_complete else "incomplete"
        return {
            "schema_version": 1,
            "status": status,
            "mandatory_complete": mandatory_complete,
            "allow_eligible": allow_eligible,
            "auto_allow_reason": auto_allow_reason,
            "records": records,
            "limits": {"max_command_bytes": MAX_COMMAND_BYTES},
            "unknowns": unknowns,
        }

    @staticmethod
    def _error_inspection_coverage(error: str) -> Dict[str, Any]:
        """Build fail-closed coverage for exceptions before inspection completed."""
        return {
            "schema_version": 1,
            "status": "failed",
            "mandatory_complete": False,
            "allow_eligible": False,
            "auto_allow_reason": None,
            "records": [
                {
                    "name": "evaluation",
                    "target": "command",
                    "mandatory": True,
                    "status": "failed",
                    "error": error,
                    "limits_reached": False,
                    "metadata": {},
                }
            ],
            "limits": {"max_command_bytes": MAX_COMMAND_BYTES},
            "unknowns": ["evaluation"],
        }

    @staticmethod
    def _validate_decision(result: Dict[str, Any], *, allow_source: Optional[str] = None) -> None:
        """Attach deterministic validation metadata and reject unsafe ALLOW states."""
        coverage = result.get("inspection_coverage") or {}
        validation = {
            "schema_version": 1,
            "status": "valid",
            "allow_source": allow_source,
            "allow_permitted": False,
            "reason": "no allow decision to validate",
        }
        if result.get("decision") == Decision.ALLOW.name:
            if not coverage.get("mandatory_complete"):
                validation.update(
                    {
                        "status": "rejected",
                        "allow_permitted": False,
                        "reason": "mandatory inspection coverage is incomplete",
                    }
                )
                result["decision"] = Decision.ERROR.name
                result["verdict"] = "error"
                result["risk_score"] = 100
                result["error"] = "ALLOW rejected because mandatory inspection coverage was incomplete"
            elif allow_source == "auto_known_safe" and not coverage.get("allow_eligible"):
                validation.update(
                    {
                        "status": "rejected",
                        "allow_permitted": False,
                        "reason": "automatic allow requires single-segment complete safe inspection",
                    }
                )
                result["decision"] = Decision.ERROR.name
                result["verdict"] = "error"
                result["risk_score"] = 100
                result["error"] = "ALLOW rejected because action is not eligible for automatic allow"
            else:
                validation.update({"allow_permitted": True, "reason": "allow decision passed validation"})
        result["decision_validation"] = validation

    def _load_runtime_options(
        self,
        rule_file_path: Optional[str],
        profile_name: Optional[str],
        mode: Optional[str],
        policy_path: Optional[str],
        include_plugins: bool,
        require_signature: bool = False,
        trust_repository_policy: bool = False,
        allow_insecure_remote_policy: bool = False,
    ) -> Dict[str, Any]:
        """Load optional policy, rules, and plugins for a command mode."""
        try:
            policy = (
                load_policy(
                    policy_path,
                    require_signature=require_signature,
                    trust_repository_policy=trust_repository_policy,
                    allow_insecure_remote_policy=allow_insecure_remote_policy,
                )
                if policy_path
                else load_policy(
                    start_dir=".",
                    require_signature=require_signature,
                    trust_repository_policy=trust_repository_policy,
                )
            )
        except ValueError as exc:
            return {
                "is_valid": False,
                "errors": [str(exc)],
                "rule_path": policy_path,
                "rules": [],
            }
        resolved_rule_path = rule_file_path or policy.get("rules_path")
        resolved_rule_definition = None if rule_file_path else policy.get("rules_definition")
        resolved_profile = profile_name or policy.get("profile")
        resolved_mode = mode or policy.get("mode") or ("strict" if policy.get("strict") else None)

        custom_rules = []
        if resolved_rule_path:
            custom_rule_result = self.load_custom_rules(resolved_rule_path, require_signature=require_signature)
            if not custom_rule_result["is_valid"]:
                return {
                    "is_valid": False,
                    "errors": custom_rule_result["errors"],
                    "rule_path": resolved_rule_path,
                    "rules": [],
                }
            custom_rules = custom_rule_result["rules"]
        elif resolved_rule_definition is not None:
            custom_rule_result = self.load_custom_rule_definition(resolved_rule_definition)
            if not custom_rule_result["is_valid"]:
                return {
                    "is_valid": False,
                    "errors": custom_rule_result["errors"],
                    "rule_path": f"{policy.get('path')}:rules",
                    "rules": [],
                }
            custom_rules = custom_rule_result["rules"]

        if include_plugins:
            try:
                custom_rules.extend(load_rule_plugins())
            except ValueError as exc:
                return {
                    "is_valid": False,
                    "errors": [str(exc)],
                    "rule_path": "plugins",
                    "rules": [],
                }

        return {
            "is_valid": True,
            "errors": [],
            "rule_path": resolved_rule_path or (f"{policy.get('path')}:rules" if resolved_rule_definition else None),
            "rules": custom_rules,
            "profile_name": resolved_profile,
            "mode": resolved_mode,
            "policy_source": policy.get("path"),
            "policy_source_type": policy.get("source_type"),
            "policy_trust_level": policy.get("trust_level"),
            "policy_trusted": policy.get("trusted"),
            "policy_signature": policy.get("signature"),
        }

    def format_output(self, result: Dict[str, Any]) -> str:
        """
        Format evaluation result for output.

        Args:
            result: Evaluation result dictionary

        Returns:
            Formatted output string
        """
        if self.output_format == "json":
            return json.dumps(result, indent=2)

        # Human-readable format
        lines = []
        lines.append(f"Command: {result['command']}")
        lines.append(f"Verdict: {result['verdict'].upper()}")

        if result["decision"]:
            lines.append(f"Decision: {result['decision']}")
            lines.append(f"Risk Score: {result.get('risk_score', 0)}")

        if result["matched_rule"]:
            lines.append(f"Matched Rule: {result['matched_rule']}")
            if result["rule_details"]:
                details = result["rule_details"]
                lines.append(f"  Title: {details['title']}")
                lines.append(f"  Severity: {details['severity']}")
                lines.append(f"  Response: {details['response']}")

        if result["operation_analysis"]:
            analysis = result["operation_analysis"]
            lines.append(f"Operation: {analysis['operation']}")
            if analysis["targets"]:
                lines.append(f"Targets: {', '.join(analysis['targets'])}")
            if analysis["flags"]:
                lines.append(f"Flags: {', '.join(analysis['flags'])}")

        if result["command_analysis"]:
            analysis = result["command_analysis"]
            if analysis["command"]:
                lines.append(f"Command Analysis: {analysis['command']}")
            if analysis["operators"]:
                lines.append(f"Operators: {', '.join(analysis['operators'])}")
            if analysis["risk_flags"]:
                lines.append(f"Command Risk Flags: {', '.join(analysis['risk_flags'])}")
            if analysis["danger_reason"]:
                lines.append(f"Command Danger: {analysis['danger_reason']}")
            if analysis["error"]:
                lines.append(f"Command Analysis Error: {analysis['error']}")

        if result["sql_analysis"]:
            analysis = result["sql_analysis"]
            has_sql_details = analysis["risk_flags"] or analysis["danger_reason"] or analysis["error"]
            if has_sql_details and analysis["statements"]:
                lines.append(f"SQL Statements: {len(analysis['statements'])}")
            if analysis["risk_flags"]:
                lines.append(f"SQL Risk Flags: {', '.join(analysis['risk_flags'])}")
            if analysis["danger_reason"]:
                lines.append(f"SQL Danger: {analysis['danger_reason']}")
            if analysis["error"]:
                lines.append(f"SQL Analysis Error: {analysis['error']}")

        if result["error"]:
            lines.append(f"Error: {result['error']}")
            if self.verbose and "traceback" in result:
                lines.append("\nTraceback:")
                lines.append(result["traceback"])

        return "\n".join(lines)

    def run_interactive(self) -> int:
        """
        Run in interactive mode, evaluating commands from stdin.

        Returns:
            Exit code
        """
        print("Agent Circuit Breaker - Interactive Mode")
        print("Type 'quit' or 'exit' to quit")
        print("Type 'help' for usage information")
        print("-" * 50)

        try:
            while True:
                try:
                    command = input("\n> ").strip()

                    if not command:
                        continue

                    if command.lower() in ("quit", "exit"):
                        break

                    if command.lower() == "help":
                        self._print_help()
                        continue

                    result = self.evaluate_command(command)
                    output = self.format_output(result)
                    print(output)

                except KeyboardInterrupt:
                    print("\nInterrupted")
                    break
                except EOFError:
                    break

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            if self.verbose:
                import traceback

                traceback.print_exc()
            return 1

        return 0

    def run_command_mode(
        self,
        command: str,
        rule_file_path: Optional[str] = None,
        *,
        profile_name: Optional[str] = None,
        mode: Optional[str] = None,
        policy_path: Optional[str] = None,
        include_plugins: bool = False,
        audit: bool = False,
        require_signature: bool = False,
        trust_repository_policy: bool = False,
        allow_insecure_remote_policy: bool = False,
    ) -> int:
        """
        Run in command mode, evaluating a single command.

        Args:
            command: Command to evaluate

        Returns:
            Exit code (0 for allow, 1 for block/error, 2 for unknown)
        """
        runtime = self._load_runtime_options(
            rule_file_path,
            profile_name,
            mode,
            policy_path,
            include_plugins,
            require_signature=require_signature,
            trust_repository_policy=trust_repository_policy,
            allow_insecure_remote_policy=allow_insecure_remote_policy,
        )
        if not runtime["is_valid"]:
            output = self.format_rule_validation_output(
                runtime["rule_path"],
                {"is_valid": False, "errors": runtime["errors"], "definition": None},
            )
            print(output)
            return 1

        result = self.evaluate_command(
            command,
            runtime["rules"],
            profile_name=runtime["profile_name"],
            mode=runtime["mode"],
        )
        if runtime.get("policy_source"):
            result["policy_source"] = runtime["policy_source"]
            result["policy_trust"] = {
                "source_type": runtime.get("policy_source_type"),
                "trust_level": runtime.get("policy_trust_level"),
                "trusted": runtime.get("policy_trusted"),
            }
        if runtime.get("policy_signature"):
            result["policy_signature"] = runtime["policy_signature"]
        if result["verdict"] == "pending_approval":
            try:
                approval = ApprovalStore().create(result)
                result["approval"] = {
                    "id": approval["id"],
                    "status": approval["status"],
                    "security": approval.get("approval_security"),
                }
            except OSError as exc:
                result["approval"] = {"id": None, "status": "not_stored", "error": str(exc)}
        if audit:
            entry = AuditLog().append(audit_event_from_result(result))
            result["audit"] = {"path": str(AuditLog().path), "entry_hash": entry["entry_hash"]}
        output = self.format_output(result)
        print(output)

        # Return appropriate exit code
        if result["verdict"] == "allow":
            return 0
        elif result["verdict"] == "block":
            return 1
        elif result["verdict"] == "error":
            return 1
        elif result["verdict"] == "pending_approval":
            return 3
        else:  # unknown
            return 2

    def run_explain_mode(
        self,
        command: str,
        rule_file_path: Optional[str] = None,
        *,
        profile_name: Optional[str] = None,
        mode: Optional[str] = None,
        policy_path: Optional[str] = None,
        include_plugins: bool = False,
        require_signature: bool = False,
        trust_repository_policy: bool = False,
        allow_insecure_remote_policy: bool = False,
    ) -> int:
        """Run explanation mode for a single action."""
        runtime = self._load_runtime_options(
            rule_file_path,
            profile_name,
            mode,
            policy_path,
            include_plugins,
            require_signature=require_signature,
            trust_repository_policy=trust_repository_policy,
            allow_insecure_remote_policy=allow_insecure_remote_policy,
        )
        if not runtime["is_valid"]:
            print(
                self.format_rule_validation_output(
                    runtime["rule_path"],
                    {"is_valid": False, "errors": runtime["errors"], "definition": None},
                )
            )
            return 1

        result = self.evaluate_command(
            command,
            runtime["rules"],
            profile_name=runtime["profile_name"],
            mode=runtime["mode"],
        )
        if runtime.get("policy_source"):
            result["policy_source"] = runtime["policy_source"]
            result["policy_trust"] = {
                "source_type": runtime.get("policy_source_type"),
                "trust_level": runtime.get("policy_trust_level"),
                "trusted": runtime.get("policy_trusted"),
            }
        explanation = explain_result(result)
        if self.output_format == "json":
            result["explanation"] = explanation
            print(json.dumps(result, indent=2))
        else:
            print(format_explanation(result, explanation))
        return self._exit_code_for_verdict(result["verdict"])

    def run_scan_mode(
        self,
        paths: List[str],
        rule_file_path: Optional[str] = None,
        *,
        profile_name: Optional[str] = None,
        mode: Optional[str] = None,
        policy_path: Optional[str] = None,
        include_plugins: bool = False,
        audit: bool = False,
        sarif: bool = False,
        require_signature: bool = False,
        trust_repository_policy: bool = False,
        allow_insecure_remote_policy: bool = False,
    ) -> int:
        """Run static scan mode over text files."""
        runtime = self._load_runtime_options(
            rule_file_path,
            profile_name,
            mode,
            policy_path,
            include_plugins,
            require_signature=require_signature,
            trust_repository_policy=trust_repository_policy,
            allow_insecure_remote_policy=allow_insecure_remote_policy,
        )
        if not runtime["is_valid"]:
            print(
                self.format_rule_validation_output(
                    runtime["rule_path"],
                    {"is_valid": False, "errors": runtime["errors"], "definition": None},
                )
            )
            return 1

        def evaluator(action: str) -> Dict[str, Any]:
            return self.evaluate_command(
                action,
                runtime["rules"],
                profile_name=runtime["profile_name"],
                mode=runtime["mode"],
            )

        scan_result = scan_paths(paths, evaluator)
        if audit:
            AuditLog().append({"source": "scan", "paths": paths, "summary": scan_result["summary"]})

        if sarif:
            print(json.dumps(scan_to_sarif(scan_result), indent=2))
        elif self.output_format == "json":
            print(json.dumps(scan_result, indent=2))
        else:
            print(format_scan_result(scan_result))

        summary = scan_result["summary"]
        if summary["blocked"] or summary["errors"]:
            return 1
        if summary["pending_approval"]:
            return 3
        return 0

    def run_trajectory_mode(
        self,
        path: str,
        rule_file_path: Optional[str] = None,
        *,
        profile_name: Optional[str] = None,
        mode: Optional[str] = None,
        policy_path: Optional[str] = None,
        include_plugins: bool = False,
        audit: bool = False,
        ledger: bool = False,
        require_signature: bool = False,
        trust_repository_policy: bool = False,
        allow_insecure_remote_policy: bool = False,
    ) -> int:
        """Run trajectory mode over a JSON run file."""
        runtime = self._load_runtime_options(
            rule_file_path,
            profile_name,
            mode,
            policy_path,
            include_plugins,
            require_signature=require_signature,
            trust_repository_policy=trust_repository_policy,
            allow_insecure_remote_policy=allow_insecure_remote_policy,
        )
        if not runtime["is_valid"]:
            print(
                self.format_rule_validation_output(
                    runtime["rule_path"],
                    {"is_valid": False, "errors": runtime["errors"], "definition": None},
                )
            )
            return 1

        try:
            run_path = Path(path)
            ensure_file_within_limit(run_path, MAX_TRAJECTORY_FILE_BYTES, "trajectory file")
            with run_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            actions, contract = self._parse_trajectory_payload(payload)
            result = evaluate_trajectory(
                actions,
                lambda action: self.evaluate_command(
                    action,
                    runtime["rules"],
                    profile_name=runtime["profile_name"],
                    mode=runtime["mode"],
                ),
                contract=contract,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result = {
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
                "error": str(exc),
            }

        if runtime.get("policy_source"):
            result["policy_source"] = runtime["policy_source"]
            result["policy_trust"] = {
                "source_type": runtime.get("policy_source_type"),
                "trust_level": runtime.get("policy_trust_level"),
                "trusted": runtime.get("policy_trusted"),
            }
        if runtime.get("policy_signature"):
            result["policy_signature"] = runtime["policy_signature"]
        if result["verdict"] == "pending_approval":
            try:
                context = approval_context(result)
                approval = ApprovalStore().create(result, context=context)
                result["approval"] = {
                    "id": approval["id"],
                    "status": approval["status"],
                    "security": approval.get("approval_security"),
                    "context": context,
                }
            except OSError as exc:
                result["approval"] = {"id": None, "status": "not_stored", "error": str(exc)}
        if audit:
            entry = AuditLog().append(
                {
                    "source": "trajectory",
                    "run_id": result.get("run_id"),
                    "verdict": result.get("verdict"),
                    "summary": result.get("summary"),
                    "policy_source": result.get("policy_source"),
                }
            )
            result["audit"] = {"path": str(AuditLog().path), "entry_hash": entry["entry_hash"]}
        if ledger:
            entry = RunLedger().append(result)
            result["ledger"] = {"path": str(RunLedger().path), "entry_hash": entry["entry_hash"]}

        print(self.format_trajectory_output(result))
        return self._exit_code_for_verdict(result["verdict"])

    @staticmethod
    def _parse_trajectory_payload(payload: Any) -> tuple[List[str], Optional[Dict[str, Any]]]:
        """Return actions and optional contract from a JSON trajectory payload."""
        if isinstance(payload, list):
            actions = payload
            contract = None
        elif isinstance(payload, dict):
            actions = payload.get("actions")
            contract = {key: value for key, value in payload.items() if key != "actions"}
        else:
            raise ValueError("trajectory file must contain a list or object")

        if not isinstance(actions, list) or not all(isinstance(item, str) for item in actions):
            raise ValueError("trajectory actions must be a list of strings")
        if len(actions) > MAX_TRAJECTORY_ACTIONS:
            raise ValueError(f"trajectory actions exceed {MAX_TRAJECTORY_ACTIONS}")
        return actions, contract

    def run_rules_test_mode(self, path: str) -> int:
        """Run fixture-based tests for custom rule files."""
        from agent_circuit_breaker.rule_testing import run_rule_tests

        result = run_rule_tests(path)
        if self.output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            summary = result["summary"]
            print(f"Rule Tests: {path}")
            print(
                f"Passed: {summary['passed']}/{summary['total']} "
                f"across {summary['files']} file(s)"
            )
            for file_result in result["files"]:
                for error in file_result["errors"]:
                    print(f"Error: {file_result['path']}: {error}")
                for case in file_result["cases"]:
                    if not case["passed"]:
                        print(f"Failed: {case['name']}: {case['failure']}")
        return 0 if result["is_valid"] else 1

    def run_schema_mode(self, name: Optional[str] = None) -> int:
        """Emit versioned public JSON schema artifacts."""
        from agent_circuit_breaker.schemas import all_schemas, get_schema

        try:
            payload = get_schema(name) if name else all_schemas()
        except KeyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    def run_catalog_mode(self) -> int:
        """Emit the built-in rule catalog."""
        if self.output_format == "json":
            print(json.dumps({"rules": built_in_rule_catalog()}, indent=2))
        else:
            print(format_catalog_markdown(), end="")
        return 0

    def format_trajectory_output(self, result: Dict[str, Any]) -> str:
        """Format a trajectory result for text or JSON output."""
        if self.output_format == "json":
            return json.dumps(result, indent=2)

        lines = [
            f"Run: {result.get('run_id') or '-'}",
            f"Verdict: {str(result.get('verdict')).upper()}",
        ]
        if result.get("decision"):
            lines.append(f"Decision: {result['decision']}")

        summary = result.get("summary") or {}
        lines.append(
            "Summary: "
            f"actions={summary.get('actions', 0)} "
            f"blocked={summary.get('blocked', 0)} "
            f"unknown={summary.get('unknown', 0)} "
            f"pending={summary.get('pending_approval', 0)} "
            f"errors={summary.get('errors', 0)} "
            f"trajectory_findings={summary.get('trajectory_findings', 0)}"
        )

        if result.get("error"):
            lines.append(f"Error: {result['error']}")

        findings = result.get("trajectory_findings") or []
        for finding in findings:
            lines.append(f"Finding: {finding['id']} ({finding['severity']})")
            lines.append(f"  Reason: {finding['reason']}")
            lines.append(f"  Indices: {', '.join(str(index) for index in finding['indices'])}")

        return "\n".join(lines)

    def run_install_hooks_mode(self, agent: str, directory: str, write: bool) -> int:
        """Print or write hook scaffold instructions."""
        if write:
            result = write_hook_scaffold(directory)
            if self.output_format == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Hook scaffold written: {result['path']}")
            return 0

        output = {"agent": agent, "instructions": hook_instructions(agent)}
        if self.output_format == "json":
            print(json.dumps(output, indent=2))
        else:
            print(output["instructions"])
        return 0

    def run_timeline_mode(self, limit: int = 20, verify: bool = False) -> int:
        """Print recent audit log entries or verify the audit chain."""
        audit_log = AuditLog()
        if verify:
            result = audit_log.verify()
            if self.output_format == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Audit Valid: {str(result['is_valid']).upper()}")
                print(f"Entries: {result['entries']}")
                if result["error"]:
                    print(f"Error: {result['error']}")
            return 0 if result["is_valid"] else 1

        entries = audit_log.tail(limit)
        if self.output_format == "json":
            print(json.dumps({"path": str(audit_log.path), "entries": entries}, indent=2))
        else:
            print(f"Audit Log: {audit_log.path}")
            for entry in entries:
                event = entry.get("event") or {}
                print(
                    f"{entry.get('timestamp')} {event.get('verdict', '-')} "
                    f"risk={event.get('risk_score', '-')} rule={event.get('matched_rule') or '-'}"
                )
        return 0

    def run_ledger_mode(self, run_id: Optional[str] = None, limit: int = 20, verify: bool = False) -> int:
        """Print recent run ledger entries, replay one run, or verify the ledger."""
        ledger = RunLedger()
        if verify:
            result = ledger.verify()
            if self.output_format == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Ledger Valid: {str(result['is_valid']).upper()}")
                print(f"Entries: {result['entries']}")
                if result["error"]:
                    print(f"Error: {result['error']}")
            return 0 if result["is_valid"] else 1

        if run_id:
            try:
                replay = ledger.replay(run_id)
            except FileNotFoundError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1
            print(json.dumps(replay, indent=2) if self.output_format == "json" else self.format_ledger_replay(replay))
            return 0

        entries = ledger.tail(limit)
        if self.output_format == "json":
            print(json.dumps({"path": str(ledger.path), "entries": entries}, indent=2))
        else:
            print(f"Run Ledger: {ledger.path}")
            for entry in entries:
                result = entry.get("result") or {}
                summary = result.get("summary") or {}
                print(
                    f"{entry.get('timestamp')} run={entry.get('run_id') or '-'} "
                    f"verdict={result.get('verdict', '-')} actions={summary.get('actions', '-')}"
                )
        return 0

    @staticmethod
    def format_ledger_replay(replay: Dict[str, Any]) -> str:
        """Format replayed ledger actions for text output."""
        lines = [
            f"Run: {replay.get('run_id')}",
            f"Verdict: {str(replay.get('verdict')).upper()}",
        ]
        summary = replay.get("summary") or {}
        lines.append(f"Actions: {summary.get('actions', len(replay.get('actions', [])))}")
        for finding in replay.get("trajectory_findings", []):
            lines.append(f"Finding: {finding.get('id')} ({finding.get('severity')})")
        for action in replay.get("actions", []):
            lines.append(
                f"{action.get('trajectory_index')}: {action.get('verdict')} "
                f"rule={action.get('matched_rule') or '-'} command={action.get('command')}"
            )
        return "\n".join(lines)

    def run_approvals_mode(
        self,
        action: str,
        approval_id: Optional[str] = None,
        approval_token: Optional[str] = None,
    ) -> int:
        """List, approve, or deny pending approval records."""
        store = ApprovalStore()
        try:
            if action == "list":
                records = store.list()
                if self.output_format == "json":
                    print(json.dumps({"approvals": records}, indent=2))
                else:
                    for record in records:
                        result = record.get("result") or {}
                        print(
                            f"{record['id']} {record['status']} "
                            f"risk={result.get('risk_score')} command={result.get('command')}"
                        )
                return 0

            if action in {"approve", "deny"} and approval_id:
                expected_token = os.environ.get("ACB_APPROVAL_TOKEN")
                if expected_token and approval_token != expected_token:
                    print("Error: approval token required", file=sys.stderr)
                    return 1
                status = "approved" if action == "approve" else "denied"
                record = store.decide(approval_id, status)
                print(json.dumps(record, indent=2) if self.output_format == "json" else f"{approval_id}: {status}")
                return 0
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        print("Error: use approvals list|approve <id>|deny <id>", file=sys.stderr)
        return 1

    def run_plugins_mode(self) -> int:
        """List installed plugin entry points."""
        plugins = discover_plugins()
        print(json.dumps(plugins, indent=2) if self.output_format == "json" else plugins)
        return 0

    @staticmethod
    def _exit_code_for_verdict(verdict: str) -> int:
        """Return CLI exit code for a verdict string."""
        if verdict == "allow":
            return 0
        if verdict in {"block", "error"}:
            return 1
        if verdict == "pending_approval":
            return 3
        return 2

    @staticmethod
    def load_custom_rules(path: str, *, require_signature: bool = False) -> Dict[str, Any]:
        """Load, validate, and build external rule definitions."""
        load_result = RuleFileLoader.load(path, require_signature=require_signature)
        if not load_result["is_valid"]:
            return {
                "is_valid": False,
                "errors": load_result["errors"],
                "definition": load_result["definition"],
                "rules": [],
            }

        build_result = RuleDefinitionBuilder.build_rules(load_result["definition"])
        return {
            "is_valid": build_result["is_valid"],
            "errors": build_result["errors"],
            "definition": load_result["definition"] if build_result["is_valid"] else None,
            "rules": build_result["rules"],
        }

    @staticmethod
    def load_custom_rule_definition(definition: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and build inline external rule definitions."""
        build_result = RuleDefinitionBuilder.build_rules(definition)
        return {
            "is_valid": build_result["is_valid"],
            "errors": build_result["errors"],
            "definition": definition if build_result["is_valid"] else None,
            "rules": build_result["rules"],
        }

    def run_validate_rules_mode(self, path: str, *, require_signature: bool = False) -> int:
        """
        Run rule-file validation mode.

        Args:
            path: JSON rule file path to validate

        Returns:
            Exit code (0 for valid, 1 for invalid)
        """
        result = RuleFileLoader.load(path, require_signature=require_signature)
        output = self.format_rule_validation_output(path, result)
        print(output)

        return 0 if result["is_valid"] else 1

    def format_rule_validation_output(self, path: str, result: Dict[str, Any]) -> str:
        """Format rule validation result for output."""
        output = {
            "path": path,
            "is_valid": result["is_valid"],
            "errors": result["errors"],
            "definition": result["definition"],
        }

        if self.output_format == "json":
            return json.dumps(output, indent=2)

        lines = [
            f"Rule File: {path}",
            f"Valid: {str(result['is_valid']).upper()}",
        ]

        if result["errors"]:
            lines.append("Errors:")
            for error in result["errors"]:
                lines.append(f"  - {error}")

        return "\n".join(lines)

    def _print_help(self) -> None:
        """Print help information."""
        help_text = """
Agent Circuit Breaker - Safety Evaluation Tool

Usage:
  agent-circuit-breaker check <ACTION> [OPTIONS]
  agent-circuit-breaker explain <ACTION> [OPTIONS]
  agent-circuit-breaker scan <PATH...> [OPTIONS]
  agent-circuit-breaker trajectory <RUN.json> [OPTIONS]
  agent-circuit-breaker install-hooks [OPTIONS]
  agent-circuit-breaker timeline [OPTIONS]
  agent-circuit-breaker ledger [RUN_ID] [OPTIONS]
  agent-circuit-breaker approvals list|approve <ID>|deny <ID>
  agent-circuit-breaker plugins [--format json]
  agent-circuit-breaker validate-rules <PATH> [OPTIONS]
  agent-circuit-breaker rules test <PATH> [OPTIONS]
  agent-circuit-breaker schemas [NAME]
  agent-circuit-breaker catalog [--format json]
  agent-circuit-breaker -c <ACTION> [OPTIONS]
  agent-circuit-breaker -i [OPTIONS]

Options:
  -h, --help              Show this help message
  -i, --interactive       Enter interactive mode
  --format text|json      Output format (default: text)
  -j, --json              Shortcut for --format json
  -v, --verbose           Enable verbose output
  -c, --command CMD       Evaluate a single command
  --rules PATH            Append validated external rules for command checks
  --profile NAME          Safety profile: solo, repo, team, prod
  --mode MODE             Policy mode: strict, advisory, approval
  --audit                 Append a tamper-evident audit entry
  --ledger                Append full trajectory results to the run ledger
  --approval-token TOKEN  Token required when ACB_APPROVAL_TOKEN is configured
  --policy PATH_OR_URL    Load central policy before local CLI overrides
  --allow-insecure-remote-policy
                          Allow http:// policy URLs; HTTPS is required by default
  --require-signature     Require policy/rule JSON signatures before loading
  --trust-repository-policy
                          Allow auto-discovered repository policy to weaken controls
  --plugins               Load optional rule-provider plugins
  --sarif                 Emit SARIF for scan mode

Examples:
  agent-circuit-breaker check 'rm -rf /'              # Evaluate an action
  agent-circuit-breaker check 'mkdir /tmp/example'    # Known safe filesystem action
  agent-circuit-breaker check 'ls -la'                # Unknown action
  agent-circuit-breaker check 'rm -rf /etc' --format json
  agent-circuit-breaker check 'deploy production' --rules ./rules.json
  agent-circuit-breaker explain 'git push --force origin main'
  agent-circuit-breaker scan ./scripts ./README.md
  agent-circuit-breaker trajectory ./agent-run.json --format json
  agent-circuit-breaker install-hooks --write
  agent-circuit-breaker timeline --verify
  agent-circuit-breaker ledger --verify
  agent-circuit-breaker approvals list
  agent-circuit-breaker plugins --format json
  agent-circuit-breaker validate-rules ./rules.json
  agent-circuit-breaker rules test ./policy-tests
  agent-circuit-breaker schemas rule-file
  agent-circuit-breaker catalog --format json
  agent-circuit-breaker -c 'mv /src /dst' -v          # Compatibility shortcut

Exit Codes:
  0 - Command allowed
  1 - Command blocked or error
  2 - Command verdict unknown
  3 - Command pending approval
"""
        print(help_text)


def main() -> int:
    """
    Main entry point for CLI.

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        prog="agent-circuit-breaker",
        description="Agent Circuit Breaker - Deterministic Safety Layer for AI Agents",
        add_help=False,
    )

    parser.add_argument("-h", "--help", action="store_true", help="Show help message")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Output format",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        dest="json_output",
        help="Shortcut for --format json",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--command", type=str, help="Command to evaluate")
    parser.add_argument("--rules", dest="rule_file_path", type=str, help="External JSON rule file")
    parser.add_argument("--profile", dest="profile_name", type=str, help="Safety profile")
    parser.add_argument("--mode", dest="mode", type=str, help="Policy mode")
    parser.add_argument("--audit", action="store_true", help="Append an audit entry")
    parser.add_argument("--ledger", action="store_true", help="Append full trajectory results to the run ledger")
    parser.add_argument("--approval-token", help="Approval token required when ACB_APPROVAL_TOKEN is configured")
    parser.add_argument("--policy", dest="policy_path", type=str, help="Central policy file or URL")
    parser.add_argument(
        "--allow-insecure-remote-policy",
        action="store_true",
        help="Allow http:// policy URLs; HTTPS is required by default",
    )
    parser.add_argument("--require-signature", action="store_true", help="Require signed policy/rule JSON")
    parser.add_argument(
        "--trust-repository-policy",
        action="store_true",
        help="Trust auto-discovered repository policy to weaken controls",
    )
    parser.add_argument("--plugins", action="store_true", help="Load installed rule plugins")
    parser.add_argument("--sarif", action="store_true", help="Emit SARIF for scan mode")
    parser.add_argument("--write", action="store_true", help="Write generated scaffolds where supported")
    parser.add_argument("--agent", default="generic", help="Agent name for hook instructions")
    parser.add_argument("--path", default=".", help="Output path for generated scaffolds")
    parser.add_argument("--limit", type=int, default=20, help="Timeline entry limit")
    parser.add_argument("--verify", action="store_true", help="Verify audit log hash chain")
    parser.add_argument(
        "command_parts",
        nargs="*",
        help="Use: check <action>",
    )

    try:
        args = parser.parse_args()
        if "--sarif" in args.command_parts:
            args.sarif = True
            args.command_parts = [part for part in args.command_parts if part != "--sarif"]
        output_format = "json" if args.json_output else args.output_format

        # Handle help
        if args.help:
            cli = CircuitBreakerCLI(verbose=args.verbose, output_format=output_format)
            cli._print_help()
            return 0

        # Create CLI instance
        cli = CircuitBreakerCLI(verbose=args.verbose, output_format=output_format)

        # Handle command mode
        if args.command:
            return cli.run_command_mode(
                args.command,
                args.rule_file_path,
                profile_name=args.profile_name,
                mode=args.mode,
                policy_path=args.policy_path,
                include_plugins=args.plugins,
                audit=args.audit,
                require_signature=args.require_signature,
                trust_repository_policy=args.trust_repository_policy,
                allow_insecure_remote_policy=args.allow_insecure_remote_policy,
            )

        if args.command_parts:
            if args.command_parts[0] == "check" and len(args.command_parts) >= 2:
                return cli.run_command_mode(
                    " ".join(args.command_parts[1:]),
                    args.rule_file_path,
                    profile_name=args.profile_name,
                    mode=args.mode,
                    policy_path=args.policy_path,
                    include_plugins=args.plugins,
                    audit=args.audit,
                    require_signature=args.require_signature,
                    trust_repository_policy=args.trust_repository_policy,
                    allow_insecure_remote_policy=args.allow_insecure_remote_policy,
                )

            if args.command_parts[0] == "explain" and len(args.command_parts) >= 2:
                return cli.run_explain_mode(
                    " ".join(args.command_parts[1:]),
                    args.rule_file_path,
                    profile_name=args.profile_name,
                    mode=args.mode,
                    policy_path=args.policy_path,
                    include_plugins=args.plugins,
                    require_signature=args.require_signature,
                    trust_repository_policy=args.trust_repository_policy,
                    allow_insecure_remote_policy=args.allow_insecure_remote_policy,
                )

            if args.command_parts[0] == "scan" and len(args.command_parts) >= 2:
                return cli.run_scan_mode(
                    args.command_parts[1:],
                    args.rule_file_path,
                    profile_name=args.profile_name,
                    mode=args.mode,
                    policy_path=args.policy_path,
                    include_plugins=args.plugins,
                    audit=args.audit,
                    sarif=args.sarif,
                    require_signature=args.require_signature,
                    trust_repository_policy=args.trust_repository_policy,
                    allow_insecure_remote_policy=args.allow_insecure_remote_policy,
                )

            if args.command_parts[0] == "trajectory" and len(args.command_parts) == 2:
                return cli.run_trajectory_mode(
                    args.command_parts[1],
                    args.rule_file_path,
                    profile_name=args.profile_name,
                    mode=args.mode,
                    policy_path=args.policy_path,
                    include_plugins=args.plugins,
                    audit=args.audit,
                    ledger=args.ledger,
                    require_signature=args.require_signature,
                    trust_repository_policy=args.trust_repository_policy,
                    allow_insecure_remote_policy=args.allow_insecure_remote_policy,
                )

            if args.command_parts[0] == "install-hooks":
                return cli.run_install_hooks_mode(args.agent, args.path, args.write)

            if args.command_parts[0] == "timeline":
                return cli.run_timeline_mode(limit=args.limit, verify=args.verify)

            if args.command_parts[0] == "ledger":
                run_id = args.command_parts[1] if len(args.command_parts) >= 2 else None
                return cli.run_ledger_mode(run_id=run_id, limit=args.limit, verify=args.verify)

            if args.command_parts[0] == "approvals" and len(args.command_parts) >= 2:
                approval_id = args.command_parts[2] if len(args.command_parts) >= 3 else None
                return cli.run_approvals_mode(args.command_parts[1], approval_id, approval_token=args.approval_token)

            if args.command_parts[0] == "plugins":
                return cli.run_plugins_mode()

            if args.command_parts[0] == "profiles":
                print(json.dumps(profile_metadata(), indent=2) if output_format == "json" else profile_metadata())
                return 0

            if args.command_parts[0] == "validate-rules" and len(args.command_parts) == 2:
                return cli.run_validate_rules_mode(args.command_parts[1], require_signature=args.require_signature)

            if args.command_parts[0] == "rules" and len(args.command_parts) == 3 and args.command_parts[1] == "test":
                return cli.run_rules_test_mode(args.command_parts[2])

            if args.command_parts[0] == "schemas":
                name = args.command_parts[1] if len(args.command_parts) >= 2 else None
                return cli.run_schema_mode(name)

            if args.command_parts[0] == "catalog":
                return cli.run_catalog_mode()

            print(
                "Error: expected 'agent-circuit-breaker check <action>' or "
                "'agent-circuit-breaker validate-rules <path>'",
                file=sys.stderr,
            )
            return 1

        # Handle interactive mode (default if no command)
        if args.interactive:
            return cli.run_interactive()

        return cli.run_interactive()

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
