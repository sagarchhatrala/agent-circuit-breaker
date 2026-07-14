"""Command-line interface for Agent Circuit Breaker."""

import sys
import json
import argparse
from typing import Dict, Any, List, Optional

from agent_circuit_breaker.engine import Engine, Decision
from agent_circuit_breaker.rules.builtin_rules import BUILTIN_RULES
from agent_circuit_breaker.rules.loader import RuleDefinitionBuilder, RuleFileLoader
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

    def evaluate_command(self, command: str, extra_rules: Optional[List[Any]] = None) -> Dict[str, Any]:
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
            "error": None,
        }

        try:
            if not isinstance(command, str):
                result["verdict"] = "error"
                result["decision"] = Decision.ERROR.name
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
                    "is_dangerous": False,
                    "danger_reason": None,
                }
                result["sql_analysis"] = {
                    "tokens": [],
                    "statements": [],
                    "is_valid": False,
                    "error": "SQL must be a string",
                    "risk_flags": [],
                    "is_dangerous": False,
                    "danger_reason": None,
                }
                result["error"] = "Command must be a string"
                return result

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
                "is_dangerous": sql_analysis["is_dangerous"],
                "danger_reason": sql_analysis["danger_reason"],
            }

            if not command_analysis["is_valid"] or not sql_analysis["is_valid"]:
                result["decision"] = Decision.ERROR.name
                result["verdict"] = "error"
                result["error"] = command_analysis["error"] or sql_analysis["error"]
                return result

            # Evaluate against engine rules
            rules = BUILTIN_RULES + (extra_rules or [])
            decision, matched_rule = self.engine.evaluate(command, rules)
            if decision == Decision.UNKNOWN and self._is_known_safe_operation(operation_analysis):
                decision = Decision.ALLOW

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
            elif decision == Decision.ERROR:
                result["verdict"] = "error"
            else:  # UNKNOWN
                result["verdict"] = "unknown"

        except Exception as e:
            result["verdict"] = "error"
            result["error"] = str(e)
            if self.verbose:
                import traceback

                result["traceback"] = traceback.format_exc()

        return result

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

    def run_command_mode(self, command: str, rule_file_path: Optional[str] = None) -> int:
        """
        Run in command mode, evaluating a single command.

        Args:
            command: Command to evaluate

        Returns:
            Exit code (0 for allow, 1 for block/error, 2 for unknown)
        """
        custom_rules = []
        if rule_file_path:
            custom_rule_result = self.load_custom_rules(rule_file_path)
            if not custom_rule_result["is_valid"]:
                output = self.format_rule_validation_output(rule_file_path, custom_rule_result)
                print(output)
                return 1
            custom_rules = custom_rule_result["rules"]

        result = self.evaluate_command(command, custom_rules)
        output = self.format_output(result)
        print(output)

        # Return appropriate exit code
        if result["verdict"] == "allow":
            return 0
        elif result["verdict"] == "block":
            return 1
        elif result["verdict"] == "error":
            return 1
        else:  # unknown
            return 2

    @staticmethod
    def load_custom_rules(path: str) -> Dict[str, Any]:
        """Load, validate, and build external rule definitions."""
        load_result = RuleFileLoader.load(path)
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

    def run_validate_rules_mode(self, path: str) -> int:
        """
        Run rule-file validation mode.

        Args:
            path: JSON rule file path to validate

        Returns:
            Exit code (0 for valid, 1 for invalid)
        """
        result = RuleFileLoader.load(path)
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
  circuit-breaker check <ACTION> [OPTIONS]
  circuit-breaker validate-rules <PATH> [OPTIONS]
  circuit-breaker -c <ACTION> [OPTIONS]
  circuit-breaker -i [OPTIONS]

Options:
  -h, --help              Show this help message
  -i, --interactive       Enter interactive mode
  --format text|json      Output format (default: text)
  -j, --json              Shortcut for --format json
  -v, --verbose           Enable verbose output
  -c, --command CMD       Evaluate a single command
  --rules PATH            Append validated external rules for command checks

Examples:
  circuit-breaker check 'rm -rf /'              # Evaluate an action
  circuit-breaker check 'mkdir /tmp/example'    # Known safe filesystem action
  circuit-breaker check 'ls -la'                # Unknown action
  circuit-breaker check 'rm -rf /etc' --format json
  circuit-breaker check 'deploy production' --rules ./rules.json
  circuit-breaker validate-rules ./rules.json
  circuit-breaker -c 'mv /src /dst' -v          # Compatibility shortcut

Exit Codes:
  0 - Command allowed
  1 - Command blocked or error
  2 - Command verdict unknown
"""
        print(help_text)


def main() -> int:
    """
    Main entry point for CLI.

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        prog="circuit-breaker",
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
    parser.add_argument(
        "command_parts",
        nargs="*",
        help="Use: check <action>",
    )

    try:
        args = parser.parse_args()
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
            return cli.run_command_mode(args.command, args.rule_file_path)

        if args.command_parts:
            if args.command_parts[0] == "check" and len(args.command_parts) >= 2:
                return cli.run_command_mode(" ".join(args.command_parts[1:]), args.rule_file_path)

            if args.command_parts[0] == "validate-rules" and len(args.command_parts) == 2:
                return cli.run_validate_rules_mode(args.command_parts[1])

            print(
                "Error: expected 'circuit-breaker check <action>' or "
                "'circuit-breaker validate-rules <path>'",
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
