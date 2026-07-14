"""Command-line interface for Agent Circuit Breaker."""

import sys
import json
import argparse
from typing import Optional, Dict, Any

from agent_circuit_breaker.engine import Engine, Decision
from agent_circuit_breaker.rules.builtin_rules import BUILTIN_RULES
from agent_circuit_breaker.inspectors.filesystem import FilesystemInspector


class CircuitBreakerCLI:
    """CLI interface for Agent Circuit Breaker safety evaluation."""

    def __init__(self, verbose: bool = False, json_output: bool = False):
        """
        Initialize the CLI.

        Args:
            verbose: Enable verbose output
            json_output: Enable JSON output format
        """
        self.verbose = verbose
        self.json_output = json_output
        self.engine = Engine()
        self.inspector = FilesystemInspector()

    def evaluate_command(self, command: str) -> Dict[str, Any]:
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
            "error": None,
        }

        try:
            # Analyze the filesystem operation
            operation_analysis = self.inspector.analyze_operation(command)
            result["operation_analysis"] = {
                "operation": operation_analysis["operation"],
                "targets": operation_analysis["targets"],
                "flags": list(operation_analysis["flags"]),
                "is_dangerous": operation_analysis["is_dangerous"],
                "danger_reason": operation_analysis["danger_reason"],
            }

            # Evaluate against engine rules
            decision, matched_rule = self.engine.evaluate(command, BUILTIN_RULES)

            result["decision"] = decision.name

            if matched_rule:
                result["matched_rule"] = matched_rule.id
                result["rule_details"] = {
                    "id": matched_rule.id,
                    "title": matched_rule.title,
                    "severity": matched_rule.severity.name,
                    "response": matched_rule.response.name,
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

    def format_output(self, result: Dict[str, Any]) -> str:
        """
        Format evaluation result for output.

        Args:
            result: Evaluation result dictionary

        Returns:
            Formatted output string
        """
        if self.json_output:
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

    def run_command_mode(self, command: str) -> int:
        """
        Run in command mode, evaluating a single command.

        Args:
            command: Command to evaluate

        Returns:
            Exit code (0 for allow, 1 for block/error, 2 for unknown)
        """
        result = self.evaluate_command(command)
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

    def _print_help(self) -> None:
        """Print help information."""
        help_text = """
Agent Circuit Breaker - Safety Evaluation Tool

Usage:
  circuit-breaker [OPTIONS] [COMMAND]

Options:
  -h, --help              Show this help message
  -i, --interactive       Enter interactive mode
  -j, --json              Output results as JSON
  -v, --verbose           Enable verbose output
  -c, --command CMD       Evaluate a single command

Examples:
  circuit-breaker -i                           # Interactive mode
  circuit-breaker -c 'rm -rf /'                # Evaluate single command
  circuit-breaker -c 'rm /tmp/file' --json    # JSON output
  circuit-breaker -c 'mv /src /dst' -v        # Verbose output

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
        "-j", "--json", action="store_true", dest="json_output", help="JSON output format"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--command", type=str, help="Command to evaluate")

    try:
        args = parser.parse_args()

        # Handle help
        if args.help:
            cli = CircuitBreakerCLI(verbose=args.verbose, json_output=args.json_output)
            cli._print_help()
            return 0

        # Create CLI instance
        cli = CircuitBreakerCLI(verbose=args.verbose, json_output=args.json_output)

        # Handle command mode
        if args.command:
            return cli.run_command_mode(args.command)

        # Handle interactive mode (default if no command)
        if args.interactive or not args.command:
            return cli.run_interactive()

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
