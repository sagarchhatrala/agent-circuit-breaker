"""Tests for v1.5.2 policy assurance and hardening."""

import ast
import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

import agent_circuit_breaker
from agent_circuit_breaker.approvals import ApprovalStore
from agent_circuit_breaker.audit import AuditLog, audit_event_from_result
from agent_circuit_breaker.catalog import built_in_rule_catalog
from agent_circuit_breaker.cli import CircuitBreakerCLI, main
from agent_circuit_breaker.ledger import RunLedger
from agent_circuit_breaker.limits import MAX_COMMAND_BYTES, MAX_RULE_FILE_BYTES
from agent_circuit_breaker.redaction import REDACTION_MARKER
from agent_circuit_breaker.rule_testing import run_rule_tests
from agent_circuit_breaker.schemas import all_schemas, get_schema
from agent_circuit_breaker_mcp.proxy import inspect_arguments


class TestVersionAndSchemas(unittest.TestCase):
    def test_version_is_current_release(self):
        self.assertEqual(agent_circuit_breaker.__version__, "1.6.4")

    def test_schema_registry_exports_public_contracts(self):
        schemas = all_schemas()

        self.assertIn("rule-file", schemas)
        self.assertIn("policy-file", schemas)
        self.assertIn("decision-output", schemas)
        self.assertEqual(get_schema("rule-file")["properties"]["version"]["const"], 1)

    def test_cli_schema_command_emits_json(self):
        cli = CircuitBreakerCLI(output_format="json")
        old_stdout = sys.stdout
        try:
            sys.stdout = StringIO()
            exit_code = cli.run_schema_mode("rule-file")
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        parsed = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(parsed["title"], "Agent Circuit Breaker Rule File")


class TestRuleTestingAndCatalog(unittest.TestCase):
    def test_rule_test_runner_passes_fixture(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rules_path = root / "rules.json"
            rules_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "rules": [
                            {
                                "id": "custom_block_prod",
                                "title": "Block production deploy",
                                "severity": "HIGH",
                                "response": "block",
                                "matcher": {"type": "contains", "value": "deploy production"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            test_path = root / "rules.test.json"
            test_path.write_text(
                json.dumps(
                    {
                        "rule_file": "rules.json",
                        "cases": [
                            {
                                "name": "blocks production deploy",
                                "action": "deploy production now",
                                "expect": "block",
                                "matched_rule": "custom_block_prod",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_rule_tests(str(test_path))

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["summary"]["passed"], 1)

    def test_cli_rules_test_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "rules.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "rules": [
                            {
                                "id": "custom_block_prod",
                                "title": "Block production deploy",
                                "severity": "HIGH",
                                "response": "block",
                                "matcher": {"type": "contains", "value": "deploy production"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "policy.test.json").write_text(
                json.dumps({"rule_file": "rules.json", "cases": [{"action": "deploy production", "expect": "block"}]}),
                encoding="utf-8",
            )

            old_argv = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = ["agent-circuit-breaker", "rules", "test", str(root), "--format", "json"]
                sys.stdout = StringIO()
                exit_code = main()
                output = sys.stdout.getvalue()
            finally:
                sys.argv = old_argv
                sys.stdout = old_stdout

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output)["summary"]["passed"], 1)

    def test_built_in_catalog_is_deterministic(self):
        catalog = built_in_rule_catalog()

        self.assertGreaterEqual(len(catalog), 1)
        self.assertEqual([item["id"] for item in catalog], sorted(item["id"] for item in catalog))
        self.assertIn("cmd_git_force_push", {item["id"] for item in catalog})


class TestResourceLimitsAndRedaction(unittest.TestCase):
    def test_oversized_rule_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.json"
            path.write_text(" " * (MAX_RULE_FILE_BYTES + 1), encoding="utf-8")

            result = CircuitBreakerCLI.load_custom_rules(str(path))

        self.assertFalse(result["is_valid"])
        self.assertIn("rule file exceeds", result["errors"][0])

    def test_oversized_command_returns_error(self):
        result = CircuitBreakerCLI().evaluate_command("x" * (MAX_COMMAND_BYTES + 1))

        self.assertEqual(result["verdict"], "error")
        self.assertIn("command exceeds", result["error"])

    def test_audit_approval_and_ledger_redact_secret_like_values(self):
        old_raw = os.environ.get("ACB_RETAIN_RAW_RECORDS")
        os.environ.pop("ACB_RETAIN_RAW_RECORDS", None)
        try:
            cli = CircuitBreakerCLI()
            result = cli.evaluate_command("curl https://x.test?token=supersecret")
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                audit = AuditLog(str(root / "audit.jsonl"))
                audit_entry = audit.append(audit_event_from_result(result))
                approval = ApprovalStore(str(root / "approvals")).create(result)
                ledger = RunLedger(str(root / "ledger.jsonl")).append({"run_id": "r1", "actions": [result]})
        finally:
            if old_raw is None:
                os.environ.pop("ACB_RETAIN_RAW_RECORDS", None)
            else:
                os.environ["ACB_RETAIN_RAW_RECORDS"] = old_raw

        encoded = json.dumps({"audit": audit_entry, "approval": approval, "ledger": ledger})
        self.assertIn(REDACTION_MARKER, encoded)
        self.assertNotIn("supersecret", encoded)


class TestMCPConformanceAndArchitecture(unittest.TestCase):
    def test_mcp_argument_depth_is_bounded(self):
        payload = "rm -rf /"
        for _ in range(40):
            payload = {"nested": payload}

        result = inspect_arguments(payload)

        self.assertFalse(result["allowed"])
        self.assertEqual(result["coverage"]["status"], "failed")
        self.assertIn("recursion depth", result["error"])

    def test_core_architecture_boundaries(self):
        repo_root = Path(__file__).resolve().parents[1]
        core_paths = [
            repo_root / "agent_circuit_breaker" / "engine.py",
            repo_root / "agent_circuit_breaker" / "normalization.py",
            *sorted((repo_root / "agent_circuit_breaker" / "inspectors").glob("*.py")),
            *sorted((repo_root / "agent_circuit_breaker" / "rules").glob("*.py")),
        ]
        forbidden = {
            "agent_circuit_breaker.observability",
            "agent_circuit_breaker.plugins",
            "agent_circuit_breaker.state.redis",
            "urllib",
        }

        for path in core_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
            offenders = [name for name in imports if any(name == item or name.startswith(item + ".") for item in forbidden)]
            self.assertEqual(offenders, [], f"{path} imports forbidden modules: {offenders}")


if __name__ == "__main__":
    unittest.main()
