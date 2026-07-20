"""Tests for v1.4 hardening fixes and integration surfaces."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.cli import CircuitBreakerCLI
from agent_circuit_breaker.policy import load_policy
from agent_circuit_breaker.rules.loader import RuleFileLoader
from agent_circuit_breaker.scan import _extract_candidate, scan_paths
from agent_circuit_breaker.signing import sign_document
from agent_circuit_breaker_mcp.proxy import inspect_jsonrpc_message


def rule_definition(value="deploy production"):
    """Build a minimal valid external rule definition."""
    return {
        "version": 1,
        "rules": [
            {
                "id": "custom_v14_rule",
                "title": "Custom v1.4 rule",
                "severity": "HIGH",
                "response": "block",
                "matcher": {"type": "contains", "value": value},
            }
        ],
    }


class TestV14ScanAndPolicyFixes(unittest.TestCase):
    """Regression tests for externally reported v1.3 scan/policy bugs."""

    def test_scan_candidate_markers_are_case_insensitive(self):
        self.assertEqual(_extract_candidate("Run: DROP TABLE users;"), "DROP TABLE users;")
        self.assertEqual(_extract_candidate("- Run: rm -rf /"), "rm -rf /")
        self.assertEqual(_extract_candidate("COMMAND: aws s3 rb s3://bucket --force"), "aws s3 rb s3://bucket --force")

    def test_scan_catches_capitalized_run_marker(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "runbook.md"
            path.write_text("Run: DROP TABLE users;\n", encoding="utf-8")
            result = scan_paths([str(path)], cli.evaluate_command)

        self.assertEqual(result["summary"]["blocked"], 1)
        self.assertEqual(result["findings"][0]["text"], "DROP TABLE users;")

    def test_ambient_policy_inline_rules_load_without_raw_path_error(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"rules": rule_definition("deploy production")}),
                encoding="utf-8",
            )
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                runtime = cli._load_runtime_options(None, None, None, None, False)
            finally:
                os.chdir(old_cwd)

        self.assertTrue(runtime["is_valid"])
        result = cli.evaluate_command("deploy production", runtime["rules"])
        self.assertEqual(result["verdict"], "block")
        self.assertEqual(result["matched_rule"], "custom_v14_rule")

    def test_policy_relative_rule_file_resolves_from_policy_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "rules.json").write_text(json.dumps(rule_definition()), encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text(json.dumps({"rules": "rules.json"}), encoding="utf-8")

            loaded = load_policy(str(policy))

        self.assertEqual(loaded["rules_path"], str((root / "rules.json").resolve()))


class TestV14StrictApprovalAndSigning(unittest.TestCase):
    """Tests for strict mode, approval routing, and signed JSON packs."""

    def test_strict_mode_blocks_unknown(self):
        cli = CircuitBreakerCLI()

        result = cli.evaluate_command("ls /home", mode="strict")

        self.assertEqual(result["verdict"], "block")
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["policy"]["original_verdict"], "unknown")
        self.assertEqual(result["policy"]["strict_reason"], "unknown verdict blocked by strict policy")

    def test_team_profile_routes_unknown_to_approval(self):
        cli = CircuitBreakerCLI()

        result = cli.evaluate_command("ls /home", profile_name="team")

        self.assertEqual(result["verdict"], "pending_approval")
        self.assertEqual(result["decision"], "PENDING_APPROVAL")
        self.assertEqual(result["policy"]["original_verdict"], "unknown")

    def test_rule_pack_signature_requirement_fails_closed_for_unsigned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.json"
            path.write_text(json.dumps(rule_definition()), encoding="utf-8")

            result = RuleFileLoader.load(str(path), require_signature=True)

        self.assertFalse(result["is_valid"])
        self.assertIn("signature is required", result["errors"])

    def test_rule_pack_sha256_signature_verifies_and_detects_tampering(self):
        signed = sign_document(rule_definition())
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.json"
            path.write_text(json.dumps(signed), encoding="utf-8")
            valid = RuleFileLoader.load(str(path), require_signature=True)
            signed["rules"][0]["matcher"]["value"] = "different"
            path.write_text(json.dumps(signed), encoding="utf-8")
            tampered = RuleFileLoader.load(str(path), require_signature=True)

        self.assertTrue(valid["is_valid"])
        self.assertFalse(tampered["is_valid"])
        self.assertIn("signature verification failed", tampered["errors"])

    def test_policy_sha256_signature_verifies(self):
        signed = sign_document({"mode": "strict"})
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text(json.dumps(signed), encoding="utf-8")

            policy = load_policy(str(path), require_signature=True)

        self.assertEqual(policy["mode"], "strict")
        self.assertIsNotNone(policy["signature"])


class TestV14MCPProxy(unittest.TestCase):
    """Tests for stdio MCP JSON-RPC tool-call inspection."""

    def test_mcp_tools_call_blocks_command_argument(self):
        message = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "shell", "arguments": {"command": "rm -rf /"}},
        }

        inspection = inspect_jsonrpc_message(message)

        self.assertFalse(inspection["allowed"])
        self.assertEqual(inspection["response"]["id"], 7)
        self.assertEqual(inspection["response"]["error"]["data"]["matched_rule"], "fs_recursive_delete")

    def test_mcp_non_tool_call_passes_through(self):
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

        inspection = inspect_jsonrpc_message(message)

        self.assertTrue(inspection["allowed"])
        self.assertIsNone(inspection["response"])

    def test_mcp_nested_sql_argument_is_blocked(self):
        message = {
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "tools/call",
            "params": {"name": "database", "arguments": {"payload": {"sql": "DROP TABLE users"}}},
        }

        inspection = inspect_jsonrpc_message(message)

        self.assertFalse(inspection["allowed"])
        self.assertEqual(inspection["response"]["error"]["data"]["field"], "payload.sql")


if __name__ == "__main__":
    unittest.main()
