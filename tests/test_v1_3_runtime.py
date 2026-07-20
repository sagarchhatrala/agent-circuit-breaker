"""Tests for v1.3 safety runtime features."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.approvals import ApprovalStore
from agent_circuit_breaker.audit import AuditLog, audit_event_from_result
from agent_circuit_breaker.cli import CircuitBreakerCLI
from agent_circuit_breaker.explain import explain_result
from agent_circuit_breaker.policy import load_policy
from agent_circuit_breaker.rules.loader import RuleDefinitionBuilder, RuleDefinitionValidator
from agent_circuit_breaker.sarif import scan_to_sarif
from agent_circuit_breaker_mcp.proxy import inspect_payload


def rule_definition(matcher, response="block"):
    """Build a valid external rule definition."""
    return {
        "version": 1,
        "rules": [
            {
                "id": "custom_v13_rule",
                "title": "Custom v1.3 rule",
                "severity": "HIGH",
                "response": response,
                "matcher": matcher,
            }
        ],
    }


class TestV13PolicyModes(unittest.TestCase):
    """Profile and policy mode tests."""

    def test_team_profile_routes_block_to_pending_approval(self):
        cli = CircuitBreakerCLI()

        result = cli.evaluate_command("git push --force origin main", profile_name="team")

        self.assertEqual(result["verdict"], "pending_approval")
        self.assertEqual(result["decision"], "PENDING_APPROVAL")
        self.assertEqual(result["policy"]["profile"], "team")
        self.assertEqual(result["policy"]["original_verdict"], "block")

    def test_default_behavior_still_blocks(self):
        cli = CircuitBreakerCLI()

        result = cli.evaluate_command("git push --force origin main")

        self.assertEqual(result["verdict"], "block")
        self.assertIsNone(result["policy"])

    def test_policy_file_loads_profile_and_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text(json.dumps({"profile": "team", "mode": "approval"}), encoding="utf-8")

            policy = load_policy(str(path))

        self.assertEqual(policy["profile"], "team")
        self.assertEqual(policy["mode"], "approval")


class TestV13RuleMatchers(unittest.TestCase):
    """Extended rule matcher tests."""

    def test_regex_matcher_builds_and_matches(self):
        definition = rule_definition({"type": "regex", "value": r"deploy\s+production"})

        validation = RuleDefinitionValidator.validate(definition)
        build = RuleDefinitionBuilder.build_rules(definition)

        self.assertTrue(validation["is_valid"])
        self.assertTrue(build["is_valid"])
        self.assertTrue(build["rules"][0].matcher("please deploy production"))

    def test_composite_matcher_builds_and_matches(self):
        definition = rule_definition(
            {
                "type": "all_of",
                "matchers": [
                    {"type": "contains", "value": "deploy"},
                    {
                        "type": "not",
                        "matcher": {"type": "contains", "value": "staging"},
                    },
                ],
            }
        )

        build = RuleDefinitionBuilder.build_rules(definition)

        self.assertTrue(build["is_valid"])
        self.assertTrue(build["rules"][0].matcher("deploy production"))
        self.assertFalse(build["rules"][0].matcher("deploy staging"))


class TestV13ExplainScanAudit(unittest.TestCase):
    """Explain, scan, SARIF, and audit tests."""

    def test_explain_returns_suggestions(self):
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command("git push --force origin main")

        explanation = explain_result(result)

        self.assertEqual(explanation["matched_rule"], "cmd_git_force_push")
        self.assertTrue(explanation["suggestions"])

    def test_scan_finds_blocked_line_and_sarif_converts(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "script.sh"
            path.write_text('echo ok\nrm -rf "/"\n', encoding="utf-8")

            scan_result = cli.run_scan_mode([str(path)])

            self.assertEqual(scan_result, 1)

            data = __import__("agent_circuit_breaker.scan", fromlist=["scan_paths"]).scan_paths(
                [str(path)],
                cli.evaluate_command,
            )
            sarif = scan_to_sarif(data)

        self.assertEqual(data["summary"]["blocked"], 1)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_audit_log_hash_chain_verifies(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "audit.jsonl"
            audit_log = AuditLog(str(log_path))
            result = cli.evaluate_command("ls -la")
            audit_log.append(audit_event_from_result(result))
            audit_log.append(audit_event_from_result(result))

            verification = audit_log.verify()

        self.assertTrue(verification["is_valid"])
        self.assertEqual(verification["entries"], 2)


class TestV13ApprovalsAndMCP(unittest.TestCase):
    """Approval queue and MCP scaffold tests."""

    def test_approval_store_decides_record(self):
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command("rm -rf /", profile_name="team")
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ApprovalStore(temp_dir)
            record = store.create(result)
            decided = store.decide(record["id"], "approved")

        self.assertEqual(decided["status"], "approved")

    def test_mcp_proxy_scaffold_blocks_command_field(self):
        result = inspect_payload({"command": "rm -rf /"})

        self.assertFalse(result["allowed"])
        self.assertEqual(result["checks"][0]["result"]["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
