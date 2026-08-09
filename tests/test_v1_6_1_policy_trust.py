"""Tests for v1.6.1 policy source trust behavior."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.cli import CircuitBreakerCLI
from agent_circuit_breaker.policy import load_policy


def rule_definition(response="block"):
    return {
        "version": 1,
        "rules": [
            {
                "id": f"custom_{response}_rule",
                "title": f"Custom {response} rule",
                "severity": "HIGH",
                "response": response,
                "matcher": {"type": "contains", "value": "deploy production"},
            }
        ],
    }


class TestRepositoryPolicyTrust(unittest.TestCase):
    def test_auto_repository_policy_can_strengthen_with_block_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"mode": "strict", "rules": rule_definition("block")}),
                encoding="utf-8",
            )

            policy = load_policy(start_dir=temp_dir)

        self.assertEqual(policy["source_type"], "repository")
        self.assertEqual(policy["trust_level"], "repository")
        self.assertFalse(policy["trusted"])
        self.assertEqual(policy["mode"], "strict")

    def test_auto_repository_policy_rejects_allow_rules_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"rules": rule_definition("allow")}),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as error:
                load_policy(start_dir=temp_dir)

        self.assertIn("untrusted repository policy cannot add allow rules", str(error.exception))

    def test_trusted_repository_policy_can_load_allow_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"rules": rule_definition("allow")}),
                encoding="utf-8",
            )

            policy = load_policy(start_dir=temp_dir, trust_repository_policy=True)

        self.assertTrue(policy["trusted"])
        self.assertEqual(policy["trust_level"], "caller_selected")

    def test_explicit_policy_path_is_caller_selected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text(json.dumps({"mode": "advisory", "rules": rule_definition("allow")}), encoding="utf-8")

            policy = load_policy(str(path))

        self.assertEqual(policy["source_type"], "explicit")
        self.assertEqual(policy["trust_level"], "caller_selected")
        self.assertTrue(policy["trusted"])
        self.assertEqual(policy["mode"], "advisory")

    def test_untrusted_repository_policy_rejects_advisory_and_strict_false(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"mode": "advisory", "strict": False}),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as error:
                load_policy(start_dir=temp_dir)

        message = str(error.exception)
        self.assertIn("untrusted repository policy cannot select advisory mode", message)
        self.assertIn("untrusted repository policy cannot disable strict mode", message)

    def test_cli_fails_closed_for_untrusted_repository_allow_policy(self):
        cli = CircuitBreakerCLI(output_format="json")
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"rules": rule_definition("allow")}),
                encoding="utf-8",
            )
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                runtime = cli._load_runtime_options(None, None, None, None, False)
            finally:
                os.chdir(old_cwd)

        self.assertFalse(runtime["is_valid"])
        self.assertIn("untrusted repository policy cannot add allow rules", runtime["errors"][0])

    def test_cli_trust_flag_allows_repository_allow_policy(self):
        cli = CircuitBreakerCLI(output_format="json")
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir) / ".agent-circuit-breaker"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({"rules": rule_definition("allow")}),
                encoding="utf-8",
            )
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                runtime = cli._load_runtime_options(
                    None,
                    None,
                    None,
                    None,
                    False,
                    trust_repository_policy=True,
                )
            finally:
                os.chdir(old_cwd)

        self.assertTrue(runtime["is_valid"])
        self.assertTrue(runtime["policy_trusted"])


if __name__ == "__main__":
    unittest.main()
