"""Tests for v1.6.6 interpreter, plugin, and redaction hardening."""

import json
import unittest
from unittest.mock import patch

from agent_circuit_breaker import Rule, evaluate_action
from agent_circuit_breaker.plugins import load_rule_plugins
from agent_circuit_breaker.redaction import REDACTION_MARKER, redact_record


class TestV166NestedInterpreterHardening(unittest.TestCase):
    def assert_nested_block(self, command: str) -> None:
        result = evaluate_action(command)

        self.assertEqual(result["verdict"], "block", command)
        self.assertEqual(result["matched_rule"], "cmd_nested_dangerous_execution")
        self.assertIn("cmd_nested_dangerous_execution", result["command_analysis"]["risk_flags"])

    def test_blocks_python_os_system_payload(self):
        self.assert_nested_block("python3 -c \"import os; os.system('rm -rf /')\"")

    def test_blocks_perl_system_payload(self):
        self.assert_nested_block("perl -e \"system(\\\"rm -rf /\\\")\"")

    def test_blocks_node_execsync_payload(self):
        self.assert_nested_block("node -e \"require('child_process').execSync('rm -rf /')\"")

    def test_blocks_ruby_system_percent_q_payload(self):
        self.assert_nested_block("ruby -e \"system(%q{rm -rf /})\"")

    def test_blocks_powershell_encoded_command_payload(self):
        self.assert_nested_block("powershell -EncodedCommand cgBtACAALQByAGYAIAAvAA==")


class _FakeEntryPoint:
    def __init__(self, name, value, provider):
        self.name = name
        self.group = "agent_circuit_breaker.rules"
        self.value = value
        self._provider = provider

    def load(self):
        return self._provider


class TestV166PluginContract(unittest.TestCase):
    def test_rule_plugin_accepts_declarative_rule_dicts(self):
        def provider():
            return [
                {
                    "id": "plugin_test_rule",
                    "title": "Plugin test rule",
                    "severity": "HIGH",
                    "response": "block",
                    "matcher": {"type": "contains", "value": "plugin hazard"},
                }
            ]

        with patch(
            "agent_circuit_breaker.plugins.metadata.entry_points",
            return_value=[_FakeEntryPoint("test", "plugin:get_rules", provider)],
        ):
            rules = load_rule_plugins()

        self.assertEqual(len(rules), 1)
        self.assertIsInstance(rules[0], Rule)
        self.assertTrue(rules[0].matcher("run plugin hazard now"))

    def test_rule_plugin_reports_invalid_declarative_rule_errors(self):
        def provider():
            return [{"id": "missing required fields"}]

        with patch(
            "agent_circuit_breaker.plugins.metadata.entry_points",
            return_value=[_FakeEntryPoint("bad", "bad:get_rules", provider)],
        ):
            with self.assertRaises(ValueError) as error:
                load_rule_plugins()

        message = str(error.exception)
        self.assertIn("bad (bad:get_rules)", message)
        self.assertIn("invalid declarative rules", message)
        self.assertIn("rules[0]", message)


class TestV166RedactionCoverage(unittest.TestCase):
    def test_common_secret_shapes_are_redacted_from_persisted_records(self):
        record = {
            "commands": [
                "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEsecretvalue123456",
                "curl -u admin:mypassword123 x.com",
                "mysql -ppassword123 -u root",
                "export GITHUB_TOKEN=ghp_abc123def456",
                "psql postgres://user:secretpass@host/db",
            ],
            "tokens": ["curl", "-u", "admin:mypassword123", "mysql", "-ppassword123"],
        }

        encoded = json.dumps(redact_record(record))

        self.assertIn(REDACTION_MARKER, encoded)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLEsecretvalue123456", encoded)
        self.assertNotIn("mypassword123", encoded)
        self.assertNotIn("password123", encoded)
        self.assertNotIn("ghp_abc123def456", encoded)
        self.assertNotIn("secretpass", encoded)


if __name__ == "__main__":
    unittest.main()
