"""Test the public Python API."""

import unittest
from pathlib import Path

import agent_circuit_breaker
from agent_circuit_breaker import (
    DecisionResult,
    EvaluationRequest,
    Finding,
    evaluate_action,
    rule_schema_metadata,
    validate_rule_file,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_RULE_DIR = REPO_ROOT / "docs" / "examples" / "rules"


class TestPublicAPI(unittest.TestCase):
    """Test package-level public API functions."""

    def test_package_exports_api_functions(self):
        """The package root should expose the v0.6 API."""
        self.assertIs(agent_circuit_breaker.evaluate_action, evaluate_action)
        self.assertIs(agent_circuit_breaker.validate_rule_file, validate_rule_file)
        self.assertIs(agent_circuit_breaker.rule_schema_metadata, rule_schema_metadata)
        self.assertIs(agent_circuit_breaker.DecisionResult, DecisionResult)
        self.assertIs(agent_circuit_breaker.EvaluationRequest, EvaluationRequest)
        self.assertIs(agent_circuit_breaker.Finding, Finding)

    def test_evaluate_action_blocks_builtin_risk(self):
        """Built-in rules should block known catastrophic actions."""
        result = evaluate_action("rm -rf /")

        self.assertEqual(result["verdict"], "block")
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["matched_rule"], "fs_recursive_delete")

    def test_evaluate_action_allows_known_safe_operation(self):
        """Known safe filesystem operations should be allowed."""
        result = evaluate_action("mkdir /tmp/example")

        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["decision"], "ALLOW")
        self.assertIsNone(result["matched_rule"])

    def test_evaluate_action_returns_unknown_for_unclassified_action(self):
        """Unclassified actions should remain unknown, not allowed."""
        result = evaluate_action("git status")

        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["decision"], "UNKNOWN")

    def test_evaluate_action_supports_custom_rule_file(self):
        """Custom JSON rules should be available through the public API."""
        rule_path = str(EXAMPLE_RULE_DIR / "custom_deploy_guard.json")
        result = evaluate_action("deploy production", rule_file_path=rule_path)

        self.assertEqual(result["verdict"], "block")
        self.assertEqual(result["matched_rule"], "custom_deploy_guard")
        self.assertEqual(
            result["custom_rules"],
            {
                "path": rule_path,
                "is_valid": True,
                "errors": [],
                "rule_count": 1,
            },
        )

    def test_evaluate_action_fails_closed_for_invalid_rule_file(self):
        """Invalid custom rule files should return an error before action evaluation."""
        rule_path = str(EXAMPLE_RULE_DIR / "invalid_matcher_type.json")
        result = evaluate_action("mkdir /tmp/example", rule_file_path=rule_path)

        self.assertEqual(result["verdict"], "error")
        self.assertEqual(result["decision"], "ERROR")
        self.assertEqual(result["error"], "Invalid rule file")
        self.assertFalse(result["custom_rules"]["is_valid"])
        self.assertIn(
            "rules[0].matcher.type must be one of",
            result["custom_rules"]["errors"][0],
        )

    def test_validate_rule_file_for_valid_fixture(self):
        """Rule file validation should expose loader results with path context."""
        rule_path = str(EXAMPLE_RULE_DIR / "multi_rule_guard.json")
        result = validate_rule_file(rule_path)

        self.assertEqual(result["path"], rule_path)
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["definition"]["rules"]), 2)

    def test_validate_rule_file_for_invalid_fixture(self):
        """Invalid rule file validation should return deterministic errors."""
        rule_path = str(EXAMPLE_RULE_DIR / "invalid_missing_rules.json")
        result = validate_rule_file(rule_path)

        self.assertEqual(result["path"], rule_path)
        self.assertFalse(result["is_valid"])
        self.assertEqual(result["definition"], None)
        self.assertIn("Missing required top-level field: rules", result["errors"])

    def test_rule_schema_metadata(self):
        """Schema metadata should be available from the public API."""
        metadata = rule_schema_metadata()

        self.assertEqual(metadata["version"], 1)
        self.assertEqual(metadata["matcher_types"], ["all_of", "any_of", "contains", "equals", "not", "prefix", "regex"])
        self.assertEqual(metadata["response_values"], ["allow", "approval", "block"])


if __name__ == "__main__":
    unittest.main()
