"""Tests for external rule definition validation."""

import json
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.engine import Decision, Engine, Rule
from agent_circuit_breaker.rules.loader import (
    RULE_SCHEMA_VERSION,
    RuleDefinitionBuilder,
    RuleDefinitionValidator,
    RuleFileLoader,
    RuleSchema,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_RULE_DIR = REPO_ROOT / "docs" / "examples" / "rules"


def valid_definition():
    """Return a minimal valid external rule definition."""
    return {
        "version": 1,
        "rules": [
            {
                "id": "custom_block_tmp_delete",
                "title": "Block tmp deletion",
                "severity": "HIGH",
                "response": "block",
                "matcher": {
                    "type": "contains",
                    "value": "rm -rf /tmp",
                },
                "metadata": {
                    "category": "custom",
                },
            }
        ],
    }


class TestRuleDefinitionValidator(unittest.TestCase):
    """Test parsed external rule definition validation."""

    def test_valid_rule_file_returns_valid(self):
        """A valid parsed rule file should pass validation."""
        result = RuleDefinitionValidator.validate(valid_definition())

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["errors"], [])

    def test_missing_rules_returns_invalid(self):
        """Missing top-level rules should fail validation."""
        result = RuleDefinitionValidator.validate({"version": 1})

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Missing required top-level field: rules"])

    def test_empty_rules_returns_invalid(self):
        """Empty rule lists should fail validation."""
        result = RuleDefinitionValidator.validate({"version": 1, "rules": []})

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["rules must not be empty"])

    def test_top_level_must_be_object(self):
        """Top-level rule definition should be an object."""
        result = RuleDefinitionValidator.validate([])

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Rule definition must be an object"])

    def test_unknown_top_level_field_returns_invalid(self):
        """Unknown top-level fields should fail validation."""
        definition = valid_definition()
        definition["remote_url"] = "https://example.com/rules.json"

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("Unknown top-level field: remote_url", result["errors"])

    def test_invalid_version_returns_invalid(self):
        """Only version 1 should be supported."""
        definition = valid_definition()
        definition["version"] = 2

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("version must be 1", result["errors"])

    def test_malformed_rule_fields_return_invalid(self):
        """Malformed required rule fields should fail validation."""
        definition = valid_definition()
        definition["rules"][0]["id"] = ""
        definition["rules"][0]["title"] = None
        definition["rules"][0]["severity"] = "URGENT"
        definition["rules"][0]["response"] = "deny"

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("rules[0].id must be a non-empty string", result["errors"])
        self.assertIn("rules[0].title must be a non-empty string", result["errors"])
        self.assertIn("rules[0].severity must be one of CRITICAL, HIGH, MEDIUM, LOW", result["errors"])
        self.assertIn("rules[0].response must be allow, block, or approval", result["errors"])

    def test_missing_required_rule_fields_return_invalid(self):
        """Missing required rule fields should fail validation."""
        result = RuleDefinitionValidator.validate({"version": 1, "rules": [{}]})

        self.assertFalse(result["is_valid"])
        self.assertEqual(
            result["errors"],
            [
                "rules[0].id is required",
                "rules[0].matcher is required",
                "rules[0].response is required",
                "rules[0].severity is required",
                "rules[0].title is required",
            ],
        )

    def test_duplicate_ids_return_invalid(self):
        """Duplicate rule IDs should fail validation."""
        definition = valid_definition()
        duplicate = dict(definition["rules"][0])
        definition["rules"].append(duplicate)

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("rules[1].id duplicates rule id: custom_block_tmp_delete", result["errors"])

    def test_unknown_matcher_type_returns_invalid(self):
        """Unknown matcher types should fail validation."""
        definition = valid_definition()
        definition["rules"][0]["matcher"]["type"] = "glob"

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("rules[0].matcher.type must be one of", result["errors"][0])

    def test_non_string_matcher_value_returns_invalid(self):
        """Matcher values should be strings."""
        definition = valid_definition()
        definition["rules"][0]["matcher"]["value"] = ["rm", "-rf"]

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("rules[0].matcher.value must be a non-empty string", result["errors"])

    def test_non_object_metadata_returns_invalid(self):
        """Metadata should be an object when provided."""
        definition = valid_definition()
        definition["rules"][0]["metadata"] = "custom"

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["rules[0].metadata must be an object"])

    def test_supported_matcher_types_return_valid(self):
        """All v1.3 scalar matcher types should be accepted."""
        for matcher_type in ("contains", "equals", "prefix", "regex"):
            with self.subTest(matcher_type=matcher_type):
                definition = valid_definition()
                definition["rules"][0]["matcher"]["type"] = matcher_type

                result = RuleDefinitionValidator.validate(definition)

                self.assertTrue(result["is_valid"])
                self.assertEqual(result["errors"], [])

    def test_validation_is_deterministic(self):
        """Repeated validation should return the same structure."""
        definition = valid_definition()
        definition["rules"][0]["matcher"]["type"] = "glob"

        result1 = RuleDefinitionValidator.validate(definition)
        result2 = RuleDefinitionValidator.validate(definition)
        result3 = RuleDefinitionValidator.validate(definition)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)

    def test_schema_metadata_matches_validator_constants(self):
        """Schema metadata should expose the validator contract deterministically."""
        metadata = RuleSchema.metadata()

        self.assertEqual(metadata["version"], RULE_SCHEMA_VERSION)
        self.assertEqual(metadata["matcher_types"], ["all_of", "any_of", "contains", "equals", "not", "prefix", "regex"])
        self.assertEqual(metadata["response_values"], ["allow", "approval", "block"])
        self.assertEqual(metadata["severity_values"], ["CRITICAL", "HIGH", "LOW", "MEDIUM"])
        self.assertEqual(metadata["required_rule_fields"], ["id", "matcher", "response", "severity", "title"])


class TestRuleFileLoader(unittest.TestCase):
    """Test external rule definition file loading."""

    def write_rule_file(self, directory, name, content):
        """Write test rule file content and return its path."""
        path = Path(directory) / name
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_missing_file_returns_invalid(self):
        """Missing rule files should fail explicitly."""
        result = RuleFileLoader.load("missing-rules.json")

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Rule file not found: missing-rules.json"])
        self.assertIsNone(result["definition"])

    def test_non_string_path_returns_invalid(self):
        """Non-string file paths should fail explicitly."""
        result = RuleFileLoader.load(None)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Rule file path must be a non-empty string"])
        self.assertIsNone(result["definition"])

    def test_directory_path_returns_invalid(self):
        """Directory paths should fail explicitly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            result = RuleFileLoader.load(temp_dir)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], [f"Rule file path is not a file: {temp_dir}"])
        self.assertIsNone(result["definition"])

    def test_invalid_json_returns_invalid(self):
        """Malformed JSON should fail with line and column details."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_rule_file(temp_dir, "rules.json", '{"rules": [')

            result = RuleFileLoader.load(path)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Invalid JSON: Expecting value at line 1, column 12"])
        self.assertIsNone(result["definition"])

    def test_top_level_array_returns_invalid(self):
        """Top-level JSON arrays should fail validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_rule_file(temp_dir, "rules.json", "[]")

            result = RuleFileLoader.load(path)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Rule definition must be an object"])
        self.assertIsNone(result["definition"])

    def test_invalid_rule_file_returns_validation_errors(self):
        """Invalid rule files should return validator errors."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_rule_file(temp_dir, "rules.json", json.dumps({"version": 1}))

            result = RuleFileLoader.load(path)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Missing required top-level field: rules"])
        self.assertIsNone(result["definition"])

    def test_valid_file_returns_parsed_definition(self):
        """Valid rule files should return parsed definitions."""
        definition = valid_definition()

        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_rule_file(temp_dir, "rules.json", json.dumps(definition))

            result = RuleFileLoader.load(path)

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["definition"], definition)

    def test_file_loading_is_deterministic(self):
        """Repeated file loading should return the same structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_rule_file(temp_dir, "rules.json", json.dumps(valid_definition()))

            result1 = RuleFileLoader.load(path)
            result2 = RuleFileLoader.load(path)
            result3 = RuleFileLoader.load(path)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)


class TestRuleSchemaFixtures(unittest.TestCase):
    """Test documented rule schema fixture files."""

    def test_valid_fixture_files_pass_validation(self):
        """Valid documented fixtures should pass loader validation."""
        for fixture_name in ("custom_deploy_guard.json", "multi_rule_guard.json"):
            with self.subTest(fixture_name=fixture_name):
                result = RuleFileLoader.load(str(EXAMPLE_RULE_DIR / fixture_name))

                self.assertTrue(result["is_valid"])
                self.assertEqual(result["errors"], [])
                self.assertIsNotNone(result["definition"])

    def test_invalid_fixture_files_fail_validation(self):
        """Invalid documented fixtures should fail loader validation."""
        cases = {
            "invalid_duplicate_ids.json": "rules[1].id duplicates rule id: duplicate_rule",
            "invalid_matcher_type.json": "rules[0].matcher.type must be one of all_of, any_of, contains, equals, not, prefix, regex",
            "invalid_metadata.json": "rules[0].metadata must be an object",
            "invalid_missing_rules.json": "Missing required top-level field: rules",
        }

        for fixture_name, expected_error in cases.items():
            with self.subTest(fixture_name=fixture_name):
                result = RuleFileLoader.load(str(EXAMPLE_RULE_DIR / fixture_name))

                self.assertFalse(result["is_valid"])
                self.assertIn(expected_error, result["errors"])
                self.assertIsNone(result["definition"])


class TestRuleDefinitionBuilder(unittest.TestCase):
    """Test building Rule objects from external rule definitions."""

    def test_build_valid_definition_returns_rules(self):
        """Valid definitions should build Rule objects."""
        result = RuleDefinitionBuilder.build_rules(valid_definition())

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["rules"]), 1)
        self.assertIsInstance(result["rules"][0], Rule)
        self.assertEqual(result["rules"][0].id, "custom_block_tmp_delete")
        self.assertEqual(result["rules"][0].metadata, {"category": "custom"})

    def test_build_invalid_definition_returns_errors(self):
        """Invalid definitions should not build Rule objects."""
        result = RuleDefinitionBuilder.build_rules({"version": 1})

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["errors"], ["Missing required top-level field: rules"])
        self.assertEqual(result["rules"], [])

    def test_contains_matcher_rule_matches_substring(self):
        """Contains matcher should match actions containing configured text."""
        result = RuleDefinitionBuilder.build_rules(valid_definition())
        rule = result["rules"][0]

        self.assertTrue(rule.matcher("please rm -rf /tmp/cache"))
        self.assertFalse(rule.matcher("rm -rf /var/cache"))

    def test_equals_matcher_rule_matches_exact_action(self):
        """Equals matcher should match only exact actions."""
        definition = valid_definition()
        definition["rules"][0]["matcher"] = {
            "type": "equals",
            "value": "deploy production",
        }

        result = RuleDefinitionBuilder.build_rules(definition)
        rule = result["rules"][0]

        self.assertTrue(rule.matcher("deploy production"))
        self.assertFalse(rule.matcher("please deploy production"))

    def test_prefix_matcher_rule_matches_prefix(self):
        """Prefix matcher should match action prefixes."""
        definition = valid_definition()
        definition["rules"][0]["matcher"] = {
            "type": "prefix",
            "value": "terraform destroy",
        }

        result = RuleDefinitionBuilder.build_rules(definition)
        rule = result["rules"][0]

        self.assertTrue(rule.matcher("terraform destroy -auto-approve"))
        self.assertFalse(rule.matcher("echo terraform destroy"))

    def test_built_custom_rule_can_be_evaluated_by_engine(self):
        """Built custom rules should work with the existing engine."""
        result = RuleDefinitionBuilder.build_rules(valid_definition())
        engine = Engine()

        decision, matched_rule = engine.evaluate("rm -rf /tmp/cache", result["rules"])

        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(matched_rule.id, "custom_block_tmp_delete")

    def test_matchers_reject_non_string_actions(self):
        """Generated matchers should reject non-string actions."""
        result = RuleDefinitionBuilder.build_rules(valid_definition())
        rule = result["rules"][0]

        self.assertFalse(rule.matcher(None))

    def test_build_rules_is_deterministic_for_rule_fields(self):
        """Repeated builds should produce equivalent rule fields."""
        result1 = RuleDefinitionBuilder.build_rules(valid_definition())
        result2 = RuleDefinitionBuilder.build_rules(valid_definition())
        result3 = RuleDefinitionBuilder.build_rules(valid_definition())

        fields1 = [(rule.id, rule.title, rule.severity, rule.response, rule.metadata) for rule in result1["rules"]]
        fields2 = [(rule.id, rule.title, rule.severity, rule.response, rule.metadata) for rule in result2["rules"]]
        fields3 = [(rule.id, rule.title, rule.severity, rule.response, rule.metadata) for rule in result3["rules"]]

        self.assertEqual(result1["is_valid"], result2["is_valid"])
        self.assertEqual(result2["is_valid"], result3["is_valid"])
        self.assertEqual(fields1, fields2)
        self.assertEqual(fields2, fields3)


if __name__ == "__main__":
    unittest.main()
