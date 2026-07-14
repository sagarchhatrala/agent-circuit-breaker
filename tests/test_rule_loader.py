"""Tests for external rule definition validation."""

import json
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.rules.loader import RuleDefinitionValidator, RuleFileLoader


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
        self.assertIn("rules[0].response must be allow or block", result["errors"])

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
        definition["rules"][0]["matcher"]["type"] = "regex"

        result = RuleDefinitionValidator.validate(definition)

        self.assertFalse(result["is_valid"])
        self.assertIn("rules[0].matcher.type must be one of contains, equals, prefix", result["errors"])

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
        """All v0.4 matcher types should be accepted."""
        for matcher_type in ("contains", "equals", "prefix"):
            with self.subTest(matcher_type=matcher_type):
                definition = valid_definition()
                definition["rules"][0]["matcher"]["type"] = matcher_type

                result = RuleDefinitionValidator.validate(definition)

                self.assertTrue(result["is_valid"])
                self.assertEqual(result["errors"], [])

    def test_validation_is_deterministic(self):
        """Repeated validation should return the same structure."""
        definition = valid_definition()
        definition["rules"][0]["matcher"]["type"] = "regex"

        result1 = RuleDefinitionValidator.validate(definition)
        result2 = RuleDefinitionValidator.validate(definition)
        result3 = RuleDefinitionValidator.validate(definition)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)


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


if __name__ == "__main__":
    unittest.main()
