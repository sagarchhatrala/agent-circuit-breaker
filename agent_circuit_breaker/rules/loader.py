"""External rule definition loading and validation."""

import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Callable, Dict, List, Set

from agent_circuit_breaker.engine import Rule


class RuleDefinitionValidator:
    """Validates parsed external rule definitions without executing them."""

    ALLOWED_TOP_LEVEL_FIELDS = {"version", "rules"}
    REQUIRED_RULE_FIELDS = {"id", "title", "severity", "response", "matcher"}
    OPTIONAL_RULE_FIELDS = {"metadata"}
    ALLOWED_RULE_FIELDS = REQUIRED_RULE_FIELDS | OPTIONAL_RULE_FIELDS
    ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    ALLOWED_RESPONSES = {"allow", "block"}
    ALLOWED_MATCHER_TYPES = {"contains", "equals", "prefix"}
    REQUIRED_MATCHER_FIELDS = {"type", "value"}
    ALLOWED_MATCHER_FIELDS = REQUIRED_MATCHER_FIELDS

    @classmethod
    def validate(cls, definition: Any) -> Dict[str, Any]:
        """Validate a parsed rule definition document."""
        errors: List[str] = []

        if not isinstance(definition, dict):
            return cls._result(False, ["Rule definition must be an object"])

        cls._validate_top_level(definition, errors)

        rules = definition.get("rules")
        if isinstance(rules, list):
            cls._validate_rules(rules, errors)

        return cls._result(not errors, errors)

    @staticmethod
    def _result(is_valid: bool, errors: List[str]) -> Dict[str, Any]:
        """Build a deterministic validation result."""
        return {
            "is_valid": is_valid,
            "errors": errors,
        }

    @classmethod
    def _validate_top_level(cls, definition: Dict[str, Any], errors: List[str]) -> None:
        """Validate top-level rule definition fields."""
        for field in definition:
            if field not in cls.ALLOWED_TOP_LEVEL_FIELDS:
                errors.append(f"Unknown top-level field: {field}")

        if "version" in definition and definition["version"] != 1:
            errors.append("version must be 1")

        if "rules" not in definition:
            errors.append("Missing required top-level field: rules")
            return

        if not isinstance(definition["rules"], list):
            errors.append("rules must be a list")
            return

        if not definition["rules"]:
            errors.append("rules must not be empty")

    @classmethod
    def _validate_rules(cls, rules: List[Any], errors: List[str]) -> None:
        """Validate each rule and duplicate IDs."""
        seen_ids: Set[str] = set()

        for index, rule in enumerate(rules):
            path = f"rules[{index}]"

            if not isinstance(rule, dict):
                errors.append(f"{path} must be an object")
                continue

            cls._validate_rule_fields(rule, path, errors)
            cls._validate_duplicate_id(rule, path, seen_ids, errors)
            cls._validate_matcher(rule, path, errors)
            cls._validate_metadata(rule, path, errors)

    @classmethod
    def _validate_rule_fields(cls, rule: Dict[str, Any], path: str, errors: List[str]) -> None:
        """Validate required, optional, and scalar rule fields."""
        for field in rule:
            if field not in cls.ALLOWED_RULE_FIELDS:
                errors.append(f"{path}.{field} is not supported")

        for field in sorted(cls.REQUIRED_RULE_FIELDS):
            if field not in rule:
                errors.append(f"{path}.{field} is required")

        cls._validate_non_empty_string(rule, "id", path, errors)
        cls._validate_non_empty_string(rule, "title", path, errors)

        if "severity" in rule and rule["severity"] not in cls.ALLOWED_SEVERITIES:
            errors.append(f"{path}.severity must be one of CRITICAL, HIGH, MEDIUM, LOW")

        if "response" in rule and rule["response"] not in cls.ALLOWED_RESPONSES:
            errors.append(f"{path}.response must be allow or block")

    @staticmethod
    def _validate_non_empty_string(
        rule: Dict[str, Any],
        field: str,
        path: str,
        errors: List[str],
    ) -> None:
        """Validate that a present rule field is a non-empty string."""
        if field not in rule:
            return

        value = rule[field]
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{path}.{field} must be a non-empty string")

    @staticmethod
    def _validate_duplicate_id(
        rule: Dict[str, Any],
        path: str,
        seen_ids: Set[str],
        errors: List[str],
    ) -> None:
        """Validate duplicate rule IDs."""
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return

        if rule_id in seen_ids:
            errors.append(f"{path}.id duplicates rule id: {rule_id}")
            return

        seen_ids.add(rule_id)

    @classmethod
    def _validate_matcher(cls, rule: Dict[str, Any], path: str, errors: List[str]) -> None:
        """Validate matcher object shape."""
        if "matcher" not in rule:
            return

        matcher = rule["matcher"]
        if not isinstance(matcher, dict):
            errors.append(f"{path}.matcher must be an object")
            return

        for field in matcher:
            if field not in cls.ALLOWED_MATCHER_FIELDS:
                errors.append(f"{path}.matcher.{field} is not supported")

        for field in sorted(cls.REQUIRED_MATCHER_FIELDS):
            if field not in matcher:
                errors.append(f"{path}.matcher.{field} is required")

        matcher_type = matcher.get("type")
        if matcher_type not in cls.ALLOWED_MATCHER_TYPES:
            errors.append(f"{path}.matcher.type must be one of contains, equals, prefix")

        matcher_value = matcher.get("value")
        if not isinstance(matcher_value, str) or not matcher_value:
            errors.append(f"{path}.matcher.value must be a non-empty string")

    @staticmethod
    def _validate_metadata(rule: Dict[str, Any], path: str, errors: List[str]) -> None:
        """Validate optional metadata field."""
        if "metadata" in rule and not isinstance(rule["metadata"], dict):
            errors.append(f"{path}.metadata must be an object")


class RuleFileLoader:
    """Loads and validates external rule definition files."""

    @staticmethod
    def load(path: str) -> Dict[str, Any]:
        """Load and validate a JSON rule definition file."""
        result: Dict[str, Any] = {
            "is_valid": False,
            "errors": [],
            "definition": None,
        }

        if not isinstance(path, str) or not path.strip():
            result["errors"] = ["Rule file path must be a non-empty string"]
            return result

        rule_path = Path(path)
        if not rule_path.exists():
            result["errors"] = [f"Rule file not found: {path}"]
            return result

        if not rule_path.is_file():
            result["errors"] = [f"Rule file path is not a file: {path}"]
            return result

        try:
            with rule_path.open("r", encoding="utf-8") as rule_file:
                definition = json.load(rule_file)
        except JSONDecodeError as exc:
            result["errors"] = [f"Invalid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}"]
            return result
        except OSError as exc:
            result["errors"] = [f"Could not read rule file: {exc}"]
            return result

        validation = RuleDefinitionValidator.validate(definition)
        result["is_valid"] = validation["is_valid"]
        result["errors"] = validation["errors"]
        result["definition"] = definition if validation["is_valid"] else None
        return result


class RuleDefinitionBuilder:
    """Builds executable Rule objects from validated rule definitions."""

    @classmethod
    def build_rules(cls, definition: Any) -> Dict[str, Any]:
        """Validate and build Rule objects from a parsed definition."""
        validation = RuleDefinitionValidator.validate(definition)
        if not validation["is_valid"]:
            return {
                "is_valid": False,
                "errors": validation["errors"],
                "rules": [],
            }

        rules: List[Rule] = []
        errors: List[str] = []

        for index, rule_definition in enumerate(definition["rules"]):
            try:
                rules.append(cls._build_rule(rule_definition))
            except ValueError as exc:
                errors.append(f"rules[{index}]: {exc}")

        return {
            "is_valid": not errors,
            "errors": errors,
            "rules": rules if not errors else [],
        }

    @classmethod
    def _build_rule(cls, rule_definition: Dict[str, Any]) -> Rule:
        """Build one Rule object from a validated rule definition."""
        matcher = cls._build_matcher(rule_definition["matcher"])
        return Rule(
            id=rule_definition["id"],
            title=rule_definition["title"],
            severity=rule_definition["severity"],
            response=rule_definition["response"],
            matcher=matcher,
            metadata=rule_definition.get("metadata") or {},
        )

    @staticmethod
    def _build_matcher(matcher_definition: Dict[str, str]) -> Callable[[str], bool]:
        """Build a deterministic matcher callable."""
        matcher_type = matcher_definition["type"]
        matcher_value = matcher_definition["value"]

        if matcher_type == "contains":
            return lambda action, value=matcher_value: isinstance(action, str) and value in action

        if matcher_type == "equals":
            return lambda action, value=matcher_value: isinstance(action, str) and action == value

        if matcher_type == "prefix":
            return lambda action, value=matcher_value: isinstance(action, str) and action.startswith(value)

        raise ValueError(f"Unsupported matcher type: {matcher_type}")
