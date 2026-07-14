"""External rule definition validation."""

from typing import Any, Dict, List, Set


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
