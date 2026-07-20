"""External rule definition loading and validation."""

import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Callable, Dict, List, Set

from agent_circuit_breaker.engine import Rule
from agent_circuit_breaker.normalization import normalize_for_matching

RULE_SCHEMA_VERSION = 1


class RuleDefinitionValidator:
    """Validates parsed external rule definitions without executing them."""

    ALLOWED_TOP_LEVEL_FIELDS = {"version", "rules"}
    REQUIRED_RULE_FIELDS = {"id", "title", "severity", "response", "matcher"}
    OPTIONAL_RULE_FIELDS = {"metadata"}
    ALLOWED_RULE_FIELDS = REQUIRED_RULE_FIELDS | OPTIONAL_RULE_FIELDS
    ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    ALLOWED_RESPONSES = {"allow", "block", "approval"}
    ALLOWED_MATCHER_TYPES = {"contains", "equals", "prefix", "regex", "all_of", "any_of", "not"}
    REQUIRED_MATCHER_FIELDS = {"type", "value"}
    ALLOWED_MATCHER_FIELDS = {"type", "value", "matchers", "matcher"}
    MAX_REGEX_LENGTH = 500
    MAX_MATCHER_DEPTH = 8

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

        if "version" in definition and definition["version"] != RULE_SCHEMA_VERSION:
            errors.append(f"version must be {RULE_SCHEMA_VERSION}")

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
            errors.append(f"{path}.response must be allow, block, or approval")

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
        cls._validate_matcher_object(rule["matcher"], f"{path}.matcher", errors, depth=0)

    @classmethod
    def _validate_matcher_object(cls, matcher: Any, path: str, errors: List[str], depth: int) -> None:
        """Validate matcher object shape recursively."""
        if not isinstance(matcher, dict):
            errors.append(f"{path} must be an object")
            return

        if depth > cls.MAX_MATCHER_DEPTH:
            errors.append(f"{path} exceeds max matcher depth")
            return

        for field in matcher:
            if field not in cls.ALLOWED_MATCHER_FIELDS:
                errors.append(f"{path}.{field} is not supported")

        matcher_type = matcher.get("type")
        if matcher_type not in cls.ALLOWED_MATCHER_TYPES:
            errors.append(f"{path}.type must be one of {', '.join(sorted(cls.ALLOWED_MATCHER_TYPES))}")
            return

        if matcher_type in {"contains", "equals", "prefix", "regex"}:
            matcher_value = matcher.get("value")
            if not isinstance(matcher_value, str) or not matcher_value:
                errors.append(f"{path}.value must be a non-empty string")
            if matcher_type == "regex":
                if isinstance(matcher_value, str) and len(matcher_value) > cls.MAX_REGEX_LENGTH:
                    errors.append(f"{path}.value exceeds max regex length")
                try:
                    re.compile(matcher_value or "")
                except re.error as exc:
                    errors.append(f"{path}.value is not a valid regex: {exc}")
            return

        if matcher_type in {"all_of", "any_of"}:
            matchers = matcher.get("matchers")
            if not isinstance(matchers, list) or not matchers:
                errors.append(f"{path}.matchers must be a non-empty list")
                return
            for index, child in enumerate(matchers):
                cls._validate_matcher_object(child, f"{path}.matchers[{index}]", errors, depth + 1)
            return

        if matcher_type == "not":
            child = matcher.get("matcher")
            if not isinstance(child, dict):
                errors.append(f"{path}.matcher must be an object")
                return
            cls._validate_matcher_object(child, f"{path}.matcher", errors, depth + 1)

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
    def _build_matcher(matcher_definition: Dict[str, Any]) -> Callable[[str], bool]:
        """Build a deterministic matcher callable."""
        matcher_type = matcher_definition["type"]

        if matcher_type == "contains":
            matcher_value = normalize_for_matching(matcher_definition["value"])
            return lambda action, value=matcher_value: isinstance(action, str) and value in normalize_for_matching(action)

        if matcher_type == "equals":
            matcher_value = normalize_for_matching(matcher_definition["value"])
            return lambda action, value=matcher_value: isinstance(action, str) and normalize_for_matching(action) == value

        if matcher_type == "prefix":
            matcher_value = normalize_for_matching(matcher_definition["value"])
            return lambda action, value=matcher_value: isinstance(action, str) and normalize_for_matching(action).startswith(value)

        if matcher_type == "regex":
            pattern = re.compile(matcher_definition["value"])
            return lambda action, compiled=pattern: isinstance(action, str) and compiled.search(normalize_for_matching(action)) is not None

        if matcher_type == "all_of":
            children = [RuleDefinitionBuilder._build_matcher(child) for child in matcher_definition["matchers"]]
            return lambda action, matchers=children: all(matcher(action) for matcher in matchers)

        if matcher_type == "any_of":
            children = [RuleDefinitionBuilder._build_matcher(child) for child in matcher_definition["matchers"]]
            return lambda action, matchers=children: any(matcher(action) for matcher in matchers)

        if matcher_type == "not":
            child = RuleDefinitionBuilder._build_matcher(matcher_definition["matcher"])
            return lambda action, matcher=child: not matcher(action)

        raise ValueError(f"Unsupported matcher type: {matcher_type}")


class RuleSchema:
    """Data-only description of the supported external rule schema."""

    @staticmethod
    def metadata() -> Dict[str, Any]:
        """Return deterministic schema metadata for docs and integrations."""
        return {
            "version": RULE_SCHEMA_VERSION,
            "top_level_fields": sorted(RuleDefinitionValidator.ALLOWED_TOP_LEVEL_FIELDS),
            "required_rule_fields": sorted(RuleDefinitionValidator.REQUIRED_RULE_FIELDS),
            "optional_rule_fields": sorted(RuleDefinitionValidator.OPTIONAL_RULE_FIELDS),
            "severity_values": sorted(RuleDefinitionValidator.ALLOWED_SEVERITIES),
            "response_values": sorted(RuleDefinitionValidator.ALLOWED_RESPONSES),
            "matcher_types": sorted(RuleDefinitionValidator.ALLOWED_MATCHER_TYPES),
            "required_matcher_fields": sorted(RuleDefinitionValidator.REQUIRED_MATCHER_FIELDS),
        }
