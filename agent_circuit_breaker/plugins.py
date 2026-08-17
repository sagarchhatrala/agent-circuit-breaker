"""Plugin discovery for optional third-party inspectors and rule providers."""

from importlib import metadata
from typing import Any, Dict, List

from agent_circuit_breaker.engine import Rule
from agent_circuit_breaker.rules.loader import RuleDefinitionBuilder


INSPECTOR_ENTRY_POINT = "agent_circuit_breaker.inspectors"
RULE_ENTRY_POINT = "agent_circuit_breaker.rules"


def discover_plugins() -> Dict[str, List[Dict[str, Any]]]:
    """Return installed plugin entry points without importing plugin code."""
    return {
        "inspectors": _entry_points(INSPECTOR_ENTRY_POINT),
        "rules": _entry_points(RULE_ENTRY_POINT),
    }


def load_rule_plugins() -> List[Any]:
    """Load rule provider plugins and collect validated Rule objects."""
    rules: List[Any] = []
    errors: List[str] = []
    for entry_point in metadata.entry_points(group=RULE_ENTRY_POINT):
        label = f"{entry_point.name} ({entry_point.value})"
        try:
            provider = entry_point.load()
        except Exception as exc:
            errors.append(f"{label}: failed to import provider: {exc}")
            continue

        if not callable(provider):
            errors.append(f"{label}: provider is not callable")
            continue

        try:
            provided = provider()
            rules.extend(_build_plugin_rules(provided, label))
        except ValueError as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(f"{label}: provider failed: {exc}")

    if errors:
        raise ValueError("; ".join(errors))
    return rules


def _build_plugin_rules(provided: Any, label: str) -> List[Rule]:
    """Build Rule objects from a plugin provider return value."""
    if isinstance(provided, dict):
        if "rules" not in provided:
            raise ValueError(f"{label}: dict provider result must contain a 'rules' list")
        return _build_declarative_plugin_rules(provided, label)

    if not isinstance(provided, list):
        raise ValueError(f"{label}: provider must return a list of Rule objects, rule dicts, or a dict with 'rules'")

    if all(isinstance(item, Rule) for item in provided):
        return list(provided)

    if all(isinstance(item, dict) for item in provided):
        return _build_declarative_plugin_rules({"rules": provided}, label)

    raise ValueError(f"{label}: provider returned mixed or unsupported rule objects")


def _build_declarative_plugin_rules(definition: Dict[str, Any], label: str) -> List[Rule]:
    build = RuleDefinitionBuilder.build_rules(definition)
    if not build["is_valid"]:
        raise ValueError(f"{label}: invalid declarative rules: {', '.join(build['errors'])}")
    return build["rules"]


def _entry_points(group: str) -> List[Dict[str, Any]]:
    return [
        {
            "name": entry_point.name,
            "group": entry_point.group,
            "value": entry_point.value,
        }
        for entry_point in metadata.entry_points(group=group)
    ]
