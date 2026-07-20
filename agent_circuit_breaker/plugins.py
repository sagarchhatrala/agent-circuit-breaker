"""Plugin discovery for optional third-party inspectors and rule providers."""

from importlib import metadata
from typing import Any, Dict, List


INSPECTOR_ENTRY_POINT = "agent_circuit_breaker.inspectors"
RULE_ENTRY_POINT = "agent_circuit_breaker.rules"


def discover_plugins() -> Dict[str, List[Dict[str, Any]]]:
    """Return installed plugin entry points without importing plugin code."""
    return {
        "inspectors": _entry_points(INSPECTOR_ENTRY_POINT),
        "rules": _entry_points(RULE_ENTRY_POINT),
    }


def load_rule_plugins() -> List[Any]:
    """Load rule provider plugins and collect Rule objects."""
    rules: List[Any] = []
    for entry_point in metadata.entry_points(group=RULE_ENTRY_POINT):
        provider = entry_point.load()
        provided = provider()
        if isinstance(provided, list):
            rules.extend(provided)
    return rules


def _entry_points(group: str) -> List[Dict[str, Any]]:
    return [
        {
            "name": entry_point.name,
            "group": entry_point.group,
            "value": entry_point.value,
        }
        for entry_point in metadata.entry_points(group=group)
    ]
