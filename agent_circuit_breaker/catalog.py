"""Built-in rule catalog helpers."""

from typing import Any, Dict, List

from agent_circuit_breaker.rules.builtin_rules import BUILTIN_RULES


def built_in_rule_catalog() -> List[Dict[str, Any]]:
    """Return deterministic metadata for built-in rules."""
    rows = []
    for rule in BUILTIN_RULES:
        metadata = rule.metadata or {}
        rows.append(
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "response": rule.response,
                "category": metadata.get("category"),
                "description": metadata.get("description"),
                "metadata": metadata,
            }
        )
    return sorted(rows, key=lambda item: item["id"])


def format_catalog_markdown() -> str:
    """Render the built-in rule catalog as Markdown."""
    lines = [
        "# Built-in Rule Catalog",
        "",
        "| Rule ID | Severity | Response | Category | Description |",
        "|---|---:|---:|---|---|",
    ]
    for rule in built_in_rule_catalog():
        lines.append(
            "| {id} | {severity} | {response} | {category} | {description} |".format(
                id=rule["id"],
                severity=rule["severity"],
                response=rule["response"],
                category=rule.get("category") or "",
                description=(rule.get("description") or "").replace("|", "\\|"),
            )
        )
    return "\n".join(lines) + "\n"
