"""SARIF output helpers for scan findings."""

from typing import Any, Dict


def scan_to_sarif(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """Convert scan findings to SARIF 2.1.0."""
    rules = {}
    results = []
    for finding in scan_result.get("findings", []):
        rule_id = finding.get("matched_rule") or "agent_circuit_breaker_error"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "help": {"text": "Agent Circuit Breaker finding"},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.get("verdict") == "block" else "warning",
                "message": {
                    "text": (
                        f"{finding.get('verdict')} risk={finding.get('risk_score')} "
                        f"{finding.get('text', '')}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("path")},
                            "region": {"startLine": max(int(finding.get("line") or 1), 1)},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Circuit Breaker",
                        "informationUri": "https://github.com/sagarchhatrala/agent-circuit-breaker",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
