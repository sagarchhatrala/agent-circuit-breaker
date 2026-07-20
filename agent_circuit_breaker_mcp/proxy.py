"""Minimal JSON-lines MCP-style proxy scaffold.

This scaffold is intentionally small: it demonstrates how to run tool-call
payloads through Agent Circuit Breaker before forwarding to a real MCP server.
It does not implement a complete MCP transport.
"""

import json
import sys
from typing import Any, Dict

from agent_circuit_breaker.api import evaluate_action


COMMAND_FIELDS = ("command", "cmd", "query", "sql", "script")


def inspect_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect command-like fields inside a JSON payload."""
    checks = []
    for field in COMMAND_FIELDS:
        value = payload.get(field)
        if isinstance(value, str):
            checks.append({"field": field, "result": evaluate_action(value)})
    blocked = any(check["result"]["verdict"] == "block" for check in checks)
    pending = any(check["result"]["verdict"] == "pending_approval" for check in checks)
    return {
        "allowed": not blocked and not pending,
        "checks": checks,
    }


def main() -> int:
    """Read JSON payloads from stdin and write inspection results to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            print(json.dumps(inspect_payload(payload), sort_keys=True))
        except Exception as exc:  # pragma: no cover - CLI fallback
            print(json.dumps({"allowed": False, "error": str(exc)}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
