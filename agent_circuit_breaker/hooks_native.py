"""Documented host-event adapters. Hooks permit host-owned execution only."""
from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024

HOST_CONFIGS = {"claude": (".claude/settings.json", True), "cursor": (".cursor/hooks.json", False)}


def decide(host: str, event: str, payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("host payload must be an object")
    if host == "claude":
        if event != "PreToolUse" or payload.get("hook_event_name") != event:
            raise ValueError("expected Claude PreToolUse payload")
        name, args = payload.get("tool_name"), payload.get("tool_input")
        if not isinstance(name, str) or not isinstance(args, dict):
            raise ValueError("missing tool name or tool_input object")
        if name == "Bash":
            command = args.get("command")
        elif name.startswith("mcp__"):
            # Hooks cannot bind a generic remote schema to real side effects.
            return {"decision": "UNKNOWN", "reason": "use ACB-owned mediated MCP tools for typed authority"}
        else:
            return {"decision": "UNKNOWN", "reason": "native tool has no supported trusted adapter"}
    elif host == "cursor":
        if payload.get("hook_event_name", event) != event:
            raise ValueError("event mismatch")
        if event == "beforeShellExecution":
            command = payload.get("command")
        elif event == "beforeMCPExecution":
            if not isinstance(payload.get("mcp_server_name"), str) or not isinstance(payload.get("tool_name"), str):
                raise ValueError("missing MCP server or tool identity")
            args = json.loads(payload["tool_input"])
            if not isinstance(args, dict):
                raise ValueError("MCP tool_input must encode an object")
            return {"decision": "UNKNOWN", "reason": "generic MCP execution requires a trusted typed adapter"}
        else:
            raise ValueError("unsupported Cursor hook event")
    else:
        raise ValueError("unsupported native host; Codex uses MCP configuration")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("missing shell command")
    # Do not let incidental library output corrupt the host protocol.
    from agent_circuit_breaker.api import evaluate_action
    with contextlib.redirect_stdout(sys.stderr):
        result = evaluate_action(command)
    return {"decision": result["decision"], "reason": result.get("reason") or result.get("error") or "deterministic command evaluation: " + result["decision"]}


def response(host: str, decision: dict) -> dict:
    allowed = decision["decision"] == "ALLOW"
    reason = "ACB " + decision["decision"] + ": " + decision["reason"]
    if host == "claude":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" if allowed else "deny", "permissionDecisionReason": reason}}
    return {"permission": "allow" if allowed else "deny", "user_message": reason, "agent_message": reason}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=("claude", "cursor"))
    parser.add_argument("event")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("host payload exceeds size limit")
        result = decide(args.host, args.event, json.loads(raw))
    except Exception as exc:
        result = {"decision": "ERROR", "reason": "invalid host event or failed check"}
        print("ACB hook error: " + type(exc).__name__, file=sys.stderr)
    print(json.dumps(response(args.host, result)), flush=True)
    return 0


def write_native_hook_scaffold(agent: str, home: str, *, force: bool = False) -> dict:
    """Compatibility entry point; now installs project-scoped documented hooks.

    Unverified Codex/Gemini/Copilot shapes are no longer generated. No global
    configuration is changed unless a caller explicitly supplies that directory.
    """
    if agent not in HOST_CONFIGS:
        raise ValueError("native scaffold retired for this host; use integrate codex --mode mcp")
    from agent_circuit_breaker.integrations import integrate
    return integrate(agent, Path(home), mode="hooks", operation="install")


if __name__ == "__main__":
    raise SystemExit(main())
