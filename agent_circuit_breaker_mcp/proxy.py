"""Dependency-free stdio JSON-RPC proxy for MCP tool calls."""

import argparse
import json
import subprocess
import sys
import threading
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker.api import evaluate_action
from agent_circuit_breaker.cli import CircuitBreakerCLI


COMMAND_FIELDS = ("command", "cmd", "query", "sql", "script", "shell", "run")
BLOCKING_VERDICTS = {"block", "pending_approval", "error"}


def inspect_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect command-like fields inside a JSON payload."""
    return inspect_arguments(payload)


def inspect_arguments(
    arguments: Any,
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect command-like values recursively inside MCP tool arguments."""
    checks = []
    for field_path, value in _command_candidates(arguments):
        if rules or profile or mode:
            cli = CircuitBreakerCLI()
            custom_rules = []
            if rules:
                loaded = cli.load_custom_rules(rules)
                if not loaded["is_valid"]:
                    checks.append(
                        {
                            "field": field_path,
                            "result": _error_result(value, "; ".join(loaded["errors"])),
                        }
                    )
                    continue
                custom_rules = loaded["rules"]
            result = cli.evaluate_command(value, custom_rules, profile_name=profile, mode=mode)
        else:
            result = evaluate_action(value)
        checks.append({"field": field_path, "result": result})

    blocked = any(check["result"]["verdict"] in BLOCKING_VERDICTS for check in checks)
    return {
        "allowed": not blocked,
        "checks": checks,
    }


def inspect_jsonrpc_message(
    message: Dict[str, Any],
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect an MCP JSON-RPC message and return forwarding metadata."""
    if message.get("method") != "tools/call":
        return {"allowed": True, "checks": [], "response": None}

    params = message.get("params") or {}
    arguments = params.get("arguments") if isinstance(params, dict) else None
    inspection = inspect_arguments(arguments or {}, profile=profile, mode=mode, rules=rules)
    response = None
    if not inspection["allowed"]:
        response = blocked_jsonrpc_response(message, inspection)
    return {**inspection, "response": response}


def blocked_jsonrpc_response(message: Dict[str, Any], inspection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a JSON-RPC error response for a blocked request."""
    if "id" not in message:
        return None
    first_block = next(
        (check for check in inspection["checks"] if check["result"]["verdict"] in BLOCKING_VERDICTS),
        None,
    )
    result = first_block["result"] if first_block else {}
    return {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {
            "code": -32080,
            "message": "Agent Circuit Breaker blocked MCP tool call",
            "data": {
                "verdict": result.get("verdict"),
                "decision": result.get("decision"),
                "risk_score": result.get("risk_score"),
                "matched_rule": result.get("matched_rule"),
                "field": first_block.get("field") if first_block else None,
            },
        },
    }


def proxy_stdio(
    server_command: List[str],
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
) -> int:
    """Run a stdio JSON-RPC MCP proxy in front of an upstream server command."""
    process = subprocess.Popen(  # nosec: explicit user-provided MCP server command
        server_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    relay = threading.Thread(target=_relay_server_stdout, args=(process,), daemon=True)
    relay.start()

    assert process.stdin is not None
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("JSON-RPC message must be an object")
                inspection = inspect_jsonrpc_message(message, profile=profile, mode=mode, rules=rules)
                if not inspection["allowed"]:
                    response = inspection.get("response")
                    if response is not None:
                        print(json.dumps(response, sort_keys=True), flush=True)
                    continue
                process.stdin.write(line)
                if not line.endswith("\n"):
                    process.stdin.write("\n")
                process.stdin.flush()
            except Exception as exc:
                print(json.dumps(_proxy_error_response(None, str(exc)), sort_keys=True), flush=True)
    finally:
        process.stdin.close()
        return process.wait()


def main(argv: Optional[List[str]] = None) -> int:
    """Run inspection mode or a stdio MCP proxy."""
    parser = argparse.ArgumentParser(
        prog="circuit-breaker-mcp-proxy",
        description="Agent Circuit Breaker stdio JSON-RPC proxy for MCP servers",
    )
    parser.add_argument("--inspect-only", action="store_true", help="Read JSON payloads and emit inspection results")
    parser.add_argument("--profile", help="Safety profile")
    parser.add_argument("--mode", help="Policy mode")
    parser.add_argument("--rules", help="External JSON rule file")
    parser.add_argument("server_command", nargs="*", help="Upstream MCP server command")
    args = parser.parse_args(argv)

    if args.inspect_only:
        return inspect_stdin(profile=args.profile, mode=args.mode, rules=args.rules)

    if not args.server_command:
        parser.error("server_command is required unless --inspect-only is used")
    return proxy_stdio(args.server_command, profile=args.profile, mode=args.mode, rules=args.rules)


def inspect_stdin(
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
) -> int:
    """Read JSON payloads from stdin and write inspection results to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            print(json.dumps(inspect_arguments(payload, profile=profile, mode=mode, rules=rules), sort_keys=True))
        except Exception as exc:  # pragma: no cover - CLI fallback
            print(json.dumps({"allowed": False, "error": str(exc)}, sort_keys=True))
            return 1
    return 0


def _command_candidates(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path or "$", value
        return

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if isinstance(child, str):
                yield child_path, child
            elif isinstance(child, (dict, list)):
                yield from _command_candidates(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            if isinstance(child, str):
                yield child_path, child
            elif isinstance(child, (dict, list)):
                yield from _command_candidates(child, child_path)


def _relay_server_stdout(process: subprocess.Popen[str]) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)


def _proxy_error_response(message_id: Any, error: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32603, "message": error}}


def _error_result(command: str, error: str) -> Dict[str, Any]:
    return {
        "command": command,
        "verdict": "error",
        "decision": "ERROR",
        "risk_score": 100,
        "matched_rule": None,
        "error": error,
    }


if __name__ == "__main__":
    raise SystemExit(main())
