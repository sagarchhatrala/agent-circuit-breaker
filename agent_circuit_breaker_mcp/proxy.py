"""Dependency-free stdio JSON-RPC proxy for MCP tool calls."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess
import sys
import threading
from urllib.request import Request, urlopen
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker import __version__
from agent_circuit_breaker.api import evaluate_action
from agent_circuit_breaker.cli import CircuitBreakerCLI
from agent_circuit_breaker.limits import MAX_MCP_MESSAGE_BYTES, MAX_MCP_RECURSION_DEPTH, ensure_text_within_limit
from agent_circuit_breaker.taint import TaintLedger
from agent_circuit_breaker.trajectory import evaluate_trajectory
from agent_circuit_breaker_mcp.security import MCPProxySecurity


COMMAND_FIELDS = ("command", "cmd", "query", "sql", "script", "shell", "run")
STOP_VERDICTS = {"block", "pending_approval", "error", "unknown"}


class MCPRunGuard:
    """Stateful trajectory guard for one MCP proxy run."""

    def __init__(
        self,
        *,
        profile: Optional[str] = None,
        mode: Optional[str] = None,
        rules: Optional[str] = None,
        contract: Optional[Dict[str, Any]] = None,
        allow_unknown: bool = False,
    ):
        self.profile = profile
        self.mode = mode
        self.rules = rules
        self.contract = contract
        self.allow_unknown = allow_unknown
        self.actions: List[str] = []
        self.forwarded_actions: List[str] = []

    def inspect_arguments(self, arguments: Any) -> Dict[str, Any]:
        """Evaluate the current tool-call arguments in accumulated run context."""
        try:
            candidates = list(_command_candidates(arguments))
        except Exception as exc:
            return {
                "allowed": False,
                "trajectory": None,
                "coverage": _argument_coverage([], status="failed", error=str(exc)),
                "error": str(exc),
            }
        values = [value for _field, value in candidates]
        if not values:
            return {
                "allowed": True,
                "trajectory": None,
                "coverage": _argument_coverage(candidates),
            }

        result = evaluate_trajectory(
            self.actions + values,
            self._evaluate_action,
            contract=self.contract,
        )
        self.actions.extend(values)
        return {
            "allowed": _verdict_allowed(result["verdict"], allow_unknown=self.allow_unknown),
            "trajectory": result,
            "coverage": _argument_coverage(candidates),
            "state": self.state_summary(),
        }

    def mark_forwarded(self, arguments: Any) -> Dict[str, Any]:
        """Record command-like values that were actually forwarded upstream."""
        values = [value for _field, value in _command_candidates(arguments)]
        self.forwarded_actions.extend(values)
        return self.state_summary()

    def state_summary(self) -> Dict[str, Any]:
        """Return compact attempted-versus-forwarded MCP run state."""
        return {
            "attempted_count": len(self.actions),
            "forwarded_count": len(self.forwarded_actions),
            "blocked_count": max(0, len(self.actions) - len(self.forwarded_actions)),
        }

    def _evaluate_action(self, action: str) -> Dict[str, Any]:
        if self.rules or self.profile or self.mode:
            cli = CircuitBreakerCLI()
            custom_rules = []
            if self.rules:
                loaded = cli.load_custom_rules(self.rules)
                if not loaded["is_valid"]:
                    return _error_result(action, "; ".join(loaded["errors"]))
                custom_rules = loaded["rules"]
            return cli.evaluate_command(action, custom_rules, profile_name=self.profile, mode=self.mode)
        return evaluate_action(action)


def inspect_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect command-like fields inside a JSON payload."""
    return inspect_arguments(payload)


def inspect_arguments(
    arguments: Any,
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
    allow_unknown: bool = False,
) -> Dict[str, Any]:
    """Inspect command-like values recursively inside MCP tool arguments."""
    checks = []
    try:
        candidates = list(_command_candidates(arguments))
    except Exception as exc:
        return {
            "allowed": False,
            "checks": [],
            "coverage": _argument_coverage([], status="failed", error=str(exc)),
            "error": str(exc),
        }

    for field_path, value in candidates:
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

    blocked = any(
        not _verdict_allowed(check["result"]["verdict"], allow_unknown=allow_unknown)
        for check in checks
    )
    return {
        "allowed": not blocked,
        "checks": checks,
        "coverage": _argument_coverage(candidates),
    }


def inspect_jsonrpc_message(
    message: Dict[str, Any],
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
    run_guard: Optional[MCPRunGuard] = None,
    proxy_security: Optional[MCPProxySecurity] = None,
    allow_unknown: bool = False,
) -> Dict[str, Any]:
    """Inspect an MCP JSON-RPC message and return forwarding metadata."""
    if proxy_security is not None and message.get("method") == "tools/call":
        params = message.get("params") or {}
        tool_name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        taint_hit = proxy_security.taint_ledger.check_value(arguments or {}, different_tool=tool_name)
        if taint_hit is not None:
            response = blocked_jsonrpc_response(
                message,
                {
                    "checks": [
                        {
                            "field": "params.arguments",
                            "result": {
                                "verdict": "pending_approval",
                                "decision": "PENDING_APPROVAL",
                                "risk_score": 90,
                                "matched_rule": "mcp_cross_tool_secret_taint",
                            },
                        }
                    ],
                    "trajectory": None,
                },
            )
            if response is not None:
                response["error"]["data"]["taint"] = taint_hit
            return {
                "allowed": False,
                "checks": response["error"]["data"] if response else [],
                "coverage": _argument_coverage([("params.arguments", json.dumps(arguments, sort_keys=True))]),
                "response": response,
                "taint": taint_hit,
            }

    if message.get("method") != "tools/call":
        if proxy_security is not None:
            response = proxy_security.record_client_message(message)
            if response is not None:
                return {
                    "allowed": False,
                    "checks": [],
                    "coverage": _argument_coverage([], status="complete", security_relevant=True),
                    "response": response,
                }
        return {
            "allowed": True,
            "checks": [],
            "coverage": _argument_coverage([], status="not_applicable", security_relevant=False),
            "response": None,
        }

    params = message.get("params") or {}
    arguments = params.get("arguments") if isinstance(params, dict) else None
    inspection = inspect_arguments(arguments or {}, profile=profile, mode=mode, rules=rules, allow_unknown=allow_unknown)
    if run_guard is not None:
        trajectory_inspection = run_guard.inspect_arguments(arguments or {})
        inspection["trajectory"] = trajectory_inspection["trajectory"]
        inspection["trajectory_coverage"] = trajectory_inspection.get("coverage")
        inspection["trajectory_state"] = trajectory_inspection.get("state")
        if not trajectory_inspection["allowed"]:
            inspection["allowed"] = False

    response = None
    if not inspection["allowed"]:
        response = blocked_jsonrpc_response(message, inspection)
    elif run_guard is not None:
        inspection["trajectory_state"] = run_guard.mark_forwarded(arguments or {})
    if response is None and proxy_security is not None:
        response = proxy_security.record_client_message(message)
        if response is not None:
            inspection["allowed"] = False
    return {**inspection, "response": response}


def blocked_jsonrpc_response(message: Dict[str, Any], inspection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a JSON-RPC error response for a blocked request."""
    if "id" not in message:
        return None
    first_block = next(
        (
            check
            for check in inspection["checks"]
            if not _verdict_allowed(check["result"]["verdict"], allow_unknown=False)
        ),
        None,
    )
    result = first_block["result"] if first_block else {}
    trajectory = inspection.get("trajectory") or {}
    first_finding = next(iter(trajectory.get("trajectory_findings") or []), None)
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
                "trajectory_verdict": trajectory.get("verdict"),
                "trajectory_finding": first_finding.get("id") if first_finding else None,
            },
        },
    }


def proxy_stdio(
    server_command: List[str],
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
    run_guard: Optional[MCPRunGuard] = None,
    proxy_security: Optional[MCPProxySecurity] = None,
    allow_unknown: bool = False,
) -> int:
    """Run a stdio JSON-RPC MCP proxy in front of an upstream server command."""
    proxy_security = proxy_security or MCPProxySecurity(upstream_label=" ".join(server_command))
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
    relay = threading.Thread(target=_relay_server_stdout, args=(process, proxy_security), daemon=True)
    relay.start()

    assert process.stdin is not None
    try:
        for line in sys.stdin:
            ensure_text_within_limit(line, MAX_MCP_MESSAGE_BYTES, "MCP message")
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("JSON-RPC message must be an object")
                inspection = inspect_jsonrpc_message(
                    message,
                    profile=profile,
                    mode=mode,
                    rules=rules,
                    run_guard=run_guard,
                    proxy_security=proxy_security,
                    allow_unknown=allow_unknown,
                )
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


def proxy_http(
    listen: str,
    upstream_url: str,
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
    allow_unknown: bool = False,
) -> int:
    """Run a minimal dependency-free HTTP JSON-RPC MCP proxy."""
    host, port_text = listen.rsplit(":", 1)
    proxy_security = MCPProxySecurity(upstream_label=upstream_url)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
            try:
                size = int(self.headers.get("content-length", "0"))
                raw = self.rfile.read(size).decode("utf-8")
                ensure_text_within_limit(raw, MAX_MCP_MESSAGE_BYTES, "MCP message")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise ValueError("JSON-RPC message must be an object")
                inspection = inspect_jsonrpc_message(
                    message,
                    profile=profile,
                    mode=mode,
                    rules=rules,
                    proxy_security=proxy_security,
                    allow_unknown=allow_unknown,
                )
                if not inspection["allowed"] and inspection.get("response") is not None:
                    self._write_json(inspection["response"])
                    return
                request = Request(
                    upstream_url,
                    data=json.dumps(message).encode("utf-8"),
                    headers={"content-type": "application/json", "accept": "application/json"},
                    method="POST",
                )
                with urlopen(request, timeout=300) as response:  # nosec: caller-selected upstream
                    upstream_raw = response.read().decode("utf-8")
                upstream_message = json.loads(upstream_raw)
                if isinstance(upstream_message, dict):
                    upstream_inspection = inspect_upstream_jsonrpc_message(upstream_message, proxy_security)
                    self._write_json(upstream_inspection["message"])
                else:
                    self._write_json(upstream_message)
            except Exception as exc:
                self._write_json(_proxy_error_response(None, str(exc)), status=500)

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            self.send_response(200)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Agent Circuit Breaker HTTP MCP proxy. POST JSON-RPC requests here.")

        def log_message(self, _format: str, *args: Any) -> None:
            return

        def _write_json(self, payload: Any, *, status: int = 200) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Run inspection mode or a stdio MCP proxy."""
    parser = argparse.ArgumentParser(
        prog="agent-circuit-breaker-mcp-proxy",
        description="Agent Circuit Breaker stdio JSON-RPC proxy for MCP servers",
    )
    parser.add_argument("--inspect-only", action="store_true", help="Read JSON payloads and emit inspection results")
    parser.add_argument("--profile", help="Safety profile")
    parser.add_argument("--mode", help="Policy mode")
    parser.add_argument("--rules", help="External JSON rule file")
    parser.add_argument("--trajectory", action="store_true", help="Enable stateful trajectory checks across MCP tool calls")
    parser.add_argument("--trajectory-policy", help="JSON file containing a trajectory run contract")
    parser.add_argument("--allow-unknown", action="store_true", help="Forward UNKNOWN tool calls instead of stopping")
    parser.add_argument("--taint-ledger", help="Path to hash-only cross-tool taint ledger")
    parser.add_argument("--mcp-pin-dir", help="Directory for MCP tools/list catalog pins")
    parser.add_argument("--http-listen", help="Run HTTP MCP proxy on host:port")
    parser.add_argument("--http-upstream", help="HTTP MCP upstream URL")
    parser.add_argument("server_command", nargs="*", help="Upstream MCP server command")
    args = parser.parse_args(argv)
    contract = _load_trajectory_contract(args.trajectory_policy) if args.trajectory_policy else None
    run_guard = (
        MCPRunGuard(
            profile=args.profile,
            mode=args.mode,
            rules=args.rules,
            contract=contract,
            allow_unknown=args.allow_unknown,
        )
        if args.trajectory or args.trajectory_policy
        else None
    )

    if args.inspect_only:
        return inspect_stdin(
            profile=args.profile,
            mode=args.mode,
            rules=args.rules,
            run_guard=run_guard,
            allow_unknown=args.allow_unknown,
        )

    if args.http_listen or args.http_upstream:
        if not args.http_listen or not args.http_upstream:
            parser.error("--http-listen and --http-upstream must be used together")
        return proxy_http(
            args.http_listen,
            args.http_upstream,
            profile=args.profile,
            mode=args.mode,
            rules=args.rules,
            allow_unknown=args.allow_unknown,
        )

    if not args.server_command:
        parser.error("server_command is required unless --inspect-only is used")
    proxy_security = MCPProxySecurity(
        upstream_label=" ".join(args.server_command),
        pin_dir=None if not args.mcp_pin_dir else __import__("pathlib").Path(args.mcp_pin_dir),
        taint_ledger=TaintLedger(args.taint_ledger) if args.taint_ledger else TaintLedger(),
    )
    return proxy_stdio(
        args.server_command,
        profile=args.profile,
        mode=args.mode,
        rules=args.rules,
        run_guard=run_guard,
        proxy_security=proxy_security,
        allow_unknown=args.allow_unknown,
    )


def inspect_stdin(
    *,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    rules: Optional[str] = None,
    run_guard: Optional[MCPRunGuard] = None,
    allow_unknown: bool = False,
) -> int:
    """Read JSON payloads from stdin and write inspection results to stdout."""
    for line in sys.stdin:
        ensure_text_within_limit(line, MAX_MCP_MESSAGE_BYTES, "MCP message")
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            inspection = inspect_arguments(payload, profile=profile, mode=mode, rules=rules, allow_unknown=allow_unknown)
            if run_guard is not None:
                trajectory_inspection = run_guard.inspect_arguments(payload)
                inspection["trajectory"] = trajectory_inspection["trajectory"]
                inspection["trajectory_coverage"] = trajectory_inspection.get("coverage")
                inspection["trajectory_state"] = trajectory_inspection.get("state")
                if not trajectory_inspection["allowed"]:
                    inspection["allowed"] = False
            print(json.dumps(inspection, sort_keys=True))
        except Exception as exc:  # pragma: no cover - CLI fallback
            print(json.dumps({"allowed": False, "error": str(exc)}, sort_keys=True))
            return 1
    return 0


def _command_candidates(value: Any, path: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    if depth > MAX_MCP_RECURSION_DEPTH:
        raise ValueError(f"MCP arguments exceed recursion depth {MAX_MCP_RECURSION_DEPTH}")
    if isinstance(value, str):
        yield path or "$", value
        return

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if isinstance(child, str):
                yield child_path, child
            elif isinstance(child, (dict, list)):
                yield from _command_candidates(child, child_path, depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            if isinstance(child, str):
                yield child_path, child
            elif isinstance(child, (dict, list)):
                yield from _command_candidates(child, child_path, depth + 1)


def _argument_coverage(
    candidates: List[tuple[str, str]],
    *,
    status: str = "complete",
    error: Optional[str] = None,
    security_relevant: bool = True,
) -> Dict[str, Any]:
    """Return additive MCP argument inspection coverage metadata."""
    inspected_fields = [field for field, _value in candidates]
    mandatory_complete = status in {"complete", "not_applicable"}
    unknowns = [] if mandatory_complete else ["arguments"]
    return {
        "schema_version": 1,
        "status": status,
        "mandatory_complete": mandatory_complete,
        "security_relevant": security_relevant,
        "inspected_fields": inspected_fields,
        "inspected_count": len(inspected_fields),
        "error": error,
        "unknowns": unknowns,
    }


def _verdict_allowed(verdict: Any, *, allow_unknown: bool = False) -> bool:
    normalized = str(verdict or "").lower()
    if allow_unknown and normalized == "unknown":
        return True
    return normalized not in STOP_VERDICTS


def inspect_upstream_jsonrpc_message(message: Dict[str, Any], proxy_security: MCPProxySecurity) -> Dict[str, Any]:
    """Inspect an upstream JSON-RPC response before it reaches the agent."""
    return proxy_security.inspect_upstream_message(message)


def _relay_server_stdout(process: subprocess.Popen[str], proxy_security: Optional[MCPProxySecurity] = None) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        if proxy_security is None:
            print(line, end="", flush=True)
            continue
        try:
            message = json.loads(line)
            if isinstance(message, dict):
                inspection = inspect_upstream_jsonrpc_message(message, proxy_security)
                print(json.dumps(inspection["message"], sort_keys=True), flush=True)
            else:
                print(line, end="", flush=True)
        except Exception:
            print(line, end="", flush=True)


def _proxy_error_response(message_id: Any, error: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32603, "message": error}}


def _load_trajectory_contract(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("trajectory policy file must contain a JSON object")
    return payload


def _error_result(command: str, error: str) -> Dict[str, Any]:
    result = {
        "command": command,
        "verdict": "error",
        "decision": "ERROR",
        "matched_rule": None,
        "rule_details": None,
        "operation_analysis": None,
        "command_analysis": None,
        "sql_analysis": None,
        "risk_score": 100,
        "policy": None,
        "engine_version": __version__,
        "error": error,
    }
    result["inspection_coverage"] = CircuitBreakerCLI._error_inspection_coverage(error)
    CircuitBreakerCLI._validate_decision(result)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
