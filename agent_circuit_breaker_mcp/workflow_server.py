"""MCP modern and legacy stdio server for ACB-owned typed workflow execution.

No generic upstream forwarding, shell tool, model-selected principal, approval
endpoint, or HTTP transport. Each tool call uses the same durable dispatcher as
the local demo and Responses example. Notifications never receive responses.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from agent_circuit_breaker import __version__
from agent_circuit_breaker.workflow import MAX_BYTES, Workflow, canonical, tool_catalog

MODERN_VERSION = "2026-07-28"
SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")


class WorkflowMCPServer:
    def __init__(self, workflow: Workflow):
        self.workflow = workflow
        self.initialized = False
        self.ready = False
        self.seen: set[str] = set()
        self.pending: dict[str, asyncio.Task] = {}

    async def handle(self, message: object) -> dict | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self.error(None, -32600, "invalid JSON-RPC message")
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if "id" not in message:
            if method == "notifications/initialized" and self.initialized:
                self.ready = True
            elif method == "notifications/cancelled" and isinstance(params, dict):
                if type(params.get("requestId")) not in (str, int):
                    return None
                pending = self.pending.get(canonical(params.get("requestId")))
                if pending is not None:
                    pending.cancel()
            # Includes malformed tools/call notifications: never execute.
            return None
        if type(request_id) not in (str, int) or not isinstance(method, str) or not isinstance(params, dict):
            return self.error(None, -32600, "invalid request")
        metadata = params.get("_meta", {})
        if not isinstance(metadata, dict):
            return self.error(request_id, -32602, "invalid metadata")
        version = metadata.get("io.modelcontextprotocol/protocolVersion")
        modern = version is not None or method == "server/discover"
        if modern:
            if not isinstance(version, str) or not isinstance(metadata.get("io.modelcontextprotocol/clientCapabilities"), dict):
                return self.error(request_id, -32602, "modern requests require protocol version and client capabilities")
            if version != MODERN_VERSION:
                return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32022, "message": "Unsupported protocol version", "data": {"requested": version, "supported": [MODERN_VERSION, *SUPPORTED_VERSIONS]}}}
            # Protocol metadata never supplies principal/capability authority.
            params = {key: value for key, value in params.items() if key != "_meta"}
        def result(value):
            if modern:
                value = {"resultType": "complete", **value, "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "acb-workflow", "version": __version__}}}
            return self.result(request_id, value)
        if method == "server/discover":
            return result({"cacheScope": "public", "ttlMs": 0, "supportedVersions": [MODERN_VERSION, *SUPPORTED_VERSIONS], "capabilities": {"tools": {}}, "instructions": "Explicit owner policy, fixed typed executors, durable approvals outside the MCP surface."})
        key = canonical(request_id)
        if key in self.seen:
            return self.error(request_id, -32600, "request ID reused; no replay")
        self.seen.add(key)
        if len(self.seen) > 10000:
            return self.error(request_id, -32000, "session request limit reached")
        if method == "initialize":
            if self.initialized or not isinstance(params.get("protocolVersion"), str) or not isinstance(params.get("capabilities"), dict) or not isinstance(params.get("clientInfo"), dict):
                return self.error(request_id, -32602, "invalid initialization")
            self.initialized = True
            return self.result(request_id, {"protocolVersion": params["protocolVersion"] if params["protocolVersion"] in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0], "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "acb-workflow", "version": __version__}, "instructions": "Typed local tools. Owner policy is explicit. Approval is outside MCP; native host tools remain outside this boundary."})
        if method == "ping":
            return self.result(request_id, {})
        if not modern and not self.ready:
            return self.error(request_id, -32000, "initialize and notifications/initialized required")
        if method == "tools/list":
            if params:
                return self.error(request_id, -32602, "pagination is not used by this bounded catalog")
            return result({"tools": self.workflow.catalog() if hasattr(self.workflow, "catalog") else tool_catalog(), **({"cacheScope": "public", "ttlMs": 0} if modern else {})})
        if method == "tools/call":
            if set(params) - {"name", "arguments", "_meta"} or not isinstance(params.get("name"), str) or not isinstance(params.get("arguments"), dict):
                return self.error(request_id, -32602, "invalid tool call")
            try:
                outcome = await self.workflow.call(params["name"], params["arguments"])
            except asyncio.CancelledError:
                # Cancellation may race with execution. RuntimeGate keeps any
                # started-but-unresolved effect. Never claim it was rolled back.
                return None
            except Exception:
                print("ACB workflow execution failed; inspect owner state", file=sys.stderr)
                outcome = {"decision": "ERROR", "reason": "trusted execution failed; inspect durable state", "outcome": "unknown"}
            return result({"content": [{"type": "text", "text": canonical(outcome)}], "isError": outcome["decision"] != "ALLOW"})
        return self.error(request_id, -32601, "method not supported")

    @staticmethod
    def result(request_id, result):
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def error(request_id, code, message):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


async def serve(workflow: Workflow) -> None:
    server = WorkflowMCPServer(workflow)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_BYTES + 1)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    async def dispatch(message):
        response = await server.handle(message)
        if response is not None:
            print(canonical(response), flush=True)

    try:
        while True:
            try:
                line = await reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                print(canonical(server.error(None, -32700, "message too large")), flush=True)
                break
            if not line:
                break
            try:
                if len(line) > MAX_BYTES:
                    raise ValueError("message too large")
                def reject_constant(value):
                    raise ValueError("non-finite JSON number")
                message = json.loads(line, parse_constant=reject_constant)
            except (ValueError, UnicodeError):
                print(canonical(server.error(None, -32700, "invalid JSON")), flush=True)
                continue
            # Lifecycle and cancellation must not wait behind an executing tool.
            if isinstance(message, dict) and message.get("method") == "tools/call" and type(message.get("id")) in (str, int):
                key = canonical(message["id"])
                if key in server.pending:
                    print(canonical(server.error(message["id"], -32600, "duplicate active request")), flush=True)
                    continue
                task = asyncio.create_task(dispatch(message))
                server.pending[key] = task
                task.add_done_callback(lambda done, k=key: server.pending.pop(k, None))
            else:
                await dispatch(message)
    finally:
        tasks = list(server.pending.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--run-id", help="resume durable run; never automatically create replacement authority")
    args = parser.parse_args(argv)
    descriptor = None
    try:
        import fcntl
        args.state = args.state.resolve()
        args.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.state.stat().st_mode & 0o077:
            raise ValueError("state directory must be private (mode 0700)")
        # One server owns a durable state directory for its entire lifetime.
        # Lock before creating keys or stores, so concurrent first use cannot
        # mint replacement authority. OS process death releases the lock.
        descriptor = os.open(args.state / "server.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("state directory is busy: another MCP server owns this run") from None
        workflow = Workflow(args.workspace, args.state, json.loads(args.policy.read_text()))
        async def run():
            index = args.state / "current-run"
            run_id = args.run_id
            if run_id is None and index.exists():
                run_id = index.read_text().strip()
                if not run_id:
                    raise ValueError("empty durable run index")
            if run_id is None:
                from contextlib import closing
                import sqlite3
                with closing(sqlite3.connect(args.state / "runtime.sqlite3")) as conn:
                    if conn.execute("SELECT COUNT(*) FROM runtime_runs").fetchone()[0]:
                        raise ValueError("run index missing; supply --run-id after owner inspection")
            await workflow.start(run_id)
            if not index.exists():
                from agent_circuit_breaker.integrations import atomic_write
                atomic_write(index, workflow.run_id.encode())
            print("ACB durable run: " + workflow.run_id, file=sys.stderr)
            await serve(workflow)
        asyncio.run(run())
    except Exception as exc:
        print("ACB startup failed: " + str(exc), file=sys.stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
