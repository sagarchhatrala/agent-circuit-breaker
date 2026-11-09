"""MCP stdio client for an already-running, separately protected owner service.

This client receives only the agent socket. It has no owner policy, credentials,
database connection, approval endpoint or direct filesystem executor.
"""
from __future__ import annotations

import argparse
import asyncio
import uuid

from agent_circuit_breaker.owner import request
from agent_circuit_breaker_mcp.workflow_server import serve


class RemoteOperations:
    def __init__(self, socket_path):
        self.socket_path = socket_path
        response = request(socket_path, {"method": "tools"})
        self.tools = response["tools"]

    def catalog(self):
        return self.tools

    async def call(self, name, arguments):
        if name == "review_operation":
            if not isinstance(arguments, dict) or set(arguments) != {"name", "arguments"}:
                return {"decision": "BLOCK", "reason": "invalid review arguments", "executor_started": False}
            payload = {"method": "review", **arguments}
        elif name == "execute_review":
            if not isinstance(arguments, dict) or set(arguments) != {"review_id"}:
                return {"decision": "BLOCK", "reason": "invalid review execution arguments", "executor_started": False}
            payload = {"method": "commit", **arguments, "request_id": uuid.uuid4().hex}
        else:
            payload = {"method": "call", "name": name, "arguments": arguments, "request_id": uuid.uuid4().hex}
        result = await asyncio.to_thread(request, self.socket_path, payload)
        if "decision" not in result:
            return {"decision": "ALLOW", "executor_started": False, "result": result}
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    args = parser.parse_args(argv)
    asyncio.run(serve(RemoteOperations(args.socket)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
