"""Durable execution for explicitly registered upstream MCP tools.

Transport supplied by trusted host. This does not make an arbitrary server safe:
registrations and reviewed catalogs describe the owner's authority contract.
A server-reported completion is distinguished from independently observed effects.
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Any, Awaitable, Callable

from agent_circuit_breaker.runtime import ExecutionUncertain, RuntimeAction, RuntimeGate
from agent_circuit_breaker.workflow import canonical, digest, relative_path
from agent_circuit_breaker_mcp.security import tool_fingerprint


class RegisteredMCPBridge:
    """A narrow, transport-independent RuntimeGate wrapper for remote calls.

    Only scalar string argument schemas and workspace-relative resources are
    supported. Owner registrations choose the operation, resource argument and
    exact catalog fingerprint. No tool annotations or client metadata grant
    authority. The upstream callable must implement a no-retry single request.
    """
    def __init__(self, gate: RuntimeGate, run_id: str, *, principal: str, capability_id: str, server_identity: str, registrations: dict, call_upstream: Callable[..., Awaitable[dict]], timeout: float = 10):
        if not principal or not server_identity or timeout <= 0:
            raise ValueError("trusted principal, server identity and positive timeout required")
        self.gate, self.run_id = gate, run_id
        self.principal, self.capability_id = principal, capability_id
        self.server_identity = server_identity
        self.registrations = __import__("json").loads(canonical(registrations))
        self.call_upstream, self.timeout = call_upstream, timeout
        self.catalog = None

    def observe_catalog(self, catalog: list[dict]) -> dict:
        from .security import extract_tool_catalog
        self.catalog = None
        validated = extract_tool_catalog(catalog)
        if any(not isinstance(t.get("inputSchema"), dict) or t["inputSchema"].get("type") != "object" for t in validated):
            self.catalog = None
            raise ValueError("invalid catalog schema")
        self.catalog = {tool["name"]: tool for tool in validated}
        unreviewed = [name for name, tool in self.catalog.items() if name not in self.registrations or self.registrations[name].get("catalog_sha256") != tool_fingerprint(tool)]
        missing = [name for name in self.registrations if name not in self.catalog]
        return {"server_identity": self.server_identity, "quarantined": sorted(unreviewed + missing), "trust": "owner-reviewed definition fingerprints; implementation identity is not attested"}

    def prepare(self, name: str, arguments: Any) -> RuntimeAction:
        registration = self.registrations.get(name)
        if not registration or self.catalog is None or name not in self.catalog:
            raise ValueError("unregistered tool or catalog not reviewed")
        if tool_fingerprint(self.catalog[name]) != registration["catalog_sha256"]:
            raise ValueError("tool definition changed; quarantined")
        fields = registration["fields"]
        if not isinstance(arguments, dict) or set(arguments) != set(fields) or not all(isinstance(v, str) and len(v) <= 4096 for v in arguments.values()):
            raise ValueError("arguments violate trusted string-field registration")
        args = __import__("json").loads(canonical(arguments))
        resource = relative_path(args[registration["resource_field"]])
        args[registration["resource_field"]] = resource
        binding = {"server": self.server_identity, "tool": name, "arguments": args, "catalog": registration["catalog_sha256"], "registration": digest(canonical(registration).encode())}
        return RuntimeAction(command="acb-mcp " + canonical(binding), actor="mcp-bridge", tool_name=name, principal=self.principal, capability_id=self.capability_id, action_type=registration["operation"], target_resource=self.server_identity + ":" + resource, metadata={"binding": binding})

    async def call(self, name: str, arguments: dict, *, approval_id: str | None = None) -> dict:
        action = self.prepare(name, arguments)
        stages = ["authorization_requested"]
        async def execute(record):
            if record != self.prepare(name, arguments).to_trajectory_record():
                raise ValueError("trusted binding changed before forwarding")
            stages.append("forwarding_started")
            try:
                # A transport write/acceptance is not proof of completion.
                response = await asyncio.wait_for(self.call_upstream(name, record["metadata"]["binding"]["arguments"]), self.timeout)
                stages.append("jsonrpc_response_received")
                if not isinstance(response, dict) or "error" in response or not isinstance(response.get("result"), dict):
                    raise ExecutionUncertain("upstream did not report tool completion")
                result = response["result"]
                if result.get("isError") not in (None, False) or result.get("resultType", "complete") != "complete" or not isinstance(result.get("content"), list) or not all(isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str) for block in result.get("content", [])):
                    raise ExecutionUncertain("upstream tool failure may follow an external effect")
                stages.append("upstream_reported_completed")
                return {"upstream": result, "completion_evidence": "server report; not independent side-effect observation"}
            except asyncio.CancelledError:
                stages.append("cancelled_outcome_uncertain")
                raise
            except Exception as exc:
                stages.append("outcome_uncertain")
                raise ExecutionUncertain("upstream effect is uncertain; no automatic retry") from exc
        if approval_id:
            result = await self.gate.execute_approved(self.run_id, action, approval_id=approval_id, executor=execute)
        else:
            decision = await self.gate.propose_action(self.run_id, action)
            if not decision.authorized:
                return {"decision": decision.decision, "reason": decision.reason, "stages": stages}
            result = await self.gate.execute_authorized(self.run_id, authorization_id=decision.authorization_id, executor=execute)
        return {"decision": "ALLOW", "stages": stages, "outcome": result.outcome, "result": result.result}
