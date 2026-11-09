"""Useful owner-mediated operations built on the existing RuntimeGate lifecycle."""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import replace

from agent_circuit_breaker.database import SQLiteMaintenance
from agent_circuit_breaker.effects import EffectResult, amounts, usage
from agent_circuit_breaker.redaction import REDACTION_MARKER, redact_text
from agent_circuit_breaker.runtime import RuntimeAction
from agent_circuit_breaker.s3 import S3Publisher
from agent_circuit_breaker.workflow import Workflow, WorkflowDenied, WorkflowUnknown, TOOL_FIELDS, canonical, digest, relative_path, tool_catalog

EXTRA_TOOLS = {
    "database_change": {"operation": "string", "parameters": "object"},
    "json_artifact": {"artifact_id": "string", "path": "string"},
    "redact_artifact": {"artifact_id": "string", "path": "string"},
}


class Operations(Workflow):
    def __init__(self, root, state_dir, configuration):
        if not isinstance(configuration, dict) or set(configuration) - {"workflow", "s3_destinations", "database", "effect_limits", "max_actions", "ttl_seconds"}:
            raise ValueError("invalid operations configuration")
        self.configuration = json.loads(canonical(configuration))
        self.effect_limits = amounts(configuration.get("effect_limits", {}), "effect_limits")
        self.database = SQLiteMaintenance(configuration["database"]) if configuration.get("database") else None
        self.destinations = {name: S3Publisher(value) for name, value in configuration.get("s3_destinations", {}).items()}
        super().__init__(root, state_dir, configuration["workflow"], publisher=self._publish)
        if set(self.destinations) != set(self.policy.get("destinations", {})):
            raise ValueError("every workflow destination must have exactly one S3 registration")
        self.policy_hash = digest(canonical({"configuration": self.configuration, "database_identity": self.database.identity if self.database else None}).encode())

    def catalog(self):
        tools = tool_catalog()
        for name, fields in EXTRA_TOOLS.items():
            if name == "database_change" and self.database is None:
                continue
            tools.append({"name": name, "description": {
                "database_change": "Apply an owner-registered SQLite operation after review; parameters only, no arbitrary SQL.",
                "json_artifact": "Canonicalize a JSON artifact while preserving its sensitivity.",
                "redact_artifact": "Redact recognized secret patterns; preserves labels until a separate owner review.",
            }[name], "inputSchema": {"type": "object", "properties": {k: {"type": v} for k, v in fields.items()}, "required": list(fields), "additionalProperties": False}})
        return tools

    async def start(self, run_id=None):
        contract = {"goal": self.policy.get("goal"), "allowed_actors": ["workflow", "owner"], "require_actor": True,
                    "capabilities": [
                        {"id": self.policy_hash, "principal": self.policy["principal"], "action_types": [t["name"] for t in self.catalog()], "actors": ["workflow"]},
                        {"id": self.policy_hash + "-review", "principal": "owner-control", "action_types": ["declassify_artifact"], "actors": ["owner"]}],
                    "approval_required_action_types": ["publish_artifact", "database_change", "declassify_artifact"],
                    "effect_limits": self.effect_limits, "max_actions": self.configuration.get("max_actions", 500),
                    "ttl_seconds": self.configuration.get("ttl_seconds", 86400)}
        if run_id:
            state = await self.gate.read_run(run_id)
            if state.contract["capabilities"][0]["id"] != self.policy_hash:
                raise WorkflowDenied("owner configuration or database identity changed; inspect existing run")
            self.run_id = run_id
        else:
            self.run_id = (await self.gate.create_run(contract)).run_id
        return self.run_id

    def _args(self, name, arguments):
        if name not in EXTRA_TOOLS:
            return super()._args(name, arguments)
        if not isinstance(arguments, dict) or set(arguments) != set(EXTRA_TOOLS[name]):
            raise WorkflowDenied("arguments do not match registered schema")
        args = json.loads(canonical(arguments))
        if name == "database_change":
            if self.database is None or not isinstance(args["operation"], str):
                raise WorkflowDenied("database operation unavailable")
            self.database._arguments(args["operation"], args["parameters"])
        else:
            if not isinstance(args["artifact_id"], str) or not args["artifact_id"]:
                raise WorkflowDenied("artifact identity required")
            args["path"] = relative_path(args["path"])
            if not args["path"].startswith(self.policy["report_directory"] + "/"):
                raise WorkflowDenied("output is outside report directory")
        return args

    def prepare(self, name, arguments):
        args = self._args(name, arguments)
        if name == "database_change":
            plan = self.database.preview(args["operation"], args["parameters"])
            payload = {"operation": name, "arguments": args, "plan": plan, "policy": self.policy_hash}
            return RuntimeAction(command="acb-workflow " + canonical(payload), actor="workflow", principal=self.policy["principal"],
                                 capability_id=self.policy_hash, action_type=name, target_resource=plan["database"] + ":" + plan["table"], tool_name=name,
                                 metadata={"adapter": "owner-operations-v1", "payload": payload, "effects": {"database_rows": plan["rows_affected"]}})
        if name in {"json_artifact", "redact_artifact"}:
            artifact = self.provenance.get(args["artifact_id"])
            data = self.workspace.read(artifact["path"])
            if digest(data) != artifact["sha256"]:
                raise WorkflowDenied("artifact changed")
            output = self._transform(name, data)
            payload = {"operation": name, "arguments": args, "versions": [artifact], "output_sha256": digest(output), "policy": self.policy_hash}
            return RuntimeAction(command="acb-workflow " + canonical(payload), actor="workflow", principal=self.policy["principal"],
                                 capability_id=self.policy_hash, action_type=name, target_resource=args["path"], tool_name=name,
                                 metadata={"adapter": "owner-operations-v1", "payload": payload, "effects": {"files_written": 1}})
        action = super().prepare(name, args)
        effects = {}
        resource = action.target_resource
        if name == "publish_artifact":
            artifact = action.metadata["payload"]["versions"][0]
            effects["export_bytes"] = len(self.workspace.read(artifact["path"]))
            target = self.destinations[args["destination"]].target(artifact["path"])
            resource = "s3://" + target["bucket"] + "/" + target["key"]
        elif name in {"copy_artifact", "encode_artifact", "write_report"}:
            effects["files_written"] = 1
        return replace(action, target_resource=resource, metadata={**action.metadata, "effects": effects})

    @staticmethod
    def _transform(name, data):
        if name == "json_artifact":
            return (canonical(json.loads(data)) + "\n").encode()
        text = data.decode("utf-8")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return redact_text(text).encode()
        def redact(value):
            if isinstance(value, dict):
                return {key: REDACTION_MARKER if re.search(r"api[_-]?key|token|secret|password|passwd|pwd|authorization|credential", key, re.I) else redact(child)
                        for key, child in value.items()}
            if isinstance(value, list):
                return [redact(child) for child in value]
            return redact_text(value) if isinstance(value, str) else value
        # Raw audit-retention preferences must not disable an explicit redaction tool.
        return (canonical(redact(parsed)) + "\n").encode()

    def _publish(self, destination, data, artifact):
        return self.destinations[destination].publish(artifact["path"], data)

    async def _execute(self, record):
        return await asyncio.to_thread(self._execute_sync, record)

    def _execute_sync(self, record):
        payload = record["metadata"]["payload"]
        name, args = payload["operation"], payload["arguments"]
        if name == "database_change":
            # Database module checks the exact approved snapshot under its write lock.
            result = self.database.execute(payload["plan"])
            return EffectResult(result, {"database_rows": result["rows_affected"]})
        if name in {"json_artifact", "redact_artifact"}:
            if self.prepare(name, args).to_trajectory_record() != record:
                raise WorkflowDenied("artifact changed before transformation")
            artifact = payload["versions"][0]
            data = self.workspace.read(artifact["path"])
            if digest(data) != artifact["sha256"]:
                raise WorkflowDenied("artifact changed before transformation")
            output = self._transform(name, data)
            self.workspace.write_new(args["path"], output)
            result = {"artifact": self.provenance.put(args["path"], output, artifact["labels"], sources=[artifact["id"]], operation=name)}
        else:
            result = super()._execute(record)
        return EffectResult(result, record["metadata"]["effects"])

    def _evaluate(self, command):
        if command.startswith("acb-owner-declassify "):
            payload = json.loads(command[len("acb-owner-declassify "):])
            allowed = payload.get("policy") == self.policy_hash
            return {"command": command, "decision": "ALLOW" if allowed else "BLOCK", "verdict": "allow" if allowed else "block", "risk_score": 0}
        return super()._evaluate(command)

    async def review(self, name, arguments):
        action = self.prepare(name, arguments)
        state = await self.gate.read_run(self.run_id)
        payload = action.metadata["payload"]
        return {"run_id": self.run_id, "action_fingerprint": action.fingerprint, "operation": name,
                "resource": action.target_resource, "arguments": arguments, "effects": action.metadata["effects"],
                "used_effects": usage(state), "effect_limits": self.effect_limits, "policy_sha256": self.policy_hash,
                "artifacts": payload.get("versions", []), "database_preview": payload.get("plan"),
                "approval": "required" if name in {"publish_artifact", "database_change"} else "not required"}

    async def declassify(self, artifact_id, path, labels, expected_sha256, reason, *, approver):
        """Owner-only review of exact bytes, never an agent-facing tool."""
        if not isinstance(labels, list) or not labels or not set(labels) <= {"public", "internal"} or not isinstance(reason, str) or not reason.strip():
            raise WorkflowDenied("declassification requires reviewed labels and a reason")
        path = relative_path(path)
        if not path.startswith(self.policy["report_directory"] + "/"):
            raise WorkflowDenied("declassified output must be in the report directory")
        artifact = self.provenance.get(artifact_id)
        data = self.workspace.read(artifact["path"])
        if digest(data) != expected_sha256 or artifact["sha256"] != expected_sha256:
            raise WorkflowDenied("declassification bytes differ from owner review")
        payload = {"artifact": artifact, "path": path, "labels": sorted(set(labels)), "reason": reason, "policy": self.policy_hash}
        action = RuntimeAction(command="acb-owner-declassify " + canonical(payload), actor="owner", principal="owner-control", capability_id=self.policy_hash + "-review",
                               action_type="declassify_artifact", target_resource=path, metadata={"effects": {"files_written": 1}})
        approval = await self.gate.grant_approval(self.run_id, action, approver=approver)
        def execute(record):
            fresh = self.workspace.read(artifact["path"])
            if digest(fresh) != expected_sha256:
                raise WorkflowDenied("artifact changed after owner review")
            self.workspace.write_new(path, fresh)
            output = self.provenance.put(path, fresh, labels, sources=[artifact_id], operation="owner_declassification: " + reason)
            return EffectResult({"artifact": output}, {"files_written": 1})
        result = await self.gate.execute_approved(self.run_id, action, approval_id=approval.approval_id, executor=execute)
        return {"decision": "ALLOW", "outcome": result.outcome, "result": result.result}
