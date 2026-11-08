import asyncio
import base64
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.workflow import Workflow, digest
from agent_circuit_breaker.runtime import ExecutionUncertain, RuntimeGate, SQLiteRunStore


class WorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspace"
        self.root.mkdir()
        (self.root / "reports").mkdir()
        (self.root / "incident.txt").write_text("Synthetic incident: three failed logins.")
        (self.root / "credential.txt").write_text("synthetic credential material — fixture only")
        self.state = Path(self.temp.name) / "state"
        self.receipts = []
        self.policy = {"principal": "demo-agent", "goal": "Summarize incident", "read_paths": {name: {"sha256": digest((self.root / name).read_bytes()), "labels": labels} for name, labels in {"incident.txt": ["internal"], "credential.txt": ["sensitive"]}.items()}, "report_directory": "reports", "destinations": {"approved-collector": ["internal"]}}
        self.workflow = Workflow(self.root, self.state, self.policy, publisher=self.publish)
        await self.workflow.start()

    def publish(self, destination, data, artifact):
        self.receipts.append((destination, data))
        return {"received": True, "sha256": digest(data)}

    async def read(self, name="incident.txt"):
        result = await self.workflow.call("read_file", {"path": name})
        self.assertEqual(result["decision"], "ALLOW", result)
        return result["result"]["artifact"]["id"]

    async def test_useful_work_is_real(self):
        source = await self.read()
        result = await self.workflow.call("write_report", {"sources": [source], "path": "reports/incident.md"})
        self.assertEqual(result["outcome"], "executed", result)
        self.assertIn("three failed logins", (self.root / "reports/incident.md").read_text())
        self.assertEqual(result["result"]["artifact"]["labels"], ["internal"])

    async def test_encoded_and_copied_sensitive_data_cannot_exit_same_tool(self):
        source = await self.read("credential.txt")
        for tool, path in [("encode_artifact", "reports/encoded.txt"), ("copy_artifact", "reports/copied.txt")]:
            result = await self.workflow.call(tool, {"artifact_id": source, "path": path})
            self.assertEqual(result["decision"], "ALLOW", result)
            self.assertEqual(result["result"]["artifact"]["labels"], ["sensitive"])
            export = await self.workflow.call("publish_artifact", {"artifact_id": result["result"]["artifact"]["id"], "destination": "approved-collector"})
            self.assertEqual(export["decision"], "BLOCK")
            self.assertFalse(export["executor_started"])
        self.assertEqual(self.receipts, [])

    async def test_exact_approval_single_use_and_restart(self):
        source = await self.read()
        args = {"artifact_id": source, "destination": "approved-collector"}
        self.assertEqual((await self.workflow.call("publish_artifact", args))["decision"], "PENDING_APPROVAL")
        approval = await self.workflow.approve("publish_artifact", args, approver="owner")
        result = await self.workflow.call("publish_artifact", args, approval_id=approval["approval_id"])
        self.assertEqual(result["decision"], "ALLOW", result)
        restarted = Workflow(self.root, self.state, self.policy, publisher=self.publish)
        await restarted.start(self.workflow.run_id)
        replay = await restarted.call("publish_artifact", args, approval_id=approval["approval_id"])
        self.assertEqual(replay["decision"], "BLOCK")
        self.assertEqual(len(self.receipts), 1)

    async def test_artifact_mutation_and_argument_substitution(self):
        source = await self.read()
        args = {"artifact_id": source, "destination": "approved-collector"}
        approval = await self.workflow.approve("publish_artifact", args, approver="owner")
        changed = await self.workflow.call("publish_artifact", {**args, "destination": "other"}, approval_id=approval["approval_id"])
        self.assertFalse(changed["executor_started"])
        (self.root / "incident.txt").write_text("changed")
        changed = await self.workflow.call("publish_artifact", args, approval_id=approval["approval_id"])
        self.assertFalse(changed["executor_started"])
        self.assertIn("changed", changed["reason"])
        self.assertEqual(self.receipts, [])

    async def test_forged_identity_path_traversal_symlink_and_unknown_tool(self):
        for args in ({"path": "incident.txt", "principal": "owner"}, {"path": "../incident.txt"}, {"path": "reports/../../incident.txt"}):
            result = await self.workflow.call("read_file", args)
            self.assertFalse(result["executor_started"])
        self.assertEqual((await self.workflow.call("python", {}))["decision"], "UNKNOWN")
        (self.root / "incident.txt").unlink()
        (self.root / "incident.txt").symlink_to(self.root / "credential.txt")
        self.assertFalse((await self.workflow.call("read_file", {"path": "incident.txt"}))["executor_started"])

    async def test_provenance_tampering(self):
        source = await self.read("credential.txt")
        with sqlite3.connect(self.workflow.provenance.path) as conn:
            payload = json.loads(conn.execute("SELECT payload FROM artifacts WHERE id = ?", (source,)).fetchone()[0])
            payload["labels"] = ["internal"]
            conn.execute("UPDATE artifacts SET payload = ? WHERE id = ?", (json.dumps(payload), source))
        result = await self.workflow.call("publish_artifact", {"artifact_id": source, "destination": "approved-collector"})
        self.assertIn("integrity", result["reason"])
        self.assertEqual(self.receipts, [])

    async def test_uncertain_publisher_blocks_restart(self):
        def uncertain(*args):
            self.receipts.append("effect happened")
            raise TimeoutError()
        self.workflow.publisher = uncertain
        source = await self.read()
        args = {"artifact_id": source, "destination": "approved-collector"}
        approval = await self.workflow.approve("publish_artifact", args, approver="owner")
        result = await self.workflow.call("publish_artifact", args, approval_id=approval["approval_id"])
        self.assertEqual(result["outcome"], "unknown_execution_status")
        restarted = Workflow(self.root, self.state, self.policy, publisher=self.publish)
        await restarted.start(self.workflow.run_id)
        retry = await restarted.call("publish_artifact", args)
        self.assertEqual(retry["decision"], "BLOCK", retry)
        self.assertEqual(len(self.receipts), 1)

    async def test_concurrent_approval_only_one_receipt(self):
        source = await self.read()
        args = {"artifact_id": source, "destination": "approved-collector"}
        approval = await self.workflow.approve("publish_artifact", args, approver="owner")
        other = Workflow(self.root, self.state, self.policy, publisher=self.publish)
        await other.start(self.workflow.run_id)
        results = await asyncio.gather(*(w.call("publish_artifact", args, approval_id=approval["approval_id"]) for w in [self.workflow, other]))
        self.assertEqual(sum(r["decision"] == "ALLOW" for r in results), 1)
        self.assertEqual(len(self.receipts), 1)
