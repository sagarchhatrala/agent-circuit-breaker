import asyncio
import json
import os
import sqlite3
import socket
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.database import SQLiteMaintenance
from agent_circuit_breaker.effects import EffectResult, usage
from agent_circuit_breaker.owner import OwnerService, serve, verify_bundle
from agent_circuit_breaker.owner_setup import initialize
from agent_circuit_breaker.operations import Operations
from unittest.mock import patch
from agent_circuit_breaker.runtime import ExecutionUncertain, RunContract, RuntimeAction, RuntimeGate, SQLiteRunStore


def allowed(command):
    return {"command": command, "decision": "ALLOW", "verdict": "allow", "risk_score": 0}


class EffectBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "runtime.sqlite3")
        self.gate = RuntimeGate(store=SQLiteRunStore(self.path), evaluator=allowed)
        self.run = (await self.gate.create_run({"effect_limits": {"bytes": 5}})).run_id

    def action(self, amount, name="write"):
        return RuntimeAction(command=name, metadata={"effects": {"bytes": amount}})

    async def test_limits_survive_sqlite_and_recheck_at_start(self):
        one = await self.gate.propose_action(self.run, self.action(3))
        two = await self.gate.propose_action(self.run, self.action(3, "other"))
        await self.gate.execute_authorized(self.run, authorization_id=one.authorization_id, executor=lambda record: "completed")
        restarted = RuntimeGate(store=SQLiteRunStore(self.path), evaluator=allowed)
        called = []
        with self.assertRaisesRegex(ValueError, "cumulative"):
            await restarted.execute_authorized(self.run, authorization_id=two.authorization_id, executor=lambda record: called.append(record))
        self.assertEqual(called, [])
        self.assertEqual(usage(await restarted.read_run(self.run)), {"bytes": 3})

    async def test_actual_measurements_release_unused_reservation(self):
        one = await self.gate.propose_action(self.run, self.action(5))
        await self.gate.execute_authorized(self.run, authorization_id=one.authorization_id, executor=lambda record: EffectResult("completed", {"bytes": 2}))
        self.assertEqual(usage(await self.gate.read_run(self.run)), {"bytes": 2})
        self.assertTrue((await self.gate.propose_action(self.run, self.action(3))).authorized)

    async def test_uncertain_effect_holds_budget_across_restart(self):
        one = await self.gate.propose_action(self.run, self.action(5))
        def uncertain(record):
            raise ExecutionUncertain("remote effect may exist")
        with self.assertRaises(ExecutionUncertain):
            await self.gate.execute_authorized(self.run, authorization_id=one.authorization_id, executor=uncertain)
        restarted = RuntimeGate(store=SQLiteRunStore(self.path), evaluator=allowed)
        self.assertEqual(usage(await restarted.read_run(self.run)), {"bytes": 5})
        self.assertFalse((await restarted.propose_action(self.run, self.action(0))).authorized)
        await restarted.reconcile_execution(self.run, authorization_id=one.authorization_id, action_fingerprint=one.action_fingerprint,
            outcome="skipped", reconciler="owner", evidence={"effects": {"bytes": 0}, "observation": "destination independently checked"})
        self.assertEqual(usage(await restarted.read_run(self.run)), {"bytes": 0})

    async def test_invalid_measurement_cannot_refund_budget(self):
        one = await self.gate.propose_action(self.run, self.action(3))
        with self.assertRaises(ExecutionUncertain):
            await self.gate.execute_authorized(self.run, authorization_id=one.authorization_id, executor=lambda record: EffectResult(None, {"bytes": -1}))
        self.assertEqual(usage(await self.gate.read_run(self.run)), {"bytes": 3})

    async def test_budget_requires_declared_trusted_effects(self):
        self.assertFalse((await self.gate.propose_action(self.run, RuntimeAction(command="undeclared"))).authorized)

    async def test_boolean_and_negative_limits_rejected(self):
        for value in (True, -1, 1.5, float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                RunContract.from_mapping({"effect_limits": {"bytes": value}})

    async def test_approved_execution_uses_same_budget_contract(self):
        run = (await self.gate.create_run({"effect_limits": {"bytes": 2}, "approval_required_action_types": ["command"]})).run_id
        action = self.action(2)
        approval = await self.gate.grant_approval(run, action, approver="owner")
        await self.gate.execute_approved(run, action, approval_id=approval.approval_id, executor=lambda record: EffectResult("result", {"bytes": 1}))
        self.assertEqual(usage(await self.gate.read_run(run)), {"bytes": 1})


class OwnerOperationsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.info = initialize(Path(self.temp.name) / "project")
        self.config = json.loads(Path(self.info["config"]).read_text())
        self.service = self.make_service()
        await self.service.start()
        self.sequence = 0

    def make_service(self):
        service = OwnerService(self.info["workspace"], self.info["state"], self.config, os.getuid(), development=True)
        self.addCleanup(service.close)
        return service

    async def call(self, name, arguments):
        self.sequence += 1
        return await self.service.dispatch({"method": "call", "name": name, "arguments": arguments, "request_id": str(self.sequence)})

    async def approve(self, pending):
        return await self.service.dispatch({"method": "approve", "review_id": pending["review_id"], "fingerprint": pending["review"]["action_fingerprint"]}, administrative=True)

    async def commit(self, pending):
        self.sequence += 1
        return await self.service.dispatch({"method": "commit", "review_id": pending["review_id"], "request_id": str(self.sequence)})

    def rows(self):
        with sqlite3.connect(self.config["database"]["path"]) as connection:
            return connection.execute("SELECT * FROM tickets ORDER BY id").fetchall()

    async def test_real_sql_requires_owner_and_changes_one_row(self):
        args = {"operation": "close_ticket", "parameters": {"id": 1, "status": "closed"}}
        pending = await self.call("database_change", args)
        self.assertEqual(pending["decision"], "PENDING_APPROVAL")
        self.assertEqual(self.rows()[0], (1, "open"))
        with self.assertRaises(ValueError):
            await self.service.dispatch({"method": "approve", "review_id": pending["review_id"], "fingerprint": pending["review"]["action_fingerprint"]})
        await self.approve(pending)
        self.assertEqual((await self.commit(pending))["outcome"], "executed")
        self.assertEqual(self.rows(), [(1, "closed"), (2, "open"), (3, "closed")])
        self.assertEqual((await self.commit(pending))["decision"], "BLOCK")

    async def test_changed_database_invalidates_review(self):
        pending = await self.call("database_change", {"operation": "close_ticket", "parameters": {"id": 1, "status": "closed"}})
        await self.approve(pending)
        with sqlite3.connect(self.config["database"]["path"]) as db:
            db.execute("UPDATE tickets SET status='changed' WHERE id=2")
        result = await self.commit(pending)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(self.rows()[0], (1, "open"))

    async def test_cumulative_row_limit_prevents_third_change(self):
        for row_id in (1, 2):
            pending = await self.call("database_change", {"operation": "close_ticket", "parameters": {"id": row_id, "status": "closed"}})
            await self.approve(pending)
            self.assertEqual((await self.commit(pending))["outcome"], "executed")
        result = await self.call("database_change", {"operation": "close_ticket", "parameters": {"id": 3, "status": "reopened"}})
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("cumulative", result["reason"])
        self.assertEqual(self.rows()[2], (3, "closed"))

    async def test_request_replay_returns_same_result_without_reexecution(self):
        payload = {"method": "call", "name": "read_file", "arguments": {"path": "incident.json"}, "request_id": "replay"}
        first = await self.service.dispatch(payload)
        self.service.close()
        self.service = self.make_service()
        await self.service.start()
        second = await self.service.dispatch(payload)
        self.assertEqual(first, second)
        with self.assertRaisesRegex(ValueError, "different arguments"):
            await self.service.dispatch({**payload, "arguments": {"path": "other.json"}})

    async def test_review_fingerprint_required(self):
        pending = await self.call("database_change", {"operation": "close_ticket", "parameters": {"id": 1, "status": "closed"}})
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            await self.service.dispatch({"method": "approve", "review_id": pending["review_id"], "fingerprint": "forged"}, administrative=True)
        self.assertEqual((await self.commit(pending))["decision"], "BLOCK")

    async def test_rejection_blocks_commit(self):
        pending = await self.call("database_change", {"operation": "close_ticket", "parameters": {"id": 1, "status": "closed"}})
        await self.approve(pending)
        await self.service.dispatch({"method": "reject", "review_id": pending["review_id"]}, administrative=True)
        self.assertEqual((await self.commit(pending))["decision"], "BLOCK")

    async def test_schema_rejects_authority_injection(self):
        with self.assertRaisesRegex(ValueError, "unexpected"):
            await self.service.dispatch({"method": "status", "principal": "owner"})
        result = await self.call("database_change", {"operation": "close_ticket", "parameters": {"id": 1, "status": "closed", "sql": "DELETE FROM tickets"}})
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(len(self.rows()), 3)

    async def test_transforms_and_owner_declassification_are_real(self):
        read = await self.call("read_file", {"path": "incident.json"})
        original = read["result"]["artifact"]
        for name in ("json_artifact", "redact_artifact"):
            changed = await self.call(name, {"artifact_id": original["id"], "path": "reports/" + name + ".json"})
            self.assertEqual(changed["result"]["artifact"]["labels"], ["internal"])
            self.assertTrue((Path(self.info["workspace"]) / changed["result"]["artifact"]["path"]).is_file())
        args = {"method": "declassify", "artifact_id": original["id"], "path": "reports/public.json", "labels": ["public"], "sha256": original["sha256"], "reason": "owner reviewed synthetic content"}
        with self.assertRaises(ValueError):
            await self.service.dispatch(args)
        result = await self.service.dispatch(args, administrative=True)
        self.assertEqual(result["result"]["artifact"]["labels"], ["public"])
        self.assertEqual((Path(self.info["workspace"]) / "reports/public.json").read_bytes(), (Path(self.info["workspace"]) / "incident.json").read_bytes())

    async def test_redaction_handles_json_keys_and_ignores_raw_audit_setting(self):
        source = b'{"nested":[{"api_key":"synthetic-secret","count":3}],"note":"token=synthetic-other"}'
        with patch.dict(os.environ, {'ACB_RETAIN_RAW_RECORDS': '1'}):
            result = json.loads(Operations._transform('redact_artifact', source))
        self.assertEqual(result, {'nested': [{'api_key': '[REDACTED]', 'count': 3}], 'note': 'token=[REDACTED]'})

    async def test_export_verifiable_and_tamper_detected(self):
        await self.call("read_file", {"path": "incident.json"})
        bundle = await self.service.dispatch({"method": "export"}, administrative=True)
        key = self.service.operations.provenance.key
        self.assertTrue(verify_bundle(bundle, key)["verified"])
        bundle["payload"]["events"] = []
        with self.assertRaises(ValueError):
            verify_bundle(bundle, key)

    async def test_owner_identity_required_without_development(self):
        with self.assertRaisesRegex(ValueError, "different OS identities"):
            OwnerService(self.info["workspace"], self.info["state"], self.config, os.getuid())

    async def test_second_owner_cannot_open_same_state(self):
        with self.assertRaises(BlockingIOError):
            self.make_service()

    async def test_live_socket_is_not_unlinked_by_second_state(self):
        path = Path(self.info['created']) / 'socket/agent.sock'
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen(1)
            before = path.stat().st_ino
            with self.assertRaisesRegex(ValueError, 'already served'):
                await serve(self.service, path)
            self.assertEqual(path.stat().st_ino, before)

    async def test_evidence_pagination_retains_contiguous_events(self):
        await self.call('read_file', {'path': 'incident.json'})
        position, events = 0, []
        while position is not None:
            page = await self.service.dispatch({'method': 'export', 'from_sequence': position, 'limit': 1}, administrative=True)
            self.assertTrue(verify_bundle(page, self.service.operations.provenance.key)['verified'])
            events.extend(page['payload']['events'])
            position = page['payload']['next_sequence']
        self.assertEqual([e['sequence'] for e in events], list(range(page['payload']['total_events'])))


class DatabaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        info = initialize(Path(self.temp.name) / "project")
        self.configuration = json.loads(Path(info["config"]).read_text())["database"]

    def test_overbroad_template_never_changes_source(self):
        self.configuration["operations"]["close_ticket"]["sql"] = "UPDATE tickets SET status=:status WHERE :id IS NOT NULL"
        adapter = SQLiteMaintenance(self.configuration)
        with self.assertRaisesRegex(ValueError, "row limit"):
            adapter.preview("close_ticket", {"status": "closed", "id": 1})
        with sqlite3.connect(self.configuration["path"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0], 2)

    def test_transaction_rejects_stale_snapshot(self):
        adapter = SQLiteMaintenance(self.configuration)
        plan = adapter.preview("close_ticket", {"status": "closed", "id": 1})
        with sqlite3.connect(self.configuration["path"]) as db:
            db.execute("UPDATE tickets SET status='changed' WHERE id=2")
        with self.assertRaisesRegex(ValueError, "changed after preview"):
            adapter.execute(plan)
        with sqlite3.connect(self.configuration["path"]) as db:
            self.assertEqual(db.execute("SELECT status FROM tickets WHERE id=1").fetchone()[0], "open")

    def test_trigger_and_attached_database_shapes_rejected(self):
        with sqlite3.connect(self.configuration["path"]) as db:
            db.execute("CREATE TRIGGER cascade_changes AFTER UPDATE ON tickets BEGIN DELETE FROM tickets WHERE id=2; END")
        adapter = SQLiteMaintenance(self.configuration)
        with self.assertRaisesRegex(ValueError, "triggers"):
            adapter.preview("close_ticket", {"status": "closed", "id": 1})

    def test_parameter_is_data(self):
        adapter = SQLiteMaintenance(self.configuration)
        value = "closed'; DELETE FROM tickets; --"
        adapter.execute(adapter.preview("close_ticket", {"status": value, "id": 1}))
        with sqlite3.connect(self.configuration["path"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT status FROM tickets WHERE id=1").fetchone()[0], value)

    def test_shadowed_row_identity_is_not_misrepresented_in_preview(self):
        with sqlite3.connect(self.configuration['path']) as db:
            db.execute('DROP TABLE tickets')
            db.execute('CREATE TABLE tickets (id INTEGER PRIMARY KEY, status TEXT, rowid INTEGER)')
        adapter = SQLiteMaintenance(self.configuration)
        with self.assertRaisesRegex(ValueError, 'row identity'):
            adapter.preview('close_ticket', {'status': 'closed', 'id': 1})

    def test_malformed_parameter_registration_is_rejected(self):
        self.configuration['operations']['close_ticket']['parameters'] = [{}]
        with self.assertRaisesRegex(ValueError, 'parameter names'):
            SQLiteMaintenance(self.configuration)
