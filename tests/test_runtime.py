"""Tests for the stateful runtime authorization gate."""

import asyncio
import os
import json
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import agent_circuit_breaker
from agent_circuit_breaker.runtime import (
    CapabilityGrant,
    RunContract,
    RuntimeMissingStateError,
    RuntimeSchemaError,
    RuntimeStoreBusy,
    RuntimeStoreUnavailable,
    RuntimeAction,
    RuntimeGate,
    RuntimeIntegrityError,
    RuntimeInvalidRecordError,
    RuntimeState,
    RuntimeToolExecutor,
    SQLiteRunStore,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _subprocess_env():
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(REPO_ROOT) if not existing else str(REPO_ROOT) + os.pathsep + existing
    return env


def _evaluator(action):
    if action == "mkdir /tmp/acb-demo":
        return {"verdict": "allow", "decision": "ALLOW", "risk_score": 0}
    if action == "git status":
        return {"verdict": "unknown", "decision": "UNKNOWN", "risk_score": 50}
    if action == "rm -rf /":
        return {"verdict": "block", "decision": "BLOCK", "risk_score": 100}
    return {"verdict": "allow", "decision": "ALLOW", "risk_score": 0}


class TestRuntimeGate(unittest.IsolatedAsyncioTestCase):
    async def test_package_exports_runtime_gate(self):
        self.assertIs(agent_circuit_breaker.RuntimeGate, RuntimeGate)
        self.assertIs(agent_circuit_breaker.SQLiteRunStore, SQLiteRunStore)
        self.assertIs(agent_circuit_breaker.CapabilityGrant, CapabilityGrant)

    async def test_allows_authorized_action_and_records_outcome(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"allowed_actors": ["orchestrator"], "require_actor": True},
            run_id="run-allow",
        )

        decision = await gate.propose_action(
            run.run_id,
            {"command": "mkdir /tmp/acb-demo", "actor": "orchestrator", "request_id": "req-1"},
        )
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.verdict, "allow")
        self.assertIsNotNone(decision.authorization_id)

        state = await gate.record_outcome(
            run.run_id,
            authorization_id=decision.authorization_id,
            outcome="executed",
        )
        self.assertEqual(state.status, "active")
        self.assertEqual([event.event_type for event in state.events], ["proposal", "outcome"])

    async def test_blocks_unknown_before_execution(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-unknown")

        decision = await gate.propose_action(run.run_id, {"command": "git status"})

        self.assertFalse(decision.authorized)
        self.assertEqual(decision.verdict, "unknown")
        self.assertEqual(decision.run_status, "blocked")
        self.assertEqual(decision.recovery["recommended_action"], "stop_current_execution_path")

    async def test_blocks_unauthorized_actor_live_and_freezes_run(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"allowed_actors": ["orchestrator"], "require_actor": True},
            run_id="run-actor",
        )

        first = await gate.propose_action(
            run.run_id,
            {"command": "mkdir /tmp/acb-demo", "actor": "subagent.release"},
        )
        second = await gate.propose_action(
            run.run_id,
            {"command": "mkdir /tmp/acb-demo", "actor": "orchestrator"},
        )

        self.assertFalse(first.authorized)
        self.assertEqual(first.run_status, "blocked")
        self.assertEqual(first.recovery["evidence"]["finding"], "traj_unauthorized_actor")
        self.assertFalse(second.authorized)
        self.assertEqual(second.reason, "run is blocked")

    async def test_blocks_missing_actor_when_contract_requires_identity(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run({"require_actor": True}, run_id="run-missing-actor")

        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})

        self.assertFalse(decision.authorized)
        self.assertEqual(decision.recovery["evidence"]["finding"], "traj_missing_actor")

    async def test_actor_token_is_required_when_configured_and_not_serialized(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {
                "allowed_actors": ["orchestrator"],
                "require_actor": True,
                "actor_tokens": {"orchestrator": "secret-token"},
            },
            run_id="run-token",
        )

        public_json = json.dumps(run.to_dict(), default=str)
        self.assertNotIn("secret-token", public_json)
        self.assertEqual(run.contract["actor_authentication"], "token")

        denied = await gate.propose_action(
            run.run_id,
            {"command": "mkdir /tmp/acb-demo", "actor": "orchestrator", "actor_token": "wrong"},
        )
        self.assertFalse(denied.authorized)
        self.assertEqual(denied.reason, "actor token is missing or invalid")

    async def test_valid_actor_token_allows_matching_actor(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {
                "allowed_actors": ["orchestrator"],
                "require_actor": True,
                "actor_tokens": {"orchestrator": "secret-token"},
            },
            run_id="run-valid-token",
        )

        decision = await gate.propose_action(
            run.run_id,
            {"command": "mkdir /tmp/acb-demo", "actor": "orchestrator", "actor_token": "secret-token"},
        )

        self.assertTrue(decision.authorized)

    async def test_principal_token_is_required_when_configured_and_not_serialized(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {
                "principal_tokens": {"service.runtime": "principal-secret"},
            },
            run_id="run-principal-token",
        )

        public_json = json.dumps(run.to_dict(), default=str)
        self.assertNotIn("principal-secret", public_json)
        self.assertEqual(run.contract["principal_authentication"], "token")

        denied = await gate.propose_action(
            run.run_id,
            {
                "command": "mkdir /tmp/acb-demo",
                "principal": "service.runtime",
                "principal_token": "wrong",
            },
        )

        self.assertFalse(denied.authorized)
        self.assertEqual(denied.reason_code, "PRINCIPAL_TOKEN_INVALID")

    async def test_capability_scope_allows_exact_authorized_context(self):
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: 100.0)
        run = await gate.create_run(
            {
                "allowed_actors": ["orchestrator"],
                "require_actor": True,
                "principal_tokens": {"service.runtime": "principal-secret"},
                "capabilities": [
                    {
                        "id": "cap-write-tmp",
                        "principal": "service.runtime",
                        "action_types": ["command"],
                        "target_resources": ["fs:/tmp/acb-demo"],
                        "actors": ["orchestrator"],
                        "expires_at": 200.0,
                    }
                ],
            },
            run_id="run-capability-allow",
        )

        decision = await gate.propose_action(
            run.run_id,
            {
                "command": "mkdir /tmp/acb-demo",
                "actor": "orchestrator",
                "principal": "service.runtime",
                "principal_token": "principal-secret",
                "capability_id": "cap-write-tmp",
                "target_resource": "fs:/tmp/acb-demo",
            },
        )

        self.assertTrue(decision.authorized)
        self.assertEqual(decision.reason_code, "AUTHORIZED")
        state = await gate.read_run(run.run_id)
        self.assertEqual(state.events[0].action["principal"], "service.runtime")
        self.assertEqual(state.events[0].action["capability_id"], "cap-write-tmp")
        self.assertEqual(state.events[0].action["target_resource"], "fs:/tmp/acb-demo")

    async def test_forged_or_out_of_scope_capabilities_are_denied(self):
        cases = [
            (
                "missing-capability",
                {
                    "principal": "service.runtime",
                    "principal_token": "principal-secret",
                    "target_resource": "fs:/tmp/acb-demo",
                },
                "CAPABILITY_MISSING",
            ),
            (
                "unknown-capability",
                {
                    "principal": "service.runtime",
                    "principal_token": "principal-secret",
                    "capability_id": "cap-other",
                    "target_resource": "fs:/tmp/acb-demo",
                },
                "CAPABILITY_UNKNOWN",
            ),
            (
                "target-mismatch",
                {
                    "principal": "service.runtime",
                    "principal_token": "principal-secret",
                    "capability_id": "cap-write-tmp",
                    "target_resource": "fs:/etc/passwd",
                },
                "CAPABILITY_TARGET_SCOPE_MISMATCH",
            ),
            (
                "action-type-mismatch",
                {
                    "principal": "service.runtime",
                    "principal_token": "principal-secret",
                    "capability_id": "cap-write-tmp",
                    "action_type": "network",
                    "target_resource": "fs:/tmp/acb-demo",
                },
                "CAPABILITY_ACTION_SCOPE_MISMATCH",
            ),
            (
                "actor-mismatch",
                {
                    "actor": "subagent.release",
                    "principal": "service.runtime",
                    "principal_token": "principal-secret",
                    "capability_id": "cap-write-tmp",
                    "target_resource": "fs:/tmp/acb-demo",
                },
                "CAPABILITY_ACTOR_SCOPE_MISMATCH",
            ),
            (
                "principal-mismatch",
                {
                    "principal": "other.service",
                    "principal_token": "other-secret",
                    "capability_id": "cap-write-tmp",
                    "target_resource": "fs:/tmp/acb-demo",
                },
                "CAPABILITY_PRINCIPAL_MISMATCH",
            ),
            (
                "expired-capability",
                {
                    "principal": "service.runtime",
                    "principal_token": "principal-secret",
                    "capability_id": "cap-expired",
                    "target_resource": "fs:/tmp/acb-demo",
                },
                "CAPABILITY_EXPIRED",
            ),
        ]

        for name, action_fields, reason_code in cases:
            with self.subTest(name=name):
                gate = RuntimeGate(evaluator=_evaluator, clock=lambda: 100.0)
                run = await gate.create_run(
                    {
                        "principal_tokens": {
                            "service.runtime": "principal-secret",
                            "other.service": "other-secret",
                        },
                        "capabilities": [
                            {
                                "id": "cap-write-tmp",
                                "principal": "service.runtime",
                                "action_types": ["command"],
                                "target_resources": ["fs:/tmp/acb-demo"],
                                "actors": ["orchestrator"],
                                "expires_at": 200.0,
                            },
                            {
                                "id": "cap-expired",
                                "principal": "service.runtime",
                                "target_resources": ["fs:/tmp/acb-demo"],
                                "expires_at": 50.0,
                            },
                        ],
                    },
                    run_id=f"run-capability-{name}",
                )

                payload = {
                    "command": "mkdir /tmp/acb-demo",
                    "actor": "orchestrator",
                    **action_fields,
                }
                decision = await gate.propose_action(run.run_id, payload)

                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason_code, reason_code)

    async def test_runtime_tool_executor_binds_principal_capability_context(self):
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: 100.0)
        run = await gate.create_run(
            {
                "principal_tokens": {"service.runtime": "principal-secret"},
                "capabilities": [
                    {
                        "id": "cap-write-tmp",
                        "principal": "service.runtime",
                        "target_resources": ["fs:/tmp/*"],
                        "expires_at": 200.0,
                    }
                ],
            },
            run_id="run-tool-principal-capability",
        )
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            executor=lambda action: calls.append(action) or "ok",
            principal="service.runtime",
            principal_token="principal-secret",
            capability_id="cap-write-tmp",
            target_resource="fs:/tmp/acb-demo",
        )

        result = await executor.execute("mkdir /tmp/acb-demo")

        self.assertTrue(result.executed)
        self.assertEqual(calls[0]["principal"], "service.runtime")
        self.assertEqual(calls[0]["capability_id"], "cap-write-tmp")
        self.assertEqual(calls[0]["target_resource"], "fs:/tmp/acb-demo")

        with self.assertRaises(ValueError):
            await executor.execute(
                {
                    "command": "mkdir /tmp/acb-demo",
                    "principal": "attacker",
                }
            )

    async def test_capability_policy_change_invalidates_existing_authorization(self):
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: 100.0)
        run = await gate.create_run(
            {
                "principal_tokens": {"service.runtime": "principal-secret"},
                "capabilities": [
                    {
                        "id": "cap-write-tmp",
                        "principal": "service.runtime",
                        "target_resources": ["fs:/tmp/acb-demo"],
                        "expires_at": 200.0,
                    }
                ],
            },
            run_id="run-capability-policy-change",
        )
        decision = await gate.propose_action(
            run.run_id,
            {
                "command": "mkdir /tmp/acb-demo",
                "principal": "service.runtime",
                "principal_token": "principal-secret",
                "capability_id": "cap-write-tmp",
                "target_resource": "fs:/tmp/acb-demo",
            },
        )
        self.assertTrue(decision.authorized)

        await gate.store.set_contract(
            run.run_id,
            agent_circuit_breaker.RunContract.from_mapping(
                {
                    "principal_tokens": {"service.runtime": "principal-secret"},
                    "capabilities": [
                        {
                            "id": "cap-write-tmp",
                            "principal": "service.runtime",
                            "target_resources": ["fs:/other"],
                            "expires_at": 200.0,
                        }
                    ],
                }
            ),
        )
        calls = []

        with self.assertRaisesRegex(ValueError, "authorization policy context changed"):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id,
                executor=lambda action: calls.append(action),
            )

        self.assertEqual(calls, [])

    async def test_approval_required_action_needs_trusted_approval_before_execution(self):
        now = 100.0
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: now)
        contract = {
            "principal_tokens": {"service.runtime": "principal-secret"},
            "capabilities": [
                {
                    "id": "cap-write-tmp",
                    "principal": "service.runtime",
                    "target_resources": ["fs:/tmp/acb-demo"],
                    "expires_at": 500.0,
                }
            ],
            "approval_required_targets": ["fs:/tmp/acb-demo"],
            "approver_tokens": {"security.lead": "approver-secret"},
        }
        run = await gate.create_run(contract, run_id="run-approval-required")
        action = {
            "command": "mkdir /tmp/acb-demo",
            "principal": "service.runtime",
            "principal_token": "principal-secret",
            "capability_id": "cap-write-tmp",
            "target_resource": "fs:/tmp/acb-demo",
        }

        pending = await gate.propose_action(run.run_id, action)
        self.assertFalse(pending.authorized)
        self.assertEqual(pending.verdict, "pending_approval")
        self.assertEqual(pending.reason_code, "APPROVAL_REQUIRED")

        with self.assertRaisesRegex(ValueError, "approver token"):
            await gate.grant_approval(
                run.run_id,
                action,
                approver="security.lead",
                approver_token="wrong",
            )

        approval = await gate.grant_approval(
            run.run_id,
            action,
            approver="security.lead",
            approver_token="approver-secret",
        )
        calls = []
        result = await gate.execute_approved(
            run.run_id,
            action,
            approval_id=approval.approval_id,
            executor=lambda executed: calls.append(executed) or "ok",
        )

        self.assertEqual(result.result, "ok")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["target_resource"], "fs:/tmp/acb-demo")
        state = await gate.read_run(run.run_id)
        self.assertIn("approval", [event.event_type for event in state.events])
        self.assertIn("approval_consumed", [event.event_type for event in state.events])

    async def test_approval_rejects_action_target_principal_policy_expiry_and_replay(self):
        now = 100.0
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: now)
        run = await gate.create_run(
            {
                "principal_tokens": {
                    "service.runtime": "principal-secret",
                    "other.service": "other-secret",
                },
                "capabilities": [
                    {
                        "id": "cap-write-tmp",
                        "principal": "service.runtime",
                        "target_resources": ["fs:/tmp/acb-demo"],
                        "expires_at": 500.0,
                    },
                    {
                        "id": "cap-other",
                        "principal": "other.service",
                        "target_resources": ["fs:/tmp/acb-demo"],
                        "expires_at": 500.0,
                    },
                ],
                "approval_required_targets": ["fs:/tmp/*"],
                "approver_tokens": {"security.lead": "approver-secret"},
            },
            run_id="run-approval-adversarial",
        )
        action = {
            "command": "mkdir /tmp/acb-demo",
            "principal": "service.runtime",
            "principal_token": "principal-secret",
            "capability_id": "cap-write-tmp",
            "target_resource": "fs:/tmp/acb-demo",
        }
        approval = await gate.grant_approval(
            run.run_id,
            action,
            approver="security.lead",
            approver_token="approver-secret",
            ttl_seconds=1,
        )
        calls = []

        with self.assertRaises(ValueError):
            await gate.execute_approved(
                run.run_id,
                {**action, "target_resource": "fs:/tmp/other"},
                approval_id=approval.approval_id,
                executor=lambda executed: calls.append(executed),
            )
        with self.assertRaisesRegex(ValueError, "approval is not valid"):
            await gate.execute_approved(
                run.run_id,
                {
                    **action,
                    "principal": "other.service",
                    "principal_token": "other-secret",
                    "capability_id": "cap-other",
                },
                approval_id=approval.approval_id,
                executor=lambda executed: calls.append(executed),
            )
        now = 102.0
        with self.assertRaisesRegex(ValueError, "approval is not valid"):
            await gate.execute_approved(
                run.run_id,
                action,
                approval_id=approval.approval_id,
                executor=lambda executed: calls.append(executed),
            )
        self.assertEqual(calls, [])

        now = 100.0
        second = await gate.grant_approval(
            run.run_id,
            action,
            approver="security.lead",
            approver_token="approver-secret",
        )
        await gate.revoke_approval(run.run_id, second.approval_id, "operator revoked")
        with self.assertRaisesRegex(ValueError, "approval is not valid"):
            await gate.execute_approved(
                run.run_id,
                action,
                approval_id=second.approval_id,
                executor=lambda executed: calls.append(executed),
            )
        self.assertEqual(calls, [])

    async def test_approval_consumption_is_single_use_after_success_and_failure(self):
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: 100.0)
        run = await gate.create_run(
            {
                "approval_required_targets": ["fs:/tmp/acb-demo"],
                "approver_tokens": {"security.lead": "approver-secret"},
            },
            run_id="run-approval-single-use",
        )
        action = {"command": "mkdir /tmp/acb-demo", "target_resource": "fs:/tmp/acb-demo"}
        approval = await gate.grant_approval(
            run.run_id,
            action,
            approver="security.lead",
            approver_token="approver-secret",
        )
        await gate.execute_approved(
            run.run_id,
            action,
            approval_id=approval.approval_id,
            executor=lambda executed: "ok",
        )
        calls = []
        with self.assertRaisesRegex(ValueError, "approval is not valid"):
            await gate.execute_approved(
                run.run_id,
                action,
                approval_id=approval.approval_id,
                executor=lambda executed: calls.append(executed),
            )
        self.assertEqual(calls, [])

        failed_run = await gate.create_run(
            {
                "approval_required_targets": ["fs:/tmp/acb-demo"],
                "approver_tokens": {"security.lead": "approver-secret"},
            },
            run_id="run-approval-failed-single-use",
        )
        failed_approval = await gate.grant_approval(
            failed_run.run_id,
            action,
            approver="security.lead",
            approver_token="approver-secret",
        )
        with self.assertRaises(RuntimeError):
            await gate.execute_approved(
                failed_run.run_id,
                action,
                approval_id=failed_approval.approval_id,
                executor=lambda executed: (_ for _ in ()).throw(RuntimeError("boom")),
            )
        with self.assertRaisesRegex(ValueError, "approval is not valid"):
            await gate.execute_approved(
                failed_run.run_id,
                action,
                approval_id=failed_approval.approval_id,
                executor=lambda executed: calls.append(executed),
            )
        self.assertEqual(calls, [])

    async def test_runtime_tool_executor_uses_approval_bound_path(self):
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: 100.0)
        run = await gate.create_run(
            {
                "approval_required_targets": ["fs:/tmp/acb-demo"],
                "approver_tokens": {"security.lead": "approver-secret"},
            },
            run_id="run-tool-approval",
        )
        action = {"command": "mkdir /tmp/acb-demo", "target_resource": "fs:/tmp/acb-demo"}
        approval = await gate.grant_approval(
            run.run_id,
            action,
            approver="security.lead",
            approver_token="approver-secret",
        )
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            target_resource="fs:/tmp/acb-demo",
            executor=lambda executed: calls.append(executed) or "ok",
        )

        result = await executor.execute("mkdir /tmp/acb-demo", approval_id=approval.approval_id)

        self.assertTrue(result.executed)
        self.assertEqual(result.decision.reason_code, "AUTHORIZED")
        self.assertEqual(len(calls), 1)

    async def test_delegation_policy_blocks_unapproved_child(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {
                "allowed_actors": ["orchestrator", "worker.docs"],
                "allowed_delegations": [{"from": "orchestrator", "to": "worker.docs"}],
            },
            run_id="run-delegation",
        )

        decision = await gate.propose_action(
            run.run_id,
            {
                "command": "mkdir /tmp/acb-demo",
                "actor": "worker.docs",
                "delegated_by": "subagent.untrusted",
            },
        )

        self.assertFalse(decision.authorized)
        self.assertEqual(decision.recovery["evidence"]["finding"], "traj_unauthorized_delegation")

    async def test_outcome_cannot_be_replayed_for_different_action(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-replay")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        self.assertTrue(decision.authorized)

        with self.assertRaises(ValueError):
            await gate.record_outcome(
                run.run_id,
                action_fingerprint="0" * 64,
                outcome="executed",
            )

    async def test_authorization_id_is_single_use_for_outcomes(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-auth-single-use")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        self.assertTrue(decision.authorized)

        await gate.record_outcome(
            run.run_id,
            authorization_id=decision.authorization_id,
            outcome="executed",
        )

        with self.assertRaises(ValueError):
            await gate.record_outcome(
                run.run_id,
                authorization_id=decision.authorization_id,
                outcome="executed",
            )

    async def test_outcome_cannot_be_recorded_for_denied_action(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-denied-outcome")
        decision = await gate.propose_action(run.run_id, {"command": "rm -rf /"})
        self.assertFalse(decision.authorized)

        with self.assertRaises(ValueError):
            await gate.record_outcome(
                run.run_id,
                action_fingerprint=decision.action_fingerprint,
                outcome="executed",
            )

    async def test_execute_authorized_invokes_executor_once_and_records_outcome(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-execute")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "req-1"})
        calls = []

        result = await gate.execute_authorized(
            run.run_id,
            authorization_id=decision.authorization_id,
            executor=lambda action: calls.append(action) or {"ok": True},
        )

        self.assertEqual(calls, [{"command": "mkdir /tmp/acb-demo", "request_id": "req-1"}])
        self.assertEqual(result.result, {"ok": True})
        self.assertEqual(result.outcome, "executed")
        self.assertEqual(
            [event.event_type for event in result.state.events],
            ["proposal", "started", "outcome"],
        )

    async def test_execute_authorized_rejects_forged_authorization_before_side_effect(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-forged-execute")
        await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        calls = []

        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id="forged",
                executor=lambda action: calls.append(action),
            )

        self.assertEqual(calls, [])

    async def test_runtime_tool_executor_executes_exact_authorized_action(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"allowed_actors": ["orchestrator"], "require_actor": True},
            run_id="run-tool-executor",
        )
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            actor="orchestrator",
            tool_name="test-tool",
            executor=lambda action: calls.append(action) or "ok",
        )

        result = await executor.execute("mkdir /tmp/acb-demo", request_id="req-tool")

        self.assertTrue(result.executed)
        self.assertEqual(result.execution.result, "ok")
        self.assertEqual(
            calls,
            [
                {
                    "command": "mkdir /tmp/acb-demo",
                    "actor": "orchestrator",
                    "tool_name": "test-tool",
                    "request_id": "req-tool",
                }
            ],
        )
        self.assertEqual(result.decision.policy_fingerprint, run.contract["policy_fingerprint"])

    async def test_runtime_tool_executor_denied_action_does_not_reach_executor(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-tool-denied")
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            executor=lambda action: calls.append(action),
        )

        result = await executor.execute("rm -rf /")

        self.assertFalse(result.executed)
        self.assertFalse(result.decision.authorized)
        self.assertIsNone(result.execution)
        self.assertEqual(calls, [])

    async def test_runtime_tool_executor_rejects_action_substitution_metadata(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-tool-substitution")
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            actor="orchestrator",
            executor=lambda action: calls.append(action),
        )

        with self.assertRaises(ValueError):
            await executor.execute({"command": "mkdir /tmp/acb-demo", "actor": "subagent"})

        self.assertEqual(calls, [])

    async def test_runtime_action_metadata_is_snapshotted_before_authorization(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-mutable-metadata")
        mutable_tags = ["before"]
        action = RuntimeAction.from_mapping(
            {
                "command": "mkdir /tmp/acb-demo",
                "metadata": {"tags": mutable_tags},
            }
        )
        expected_fingerprint = action.fingerprint
        mutable_tags.append("after")

        decision = await gate.propose_action(run.run_id, action)
        result = await gate.execute_authorized(
            run.run_id,
            authorization_id=decision.authorization_id,
            executor=lambda authorized_action: authorized_action,
        )

        self.assertEqual(decision.action_fingerprint, expected_fingerprint)
        self.assertEqual(result.result["metadata"]["tags"], ["before"])

    async def test_runtime_tool_executor_malformed_action_does_not_reach_executor(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-tool-malformed")
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            executor=lambda action: calls.append(action),
        )

        with self.assertRaises(ValueError):
            await executor.execute({"actor": "orchestrator"})

        self.assertEqual(calls, [])

    async def test_runtime_tool_executor_exception_records_failure(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-tool-exception")

        def fail(_action):
            raise RuntimeError("adapter exploded")

        executor = RuntimeToolExecutor(gate, run_id=run.run_id, executor=fail)

        with self.assertRaises(RuntimeError):
            await executor.execute("mkdir /tmp/acb-demo")

        state = await gate.read_run(run.run_id)
        self.assertEqual([event.event_type for event in state.events], ["proposal", "started", "outcome"])
        self.assertEqual(state.events[-1].outcome, "failed")

    async def test_runtime_tool_executor_timeout_records_uncertain_failure_and_blocks_next_action(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-tool-timeout")

        async def slow(_action):
            await asyncio.sleep(1)

        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            executor=slow,
            timeout_seconds=0.01,
        )

        with self.assertRaises(TimeoutError):
            await executor.execute("mkdir /tmp/acb-demo")

        state = await gate.read_run(run.run_id)
        self.assertEqual(state.events[-1].outcome, "unknown_execution_status")
        next_result = await executor.execute("mkdir /tmp/acb-demo")
        self.assertFalse(next_result.decision.authorized)
        self.assertEqual(next_result.decision.reason, "run has uncertain execution status")

    async def test_runtime_tool_executor_concurrent_calls_respect_run_limits(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run({"max_actions": 1}, run_id="run-tool-concurrent")
        calls = []
        executor = RuntimeToolExecutor(
            gate,
            run_id=run.run_id,
            executor=lambda action: calls.append(action) or "ok",
        )

        results = await asyncio.gather(
            executor.execute({"command": "mkdir /tmp/acb-demo", "request_id": "a"}),
            executor.execute({"command": "mkdir /tmp/acb-demo", "request_id": "b"}),
        )

        self.assertEqual(sum(1 for result in results if result.executed), 1)
        self.assertEqual(len(calls), 1)

    async def test_direct_executor_bypass_is_outside_acb_boundary(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-direct-bypass")
        calls = []

        def raw_executor(action):
            calls.append(action)

        raw_executor({"command": "rm -rf /"})

        state = await gate.read_run(run.run_id)
        self.assertEqual(calls, [{"command": "rm -rf /"}])
        self.assertEqual(state.events, ())

    async def test_execute_authorized_rejects_denied_action_before_side_effect(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-denied-execute")
        decision = await gate.propose_action(run.run_id, {"command": "rm -rf /"})
        calls = []

        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id or "missing",
                executor=lambda action: calls.append(action),
            )

        self.assertEqual(calls, [])

    async def test_execute_authorized_replay_is_blocked_before_second_side_effect(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-execute-replay")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        calls = []

        await gate.execute_authorized(
            run.run_id,
            authorization_id=decision.authorization_id,
            executor=lambda action: calls.append(action) or "first",
        )

        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id,
                executor=lambda action: calls.append(action) or "second",
            )

        self.assertEqual(len(calls), 1)

    async def test_executor_failure_records_failed_outcome_and_reraises(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-executor-failure")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})

        def fail(_action):
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id,
                executor=fail,
            )

        state = await gate.read_run(run.run_id)
        self.assertEqual([event.event_type for event in state.events], ["proposal", "started", "outcome"])
        self.assertEqual(state.events[-1].outcome, "failed")
        self.assertEqual(state.events[-1].trajectory["details"]["error_type"], "RuntimeError")

    async def test_unresolved_started_execution_blocks_dependent_proposal(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-unresolved")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})

        await gate._mark_execution_started(run.run_id, decision.authorization_id)
        next_decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})

        self.assertFalse(next_decision.authorized)
        self.assertEqual(next_decision.reason, "run has unresolved execution")

    async def test_max_actions_is_enforced_atomically_for_concurrent_proposals(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run({"max_actions": 1}, run_id="run-concurrent")

        results = await asyncio.gather(
            gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "a"}),
            gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "b"}),
        )

        authorized = [result for result in results if result.authorized]
        denied = [result for result in results if not result.authorized]
        self.assertEqual(len(authorized), 1)
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0].reason, "run exceeded max_actions")

    async def test_expired_and_cancelled_runs_block_new_actions(self):
        now = 1000.0
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: now)
        expired = await gate.create_run({"ttl_seconds": 1}, run_id="run-expired")
        now = 1002.0

        expired_decision = await gate.propose_action(
            expired.run_id,
            {"command": "mkdir /tmp/acb-demo"},
        )
        self.assertFalse(expired_decision.authorized)
        self.assertEqual(expired_decision.run_status, "expired")

        active = await gate.create_run(run_id="run-cancel")
        await gate.cancel_run(active.run_id, "test cancellation")
        cancelled_decision = await gate.propose_action(
            active.run_id,
            {"command": "mkdir /tmp/acb-demo"},
        )
        self.assertFalse(cancelled_decision.authorized)
        self.assertEqual(cancelled_decision.reason, "run is cancelled")

    async def test_malformed_contract_and_action_fail_before_evaluation(self):
        gate = RuntimeGate(evaluator=_evaluator)

        with self.assertRaises(ValueError):
            await gate.create_run({"allowed_actors": "orchestrator"})

        run = await gate.create_run(run_id="run-malformed")
        with self.assertRaises(ValueError):
            await gate.propose_action(run.run_id, {"actor": "orchestrator"})

    async def test_expired_authorization_fails_before_executor_side_effect(self):
        now = 1000.0
        gate = RuntimeGate(evaluator=_evaluator, clock=lambda: now)
        run = await gate.create_run({"ttl_seconds": 1}, run_id="run-expired-auth")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        now = 1002.0
        calls = []

        with self.assertRaisesRegex(ValueError, "run expired"):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id,
                executor=lambda action: calls.append(action),
            )

        self.assertEqual(calls, [])

    async def test_policy_context_change_invalidates_existing_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            store = SQLiteRunStore(db_path)
            gate = RuntimeGate(store=store, evaluator=_evaluator)
            run = await gate.create_run({"max_actions": 10}, run_id="run-policy-change")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            await store.set_contract(run.run_id, agent_circuit_breaker.RunContract(max_actions=1))
            calls = []

            with self.assertRaisesRegex(ValueError, "policy context changed"):
                await gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action),
                )

            self.assertEqual(calls, [])

    async def test_suspension_persists_and_blocks_new_authorization_and_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            first_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await first_gate.create_run(run_id="run-suspend")
            decision = await first_gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            await first_gate.suspend_run(
                run.run_id,
                "critical policy violation",
                evidence={"sequence": decision.sequence},
            )

            restarted_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            suspended = await restarted_gate.read_run(run.run_id)
            self.assertEqual(suspended.status, "suspended")
            self.assertEqual(suspended.events[-1].event_type, "suspension")

            next_decision = await restarted_gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            self.assertFalse(next_decision.authorized)
            self.assertEqual(next_decision.reason, "run is suspended")

            calls = []
            with self.assertRaisesRegex(ValueError, "run is suspended"):
                await restarted_gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action),
                )
            self.assertEqual(calls, [])

    async def test_resume_is_explicit_and_preserves_prior_uncertainty(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-resume-uncertain")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        await gate.record_outcome(
            run.run_id,
            authorization_id=decision.authorization_id,
            outcome="unknown_execution_status",
        )
        await gate.suspend_run(run.run_id, "operator investigation")
        await gate.resume_run(run.run_id, "operator accepted recovery risk")

        result = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})

        self.assertFalse(result.authorized)
        self.assertEqual(result.reason, "run has uncertain execution status")

    async def test_revocation_invalidates_outstanding_authorization_but_keeps_run_active(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-revocation")
        revoked = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "old"})
        await gate.revoke_authorizations(
            run.run_id,
            "scope revoked",
            authorization_id=revoked.authorization_id,
            evidence={"source": "test"},
        )
        calls = []

        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=revoked.authorization_id,
                executor=lambda action: calls.append(action),
            )

        self.assertEqual(calls, [])
        fresh = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "new"})
        self.assertTrue(fresh.authorized)
        state = await gate.read_run(run.run_id)
        self.assertIn("revocation", [event.event_type for event in state.events])

    async def test_revocation_after_started_does_not_prevent_outcome_recording_or_claim_cancellation(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(run_id="run-revoke-started")
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        await gate._mark_execution_started(run.run_id, decision.authorization_id)
        await gate.revoke_authorizations(run.run_id, "revoked after start")

        state = await gate.record_outcome(
            run.run_id,
            authorization_id=decision.authorization_id,
            outcome="unknown_execution_status",
        )

        self.assertEqual(state.events[-1].outcome, "unknown_execution_status")

    async def test_failed_and_uncertain_outcomes_cannot_replay_authorization(self):
        gate = RuntimeGate(evaluator=_evaluator)
        failed_run = await gate.create_run(run_id="run-failed-replay")
        failed = await gate.propose_action(failed_run.run_id, {"command": "mkdir /tmp/acb-demo"})

        with self.assertRaises(RuntimeError):
            await gate.execute_authorized(
                failed_run.run_id,
                authorization_id=failed.authorization_id,
                executor=lambda _action: (_ for _ in ()).throw(RuntimeError("boom")),
            )
        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                failed_run.run_id,
                authorization_id=failed.authorization_id,
                executor=lambda action: "replay",
            )

        uncertain_run = await gate.create_run(run_id="run-uncertain-replay")
        uncertain = await gate.propose_action(uncertain_run.run_id, {"command": "mkdir /tmp/acb-demo"})
        await gate._mark_execution_started(uncertain_run.run_id, uncertain.authorization_id)
        await gate.record_outcome(
            uncertain_run.run_id,
            authorization_id=uncertain.authorization_id,
            outcome="unknown_execution_status",
        )
        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                uncertain_run.run_id,
                authorization_id=uncertain.authorization_id,
                executor=lambda action: "replay",
            )

    async def test_reconciliation_requires_trusted_evidence_and_clears_unresolved_state(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"reconciler_tokens": {"external.system": "reconcile-secret"}},
            run_id="run-reconcile",
        )
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        started = await gate._mark_execution_started(run.run_id, decision.authorization_id)

        blocked = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        self.assertFalse(blocked.authorized)
        self.assertEqual(blocked.reason_code, "EXECUTION_UNRESOLVED")

        with self.assertRaisesRegex(ValueError, "reconciler token"):
            await gate.reconcile_execution(
                run.run_id,
                authorization_id=decision.authorization_id,
                action_fingerprint=started.action_fingerprint,
                outcome="executed",
                reconciler="external.system",
                reconciler_token="wrong",
                evidence={"external_id": "op-1"},
            )

        reconciled = await gate.reconcile_execution(
            run.run_id,
            authorization_id=decision.authorization_id,
            action_fingerprint=started.action_fingerprint,
            outcome="executed",
            reconciler="external.system",
            reconciler_token="reconcile-secret",
            evidence={"external_id": "op-1"},
            idempotency_key="idem-1",
        )
        self.assertEqual(reconciled.events[-1].event_type, "reconciliation")

        allowed = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        self.assertTrue(allowed.authorized)

    async def test_reconciliation_invalidates_preexisting_outstanding_authorizations(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"reconciler_tokens": {"operator": "secret"}},
            run_id="run-reconcile-invalidates-stale-auth",
        )
        unresolved = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "started"})
        stale = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "stale"})
        started = await gate._mark_execution_started(run.run_id, unresolved.authorization_id)

        await gate.reconcile_execution(
            run.run_id,
            authorization_id=unresolved.authorization_id,
            action_fingerprint=started.action_fingerprint,
            outcome="executed",
            reconciler="operator",
            reconciler_token="secret",
            evidence={"external_id": "op-1"},
        )

        calls = []
        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=stale.authorization_id,
                executor=lambda action: calls.append(action),
            )
        self.assertEqual(calls, [])

        fresh = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo", "request_id": "fresh"})
        self.assertTrue(fresh.authorized)

    async def test_reconciliation_rejects_wrong_action_duplicate_and_replay(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"reconciler_tokens": {"operator": "secret"}},
            run_id="run-reconcile-adversarial",
        )
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        await gate._mark_execution_started(run.run_id, decision.authorization_id)
        calls = []

        with self.assertRaisesRegex(ValueError, "fingerprint"):
            await gate.reconcile_execution(
                run.run_id,
                authorization_id=decision.authorization_id,
                action_fingerprint="0" * 64,
                outcome="failed",
                reconciler="operator",
                reconciler_token="secret",
            )
        await gate.reconcile_execution(
            run.run_id,
            authorization_id=decision.authorization_id,
            action_fingerprint=decision.action_fingerprint,
            outcome="failed",
            reconciler="operator",
            reconciler_token="secret",
            evidence={"ticket": "INC-1"},
        )
        with self.assertRaisesRegex(ValueError, "terminal outcome"):
            await gate.reconcile_execution(
                run.run_id,
                authorization_id=decision.authorization_id,
                action_fingerprint=decision.action_fingerprint,
                outcome="executed",
                reconciler="operator",
                reconciler_token="secret",
            )
        with self.assertRaises(ValueError):
            await gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id,
                executor=lambda action: calls.append(action),
            )
        self.assertEqual(calls, [])

    async def test_uncertain_outcome_remains_blocking_until_reconciled(self):
        gate = RuntimeGate(evaluator=_evaluator)
        run = await gate.create_run(
            {"reconciler_tokens": {"external.system": "secret"}},
            run_id="run-reconcile-uncertain",
        )
        decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        await gate._mark_execution_started(run.run_id, decision.authorization_id)
        await gate.record_outcome(
            run.run_id,
            authorization_id=decision.authorization_id,
            outcome="unknown_execution_status",
        )
        blocked = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        self.assertFalse(blocked.authorized)
        self.assertEqual(blocked.reason_code, "EXECUTION_OUTCOME_UNKNOWN")

        await gate.reconcile_execution(
            run.run_id,
            authorization_id=decision.authorization_id,
            action_fingerprint=decision.action_fingerprint,
            outcome="executed",
            reconciler="external.system",
            reconciler_token="secret",
            evidence={"external_status": "completed"},
        )
        allowed = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
        self.assertTrue(allowed.authorized)

    async def test_sqlite_locked_database_fails_before_executor_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            gate = RuntimeGate(store=SQLiteRunStore(db_path, timeout_seconds=0.05), evaluator=_evaluator)
            run = await gate.create_run(run_id="run-locked")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            calls = []
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("BEGIN EXCLUSIVE")
                with self.assertRaises(RuntimeStoreBusy):
                    await gate.execute_authorized(
                        run.run_id,
                        authorization_id=decision.authorization_id,
                        executor=lambda action: calls.append(action),
                    )
            finally:
                connection.rollback()
                connection.close()

            self.assertEqual(calls, [])

    async def test_sqlite_corrupted_state_fails_before_executor_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await gate.create_run(run_id="run-corrupt")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            connection = sqlite3.connect(db_path)
            try:
                connection.execute(
                    "UPDATE runtime_runs SET state_json = ? WHERE run_id = ?",
                    ("not-json", run.run_id),
                )
                connection.commit()
            finally:
                connection.close()
            calls = []

            with self.assertRaises(RuntimeInvalidRecordError):
                await gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action),
                )

            self.assertEqual(calls, [])

    async def test_sqlite_schema_metadata_and_health_are_initialized(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            store = SQLiteRunStore(db_path)
            health = await store.health()

            self.assertTrue(health["ok"])
            self.assertEqual(health["schema_version"], 1)
            connection = sqlite3.connect(db_path)
            try:
                version = connection.execute(
                    "SELECT value FROM runtime_metadata WHERE key = 'schema_version'"
                ).fetchone()[0]
                state = connection.execute(
                    "SELECT value FROM runtime_metadata WHERE key = 'migration_state'"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(version, "1")
            self.assertEqual(state, "complete")

    async def test_sqlite_legacy_two_table_schema_migrates_without_losing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            contract = RunContract()
            state = RuntimeState(
                run_id="run-legacy",
                status="active",
                contract=contract.public_summary(),
                created_at=1.0,
                expires_at=None,
                version=0,
                events=(),
            )
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE runtime_runs (run_id TEXT PRIMARY KEY, state_json TEXT NOT NULL)")
                connection.execute("CREATE TABLE runtime_contracts (run_id TEXT PRIMARY KEY, contract_json TEXT NOT NULL)")
                connection.execute(
                    "INSERT INTO runtime_runs (run_id, state_json) VALUES (?, ?)",
                    (state.run_id, json.dumps(state.to_dict(), sort_keys=True, default=str)),
                )
                connection.execute(
                    "INSERT INTO runtime_contracts (run_id, contract_json) VALUES (?, ?)",
                    (state.run_id, json.dumps(contract.__dict__, sort_keys=True, default=str)),
                )
                connection.commit()
            finally:
                connection.close()

            store = SQLiteRunStore(db_path)
            restored = await store.read("run-legacy")
            health = await store.health()

            self.assertEqual(restored.run_id, "run-legacy")
            self.assertEqual(health["schema_version"], 1)

    async def test_sqlite_future_or_incomplete_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "future.sqlite3")
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE runtime_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute("INSERT INTO runtime_metadata (key, value) VALUES ('schema_version', '999')")
                connection.execute("INSERT INTO runtime_metadata (key, value) VALUES ('migration_state', 'complete')")
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(RuntimeSchemaError):
                SQLiteRunStore(db_path)

    async def test_sqlite_integrity_rejects_mismatched_action_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await gate.create_run(run_id="run-bad-fingerprint")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            connection = sqlite3.connect(db_path)
            try:
                state = json.loads(
                    connection.execute(
                        "SELECT state_json FROM runtime_runs WHERE run_id = ?",
                        (run.run_id,),
                    ).fetchone()[0]
                )
                state["events"][0]["action_fingerprint"] = "0" * 64
                connection.execute(
                    "UPDATE runtime_runs SET state_json = ? WHERE run_id = ?",
                    (json.dumps(state, sort_keys=True), run.run_id),
                )
                connection.commit()
            finally:
                connection.close()
            calls = []

            with self.assertRaises(RuntimeIntegrityError):
                await gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action),
                )

            self.assertEqual(calls, [])

    async def test_sqlite_missing_contract_fails_before_executor_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await gate.create_run(run_id="run-missing-contract")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("DELETE FROM runtime_contracts WHERE run_id = ?", (run.run_id,))
                connection.commit()
            finally:
                connection.close()
            calls = []

            with self.assertRaises(RuntimeMissingStateError):
                await gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action),
                )

            self.assertEqual(calls, [])

    async def test_sqlite_unavailable_database_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeStoreUnavailable):
                SQLiteRunStore(str(Path(directory)))

    async def test_sqlite_run_store_survives_gate_restart_and_preserves_private_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            first_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await first_gate.create_run(
                {
                    "allowed_actors": ["orchestrator"],
                    "require_actor": True,
                    "actor_tokens": {"orchestrator": "secret-token"},
                },
                run_id="run-sqlite-restart",
            )

            persisted_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            restored = await persisted_gate.read_run(run.run_id)
            self.assertEqual(restored.run_id, run.run_id)
            self.assertNotIn("secret-token", json.dumps(restored.to_dict(), default=str))

            denied = await persisted_gate.propose_action(
                run.run_id,
                {"command": "mkdir /tmp/acb-demo", "actor": "orchestrator", "actor_token": "wrong"},
            )
            self.assertFalse(denied.authorized)
            self.assertEqual(denied.reason, "actor token is missing or invalid")

    async def test_sqlite_run_store_rejects_authorization_replay_across_store_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            first_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await first_gate.create_run(run_id="run-sqlite-replay")
            decision = await first_gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            self.assertTrue(decision.authorized)

            second_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            first_calls = []
            second_calls = []

            first = await first_gate.execute_authorized(
                run.run_id,
                authorization_id=decision.authorization_id,
                executor=lambda action: first_calls.append(action) or "first",
            )
            self.assertEqual(first.outcome, "executed")

            with self.assertRaises(ValueError):
                await second_gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: second_calls.append(action) or "second",
                )

            self.assertEqual(len(first_calls), 1)
            self.assertEqual(second_calls, [])

    async def test_sqlite_run_store_consumes_authorization_atomically_across_gate_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            first_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            second_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await first_gate.create_run(run_id="run-sqlite-atomic")
            decision = await first_gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            calls = []

            async def execute(gate, label):
                return await gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append((label, action)) or label,
                )

            results = await asyncio.gather(
                execute(first_gate, "first"),
                execute(second_gate, "second"),
                return_exceptions=True,
            )

            successes = [result for result in results if not isinstance(result, Exception)]
            failures = [result for result in results if isinstance(result, Exception)]
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], ValueError)
            self.assertEqual(len(calls), 1)

    async def test_sqlite_run_store_consumes_authorization_atomically_across_os_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            side_effect_path = str(Path(directory) / "side-effect.txt")
            gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await gate.create_run(run_id="run-process-race")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            worker = Path(directory) / "worker.py"
            worker.write_text(
                textwrap.dedent(
                    """
                    import asyncio
                    import json
                    import sys
                    from pathlib import Path
                    from agent_circuit_breaker.runtime import RuntimeGate, SQLiteRunStore

                    async def main():
                        db_path, run_id, authorization_id, side_effect_path, label = sys.argv[1:6]
                        gate = RuntimeGate(store=SQLiteRunStore(db_path))
                        def executor(action):
                            with Path(side_effect_path).open("a", encoding="utf-8") as handle:
                                handle.write(label + "\\n")
                            return label
                        try:
                            result = await gate.execute_authorized(
                                run_id,
                                authorization_id=authorization_id,
                                executor=executor,
                            )
                            print(json.dumps({"ok": True, "outcome": result.outcome}))
                        except Exception as exc:
                            print(json.dumps({"ok": False, "error": exc.__class__.__name__}))

                    asyncio.run(main())
                    """
                ),
                encoding="utf-8",
            )

            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        str(worker),
                        db_path,
                        run.run_id,
                        decision.authorization_id,
                        side_effect_path,
                        label,
                    ],
                    cwd=str(REPO_ROOT),
                    env=_subprocess_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for label in ("first", "second")
            ]
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(stderr, "")
                outputs.append(json.loads(stdout.strip()))

            self.assertEqual(sum(1 for output in outputs if output["ok"]), 1)
            self.assertEqual(sum(1 for output in outputs if not output["ok"]), 1)
            lines = Path(side_effect_path).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

    async def test_sqlite_run_store_consumes_approval_atomically_across_os_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            side_effect_path = str(Path(directory) / "approval-side-effect.txt")
            gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await gate.create_run(
                {
                    "approval_required_targets": ["fs:/tmp/acb-demo"],
                    "approver_tokens": {"security.lead": "approver-secret"},
                },
                run_id="run-approval-process-race",
            )
            action = {"command": "mkdir /tmp/acb-demo", "target_resource": "fs:/tmp/acb-demo"}
            approval = await gate.grant_approval(
                run.run_id,
                action,
                approver="security.lead",
                approver_token="approver-secret",
            )
            worker = Path(directory) / "approval_worker.py"
            worker.write_text(
                textwrap.dedent(
                    """
                    import asyncio
                    import json
                    import sys
                    from pathlib import Path
                    from agent_circuit_breaker.runtime import RuntimeGate, SQLiteRunStore

                    async def main():
                        db_path, run_id, approval_id, side_effect_path, label = sys.argv[1:6]
                        gate = RuntimeGate(store=SQLiteRunStore(db_path))
                        action = {"command": "mkdir /tmp/acb-demo", "target_resource": "fs:/tmp/acb-demo"}
                        def executor(executed):
                            with Path(side_effect_path).open("a", encoding="utf-8") as handle:
                                handle.write(label + "\\n")
                            return label
                        try:
                            result = await gate.execute_approved(
                                run_id,
                                action,
                                approval_id=approval_id,
                                executor=executor,
                            )
                            print(json.dumps({"ok": True, "outcome": result.outcome}))
                        except Exception as exc:
                            print(json.dumps({"ok": False, "error": exc.__class__.__name__}))

                    asyncio.run(main())
                    """
                ),
                encoding="utf-8",
            )

            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        str(worker),
                        db_path,
                        run.run_id,
                        approval.approval_id,
                        side_effect_path,
                        label,
                    ],
                    cwd=str(REPO_ROOT),
                    env=_subprocess_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for label in ("first", "second")
            ]
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(stderr, "")
                outputs.append(json.loads(stdout.strip()))

            self.assertEqual(sum(1 for output in outputs if output["ok"]), 1)
            self.assertEqual(sum(1 for output in outputs if not output["ok"]), 1)
            lines = Path(side_effect_path).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

    async def test_concurrent_suspension_and_execution_have_serialized_ordering(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            first_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            second_gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await first_gate.create_run(run_id="run-suspend-race")
            decision = await first_gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            calls = []

            async def execute():
                return await first_gate.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action) or "executed",
                )

            async def suspend():
                return await second_gate.suspend_run(run.run_id, "race suspension")

            results = await asyncio.gather(execute(), suspend(), return_exceptions=True)
            state = await first_gate.read_run(run.run_id)
            event_types = [event.event_type for event in state.events]

            if calls:
                self.assertIn("started", event_types)
                self.assertIn("outcome", event_types)
                self.assertIn("suspension", event_types)
                self.assertEqual(len(calls), 1)
            else:
                self.assertTrue(any(isinstance(result, ValueError) for result in results))
                self.assertIn("suspension", event_types)
                self.assertNotIn("started", event_types)

    async def test_process_termination_after_started_blocks_restart_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "runtime.sqlite3")
            gate = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            run = await gate.create_run(run_id="run-process-crash")
            decision = await gate.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            worker = Path(directory) / "crash_after_start.py"
            worker.write_text(
                textwrap.dedent(
                    """
                    import asyncio
                    import os
                    import sys
                    from agent_circuit_breaker.runtime import RuntimeGate, SQLiteRunStore

                    async def main():
                        db_path, run_id, authorization_id = sys.argv[1:4]
                        gate = RuntimeGate(store=SQLiteRunStore(db_path))
                        await gate._mark_execution_started(run_id, authorization_id)
                        os._exit(77)

                    asyncio.run(main())
                    """
                ),
                encoding="utf-8",
            )

            process = subprocess.run(
                [sys.executable, str(worker), db_path, run.run_id, decision.authorization_id],
                cwd=str(REPO_ROOT),
                env=_subprocess_env(),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(process.returncode, 77)

            restarted = RuntimeGate(store=SQLiteRunStore(db_path), evaluator=_evaluator)
            next_decision = await restarted.propose_action(run.run_id, {"command": "mkdir /tmp/acb-demo"})
            self.assertFalse(next_decision.authorized)
            self.assertEqual(next_decision.reason, "run has unresolved execution")

            calls = []
            with self.assertRaises(ValueError):
                await restarted.execute_authorized(
                    run.run_id,
                    authorization_id=decision.authorization_id,
                    executor=lambda action: calls.append(action),
                )
            self.assertEqual(calls, [])
