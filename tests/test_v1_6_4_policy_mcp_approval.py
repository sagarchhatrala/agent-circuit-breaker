"""Tests for v1.6.4 policy, MCP, approval, and trajectory hardening."""

import json
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.api import evaluate_action, evaluate_trajectory
from agent_circuit_breaker.approvals import ApprovalStore
from agent_circuit_breaker.policy import load_policy
from agent_circuit_breaker_mcp.proxy import MCPRunGuard, inspect_jsonrpc_message


class TestRemotePolicySecurity(unittest.TestCase):
    def test_http_remote_policy_rejected_by_default(self):
        with self.assertRaises(ValueError) as context:
            load_policy("http://example.test/policy.json")

        self.assertIn("insecure remote policy transport is disabled", str(context.exception))

    def test_http_remote_policy_requires_explicit_opt_in(self):
        import agent_circuit_breaker.policy as policy_module

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, _limit):
                return b'{"mode":"strict"}'

        original = policy_module.urlopen
        policy_module.urlopen = lambda *_args, **_kwargs: FakeResponse()
        try:
            policy = load_policy(
                "http://example.test/policy.json",
                allow_insecure_remote_policy=True,
            )
        finally:
            policy_module.urlopen = original

        self.assertEqual(policy["mode"], "strict")
        self.assertEqual(policy["source_type"], "remote")


class TestMCPConsistency(unittest.TestCase):
    def test_non_tool_call_is_not_security_relevant(self):
        inspection = inspect_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

        self.assertTrue(inspection["allowed"])
        self.assertEqual(inspection["coverage"]["status"], "not_applicable")
        self.assertFalse(inspection["coverage"]["security_relevant"])

    def test_blocked_tool_call_is_attempted_but_not_forwarded(self):
        guard = MCPRunGuard()
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {"command": 'bash -c "rm -rf /"'}},
        }

        inspection = inspect_jsonrpc_message(message, run_guard=guard)

        self.assertFalse(inspection["allowed"])
        self.assertEqual(inspection["trajectory_state"]["attempted_count"], 1)
        self.assertEqual(inspection["trajectory_state"]["forwarded_count"], 0)
        self.assertIsNotNone(inspection["response"])

    def test_allowed_tool_call_is_marked_forwarded(self):
        guard = MCPRunGuard()
        message = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"arguments": {"command": "mkdir /tmp/acb"}},
        }

        inspection = inspect_jsonrpc_message(message, run_guard=guard)

        self.assertTrue(inspection["allowed"])
        self.assertEqual(inspection["trajectory_state"]["attempted_count"], 1)
        self.assertEqual(inspection["trajectory_state"]["forwarded_count"], 1)
        self.assertEqual(inspection["trajectory_coverage"]["status"], "complete")


class TestApprovalRevalidation(unittest.TestCase):
    def test_approved_record_validates_against_same_fresh_result(self):
        result = evaluate_action("rm -rf /")

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ApprovalStore(temp_dir, ttl_seconds=60)
            record = store.create(result)
            store.decide(record["id"], "approved")
            validation = store.is_valid_for_result(record["id"], result)

        self.assertTrue(validation["is_valid"])

    def test_approved_record_rejects_changed_action_context(self):
        first = evaluate_action("rm -rf /")
        second = evaluate_action('bash -c "rm -rf /"')

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ApprovalStore(temp_dir, ttl_seconds=60)
            record = store.create(first)
            store.decide(record["id"], "approved")
            validation = store.is_valid_for_result(record["id"], second)

        self.assertFalse(validation["is_valid"])
        self.assertIn("does not match", validation["reason"])

    def test_expired_approval_is_not_valid_for_result(self):
        result = evaluate_action("rm -rf /")

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ApprovalStore(temp_dir, ttl_seconds=60)
            record = store.create(result)
            store.decide(record["id"], "approved")
            path = Path(temp_dir) / f"{record['id']}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["expires_at"] = "2000-01-01T00:00:00+00:00"
            path.write_text(json.dumps(payload), encoding="utf-8")
            validation = store.is_valid_for_result(record["id"], result)

        self.assertFalse(validation["is_valid"])
        self.assertEqual(validation["reason"], "approval expired")


class TestTrajectoryFingerprint(unittest.TestCase):
    def test_run_fingerprint_is_stable_and_additive(self):
        first = evaluate_trajectory(["mkdir /tmp/acb"], contract={"allowed_scopes": ["tmp/"]})
        second = evaluate_trajectory(["mkdir /tmp/acb"], contract={"allowed_scopes": ["tmp/"]})

        self.assertEqual(first["run_fingerprint"], second["run_fingerprint"])
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual(first["actions"][0]["canonical_decision"]["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
