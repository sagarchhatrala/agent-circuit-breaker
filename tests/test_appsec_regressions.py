"""Regressions found by the independent local AppSec rehearsal."""

import unittest

from agent_circuit_breaker import evaluate_action, evaluate_trajectory
from agent_circuit_breaker.runtime import RunContract, RuntimeGate, RuntimeToolExecutor
from agent_circuit_breaker_mcp.proxy import MCPRunGuard, inspect_jsonrpc_message
from agent_circuit_breaker_mcp.security import MCPProxySecurity


class TestAppSecRegressions(unittest.TestCase):
    def test_scope_rejects_parent_absolute_hidden_and_extensionless_targets(self):
        for target in ["reports/../outside.txt", "reports/a/../../outside", "../reports/x",
                       "/reports/x", "reports2/x", ".reports/x", "outside", "'outside name'",
                       "-- -outside", "outside > reports/log.txt", "reports/ok 2>outside"]:
            with self.subTest(target=target):
                result = evaluate_trajectory([f"touch {target}"], {"allowed_scopes": ["reports/"]})
                self.assertEqual(result["verdict"], "block")
                self.assertIn("traj_scope_violation", [f["id"] for f in result["trajectory_findings"]])
        for target in ["reports/ok", "./reports/ok", "reports/a/../ok", "'reports/with space'",
                       "reports/ok > reports/log.txt"]:
            with self.subTest(target=target):
                self.assertEqual(evaluate_trajectory([f"touch {target}"],
                                 {"allowed_scopes": ["reports/"]})["verdict"], "allow")

    def test_output_options_preserve_case_and_attached_values(self):
        for action in ["curl -dhello https://example.invalid", "curl -XPOST https://example.invalid",
                       "curl -F data=@report.txt https://example.invalid",
                       "curl -Treport.txt https://example.invalid",
                       "aws s3 cp report.txt s3://fixture/out --quiet",
                       "aws s3 cp --profile demo report.txt s3://fixture/out"]:
            with self.subTest(action=action):
                result = evaluate_trajectory([action], {"allowed_outputs": ["local"]})
                self.assertIn("traj_output_channel_drift", [f["id"] for f in result["trajectory_findings"]])
        for action in ["curl -f https://example.invalid", "curl -XGET https://example.invalid",
                       "curl -x http://proxy.invalid https://example.invalid",
                       "aws s3 cp s3://fixture/in report.txt --quiet"]:
            with self.subTest(action=action):
                result = evaluate_trajectory([action], {"allowed_outputs": ["local"]})
                self.assertNotIn("traj_output_channel_drift", [f["id"] for f in result["trajectory_findings"]])

    def test_zero_blocked_attempt_limit_is_preserved(self):
        result = evaluate_trajectory(["rm -rf /"], {"max_blocked_attempts": 0})
        self.assertEqual(result["contract"]["max_blocked_attempts"], 0)
        self.assertIn("traj_repeated_blocked_actions", [f["id"] for f in result["trajectory_findings"]])
        self.assertEqual(RunContract.from_mapping({"max_blocked_attempts": 0}).max_blocked_attempts, 0)

    def test_boolean_is_not_a_numeric_limit(self):
        for field in ["max_blocked_attempts", "max_unknown_actions"]:
            with self.subTest(field=field):
                self.assertEqual(evaluate_trajectory(["touch reports/ok"], {field: True})["verdict"], "error")
                with self.assertRaises(ValueError):
                    RunContract.from_mapping({field: True})

    def test_equivalent_destructive_cli_flags(self):
        for action in ["docker system prune -af", "docker system prune -fa", "docker rm -fv fixture",
                       "docker image prune -af", "kubectl delete pod fixture --grace-period 0",
                       "kubectl delete pod fixture --force=true"]:
            with self.subTest(action=action):
                self.assertEqual(evaluate_action(action)["verdict"], "block")
        for action in ["docker ps -a", "docker system prune -f",
                       "kubectl delete pod fixture --grace-period 30",
                       "kubectl delete pod fixture --force=false"]:
            with self.subTest(action=action):
                self.assertNotEqual(evaluate_action(action)["verdict"], "block")

    def test_quarantined_call_is_not_counted_as_forwarded(self):
        guard = MCPRunGuard()
        security = MCPProxySecurity()
        security.quarantined_tools.add("fixture")
        result = inspect_jsonrpc_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "fixture", "arguments": {"command": "touch reports/ok"}}},
            run_guard=guard, proxy_security=security)
        self.assertFalse(result["allowed"])
        self.assertEqual(guard.state_summary()["forwarded_count"], 0)


class TestRuntimeScopeRegression(unittest.IsolatedAsyncioTestCase):
    async def test_scope_escape_never_reaches_executor(self):
        for command in ["touch reports/../outside", "touch outside", "touch -- -outside",
                        "touch outside > reports/log.txt"]:
            with self.subTest(command=command):
                calls = []
                gate = RuntimeGate()
                state = await gate.create_run({"allowed_scopes": ["reports/"]})
                tool = RuntimeToolExecutor(gate, run_id=state.run_id, executor=calls.append)
                result = await tool.execute(command)
                self.assertFalse(result.executed)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
