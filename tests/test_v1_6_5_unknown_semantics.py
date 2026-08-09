"""Tests for v1.6.5 UNKNOWN execution consistency."""

import unittest

from agent_circuit_breaker import AgentCircuitBreaker
from agent_circuit_breaker_mcp.proxy import MCPRunGuard, inspect_jsonrpc_message


class TestMCPUnknownSemantics(unittest.TestCase):
    def test_mcp_blocks_unknown_tool_call_by_default(self):
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {"command": "git status"}},
        }

        inspection = inspect_jsonrpc_message(message, run_guard=MCPRunGuard())

        self.assertFalse(inspection["allowed"])
        self.assertEqual(inspection["checks"][0]["result"]["verdict"], "unknown")
        self.assertEqual(inspection["trajectory_state"]["forwarded_count"], 0)
        self.assertIsNotNone(inspection["response"])

    def test_mcp_unknown_forwarding_requires_explicit_opt_in(self):
        message = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"arguments": {"command": "git status"}},
        }

        inspection = inspect_jsonrpc_message(
            message,
            run_guard=MCPRunGuard(allow_unknown=True),
            allow_unknown=True,
        )

        self.assertTrue(inspection["allowed"])
        self.assertEqual(inspection["trajectory_state"]["forwarded_count"], 1)


class TestPipelineUnknownSemantics(unittest.TestCase):
    def test_default_pipeline_blocks_core_unknown(self):
        result = AgentCircuitBreaker().evaluate_tool_call_sync(
            tool_name="shell",
            tool_args={"command": "git status"},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, "unknown")
        self.assertIn("legacy_action_guard", result.validation["applicable_unknowns"])

    def test_pipeline_core_unknown_allow_requires_explicit_opt_in(self):
        result = AgentCircuitBreaker(allow_core_unknown=True).evaluate_tool_call_sync(
            tool_name="shell",
            tool_args={"command": "git status"},
        )

        self.assertTrue(result.allowed)

    def test_interpreter_wrapper_unknown_is_not_allowed_by_default_pipeline(self):
        result = AgentCircuitBreaker().evaluate_tool_call_sync(
            tool_name="shell",
            tool_args={"command": "python -c \"import os; os.system('rm -rf /')\""},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, "unknown")


if __name__ == "__main__":
    unittest.main()
