"""Tests for typed decision result primitives."""

import unittest

import agent_circuit_breaker
from agent_circuit_breaker import DecisionResult, EvaluationRequest, Finding, evaluate_action


class TestTypedDecisionResults(unittest.TestCase):
    """Typed decision results should preserve v1.x public behavior."""

    def test_package_exports_typed_result_primitives(self):
        """The package root should expose the typed decision primitives."""
        self.assertIs(agent_circuit_breaker.DecisionResult, DecisionResult)
        self.assertIs(agent_circuit_breaker.EvaluationRequest, EvaluationRequest)
        self.assertIs(agent_circuit_breaker.Finding, Finding)

    def test_block_result_builds_structured_finding(self):
        """A legacy block result should convert into a typed finding."""
        legacy = evaluate_action("rm -rf /")
        request = EvaluationRequest.from_action("rm -rf /")
        typed = DecisionResult.from_legacy_result(legacy, request=request)

        self.assertEqual(typed.verdict, "block")
        self.assertEqual(typed.decision, "BLOCK")
        self.assertEqual(typed.matched_rule, "fs_recursive_delete")
        self.assertTrue(typed.fail_secure)
        self.assertEqual(len(typed.findings), 1)
        self.assertEqual(typed.findings[0].rule_id, "fs_recursive_delete")
        self.assertEqual(typed.findings[0].domain, "filesystem")
        self.assertEqual(typed.findings[0].pack_id, "acb.filesystem.core")
        self.assertEqual(typed.to_legacy_dict(), legacy)

    def test_unknown_result_has_reason_without_finding(self):
        """Unknown results should stay explicit without fabricating a rule finding."""
        legacy = evaluate_action("git status")
        typed = DecisionResult.from_legacy_result(
            legacy,
            request=EvaluationRequest.from_action("git status"),
        )

        self.assertEqual(typed.verdict, "unknown")
        self.assertEqual(typed.decision, "UNKNOWN")
        self.assertFalse(typed.fail_secure)
        self.assertEqual(typed.findings, ())
        self.assertEqual(typed.reason, "No deterministic allow or block rule matched")

    def test_error_result_builds_fail_secure_core_finding(self):
        """Error results should carry fail-secure evidence."""
        legacy = evaluate_action(None)
        typed = DecisionResult.from_legacy_result(
            legacy,
            request=EvaluationRequest.from_action(None),
        )

        self.assertEqual(typed.verdict, "error")
        self.assertEqual(typed.decision, "ERROR")
        self.assertTrue(typed.fail_secure)
        self.assertEqual(typed.findings[0].rule_id, "acb.evaluation_error")
        self.assertEqual(typed.findings[0].domain, "core")
        self.assertEqual(typed.error, "Command must be a string")

    def test_evaluation_id_is_deterministic(self):
        """Equivalent typed decisions should produce the same stable evaluation ID."""
        legacy = evaluate_action("rm -rf /")
        request = EvaluationRequest.from_action("rm -rf /")

        first = DecisionResult.from_legacy_result(legacy, request=request)
        second = DecisionResult.from_legacy_result(legacy, request=request)

        self.assertEqual(first.evaluation_id, second.evaluation_id)
        self.assertEqual(len(first.evaluation_id), 16)

    def test_typed_dict_contains_findings_without_changing_legacy_output(self):
        """Typed output should add findings while legacy output remains unchanged."""
        legacy = evaluate_action("rm -rf /")
        typed = DecisionResult.from_legacy_result(
            legacy,
            request=EvaluationRequest.from_action("rm -rf /"),
        )

        typed_dict = typed.to_dict()

        self.assertIn("findings", typed_dict)
        self.assertEqual(typed_dict["findings"][0]["rule_id"], "fs_recursive_delete")
        self.assertNotIn("findings", typed.to_legacy_dict())


if __name__ == "__main__":
    unittest.main()
