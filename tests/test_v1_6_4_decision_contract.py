"""Tests for v1.6.4 canonical decision contract."""

import json
import unittest
from pathlib import Path

from agent_circuit_breaker.api import evaluate_action
from agent_circuit_breaker.audit import audit_event_from_result
from agent_circuit_breaker.decision import from_legacy_result


class TestCanonicalDecisionContract(unittest.TestCase):
    def test_legacy_allow_maps_to_executable_canonical_decision(self):
        result = evaluate_action("mkdir /tmp/acb")
        decision = from_legacy_result(result)

        self.assertEqual(decision.decision, "ALLOW")
        self.assertTrue(decision.executable)
        self.assertFalse(decision.stop_state)
        self.assertTrue(decision.to_summary()["evidence"]["coverage"]["mandatory_complete"])

    def test_legacy_unknown_maps_to_stop_state(self):
        result = evaluate_action("git status")
        decision = from_legacy_result(result)

        self.assertEqual(decision.decision, "UNKNOWN")
        self.assertFalse(decision.executable)
        self.assertTrue(decision.stop_state)

    def test_audit_event_includes_canonical_decision_summary(self):
        result = evaluate_action("rm -rf /")
        event = audit_event_from_result(result)

        self.assertEqual(event["canonical_decision"]["decision"], "BLOCK")
        self.assertEqual(event["canonical_decision"]["matched_rule"], "fs_recursive_delete")


class TestSecurityCorpus(unittest.TestCase):
    def test_api_matches_security_corpus(self):
        corpus_path = Path(__file__).parent / "fixtures" / "security_corpus.json"
        cases = json.loads(corpus_path.read_text(encoding="utf-8"))

        for case in cases:
            with self.subTest(case=case["id"]):
                result = evaluate_action(case["action"])
                self.assertEqual(result["decision"], case["expected_decision"])
                self.assertEqual(result["verdict"], case["expected_verdict"])
                self.assertEqual(result["matched_rule"], case["expected_matched_rule"])
                canonical = from_legacy_result(result)
                self.assertEqual(canonical.executable, case["expected_decision"] == "ALLOW")


if __name__ == "__main__":
    unittest.main()
