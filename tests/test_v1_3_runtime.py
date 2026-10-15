"""Tests for v1.3 safety runtime features."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_circuit_breaker.approvals import ApprovalStore
from agent_circuit_breaker.audit import AuditLog, audit_event_from_result
from agent_circuit_breaker.cli import CircuitBreakerCLI
from agent_circuit_breaker.explain import explain_result
from agent_circuit_breaker.policy import load_policy
from agent_circuit_breaker.rules.loader import RuleDefinitionBuilder, RuleDefinitionValidator
from agent_circuit_breaker.sarif import scan_to_sarif
from agent_circuit_breaker_mcp.proxy import inspect_payload


def rule_definition(matcher, response="block"):
    """Build a valid external rule definition."""
    return {
        "version": 1,
        "rules": [
            {
                "id": "custom_v13_rule",
                "title": "Custom v1.3 rule",
                "severity": "HIGH",
                "response": response,
                "matcher": matcher,
            }
        ],
    }


class TestV13PolicyModes(unittest.TestCase):
    """Profile and policy mode tests."""

    def test_team_profile_routes_block_to_pending_approval(self):
        cli = CircuitBreakerCLI()

        result = cli.evaluate_command("git push --force origin main", profile_name="team")

        self.assertEqual(result["verdict"], "pending_approval")
        self.assertEqual(result["decision"], "PENDING_APPROVAL")
        self.assertEqual(result["policy"]["profile"], "team")
        self.assertEqual(result["policy"]["original_verdict"], "block")

    def test_default_behavior_still_blocks(self):
        cli = CircuitBreakerCLI()

        result = cli.evaluate_command("git push --force origin main")

        self.assertEqual(result["verdict"], "block")
        self.assertIsNone(result["policy"])

    def test_policy_file_loads_profile_and_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text(json.dumps({"profile": "team", "mode": "approval"}), encoding="utf-8")

            policy = load_policy(str(path))

        self.assertEqual(policy["profile"], "team")
        self.assertEqual(policy["mode"], "approval")


class TestV13RuleMatchers(unittest.TestCase):
    """Extended rule matcher tests."""

    def test_regex_matcher_builds_and_matches(self):
        definition = rule_definition({"type": "regex", "value": r"deploy\s+production"})

        validation = RuleDefinitionValidator.validate(definition)
        build = RuleDefinitionBuilder.build_rules(definition)

        self.assertTrue(validation["is_valid"])
        self.assertTrue(build["is_valid"])
        self.assertTrue(build["rules"][0].matcher("please deploy production"))

    def test_composite_matcher_builds_and_matches(self):
        definition = rule_definition(
            {
                "type": "all_of",
                "matchers": [
                    {"type": "contains", "value": "deploy"},
                    {
                        "type": "not",
                        "matcher": {"type": "contains", "value": "staging"},
                    },
                ],
            }
        )

        build = RuleDefinitionBuilder.build_rules(definition)

        self.assertTrue(build["is_valid"])
        self.assertTrue(build["rules"][0].matcher("deploy production"))
        self.assertFalse(build["rules"][0].matcher("deploy staging"))


class TestV13ExplainScanAudit(unittest.TestCase):
    """Explain, scan, SARIF, and audit tests."""

    def test_explain_returns_suggestions(self):
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command("git push --force origin main")

        explanation = explain_result(result)

        self.assertEqual(explanation["matched_rule"], "cmd_git_force_push")
        self.assertTrue(explanation["suggestions"])

    def test_scan_finds_blocked_line_and_sarif_converts(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "script.sh"
            path.write_text('echo ok\nrm -rf "/"\n', encoding="utf-8")

            scan_result = cli.run_scan_mode([str(path)])

            self.assertEqual(scan_result, 1)

            data = __import__("agent_circuit_breaker.scan", fromlist=["scan_paths"]).scan_paths(
                [str(path)],
                cli.evaluate_command,
            )
            sarif = scan_to_sarif(data)

        self.assertEqual(data["summary"]["blocked"], 1)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_audit_log_hash_chain_verifies(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "audit.jsonl"
            audit_log = AuditLog(str(log_path))
            result = cli.evaluate_command("ls -la")
            audit_log.append(audit_event_from_result(result))
            audit_log.append(audit_event_from_result(result))

            verification = audit_log.verify()

        self.assertTrue(verification["is_valid"])
        self.assertEqual(verification["entries"], 2)
        self.assertFalse(verification["signature_checked"])

    def test_audit_checkpoint_detects_tail_deletion(self):
        cli = CircuitBreakerCLI()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "audit.jsonl"
            audit_log = AuditLog(str(log_path))
            result = cli.evaluate_command("ls -la")
            audit_log.append(audit_event_from_result(result))
            audit_log.append(audit_event_from_result(result))
            checkpoint = audit_log.checkpoint()

            entries = log_path.read_text(encoding="utf-8").splitlines()
            log_path.write_text(entries[0] + "\n", encoding="utf-8")

            normal_verification = audit_log.verify()
            checkpoint_verification = audit_log.verify_checkpoint(checkpoint)

        self.assertTrue(normal_verification["is_valid"])
        self.assertFalse(checkpoint_verification["is_valid"])
        self.assertEqual(checkpoint_verification["error"], "audit log is shorter than checkpoint")

    def test_audit_checkpoint_hmac_rejects_wrong_key(self):
        cli = CircuitBreakerCLI()
        old_key = os.environ.get("ACB_AUDIT_HMAC_KEY")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_path = Path(temp_dir) / "audit.jsonl"
                audit_log = AuditLog(str(log_path))
                result = cli.evaluate_command("ls -la")

                os.environ["ACB_AUDIT_HMAC_KEY"] = "test-audit-key-32-bytes-local"
                audit_log.append(audit_event_from_result(result))
                checkpoint = audit_log.checkpoint()

                os.environ["ACB_AUDIT_HMAC_KEY"] = "wrong-audit-key-32-bytes-local"
                verification = audit_log.verify_checkpoint(checkpoint)

            self.assertFalse(verification["is_valid"])
            self.assertEqual(verification["error"], "checkpoint_signature mismatch")
        finally:
            if old_key is None:
                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
            else:
                os.environ["ACB_AUDIT_HMAC_KEY"] = old_key

    def test_audit_log_hmac_signature_detects_modified_event(self):
        cli = CircuitBreakerCLI()
        old_key = os.environ.get("ACB_AUDIT_HMAC_KEY")
        os.environ["ACB_AUDIT_HMAC_KEY"] = "test-audit-key-32-bytes-local"
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_path = Path(temp_dir) / "audit.jsonl"
                audit_log = AuditLog(str(log_path))
                result = cli.evaluate_command("ls -la")
                audit_log.append(audit_event_from_result(result))
                verification = audit_log.verify()
                self.assertTrue(verification["is_valid"])
                self.assertTrue(verification["signature_checked"])

                entry = json.loads(log_path.read_text(encoding="utf-8").strip())
                entry["event"]["decision"] = "BLOCK"
                log_path.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

                tampered = audit_log.verify()
                self.assertFalse(tampered["is_valid"])
                self.assertIn(tampered["error"], {"entry_hash mismatch", "entry_signature mismatch"})
        finally:
            if old_key is None:
                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
            else:
                os.environ["ACB_AUDIT_HMAC_KEY"] = old_key

    def test_audit_log_hmac_rejects_missing_or_wrong_verification_key(self):
        cli = CircuitBreakerCLI()
        old_key = os.environ.get("ACB_AUDIT_HMAC_KEY")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_path = Path(temp_dir) / "audit.jsonl"
                audit_log = AuditLog(str(log_path))
                result = cli.evaluate_command("ls -la")

                os.environ["ACB_AUDIT_HMAC_KEY"] = "test-audit-key-32-bytes-local"
                audit_log.append(audit_event_from_result(result))

                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
                missing_key = audit_log.verify()
                self.assertFalse(missing_key["is_valid"])
                self.assertEqual(missing_key["error"], "entry_signature present but verification key unavailable")

                os.environ["ACB_AUDIT_HMAC_KEY"] = "wrong-audit-key-32-bytes-local"
                wrong_key = audit_log.verify()
                self.assertFalse(wrong_key["is_valid"])
                self.assertEqual(wrong_key["error"], "entry_signature mismatch")
        finally:
            if old_key is None:
                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
            else:
                os.environ["ACB_AUDIT_HMAC_KEY"] = old_key

    def test_audit_log_hmac_rejects_legacy_unsigned_log_when_key_required(self):
        old_key = os.environ.get("ACB_AUDIT_HMAC_KEY")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_path = Path(temp_dir) / "audit.jsonl"
                entry = {
                    "schema_version": 1,
                    "timestamp": "2026-10-15T00:00:00+00:00",
                    "previous_hash": None,
                    "event": {"decision": "ALLOW"},
                }
                entry["entry_hash"] = AuditLog._hash_entry(entry)
                log_path.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
                audit_log = AuditLog(str(log_path))

                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
                unsigned = audit_log.verify()
                self.assertTrue(unsigned["is_valid"])
                self.assertFalse(unsigned["signature_checked"])

                os.environ["ACB_AUDIT_HMAC_KEY"] = "test-audit-key-32-bytes-local"
                required = audit_log.verify()
                self.assertFalse(required["is_valid"])
                self.assertEqual(required["error"], "unsupported signature algorithm")
        finally:
            if old_key is None:
                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
            else:
                os.environ["ACB_AUDIT_HMAC_KEY"] = old_key

    def test_audit_log_hmac_rejects_empty_or_short_key(self):
        old_key = os.environ.get("ACB_AUDIT_HMAC_KEY")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                audit_log = AuditLog(str(Path(temp_dir) / "audit.jsonl"))
                os.environ["ACB_AUDIT_HMAC_KEY"] = ""
                with self.assertRaisesRegex(ValueError, "set but empty"):
                    audit_log.append({"event": "test"})

                os.environ["ACB_AUDIT_HMAC_KEY"] = "short"
                with self.assertRaisesRegex(ValueError, "at least"):
                    audit_log.verify()
        finally:
            if old_key is None:
                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
            else:
                os.environ["ACB_AUDIT_HMAC_KEY"] = old_key

    def test_audit_log_hmac_rejects_signed_record_with_unsupported_algorithm(self):
        cli = CircuitBreakerCLI()
        old_key = os.environ.get("ACB_AUDIT_HMAC_KEY")
        os.environ["ACB_AUDIT_HMAC_KEY"] = "test-audit-key-32-bytes-local"
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_path = Path(temp_dir) / "audit.jsonl"
                audit_log = AuditLog(str(log_path))
                result = cli.evaluate_command("ls -la")
                audit_log.append(audit_event_from_result(result))

                entry = json.loads(log_path.read_text(encoding="utf-8").strip())
                entry["integrity"]["signature_algorithm"] = "none"
                entry["entry_hash"] = AuditLog._hash_entry(entry)
                entry["entry_signature"] = AuditLog._sign_entry(entry, os.environ["ACB_AUDIT_HMAC_KEY"])
                log_path.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

                verification = audit_log.verify()
                self.assertFalse(verification["is_valid"])
                self.assertEqual(verification["error"], "unsupported signature algorithm")
        finally:
            if old_key is None:
                os.environ.pop("ACB_AUDIT_HMAC_KEY", None)
            else:
                os.environ["ACB_AUDIT_HMAC_KEY"] = old_key


class TestV13ApprovalsAndMCP(unittest.TestCase):
    """Approval queue and MCP scaffold tests."""

    def test_approval_store_decides_record(self):
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command("rm -rf /", profile_name="team")
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ApprovalStore(temp_dir)
            record = store.create(result)
            decided = store.decide(record["id"], "approved")

        self.assertEqual(decided["status"], "approved")

    def test_approval_store_preserves_decision_on_duplicate_create(self):
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command("rm -rf /var/lib/data", profile_name="team")
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ApprovalStore(temp_dir)
            record = store.create(result)
            denied = store.decide(record["id"], "denied")
            recreated = store.create(result)

        self.assertEqual(recreated["status"], "denied")
        self.assertEqual(recreated["decided_at"], denied["decided_at"])

    def test_mcp_proxy_scaffold_blocks_command_field(self):
        result = inspect_payload({"command": "rm -rf /"})

        self.assertFalse(result["allowed"])
        self.assertEqual(result["checks"][0]["result"]["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
