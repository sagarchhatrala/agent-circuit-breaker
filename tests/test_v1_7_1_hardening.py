"""Security regressions proven against real local state and executors."""

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_circuit_breaker import evaluate_action, evaluate_trajectory
from agent_circuit_breaker.audit import AuditLog
from agent_circuit_breaker.ledger import RunLedger
from agent_circuit_breaker_mcp.proxy import MCPRunGuard, inspect_arguments, inspect_jsonrpc_message


class TestSQL171(unittest.TestCase):
    def test_actual_bulk_deletes_are_blocked(self):
        for sql in ["WITH x AS (SELECT 1) DELETE FROM demo",
                    "WITH x(v) AS (SELECT 1), y AS (SELECT 2) DELETE FROM demo",
                    "DELETE FROM demo WHERE 2>1", "DELETE FROM demo WHERE id=1 OR 2>=1",
                    "DELETE FROM demo WHERE (1=1 AND NOT 2<1)",
                    "DELETE FROM demo RETURNING 'where'"]:
            with self.subTest(sql=sql), sqlite3.connect(":memory:") as db:
                db.executescript("CREATE TABLE demo(id INTEGER); INSERT INTO demo VALUES(1),(2),(3);")
                result = evaluate_action(sql)
                self.assertEqual(result["verdict"], "block")
                db.executescript(sql)
                self.assertEqual(db.execute("SELECT count(*) FROM demo").fetchone()[0], 0)

    def test_selective_conjunct_is_not_a_tautology(self):
        for sql in ["DELETE FROM demo WHERE id=1 AND 1=1",
                    "DELETE FROM demo WHERE (id=1 AND (2>1))",
                    "DELETE FROM demo WHERE 1=1 AND id=1",
                    "UPDATE demo SET active=1 WHERE active=0 AND id=1"]:
            with self.subTest(sql=sql):
                self.assertEqual(evaluate_action(sql)["verdict"], "unknown")

    def test_literals_and_subquery_where_do_not_change_scope(self):
        self.assertEqual(evaluate_action("UPDATE demo SET value='where'")["verdict"], "block")
        self.assertEqual(evaluate_action("UPDATE demo SET value=(SELECT 1 WHERE 1=1)")["verdict"], "block")
        self.assertEqual(evaluate_action("DELETE FROM demo WHERE value='Bob''s account'")["verdict"], "unknown")
        self.assertEqual(evaluate_action("WITH gone AS (DELETE FROM demo RETURNING id) SELECT * FROM gone")["verdict"], "block")


class TestMCP171(unittest.TestCase):
    def message(self, name="status", arguments=None):
        return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": {} if arguments is None else arguments}}

    def test_uninspectable_arguments_fail_closed_even_with_allow_unknown(self):
        for arguments in [{}, {"id": 7}, {"all": True}, {"items": []}]:
            with self.subTest(arguments=arguments):
                self.assertFalse(inspect_arguments(arguments, allow_unknown=True)["allowed"])
                self.assertFalse(inspect_jsonrpc_message(self.message(arguments=arguments))["allowed"])

    def test_empty_tool_grant_is_exact_and_keeps_prior_trajectory_denial(self):
        self.assertTrue(inspect_jsonrpc_message(self.message(), trusted_empty_tools=["status"])["allowed"])
        self.assertFalse(inspect_jsonrpc_message(self.message("delete_all"), trusted_empty_tools=["status"])["allowed"])
        self.assertFalse(inspect_jsonrpc_message(self.message(arguments={"id": 7}), trusted_empty_tools=["status"])["allowed"])
        guard = MCPRunGuard()
        inspect_jsonrpc_message(self.message(arguments={"command": "rm -rf /"}), run_guard=guard)
        self.assertFalse(inspect_jsonrpc_message(self.message(), run_guard=guard, trusted_empty_tools=["status"])["allowed"])
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "rules.json"
            invalid.write_text("{")
            self.assertFalse(inspect_jsonrpc_message(self.message(), rules=str(invalid),
                                                     trusted_empty_tools=["status"])["allowed"])


class TestLogs171(unittest.TestCase):
    def test_signed_ledger_forgery_replay_and_truncation(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ACB_AUDIT_HMAC_KEY": "synthetic-fixture-key-171"}):
            path = Path(directory) / "ledger.jsonl"
            ledger = RunLedger(str(path))
            result = evaluate_trajectory(["touch harmless.txt"])
            ledger.append(result)
            ledger.append(result)
            original = path.read_text()
            checkpoint = ledger.checkpoint()
            self.assertTrue(ledger.verify(require_signature=True)["is_valid"])
            self.assertTrue(ledger.verify_checkpoint(checkpoint)["is_valid"])
            self.assertEqual(ledger.replay(result["run_id"])["verdict"], "allow")
            entries = [json.loads(line) for line in original.splitlines()]
            entries[0]["result"]["verdict"] = "forged"
            previous = None
            for entry in entries:
                entry["previous_hash"] = previous
                entry["entry_hash"] = RunLedger._hash_entry(entry)
                previous = entry["entry_hash"]
            path.write_text("\n".join(json.dumps(entry) for entry in entries) + "\n")
            self.assertFalse(ledger.verify()["is_valid"])
            with self.assertRaises(ValueError):
                ledger.replay(result["run_id"])
            with self.assertRaises(ValueError):
                ledger.append(result)
            path.write_text(original.splitlines()[0] + "\n")
            self.assertTrue(ledger.verify()["is_valid"])
            self.assertFalse(ledger.verify_checkpoint(checkpoint)["is_valid"])
            forged = copy.deepcopy(checkpoint)
            forged.pop("checkpoint_signature")
            forged["integrity"]["signature_algorithm"] = None
            forged["entry_count"] = 0
            forged["last_entry_hash"] = None
            forged["checkpoint_hash"] = AuditLog._hash_checkpoint(forged)
            self.assertFalse(ledger.verify_checkpoint(forged)["is_valid"])
            with patch.dict(os.environ, {"ACB_AUDIT_HMAC_KEY": "another-synthetic-key-171"}):
                self.assertFalse(ledger.verify()["is_valid"])

    def test_unsigned_legacy_requires_explicit_authentication_upgrade(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            ledger = RunLedger(str(Path(directory) / "ledger"))
            ledger.append(evaluate_trajectory(["touch harmless.txt"]))
            self.assertTrue(ledger.verify()["is_valid"])
            self.assertFalse(ledger.verify(require_signature=True)["is_valid"])

    def test_real_concurrent_process_writers_keep_valid_chains(self):
        code = """import sys
from agent_circuit_breaker.audit import AuditLog
from agent_circuit_breaker.ledger import RunLedger
for i in range(12):
    AuditLog(sys.argv[1]).append({'index':i})
    RunLedger(sys.argv[2]).append({'run_id':str(i), 'verdict':'allow', 'actions':[]})
"""
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ACB_AUDIT_HMAC_KEY": "synthetic-concurrent-key-171"}):
            paths = [str(Path(directory) / name) for name in ("audit", "ledger")]
            def writer(_):
                return subprocess.run([sys.executable, "-c", code, *paths], capture_output=True, text=True, timeout=30)
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(writer, range(4)))
            for result in results:
                self.assertEqual(result.returncode, 0, result.stderr)
            for log in (AuditLog(paths[0]), RunLedger(paths[1])):
                self.assertTrue(log.verify()["is_valid"])
                self.assertEqual(log.verify()["entries"], 48)

    def test_malformed_log_verification_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken"
            path.write_text('{"partial":')
            self.assertFalse(RunLedger(str(path)).verify()["is_valid"])


class TestTarget171(unittest.TestCase):
    def test_complex_forbidden_target_uses_boundaries(self):
        for command, blocked in [("cat /srv/prod/file", True), ("cat /srv/prod", True),
                                  ("cat /srv/prod-backup/file", False), ("cat /srv/production/file", False)]:
            with self.subTest(command=command):
                result = evaluate_trajectory([command], {"forbidden_targets": ["/srv/prod"]})
                self.assertEqual(any(f["id"] == "traj_forbidden_target" for f in result["trajectory_findings"]), blocked)


if __name__ == "__main__":
    unittest.main()
