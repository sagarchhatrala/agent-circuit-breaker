"""Tests for local production-readiness checks."""

import asyncio
import json
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from agent_circuit_breaker.audit import AUDIT_HMAC_ENV, AuditLog
from agent_circuit_breaker.cli import CircuitBreakerCLI, main
from agent_circuit_breaker.production import evaluate_production_readiness
from agent_circuit_breaker.runtime import RuntimeGate, SQLiteRunStore
from agent_circuit_breaker.validation import run_safe_environment_validation


class TestProductionReadiness(unittest.TestCase):
    def setUp(self):
        self._old_hmac = os.environ.get(AUDIT_HMAC_ENV)
        os.environ.pop(AUDIT_HMAC_ENV, None)

    def tearDown(self):
        if self._old_hmac is None:
            os.environ.pop(AUDIT_HMAC_ENV, None)
        else:
            os.environ[AUDIT_HMAC_ENV] = self._old_hmac

    def test_missing_runtime_store_fails_local_runtime_target(self):
        result = asyncio.run(evaluate_production_readiness())

        self.assertFalse(result["is_production_ready"])
        self.assertIn("runtime_store_configured", {check["id"] for check in result["checks"]})

    def test_healthy_runtime_store_and_signed_audit_pass_local_runtime_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            store_path = root / "runtime.sqlite3"
            audit_path = root / "audit.jsonl"
            os.environ[AUDIT_HMAC_ENV] = "production-check-test-key-32-bytes"

            async def create_store():
                gate = RuntimeGate(store=SQLiteRunStore(str(store_path)))
                await gate.create_run(run_id="run-prod-check")

            asyncio.run(create_store())
            AuditLog(str(audit_path)).append({"source": "test", "verdict": "allow"})

            result = asyncio.run(
                evaluate_production_readiness(
                    runtime_store_path=str(store_path),
                    audit_log_path=str(audit_path),
                    require_audit_hmac=True,
                )
            )

        self.assertTrue(result["is_production_ready"], json.dumps(result, indent=2))
        checks = {check["id"]: check for check in result["checks"]}
        self.assertEqual(checks["runtime_store_health"]["status"], "pass")
        self.assertEqual(checks["audit_hmac"]["status"], "pass")

    def test_require_audit_hmac_fails_without_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "runtime.sqlite3"

            async def create_store():
                gate = RuntimeGate(store=SQLiteRunStore(str(store_path)))
                await gate.create_run(run_id="run-prod-check")

            asyncio.run(create_store())

            result = asyncio.run(
                evaluate_production_readiness(
                    runtime_store_path=str(store_path),
                    require_audit_hmac=True,
                )
            )

        self.assertFalse(result["is_production_ready"])
        checks = {check["id"]: check for check in result["checks"]}
        self.assertEqual(checks["audit_hmac"]["status"], "fail")

    def test_missing_runtime_store_path_fails_without_creating_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "missing.sqlite3"

            result = asyncio.run(
                evaluate_production_readiness(
                    runtime_store_path=str(store_path),
                )
            )

            self.assertFalse(result["is_production_ready"])
            self.assertFalse(store_path.exists())
            checks = {check["id"]: check for check in result["checks"]}
            self.assertEqual(checks["runtime_store_health"]["status"], "fail")

    def test_general_containment_target_fails_with_explicit_blockers(self):
        result = asyncio.run(evaluate_production_readiness(target="general-containment"))

        self.assertFalse(result["is_production_ready"])
        check_ids = {check["id"] for check in result["checks"]}
        self.assertIn("os_sandbox", check_ids)
        self.assertIn("unmediated_tool_bypass", check_ids)

    def test_cli_production_check_outputs_json_and_returns_nonzero_for_missing_store(self):
        stdout = StringIO()
        with patch.object(
            os.sys,
            "argv",
            ["agent-circuit-breaker", "--format", "json", "production-check"],
        ), patch("sys.stdout", stdout):
            exit_code = main()

        self.assertEqual(exit_code, 1)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["is_production_ready"])

    def test_cli_production_check_returns_zero_for_healthy_local_runtime(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            store_path = root / "runtime.sqlite3"
            audit_path = root / "audit.jsonl"
            os.environ[AUDIT_HMAC_ENV] = "production-check-test-key-32-bytes"

            async def create_store():
                gate = RuntimeGate(store=SQLiteRunStore(str(store_path)))
                await gate.create_run(run_id="run-prod-check-cli")

            asyncio.run(create_store())
            AuditLog(str(audit_path)).append({"source": "test", "verdict": "allow"})

            cli = CircuitBreakerCLI(output_format="json")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = cli.run_production_check_mode(
                    target="local-runtime",
                    runtime_store_path=str(store_path),
                    audit_log_path=str(audit_path),
                    require_audit_hmac=True,
                )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["is_production_ready"])

    def test_safe_environment_validation_passes_with_synthetic_side_effects(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = asyncio.run(run_safe_environment_validation(temp_dir))
            side_effects_exists = Path(result["side_effects"]).exists()
            checkpoint_exists = Path(result["checkpoint"]).exists()

        self.assertEqual(result["failures"], [], json.dumps(result, indent=2))
        self.assertTrue(side_effects_exists)
        self.assertTrue(checkpoint_exists)

    def test_cli_safe_validate_returns_zero_and_writes_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with patch.object(
                os.sys,
                "argv",
                ["agent-circuit-breaker", "--format", "json", "safe-validate", "--validation-root", temp_dir],
            ), patch("sys.stdout", stdout):
                exit_code = main()

            payload = json.loads(stdout.getvalue())
            root_exists = Path(payload["root"]).exists()

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["failures"], [])
        self.assertTrue(root_exists)

    def test_safe_environment_validation_refuses_existing_managed_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence = Path(temp_dir) / "evidence"
            evidence.mkdir()
            existing = evidence / "allowed.txt"
            existing.write_text("existing\n", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                asyncio.run(run_safe_environment_validation(temp_dir))

            self.assertEqual(existing.read_text(encoding="utf-8"), "existing\n")


if __name__ == "__main__":
    unittest.main()
