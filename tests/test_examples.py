"""Example regression tests."""

import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"


class TestExamples(unittest.TestCase):
    """Test example files and basic execution."""

    def test_example_files_exist(self):
        """Expected examples should be present."""
        for file_name in (
            "README.md",
            "cli_gate.py",
            "python_api_integration.py",
            "custom_rules.json",
            "custom_rules_example.py",
            "allowlist_rules.json",
            "allowlist_example.py",
        ):
            with self.subTest(file_name=file_name):
                self.assertTrue((EXAMPLES_DIR / file_name).is_file())

    def test_python_api_example_runs(self):
        """The Python API example should run successfully."""
        completed = subprocess.run(
            [sys.executable, str(EXAMPLES_DIR / "python_api_integration.py")],
            check=False,
            text=True,
            capture_output=True,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("'rm -rf /': block", completed.stdout)

    def test_custom_rules_example_runs(self):
        """The custom rules example should run successfully."""
        completed = subprocess.run(
            [sys.executable, str(EXAMPLES_DIR / "custom_rules_example.py")],
            check=False,
            text=True,
            capture_output=True,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("custom_rule_verdict=block", completed.stdout)

    def test_allowlist_example_runs(self):
        """The allowlist example should run successfully."""
        completed = subprocess.run(
            [sys.executable, str(EXAMPLES_DIR / "allowlist_example.py")],
            check=False,
            text=True,
            capture_output=True,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("allowlist_verdict=allow", completed.stdout)
        self.assertIn("builtin_block_rule=fs_recursive_delete", completed.stdout)


if __name__ == "__main__":
    unittest.main()
