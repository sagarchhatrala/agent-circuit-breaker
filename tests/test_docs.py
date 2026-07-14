"""Documentation regression tests."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"


class TestSecurityDocs(unittest.TestCase):
    """Test security documentation exists and is linked."""

    def test_security_docs_exist(self):
        """The v0.8 security documentation files should exist."""
        for file_name in ("SECURITY_MODEL.md", "THREAT_MODEL.md", "INTEGRATION_GUIDE.md"):
            with self.subTest(file_name=file_name):
                self.assertTrue((DOCS_DIR / file_name).is_file())

    def test_docs_index_links_security_docs(self):
        """The docs index should link the security documentation set."""
        docs_index = (DOCS_DIR / "README.md").read_text(encoding="utf-8")

        self.assertIn("[SECURITY_MODEL.md](SECURITY_MODEL.md)", docs_index)
        self.assertIn("[THREAT_MODEL.md](THREAT_MODEL.md)", docs_index)
        self.assertIn("[INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)", docs_index)

    def test_security_model_states_non_sandbox_boundary(self):
        """The security model must clearly state the sandbox non-goal."""
        security_model = (DOCS_DIR / "SECURITY_MODEL.md").read_text(encoding="utf-8")

        self.assertIn("It is not a sandbox.", security_model)
        self.assertIn("execute only on `ALLOW`", security_model)
        self.assertIn("Built-in rules are evaluated before custom rules.", security_model)

    def test_threat_model_lists_out_of_scope_bypass(self):
        """The threat model should document bypass risk."""
        threat_model = (DOCS_DIR / "THREAT_MODEL.md").read_text(encoding="utf-8")

        self.assertIn("callers that ignore the result and execute anyway", threat_model)
        self.assertIn("actions executed through bypass paths that skip evaluation", threat_model)

    def test_integration_guide_defines_unknown_policy(self):
        """The integration guide should define UNKNOWN handling."""
        integration_guide = (DOCS_DIR / "INTEGRATION_GUIDE.md").read_text(encoding="utf-8")

        self.assertIn("`UNKNOWN` does not mean safe.", integration_guide)
        self.assertIn("continue only on exit code `0`", integration_guide)


if __name__ == "__main__":
    unittest.main()
