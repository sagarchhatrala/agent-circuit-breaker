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


class TestReleaseReadinessDocs(unittest.TestCase):
    """Test release-readiness documentation exists and is linked."""

    def test_release_readiness_docs_exist(self):
        """The v0.9 release-readiness docs should exist."""
        for file_name in (
            "COMPATIBILITY.md",
            "RELEASE_CHECKLIST.md",
            "PUBLISHING.md",
            "BRANCH_PROTECTION.md",
            "V1_0_PRODUCTION_READINESS.md",
        ):
            with self.subTest(file_name=file_name):
                self.assertTrue((DOCS_DIR / file_name).is_file())

    def test_docs_index_links_release_readiness_docs(self):
        """The docs index should link release-readiness docs."""
        docs_index = (DOCS_DIR / "README.md").read_text(encoding="utf-8")

        self.assertIn("[COMPATIBILITY.md](COMPATIBILITY.md)", docs_index)
        self.assertIn("[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)", docs_index)
        self.assertIn("[PUBLISHING.md](PUBLISHING.md)", docs_index)
        self.assertIn("[BRANCH_PROTECTION.md](BRANCH_PROTECTION.md)", docs_index)
        self.assertIn("[V1_0_PRODUCTION_READINESS.md](V1_0_PRODUCTION_READINESS.md)", docs_index)

    def test_compatibility_policy_defines_stable_contracts(self):
        """Compatibility docs should define stable API, CLI, and schema contracts."""
        compatibility = (DOCS_DIR / "COMPATIBILITY.md").read_text(encoding="utf-8")

        self.assertIn("`evaluate_action(action, rule_file_path=None)`", compatibility)
        self.assertIn("The stable CLI commands are:", compatibility)
        self.assertIn("The current external JSON rule schema version is `1`.", compatibility)
        self.assertIn("Fail-closed behavior", compatibility)

    def test_release_checklist_includes_required_gates(self):
        """Release checklist should include tests, smokes, tags, and GitHub Release."""
        checklist = (DOCS_DIR / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")

        self.assertIn("python -m unittest discover", checklist)
        self.assertIn("git diff --check", checklist)
        self.assertIn("python -m twine check dist/*", checklist)
        self.assertIn("Push `main`.", checklist)
        self.assertIn("Create the GitHub Release", checklist)

    def test_publishing_docs_define_testpypi_first(self):
        """Publishing docs should require TestPyPI before PyPI."""
        publishing = (DOCS_DIR / "PUBLISHING.md").read_text(encoding="utf-8")

        self.assertIn("Use TestPyPI before publishing to PyPI.", publishing)
        self.assertIn("python -m build", publishing)
        self.assertIn("python -m twine check dist/*", publishing)

    def test_production_readiness_defines_stable_release_gate(self):
        """Production-readiness docs should define stable release gates."""
        readiness = (DOCS_DIR / "V1_0_PRODUCTION_READINESS.md").read_text(encoding="utf-8")

        self.assertIn("public Python API, CLI, decision contract, and rule schema version 1", readiness)
        self.assertIn("GitHub Release is published as a stable release, not a prerelease", readiness)


class TestRepositoryHygiene(unittest.TestCase):
    """Test repository hygiene files exist."""

    def test_ci_workflow_exists(self):
        """The repository should have a Python CI workflow."""
        workflow = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        content = workflow.read_text(encoding="utf-8")

        self.assertIn("python -m unittest discover", content)
        self.assertIn("git diff --check", content)
        self.assertIn('"3.11"', content)
        self.assertIn('"3.12"', content)

    def test_issue_and_pr_templates_exist(self):
        """The repository should have issue and PR templates."""
        self.assertTrue((REPO_ROOT / ".github" / "pull_request_template.md").is_file())
        self.assertTrue((REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.md").is_file())
        self.assertTrue((REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.md").is_file())

    def test_security_and_changelog_exist(self):
        """The repository should have root security and changelog files."""
        security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

        self.assertIn("Reporting A Vulnerability", security)
        self.assertIn("## [1.0.0] - 2026-07-15", changelog)


if __name__ == "__main__":
    unittest.main()
