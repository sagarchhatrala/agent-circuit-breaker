# Branch Protection

Recommended protection for `main`:

- Require pull requests before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Require the CI matrix checks:
  - `test-python-3.11`
  - `test-python-3.12`
- Require conversation resolution before merging.
- Restrict force pushes.
- Restrict branch deletion.

If the project has at least two trusted maintainers with write access, require
at least one approving review and dismiss stale pull request approvals when new
commits are pushed. Do not require approvals when there is no real reviewer for
the solo maintainer; that creates an impossible release gate rather than a
security control.

These settings should be configured in GitHub repository settings after the CI workflow has run at least once.

As of the v1.6.7 OpenSSF readiness pass, the GitHub API showed these controls
enabled for `main`: pull requests required, strict `test-python-3.11` and
`test-python-3.12` status checks, conversation resolution, administrator
enforcement, force-push restriction, and deletion restriction. Re-check these
settings before claiming OpenSSF evidence after
repository ownership or branch ruleset changes.
