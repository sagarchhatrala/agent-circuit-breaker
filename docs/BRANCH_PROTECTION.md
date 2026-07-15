# Branch Protection

Recommended protection for `main`:

- Require pull requests before merging.
- Require at least one approving review.
- Dismiss stale pull request approvals when new commits are pushed.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Require the CI matrix checks:
  - `test-python-3.11`
  - `test-python-3.12`
- Require conversation resolution before merging.
- Restrict force pushes.
- Restrict branch deletion.

These settings should be configured in GitHub repository settings after the CI workflow has run at least once.
