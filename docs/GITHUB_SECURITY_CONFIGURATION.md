# GitHub Security Configuration

This document separates repository-controlled security settings from manual
GitHub account or repository settings. Do not mark a manual item as satisfied
unless it has been verified in GitHub.

## Verified Repository Settings

Verified through the GitHub API on 2026-08-24:

- Repository visibility: public.
- Default branch: `main`.
- Secret scanning: enabled.
- Secret scanning push protection: enabled.
- Dependabot security updates: enabled.
- Private vulnerability reporting: enabled.
- Actions default workflow token permissions: read-only.
- Fork pull request workflow approval: first-time contributors.
- `main` branch protection requires pull requests, one approving review,
  strict status checks for `test-python-3.11` and `test-python-3.12`, and
  conversation resolution.
- `main` branch protection is enforced for administrators.
- `main` branch protection disallows force pushes and branch deletion.

## Repository Implemented

- Workflows request least-privilege permissions at workflow or job scope.
- Release publishing uses GitHub OIDC trusted publishing and does not store
  PyPI API tokens in the repository.
- Dependabot is configured for GitHub Actions and Python packaging metadata.
- `SECURITY.md` provides security contacts and private reporting guidance.
- `CONTRIBUTING.md` documents the contribution and review process.
- `.gitignore` excludes local build output, virtual environments, caches, and
  local environment files.

## Manual GitHub Action Required

These settings depend on GitHub account, organization, or repository controls
that cannot be safely inferred from files alone:

- Confirm multi-factor authentication or passkeys are enforced for every
  account with repository admin, maintainer, or push access.
- Keep collaborator permissions least-privilege. Add contributors with the
  lowest role that supports their work, and grant admin access only when
  necessary.
- Keep branch protection/rulesets enabled for `main`. Require pull requests,
  at least one approving review, required status checks, conversation
  resolution, enforce protection for administrators, and disable force pushes
  and deletion.
- Keep repository Actions permissions defaulted to read-only.
- Keep private vulnerability reporting, secret scanning, push protection, and
  Dependabot security updates enabled.
- Grant the GitHub token used for release engineering the `workflow` scope, then
  pin third-party Actions to immutable commit SHAs and keep SARIF upload out of
  pull-request jobs that evaluate untrusted code.
- Review GitHub Environments for `testpypi` and `pypi`. Production publishing
  should require maintainer approval if more maintainers are added.

## What Not To Do

- Do not add CODEOWNERS unless the listed owners are real active reviewers.
- Do not publish from pull request workflows.
- Do not add long-lived PyPI tokens or cloud credentials to repository secrets
  when OIDC trusted publishing is available.
- Do not bypass branch protection for routine releases.
