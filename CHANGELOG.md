# Changelog

All notable changes to Agent Circuit Breaker are tracked here.

This project follows semantic versioning after `v1.0.0`.

## [1.0.1] - 2026-07-15

### Added

- `pyproject.toml` build-system declaration.
- Publishing guide for TestPyPI and PyPI.
- Release checklist publishing steps.

### Changed

- Package metadata now includes README long description and project URLs.
- Published wheel excludes the test suite package.

## [1.0.0] - 2026-07-15

### Added

- CI and release hygiene:
  - GitHub Actions workflow for Python 3.11 and 3.12.
  - PR and issue templates.
  - Security policy.
  - Branch protection documentation.
- Stable public Python API.
- Stable CLI commands and exit codes.
- External JSON rule schema version 1.
- Filesystem, command, and SQL safety inspectors.
- Built-in rules for recursive deletion, dangerous filesystem paths, git force pushes, recursive chmod 777, remote scripts piped to shells, destructive SQL, and unqualified SQL mutations.
- External rule validation and custom rule enforcement.
- Adversarial and documentation regression tests.
- Security model, threat model, integration guide, compatibility policy, and release checklist.

### Changed

- Package metadata is marked production/stable.

### Verification

- `python -m unittest discover`
- `git diff --check`
- CLI smoke checks
- Python API smoke checks
