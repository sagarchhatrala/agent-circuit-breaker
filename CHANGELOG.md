# Changelog

All notable changes to Agent Circuit Breaker are tracked here.

This project follows semantic versioning after `v1.0.0`.

## [1.1.2] - 2026-07-16

### Fixed

- Blocked renamed shell fork-bomb variants such as `f(){ f|f& };f` and `bomb(){ bomb|bomb& };bomb`.
- Blocked `find -delete` rooted at protected path children and trailing-slash variants such as `find /etc/ -delete` and `find /home/someuser -delete`.
- Blocked AWS S3 bucket removal through `aws s3 rb`.
- Blocked comma-separated and grouped symbolic recursive world-writable chmod modes such as `u+rwx,g+rwx,o+rwx` and `ugo+rwx`.

## [1.1.1] - 2026-07-16

### Fixed

- Replaced substring-based recursive delete matching with tokenized filesystem operation analysis.
- Fixed false positives for non-delete commands containing `rm`, such as `transform -rf`.
- Blocked split and long-form recursive delete flags such as `rm -r -f /etc` and `rm --recursive --force /etc`.
- Blocked unquoted system path deletion targets such as `rm /etc/passwd`.
- Blocked symbolic recursive world-writable chmod such as `chmod -R a+rwx /tmp`.
- Blocked AWS S3 recursive removal through `aws s3 rm --recursive`.
- Blocked simple SQL tautological bulk mutations such as `WHERE 1=1`.
- Fixed SQL block comments between keywords, such as `DROP/**/TABLE`.
- Added catastrophic command coverage for disk overwrite/format, root-level `find -delete`, and shell fork bomb patterns.

## [1.1.0] - 2026-07-15

### Added

- Built-in command rules for package publish commands without explicit release context.
- Built-in command rules for destructive Docker command shapes.
- Built-in command rules for cloud resource deletion command shapes.
- Built-in command rules for forceful Kubernetes deletion command shapes.
- Detailed JSON output contract documentation.
- Local allowlist pattern documentation and examples.

### Changed

- Known dangerous command rules can block before unrelated heuristic SQL parser errors.

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
