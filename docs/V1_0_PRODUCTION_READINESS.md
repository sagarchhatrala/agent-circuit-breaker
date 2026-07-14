# v1.0 Production Readiness Plan

The v1.0 milestone marks the first stable release of Agent Circuit Breaker.

## Goals

- Stabilize the public Python API, CLI, decision contract, and rule schema version 1.
- Update package metadata and docs from release-candidate status to stable status.
- Confirm compatibility, security, integration, and release-process docs are present.
- Run full regression, smoke, and release-readiness checks.
- Publish a non-prerelease GitHub Release.

## Non-Goals

- New feature expansion after the release candidate.
- Breaking public API changes.
- Runtime dependency additions.
- Remote rule loading.
- Sandbox or process isolation.

## Scope Slice 1: Stable Docs

Update docs to clearly identify v1.0 as stable and point users to:

- public API reference.
- rule schema reference.
- security model.
- threat model.
- integration guide.
- compatibility policy.
- release checklist.

## Scope Slice 2: Stable Metadata

Update:

- package version to `1.0.0`.
- setup classifier to production/stable.
- release notes for `v1.0.0`.

## Scope Slice 3: Final Verification

Run:

- full unit test suite.
- whitespace check.
- focused API, adversarial, and docs tests.
- CLI smoke checks.
- Python API smoke checks.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- CLI smoke checks return expected exit codes.
- Python API smoke checks return expected values.
- `main` is pushed.
- `v1.0.0` tag is pushed.
- GitHub Release is published as a stable release, not a prerelease.

## Release Target

```text
v1.0.0
```
