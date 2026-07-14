# v0.9 Release Candidate Plan

The v0.9 milestone freezes the intended v1.0 surface and performs release-readiness cleanup.

## Goals

- Document the compatibility policy for the public API, CLI, rule schema, and decisions.
- Add a release checklist that can be reused for v1.0 and later releases.
- Review README, quickstart, API, rule schema, and security docs for consistency.
- Keep the package dependency-free and local-first.
- Run full regression and smoke verification before tagging.

## Non-Goals

- New major feature areas.
- Breaking public API changes after the release candidate.
- Runtime dependency additions.
- Remote rule loading.
- Sandbox or process isolation.

## Scope Slice 1: Compatibility Policy

Add a compatibility reference covering:

- semantic versioning intent.
- public API stability.
- CLI stability.
- rule schema stability.
- decision contract stability.
- documented pre-1.0 caveats.

## Scope Slice 2: Release Checklist

Add a repeatable release checklist covering:

- tests.
- whitespace checks.
- CLI smoke tests.
- Python API smoke tests.
- docs checks.
- tag and GitHub Release publishing.

## Scope Slice 3: Readiness Tests

Add tests that assert compatibility and checklist docs exist and are linked from the docs index.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- Compatibility policy is documented.
- Release checklist is documented.
- Docs index links the release-candidate docs.
- Release notes describe the RC scope.

## Release Target

Recommended prerelease tag:

```text
v0.9.0-rc.1
```
