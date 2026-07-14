# v0.5 Rule Schema Hardening Plan

The v0.5 milestone hardens the v0.4 external JSON rule format. The goal is to make the supported schema explicit, test fixture-backed, and stable enough to document as a pre-1.0 contract.

Status: implemented for `v0.5.0-alpha.1`.

## Goals

- Document the full rule schema in one dedicated reference.
- Expose schema metadata from the package without adding dependencies.
- Add valid and invalid fixture rule files.
- Test every fixture file through the existing loader.
- Clarify matcher semantics for `contains`, `equals`, and `prefix`.
- Preserve the no-arbitrary-code security property of custom rules.

## Non-Goals

- JSON Schema dependency.
- YAML support.
- Regex support.
- Remote rule fetching.
- Rule signing.
- Dynamic Python matchers.

## Scope Slice 1: Schema Reference

Add a dedicated schema reference document that defines:

- top-level fields
- required rule fields
- optional rule fields
- matcher object shape
- supported matcher types
- rejection behavior
- examples

## Scope Slice 2: Schema Metadata API

Expose small deterministic schema metadata from the rule loader module:

- schema version
- allowed severities
- allowed responses
- allowed matcher types
- required and optional fields

This should be data only, not a runtime dependency on a schema library.

## Scope Slice 3: Fixtures

Add fixture files:

- valid custom rule
- valid multi-rule file
- invalid missing rules
- invalid duplicate IDs
- invalid matcher type
- invalid metadata

## Scope Slice 4: Fixture Tests

Add tests that load every fixture through `RuleFileLoader`.

Valid fixtures should pass.
Invalid fixtures should fail with deterministic errors.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- All rule schema fixtures are validated by tests.
- Documentation and fixture behavior match.
- No runtime dependencies are added.

## Release Target

Recommended prerelease tag:

```text
v0.5.0-alpha.1
```
