# v0.6 Public API Alpha Plan

The v0.6 milestone exposes a small Python API for callers that want deterministic safety checks without shelling out to the CLI.

Status: implemented for `v0.6.0-alpha.1`.

## Goals

- Provide package-level functions for action evaluation and rule file validation.
- Reuse the existing CLI evaluation path so behavior stays consistent.
- Support optional external JSON rule files through the API.
- Return deterministic dictionaries that are easy to serialize or log.
- Document the alpha API contract before v1.0 stabilization.

## Non-Goals

- Async API.
- Network rule loading.
- Process execution or sandboxing.
- Plugin systems.
- Breaking changes to the CLI.

## Scope Slice 1: Public Module

Add `agent_circuit_breaker.api` with:

- `evaluate_action(action, rule_file_path=None)`
- `validate_rule_file(path)`
- `rule_schema_metadata()`

## Scope Slice 2: Package Exports

Expose the public API from `agent_circuit_breaker.__init__` so integrations can import directly from the package.

## Scope Slice 3: API Tests

Add tests for:

- built-in block results.
- known safe allow results.
- unknown results.
- custom rule-file enforcement.
- invalid rule-file fail-closed behavior.
- rule file validation.
- schema metadata.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- Public API behavior matches CLI behavior for supported cases.
- Invalid custom rule files return `error` and do not evaluate the action as allowed.
- API docs describe only supported behavior.

## Release Target

Recommended prerelease tag:

```text
v0.6.0-alpha.1
```
