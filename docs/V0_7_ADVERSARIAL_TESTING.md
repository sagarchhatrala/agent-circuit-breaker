# v0.7 Adversarial Test Alpha Plan

The v0.7 milestone increases confidence by exercising hostile, malformed, and edge-case inputs across the existing safety surface.

Status: implemented for `v0.7.0-alpha.1`.

## Goals

- Add adversarial tests for command parsing, SQL parsing, rule loading, CLI behavior, and public API behavior.
- Verify fail-closed handling for malformed and invalid inputs.
- Preserve deterministic output for repeated evaluations.
- Fix any implementation gaps discovered by the tests.
- Keep the runtime dependency-free.

## Non-Goals

- Complete shell grammar support.
- Complete SQL dialect support.
- Fuzzing infrastructure.
- Sandbox or process execution.
- Network rule loading.

## Scope Slice 1: Edge-Case Inputs

Add tests for:

- empty and whitespace-only actions.
- non-string API inputs.
- multiline command strings.
- shell operators and mixed-risk command chains.
- comments and strings in SQL-like input.
- suspicious but unsupported rule features.

## Scope Slice 2: Fail-Closed Rule Handling

Add tests that invalid custom rule files:

- do not allow the action.
- return deterministic errors.
- do not build executable rules.

## Scope Slice 3: Determinism

Add repeated-evaluation tests for representative risky and malformed inputs.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- All new adversarial tests pass.
- Any discovered bug is fixed before release.
- Release notes list the tested adversarial surface.

## Release Target

Recommended prerelease tag:

```text
v0.7.0-alpha.1
```
