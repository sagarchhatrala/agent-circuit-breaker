# v1.1 Compatible Additions Plan

The v1.1 milestone should add compatible safety coverage without changing the v1.0 public contracts.

Status: completed in `v1.1.0`.

## Goals

- Add more built-in command rules for common high-risk agent actions.
- Document the JSON result contract in more detail.
- Explore an explicit allowlist pattern for trusted workflows.
- Add integration-focused examples and tests.
- Preserve the public Python API, CLI, decision contract, and rule schema version 1.

## Non-Goals

- Breaking public API changes.
- Breaking CLI changes.
- Rule schema version 2.
- Runtime dependencies.
- Sandbox or process isolation.

## Candidate Scope

### Command Rule Expansion

Candidate rules:

- package publish commands without explicit release context.
- destructive Docker commands.
- cloud resource deletion command shapes.
- forceful Kubernetes deletion command shapes.

Each rule should be small, documented, and covered by tests.

### JSON Output Contract

Document stable JSON fields for:

- top-level evaluation result.
- rule details.
- operation analysis.
- command analysis.
- SQL analysis.
- custom rule summaries.

### Allowlist Pattern

Explore an explicit, local allowlist pattern for known-safe workflows.

Constraints:

- no override of built-in block rules.
- no arbitrary code execution.
- no remote fetching.
- deterministic validation.

### Integration Tests

Add tests that run examples and validate installed-package behavior where practical.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- New rules have focused tests.
- Docs describe only supported behavior.
- Compatibility policy remains true.

## Completed Scope

- Package publish commands without explicit release context.
- Destructive Docker command shapes.
- Cloud resource deletion command shapes.
- Forceful Kubernetes deletion command shapes.
- Detailed JSON output contract documentation.
- Local allowlist pattern documentation and example.
- Integration-focused example regression coverage.

## Release Target

Recommended tag:

```text
v1.1.0
```
