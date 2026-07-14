# v0.8 Security Documentation Alpha Plan

The v0.8 milestone documents how Agent Circuit Breaker should and should not be trusted by real integrations.

## Goals

- Document the security model and trust boundaries.
- Document the threat model and supported mitigations.
- Add an integration guide for CLI and Python API callers.
- Make non-goals explicit so users do not mistake the project for a sandbox.
- Add lightweight documentation regression tests.

## Non-Goals

- New runtime enforcement features.
- Complete shell or SQL grammar support.
- Process isolation.
- Remote policy distribution.
- Telemetry or cloud integrations.

## Scope Slice 1: Security Model

Add a security model reference covering:

- deterministic evaluation.
- fail-closed behavior.
- rule ordering.
- local-first operation.
- explicit non-goals.

## Scope Slice 2: Threat Model

Add a threat model reference covering:

- accidental destructive commands.
- malformed model output.
- destructive SQL.
- invalid custom policies.
- out-of-scope attacker capabilities.

## Scope Slice 3: Integration Guide

Add integration guidance for:

- CLI gate usage.
- Python API usage.
- exit code handling.
- `UNKNOWN` handling.
- custom rule validation.

## Scope Slice 4: Doc Regression Tests

Add tests that assert key security docs exist and are linked from the docs index.

## Acceptance Criteria

- `python -m unittest discover` passes.
- `git diff --check` has no whitespace errors.
- Security docs describe only currently supported behavior.
- Docs clearly state that this project is not a sandbox.
- Release notes list the documentation surface.

## Release Target

Recommended prerelease tag:

```text
v0.8.0-alpha.1
```
