# Compatibility Policy

This policy describes the intended stability contract for Agent Circuit Breaker.

The project is currently at release-candidate maturity. The v1.0 release is intended to stabilize the public API, CLI contract, rule schema version, and decision contract described here.

## Versioning

After v1.0, the project intends to use semantic versioning:

- Patch releases fix bugs without intentional behavior breaks.
- Minor releases add compatible features.
- Major releases may include breaking changes.

Before v1.0, release candidates may still receive compatibility fixes, but breaking changes should be avoided unless they correct a safety issue.

## Public Python API

The public Python API is:

- `evaluate_action(action, rule_file_path=None)`
- `validate_rule_file(path)`
- `rule_schema_metadata()`
- `Decision`
- `Rule`
- `Engine`

The stable result shape for `evaluate_action` includes:

- `command`
- `verdict`
- `decision`
- `matched_rule`
- `rule_details`
- `operation_analysis`
- `command_analysis`
- `sql_analysis`
- `error`

When a custom rule file is provided, results may also include:

- `custom_rules`

New fields may be added in minor releases. Existing fields should not be removed or renamed without a major release.

## CLI Contract

The stable CLI commands are:

- `circuit-breaker check <action>`
- `circuit-breaker validate-rules <path>`
- `circuit-breaker -c <action>`

The stable output modes are:

- text output.
- JSON output through `--format json`.
- JSON output through `--json`.

The stable exit codes are:

- `0`: allowed.
- `1`: blocked or error.
- `2`: unknown.

## Decision Contract

The stable decision values are:

- `ALLOW`
- `BLOCK`
- `ERROR`
- `UNKNOWN`

The stable verdict values are:

- `allow`
- `block`
- `error`
- `unknown`

`UNKNOWN` does not mean safe. Integrations should treat it as review-required unless they have a separate allowlist.

## Rule Schema

The current external JSON rule schema version is `1`.

Stable schema version 1 includes:

- top-level `version`.
- top-level `rules`.
- rule fields `id`, `title`, `severity`, `response`, `matcher`, and optional `metadata`.
- matcher fields `type` and `value`.
- matcher types `contains`, `equals`, and `prefix`.

Unsupported features remain unsupported unless a future schema version adds them:

- YAML.
- regex matchers.
- remote rule fetching.
- rule signing.
- arbitrary Python matchers.

## Behavior Compatibility

Built-in rule coverage may expand in minor releases. That means an action that was previously `UNKNOWN` may become `BLOCK`.

An action that is currently `BLOCK` for a built-in catastrophic pattern should not become `ALLOW` without a major release and explicit migration guidance.

Fail-closed behavior for malformed input, invalid rule files, and evaluator errors is part of the compatibility contract.
