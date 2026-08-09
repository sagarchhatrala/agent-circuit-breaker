# Compatibility Policy

This policy describes the intended stability contract for Agent Circuit Breaker.

The project is stable at v1.x. The public API, CLI contract, rule schema version, and decision contract described here are additive compatibility contracts.

## Versioning

After v1.0, the project intends to use semantic versioning:

- Patch releases fix bugs without intentional behavior breaks.
- Minor releases add compatible features.
- Major releases may include breaking changes.

Security hardening can add fail-closed validation in any compatible release when needed to preserve the safety contract.

## Public Python API

The public Python API is:

- `evaluate_action(action, rule_file_path=None)`
- `evaluate_trajectory(actions, contract=None, rule_file_path=None)`
- `validate_rule_file(path)`
- `rule_schema_metadata()`
- `Decision`
- `Rule`
- `Engine`
- `EvaluationRequest`
- `DecisionResult`
- `Finding`
- pipeline SDK DTOs and `AgentCircuitBreaker`

The stable result shape for `evaluate_action` includes:

- `command`
- `verdict`
- `decision`
- `matched_rule`
- `rule_details`
- `operation_analysis`
- `command_analysis`
- `sql_analysis`
- `risk_score`
- `error`

When a custom rule file is provided, results may also include:

- `custom_rules`

New fields may be added in minor releases. Existing fields should not be removed or renamed without a major release.

Typed decision primitives added in v1.6.0 are additive. They may be used by
advanced integrations, but `evaluate_action(...)` continues to return the stable
dictionary shape above.

## CLI Contract

The stable CLI commands are:

- `agent-circuit-breaker check <action>`
- `agent-circuit-breaker validate-rules <path>`
- `agent-circuit-breaker -c <action>`
- `agent-circuit-breaker explain <action>`
- `agent-circuit-breaker scan <path...>`
- `agent-circuit-breaker trajectory <run.json>`
- `agent-circuit-breaker rules test <path>`
- `agent-circuit-breaker schemas [name]`
- `agent-circuit-breaker catalog`

The published console entry points are:

- `agent-circuit-breaker`
- `agent-circuit-breaker-mcp-proxy`

The stable output modes are:

- text output.
- JSON output through `--format json`.
- JSON output through `--json`.

The stable exit codes are:

- `0`: allowed.
- `1`: blocked or error.
- `2`: unknown.
- `3`: pending approval.

## Decision Contract

The stable decision values are:

- `ALLOW`
- `BLOCK`
- `ERROR`
- `UNKNOWN`
- `PENDING_APPROVAL`

The stable verdict values are:

- `allow`
- `block`
- `error`
- `unknown`
- `pending_approval`

`UNKNOWN` does not mean safe. Integrations should treat it as review-required unless they have a separate allowlist.

## Rule Schema

The current external JSON rule schema version is `1`.

Stable schema version 1 includes:

- top-level `version`.
- top-level `rules`.
- optional top-level `signature`.
- rule fields `id`, `title`, `severity`, `response`, `matcher`, and optional `metadata`.
- responses `allow`, `block`, and `approval`.
- matcher fields `type`, `value`, `matchers`, and `matcher`.
- matcher types `contains`, `equals`, `prefix`, `regex`, `all_of`, `any_of`, and `not`.

Unsupported features remain unsupported unless a future schema version adds them:

- YAML.
- remote rule fetching.
- arbitrary Python matchers.

Signed rule and policy JSON support currently requires authenticity when `--require-signature` is used. `hmac-sha256` signatures are accepted; checksum-only `sha256` documents are not accepted as required signatures.

## Policy Source Trust

Explicit `--policy` paths, `ACB_POLICY`, and caller-selected remote policy URLs are
treated as caller-selected sources. Auto-discovered repository policy is treated as
repository-sourced policy.

Repository-sourced policy may strengthen enforcement by default. It cannot add
allow rules, select `advisory` mode, select the `solo` profile, or explicitly set
`strict` to `false` unless the caller passes `--trust-repository-policy`.

## Resource Limits

Policy, rule, trajectory, approval, and MCP inputs are subject to explicit resource limits. Oversized inputs fail closed with validation errors or error verdicts. Limit values may become stricter in compatible v1.x releases when required for security.

## Behavior Compatibility

Built-in rule coverage may expand in compatible releases. That means an action that was previously `UNKNOWN` may become `BLOCK`.

An action that is currently `BLOCK` for a built-in catastrophic pattern should not become `ALLOW` without a major release and explicit migration guidance.

Fail-closed behavior for malformed input, invalid rule files, oversized inputs, signature failures, and evaluator errors is part of the compatibility contract.
