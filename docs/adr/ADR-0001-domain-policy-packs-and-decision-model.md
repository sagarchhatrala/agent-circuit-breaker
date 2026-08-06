# ADR-0001: Domain Policy Packs And Decision Model

Status: proposed

Date: 2026-08-06

## Context

Agent Circuit Breaker has grown from a small deterministic engine into a local-first
safety runtime for shell commands, filesystem operations, SQL text, MCP tool-call
arguments, trajectory checks, and pipeline guards.

The next architecture step should preserve the existing philosophy:

- fail secure when safety cannot be established.
- keep the trusted core small and deterministic.
- make policy decisions explainable and auditable.
- keep built-in safety controls ahead of local allow rules.
- avoid turning the project into an observability platform, sandbox, SIEM, EDR, or
  agent analytics product.

The current structure is still workable, but continued growth will put pressure on
three areas:

1. built-in rules can become hard to organize as more domains are added.
2. decision outputs need a stable evidence model for SDKs, audit, SARIF, policy
   tests, and enterprise integrations.
3. policy loading needs an explicit trust model for system, user, repository, and
   signed policy sources.

## Decision

The next major architecture slice will introduce three compatible concepts:

1. **Domain policy packs**
2. **Typed decision findings**
3. **Policy source trust levels**

These concepts should be additive and should not break the v1.x public API. Existing
callers should continue to receive the current dictionary-shaped results while the
new internal model becomes the canonical source.

## Domain Policy Packs

A policy pack groups related rules, metadata, schemas, tests, and documentation for
one safety domain.

Initial first-party domains:

- `shell`
- `filesystem`
- `sql`
- `mcp`
- `pipeline`
- `network`
- `package`

Likely later domains:

- `http`
- `cloud`
- `kubernetes`
- `terraform`
- `docker`
- `ci`

Each pack should have:

- stable pack ID.
- stable rule IDs.
- domain name.
- rule metadata.
- severity.
- deterministic matcher or guard entrypoint.
- audit-safe reason text.
- examples.
- regression fixtures.
- generated catalog output.

Built-in packs remain trusted first-party code. External policy packs should prefer
declarative JSON rules. Executable Python plugins remain an explicit trusted-code
extension mechanism, not the default policy distribution format.

### Pack ID Rules

First-party pack IDs use the reserved `acb.` namespace.

Examples:

- `acb.shell.core`
- `acb.filesystem.core`
- `acb.sql.core`
- `acb.mcp.core`
- `acb.pipeline.core`

External packs must not override first-party pack IDs or first-party rule IDs.

## Typed Decision Findings

The canonical evaluation result should include a stable list of findings.

Proposed internal model:

```text
EvaluationRequest
  request_id
  action_type
  subject
  arguments
  actor
  workspace
  metadata

DecisionResult
  decision
  reason
  findings
  policy_source
  evaluation_id
  elapsed_ms
  fail_secure

Finding
  rule_id
  pack_id
  domain
  severity
  message
  evidence
  location
  recommendation
```

The public API can expose this gradually:

- preserve existing result dictionaries.
- add compatible fields where possible.
- provide a stable conversion helper for callers that want typed results.
- keep JSON output deterministic.

Every block should have at least:

- `decision = BLOCK`
- stable `rule_id`
- stable `reason`
- domain or pack source
- audit-safe evidence

Every error should clearly state whether the runtime failed secure.

## Policy Source Trust Levels

Policy source trust must be explicit. A policy file loaded from an untrusted
repository must not silently weaken a user, system, enterprise, or signed policy.

Proposed trust order, strongest first:

1. signed enterprise policy.
2. system policy.
3. user policy.
4. explicitly supplied local policy.
5. repository policy.
6. environment defaults.

Repository policy should be allowed to strengthen enforcement by default, but not
weaken inherited controls unless the caller explicitly marks the repository policy as
trusted.

Examples of strengthening:

- adding block rules.
- requiring strict mode.
- lowering approval thresholds.
- adding narrower allowed scopes.

Examples of weakening:

- disabling built-in packs.
- disabling strict mode inherited from a stronger policy.
- adding allow rules that bypass built-in blocks.
- reducing audit requirements.
- replacing signed policy with unsigned local policy.

## Testing Standard

Every new first-party pack should include:

- allow fixtures.
- block fixtures.
- unknown fixtures.
- adversarial or bypass fixtures when relevant.
- generated catalog coverage.
- golden JSON decision coverage for at least one block.
- documentation or example coverage.

Parser-heavy domains should also include property or fuzz-style tests once the test
tooling is introduced.

## Compatibility

This ADR does not require a breaking change.

Compatible implementation path:

1. add internal dataclasses for `EvaluationRequest`, `DecisionResult`, and
   `Finding`.
2. adapt current engine/API results into the new model internally.
3. expose compatible dictionary output exactly as today.
4. migrate built-in rules into first-party pack modules incrementally.
5. add trust-level enforcement around policy loading without changing safe existing
   defaults.

## Non-Goals

This ADR does not propose:

- a sandbox.
- behavioral AI detection.
- probabilistic policy decisions.
- centralized telemetry.
- agent analytics.
- an observability backend.
- remote execution.
- self-updating runtime behavior.
- untrusted executable policy plugins.

## Open Questions

1. Should typed results be public dataclasses, frozen dataclasses, or protocols?
2. Should the first implementation expose pack metadata through the existing catalog
   CLI or a new `packs` command?
3. Should repository policy trust be controlled by a CLI flag, environment variable,
   signed marker, or all of the above?
4. Should rule severity affect default behavior, or remain informational in v1.x?

## Recommended Implementation Order

1. internal typed decision model.
2. policy source trust model.
3. first-party pack metadata and catalog output.
4. migrate shell/filesystem/SQL built-ins into pack modules.
5. add canonical corpus and golden decision tests.
6. add adapter-facing `EvaluationRequest` entrypoints for future integrations.

## Consequences

Positive:

- rule growth becomes easier to manage.
- policy decisions become easier to audit.
- integrations get a more stable contract.
- repository policy becomes safer in hostile workspaces.
- tests become naturally organized by safety domain.

Negative:

- introduces more architecture surface.
- requires careful compatibility wrappers.
- may require temporary duplication while built-in rules migrate to packs.
- policy precedence behavior must be documented very clearly.

The added complexity is justified because it directly supports the project mission:
prevent dangerous AI-agent actions before execution while keeping decisions
deterministic, explainable, and fail secure.
