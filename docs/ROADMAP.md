# Roadmap

This roadmap tracks planned milestones while keeping each release narrow and testable.

## v0.1: Filesystem Safety Alpha

Status: released as `v0.1.0-alpha.1`.

Current completed work:

- core engine
- rule dataclass validation
- built-in filesystem rules
- filesystem inspector
- CLI check command
- text and JSON output
- test suite with 100+ tests
- README and quickstart alignment

Exit criteria met:

- all tests pass with `python -m unittest discover`
- docs accurately describe current behavior
- no README claims unsupported features
- examples work locally
- GitHub `main` is current

## v0.2: Command Inspector

Goal: inspect command-level hazards beyond basic filesystem heuristics.

Status: released as `v0.2.0-alpha.1`.

Detailed plan: [V0_2_COMMAND_INSPECTOR.md](V0_2_COMMAND_INSPECTOR.md)

Candidate coverage:

- command tokenization
- shell operator awareness for `&&`, `||`, pipes, and command chains
- dangerous git operations such as force pushes
- credential exfiltration patterns
- script execution patterns
- safer handling of quoted and escaped shell arguments

Implemented so far:

- tokenizer foundation
- shell operator splitting for `&&`, `||`, `;`, and `|`
- command risk detection for git force push, recursive chmod 777, and remote script piped to shell
- CLI command analysis output
- built-in command safety rules for the detected command risks

Design questions:

- How much shell parsing can be implemented safely without external dependencies?
- Which shell dialects are in scope first?
- Should Windows PowerShell and POSIX shells be separate inspectors?

## v0.3: SQL Inspector

Goal: detect destructive SQL statements before execution.

Status: released as `v0.3.0-alpha.1`.

Detailed plan: [V0_3_SQL_INSPECTOR.md](V0_3_SQL_INSPECTOR.md)

Candidate coverage:

- `DROP TABLE`
- `DROP DATABASE`
- `TRUNCATE`
- unqualified `DELETE`
- unqualified `UPDATE`
- migration commands with destructive statements

Implemented so far:

- SQL tokenizer foundation
- statement splitting on semicolons outside strings and comments
- destructive statement detection
- CLI SQL analysis output
- built-in SQL safety rules for scoped destructive statements

Design questions:

- Is a small SQL tokenizer enough for v0.3?
- Which SQL dialects are in scope?
- How should the inspector distinguish test databases from production-like targets?

## v0.4: Rule Loading And Validation

Goal: support external rule files safely.

Status: released as `v0.4.0-alpha.1`.

Detailed plan: [V0_4_RULE_LOADING.md](V0_4_RULE_LOADING.md)

Candidate work:

- JSON rule format
- rule validation CLI
- schema documentation
- clear errors for malformed rules
- fixture-based rule examples

Implemented so far:

- JSON rule format.
- deterministic rule definition validator.
- JSON rule file loading.
- CLI validation through `validate-rules`.
- safe rule construction for `contains`, `equals`, and `prefix`.
- optional custom rule enforcement through `--rules`.
- fixture-based JSON rule example.

Design questions:

- Should YAML wait until an optional dependency is justified?
- How should callable logic be represented declaratively?
- What rule features are intentionally unsupported?

## v0.5: Rule Schema Hardening

Goal: make the external rule format explicit, documented, and regression-tested.

Status: released as `v0.5.0-alpha.1`.

Detailed plan: [V0_5_RULE_SCHEMA.md](V0_5_RULE_SCHEMA.md)

Candidate work:

- formal rule schema documentation
- schema constants exposed by the package
- valid and invalid fixture files
- tests that validate every documented fixture
- clearer matcher semantics
- stronger duplicate and unsupported-field examples

Implemented so far:

- dedicated rule schema reference.
- schema version constant and deterministic metadata export.
- valid single-rule and multi-rule fixtures.
- invalid duplicate ID, matcher type, metadata, and missing-rules fixtures.
- fixture validation tests.

## v0.6: Public API Alpha

Goal: expose a stable Python integration surface for callers that do not want to shell out to the CLI.

Status: released as `v0.6.0-alpha.1`.

Candidate work:

- public package-level evaluation function.
- public rule-file validation function.
- deterministic dictionary result contract.
- custom rule file support through the API.
- API-focused tests and docs.

Implemented so far:

- `agent_circuit_breaker.api` public module.
- package-level exports for `evaluate_action`, `validate_rule_file`, and `rule_schema_metadata`.
- custom rule-file support through the public API.
- fail-closed error result for invalid custom rule files.
- API reference docs and API-focused tests.

## v0.7: Adversarial Test Alpha

Goal: increase confidence with hostile, malformed, and edge-case inputs across inspectors and rule loading.

Status: released as `v0.7.0-alpha.1`.

Candidate work:

- adversarial command parsing cases.
- adversarial SQL parsing cases.
- malformed and suspicious custom rule cases.
- CLI determinism checks.
- regression tests for fail-closed behavior.

Implemented so far:

- adversarial test suite covering command chains, malformed parser inputs, SQL comments and quotes, blank inputs, non-string API inputs, invalid custom rules, and determinism.
- newline-separated command chain inspection.
- fail-closed `ERROR` results for malformed command and SQL analysis.

## v0.8: Security Documentation Alpha

Goal: document the security model, threat assumptions, and integration boundaries.

Status: released as `v0.8.0-alpha.1`.

Candidate work:

- security model reference.
- threat model reference.
- integration guide.
- explicit non-goals and trust boundaries.
- documentation link checks.

Implemented so far:

- security model reference.
- threat model reference.
- CLI and Python integration guide.
- documentation regression tests for security links and key trust-boundary statements.

## v0.9: Release Candidate

Goal: freeze the v1.0 surface and complete release readiness checks.

Status: released as `v0.9.0-rc.1`.

Candidate work:

- compatibility policy.
- release checklist.
- final README and quickstart pass.
- public API contract review.
- full regression and smoke verification.

Implemented so far:

- compatibility policy covering public API, CLI, decision contract, and rule schema.
- repeatable release checklist.
- documentation regression tests for release-readiness docs.

## v1.0: Production Readiness

Goal: make the project reliable enough for real agent integration.

Status: released as `v1.0.0`.

Candidate requirements:

- stable public API
- documented rule schema
- versioned built-in rule set
- compatibility policy
- clear security model
- release checklist
- complete documentation
- broader adversarial test suite

Implemented so far:

- stable public Python API.
- stable CLI commands and exit codes.
- stable decision contract.
- external JSON rule schema version 1.
- compatibility policy.
- release checklist.
- security model, threat model, and integration guide.
- adversarial and documentation regression tests.

## v1.1: Compatible Additions

Goal: add compatible safety coverage and integration polish without breaking v1.0 contracts.

Status: released as `v1.1.0`.

Detailed plan: [V1_1_PLAN.md](V1_1_PLAN.md)

Candidate work:

- more built-in command rules.
- detailed JSON output contract documentation.
- explicit allowlist pattern exploration.
- additional integration examples and tests.
- installed-package verification improvements.

Implemented so far:

- command rules for package publish commands without explicit release context.
- command rules for destructive Docker command shapes.
- command rules for cloud resource deletion command shapes.
- command rules for forceful Kubernetes deletion command shapes.
- detailed JSON output contract documentation.
- local allowlist pattern documentation and example.

## Companion Products

These are intentionally outside the v0.1 core.

### Rule Validator CLI

Validates custom rules before they are used.

### Log Analyzer

Reads historical agent action logs and reports which actions would have been blocked.

### Rule Library

Provides versioned community or curated rules with documentation and examples.

## Deferred Ideas

Deferred until the core is proven:

- rule signing
- remote rule fetching
- telemetry
- IDE integrations
- cloud platform support
- sandboxing
- machine learning detection
- performance benchmarking

## v1.4.x: Long-Horizon Agent Safety Series

Goal: evolve the v1.4 runtime/MCP hardening line into deterministic controls for longer-running agent work without breaking v1.x compatibility.

### v1.4.3: Trajectory Safety Foundation

Status: released as `v1.4.3`.

Implemented so far:

- `evaluate_trajectory(...)` public API.
- `circuit-breaker trajectory <run.json>` CLI mode.
- optional run contracts for goals, allowed scopes, forbidden targets, allowed outputs, blocked-attempt limits, and unknown-action limits.
- trajectory findings for repeated blocked actions, output-channel drift, forbidden targets, scope violations, unknown-action volume, and secret-like reads followed by egress.

### v1.4.4: Stateful MCP Trajectory Enforcement

Status: released as `v1.4.4`.

Implemented so far:

- `circuit-breaker-mcp-proxy --trajectory`.
- `circuit-breaker-mcp-proxy --trajectory-policy <path>`.
- programmatic `MCPRunGuard`.
- MCP JSON-RPC block metadata for trajectory verdicts and findings.

### v1.4.5: Contextual Approvals And Run Ledger

Status: released as `v1.4.5`.

Implemented so far:

- contextual approval summaries for trajectory runs.
- `circuit-breaker trajectory <run.json> --ledger`.
- `circuit-breaker ledger`, `circuit-breaker ledger <RUN_ID>`, and `circuit-breaker ledger --verify`.
- local hash-chained `RunLedger`.

### v1.4.6: Broader Secret And Data Egress Flows

Status: released as `v1.4.6`.

Implemented so far:

- direct secret-like material in egress action detection.
- data export followed by external egress detection.
- broader egress channel coverage.
- broader sensitive-reference coverage.

### v1.4.7: Trajectory Bypass Hardening

Status: released as `v1.4.7`.

Implemented so far:

- custom-script and SSH-style egress detection after secret reads.
- boundary-aware forbidden target matching.
- `tee`, `curl -o`, and `wget -O` scope-violation detection.
- optional approval-token gate for local approve/deny decisions.
- documentation clarifying local approval trust boundaries.

### v1.4.8: Output-Channel Drift Precision

Status: released as `v1.4.8`.

Implemented so far:

- outbound-only output-channel drift checks for trajectory contracts.
- no output-channel false positives for `curl` health checks, `wget` downloads, `git clone`, or S3 downloads.
- approval record warning metadata when no approval token is configured.
- release workflow sequencing through TestPyPI before PyPI.

### v1.4.9: Dependency-Free Pipeline Architecture

Status: released as `v1.4.9`.

Implemented so far:

- async `PipelineEngine` and immutable tool-call context DTOs.
- guard/state/hook/exporter protocol contracts.
- `AgentCircuitBreaker` SDK facade.
- in-memory and SQLite state stores.
- deterministic guards for shell, filesystem, network egress, package install, loop breaking, and context-window checks.
- dependency-free pipeline events and logging exporter.

### Planned Patch Slices

- later `v1.4.x`: OWASP/NIST posture reporting and curated policy packs.
