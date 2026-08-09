# JSON Output Contract

This document describes the stable JSON fields returned by the CLI and Python API.

The contract is additive for v1.x compatible releases. Existing fields keep their meaning. New fields may be added when they do not change the meaning of existing fields.

v1.6.0 adds internal typed `DecisionResult` and `Finding` primitives. The public
CLI and `evaluate_action(...)` JSON/dictionary output remains unchanged by
default. Callers that opt into typed conversion can use
`DecisionResult.from_legacy_result(result)` and then call `to_dict()` for typed
findings or `to_legacy_dict()` for the stable v1.x shape.

v1.6.2 adds additive `inspection_coverage`, `decision_validation`, and
`engine_version` fields. These fields do not change existing field meaning, but
they make it possible for integrations and audit pipelines to answer what was
inspected before a decision was returned.

## Top-Level Result

`agent-circuit-breaker check "<action>" --format json` and `evaluate_action(action)` return an object with these fields:

- `command`: original action value passed by the caller.
- `verdict`: lowercase result: `allow`, `block`, `error`, `unknown`, or `pending_approval`.
- `decision`: uppercase engine decision: `ALLOW`, `BLOCK`, `ERROR`, `UNKNOWN`, or `PENDING_APPROVAL`.
- `matched_rule`: matching rule ID, or `null` when no rule matched.
- `rule_details`: matching rule object details, or `null`.
- `operation_analysis`: filesystem-oriented analysis object, or `null` before analysis.
- `command_analysis`: command-oriented analysis object, or `null` before analysis.
- `sql_analysis`: SQL-oriented analysis object, or `null` before analysis.
- `risk_score`: additive integer risk score from `0` to `100`; existing `verdict` and `decision` remain authoritative for compatibility.
- `error`: error text when verdict is `error`, otherwise `null`.
- `policy`: present when a safety profile or policy mode is applied, otherwise `null`.
- `approval`: present when a pending approval record is created by the CLI.
- `audit`: present when CLI audit logging is requested.
- `policy_source`: present when a central policy file or URL was loaded.
- `policy_trust`: present when a central policy file or URL was loaded and trust metadata is available.
- `policy_signature`: present when a loaded policy contained a verified signature.
- `engine_version`: Agent Circuit Breaker engine version that produced the result.
- `inspection_coverage`: mandatory inspection evidence for filesystem, command, and SQL analysis.
- `decision_validation`: final decision validation evidence, including `ALLOW` eligibility checks.
- `custom_rules`: present only when the Python API is called with `rule_file_path`.

## Inspection Coverage

`inspection_coverage` is an additive object with:

- `schema_version`: coverage schema version.
- `status`: `complete`, `incomplete`, or `failed`.
- `mandatory_complete`: whether every mandatory inspector completed.
- `allow_eligible`: whether the action is eligible for automatic known-safe allow.
- `auto_allow_reason`: reason string when automatic known-safe allow was used, otherwise `null`.
- `records`: per-inspector records for `filesystem`, `command`, and `sql`.
- `limits`: relevant evaluation limits such as `max_command_bytes`.
- `unknowns`: mandatory inspection areas that did not complete.

Each coverage record contains:

- `name`: inspector name.
- `target`: inspected target.
- `mandatory`: whether the inspector is mandatory for action decisions.
- `status`: `complete` or `failed`.
- `error`: error text or `null`.
- `limits_reached`: whether a configured limit was reached.
- `metadata`: compact inspector-specific evidence.

`ALLOW` is valid only when mandatory coverage is complete. Automatic known-safe
allow additionally requires a single complete command segment with no shell
operators, no command risk flags, valid SQL inspection, and no SQL risk flags.

## Decision Validation

`decision_validation` is an additive object with:

- `schema_version`: validation schema version.
- `status`: `valid` or `rejected`.
- `allow_source`: `auto_known_safe`, `rule`, or `null`.
- `allow_permitted`: whether an `ALLOW` decision was allowed to stand.
- `reason`: deterministic explanation text.

## Rule Details

When a rule matches, `rule_details` contains:

- `id`: stable rule identifier.
- `title`: human-readable title.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `response`: `allow`, `block`, or `approval`.
- `metadata`: rule metadata object.

## Operation Analysis

`operation_analysis` contains:

- `operation`: detected filesystem operation, or `unknown`.
- `targets`: target paths detected by the filesystem inspector.
- `flags`: operation flags detected by the filesystem inspector.
- `is_dangerous`: boolean risk summary.
- `danger_reason`: explanation text or `null`.

## Command Analysis

`command_analysis` contains:

- `tokens`: first command segment tokens.
- `command`: first segment command name, or `null`.
- `args`: first segment arguments.
- `segments`: list of analyzed command segments.
- `operators`: shell operators between segments.
- `is_valid`: whether command parsing succeeded.
- `error`: command parsing error text or `null`.
- `risk_flags`: aggregate command risk flags.
- `risk_score`: aggregate command risk score from `0` to `100`.
- `is_dangerous`: boolean risk summary.
- `danger_reason`: explanation text or `null`.

Each command segment contains:

- `raw`: raw segment text.
- `tokens`: segment tokens.
- `command`: segment command name, or `null`.
- `args`: segment arguments.
- `risk_flags`: segment risk flags.
- `risk_score`: segment risk score from `0` to `100`.
- `is_dangerous`: boolean segment risk summary.
- `danger_reason`: explanation text or `null`.

## SQL Analysis

`sql_analysis` contains:

- `tokens`: SQL tokens.
- `statements`: analyzed SQL statements.
- `is_valid`: whether SQL parsing succeeded.
- `error`: SQL parsing error text or `null`.
- `risk_flags`: aggregate SQL risk flags.
- `risk_score`: aggregate SQL risk score from `0` to `100`.
- `is_dangerous`: boolean risk summary.
- `danger_reason`: explanation text or `null`.

Each SQL statement contains:

- `raw`: raw statement text.
- `tokens`: statement tokens.
- `statement_type`: first token lowercased, or `null`.
- `risk_flags`: statement risk flags.
- `risk_score`: statement risk score from `0` to `100`.
- `is_dangerous`: boolean statement risk summary.
- `danger_reason`: explanation text or `null`.

## Custom Rule Summary

When `evaluate_action(action, rule_file_path=...)` is used, `custom_rules` contains:

- `path`: supplied rule file path.
- `is_valid`: whether the file loaded and validated.
- `errors`: validation or build errors.
- `rule_count`: number of built custom rules.

Invalid custom rule files fail closed with `verdict` set to `error`.

## Scan Output

`agent-circuit-breaker scan <path...> --format json` returns:

- `files_scanned`: number of scanned text files.
- `findings`: list of blocked, pending approval, or error findings.
- `summary`: counts for total findings, blocked findings, pending approvals, and errors.

`agent-circuit-breaker scan <path...> --sarif` emits SARIF 2.1.0 for GitHub code scanning integrations.

## Trajectory Output

`agent-circuit-breaker trajectory <run.json> --format json` and `evaluate_trajectory(actions, contract=...)` return:

- `schema_version`: trajectory output schema version.
- `run_id`: deterministic short hash derived from the actions and contract.
- `verdict`: aggregate run verdict: `allow`, `block`, `error`, `unknown`, or `pending_approval`.
- `decision`: uppercase aggregate decision.
- `summary`: counts for actions, allowed, blocked, unknown, pending approval, errors, and trajectory findings.
- `contract`: normalized run contract.
- `actions`: per-action evaluation results. Each action result preserves the normal check result fields and adds `trajectory_index`.
- `trajectory_findings`: sequence-level findings.
- `error`: present when trajectory parsing or validation fails.
- `audit`: present when CLI audit logging is requested.
- `ledger`: present when trajectory ledger logging is requested.
- `policy_source`: present when a central policy file or URL was loaded.
- `policy_trust`: present when a central policy file or URL was loaded and trust metadata is available.
- `policy_signature`: present when a loaded policy contained a verified signature.

Trajectory findings contain:

- `id`: stable finding identifier.
- `title`: human-readable title.
- `severity`: `CRITICAL`, `HIGH`, or `MEDIUM`.
- `response`: `block` or `approval`.
- `indices`: action indices that contributed to the finding.
- `reason`: deterministic explanation.

Current trajectory finding IDs:

- `traj_repeated_blocked_actions`
- `traj_unknown_action_volume`
- `traj_forbidden_target`
- `traj_scope_violation`
- `traj_output_channel_drift`
- `traj_secret_in_egress_action`
- `traj_secret_then_egress`
- `traj_data_export_then_egress`

## MCP Trajectory Metadata

When `agent-circuit-breaker-mcp-proxy` is run with `--trajectory` or `--trajectory-policy`, blocked JSON-RPC error responses may include these extra `error.data` fields:

- `trajectory_verdict`: aggregate trajectory verdict that contributed to the block.
- `trajectory_finding`: first trajectory finding ID that contributed to the block.

When trajectory mode is not enabled, MCP proxy responses remain stateless and these fields are `null` or absent depending on the response path.

## Approval Context

Approval records include an additive `context` object.

For single-action approvals, `context` contains:

- `type`: `action`.
- `command`, `verdict`, `decision`, `risk_score`, `matched_rule`, and `policy`.

For trajectory approvals, `context` contains:

- `type`: `trajectory`.
- `run_id`: trajectory run ID.
- `verdict`: aggregate trajectory verdict.
- `summary`: trajectory summary counts.
- `findings`: compact finding IDs, severities, indices, and reasons.
- `recent_actions`: the last five action summaries.

When `ACB_APPROVAL_TOKEN` is configured, CLI approve/deny operations require `--approval-token`. The token is not stored in approval records.

Approval records also include an additive `approval_security` object:

- `token_required`: whether `ACB_APPROVAL_TOKEN` was configured when the record was created.
- `warning`: a local trust-boundary warning when approval decisions are not token-gated.

## Run Ledger

`agent-circuit-breaker trajectory <run.json> --ledger` appends the full trajectory result to a local hash-chained JSONL ledger.

`agent-circuit-breaker ledger --format json` returns:

- `path`: ledger path.
- `entries`: recent ledger entries.

Each ledger entry contains:

- `schema_version`
- `timestamp`
- `previous_hash`
- `run_id`
- `result`
- `entry_hash`

`agent-circuit-breaker ledger <RUN_ID> --format json` returns replayable run data with command, verdict, decision, matched rule, risk score, contract, summary, and trajectory findings.
