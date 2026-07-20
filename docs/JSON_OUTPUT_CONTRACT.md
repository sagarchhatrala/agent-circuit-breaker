# JSON Output Contract

This document describes the stable JSON fields returned by the CLI and Python API.

The contract is additive for v1.x compatible releases. Existing fields keep their meaning. New fields may be added when they do not change the meaning of existing fields.

## Top-Level Result

`circuit-breaker check "<action>" --format json` and `evaluate_action(action)` return an object with these fields:

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
- `policy_signature`: present when a loaded policy contained a verified signature.
- `custom_rules`: present only when the Python API is called with `rule_file_path`.

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

`circuit-breaker scan <path...> --format json` returns:

- `files_scanned`: number of scanned text files.
- `findings`: list of blocked, pending approval, or error findings.
- `summary`: counts for total findings, blocked findings, pending approvals, and errors.

`circuit-breaker scan <path...> --sarif` emits SARIF 2.1.0 for GitHub code scanning integrations.
