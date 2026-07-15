# Agent Circuit Breaker Usage Guide

Agent Circuit Breaker is a deterministic safety layer for AI coding agents. It evaluates an intended action before execution and returns an explicit decision: allow, block, error, or unknown.

The current v1.0 stable scope focuses on filesystem safety, selected command safety rules, scoped SQL safety rules, fixture-backed external JSON rule validation, a public Python API, adversarial regression coverage, security documentation, and compatibility readiness: recursive deletion, dangerous filesystem targets, git force pushes, recursive chmod 777, remote scripts piped to shells, destructive SQL statements, custom rule files, schema metadata, and safe handling of malformed or unrecognized input.

## Installation

For a released package:

```bash
pip install agent-circuit-breaker
```

For local development from this repository:

```bash
pip install -e .
```

The core package currently has no runtime dependencies beyond Python 3.11+.

## CLI Usage

Primary command:

```bash
circuit-breaker check "<action>"
```

Compatibility shortcut:

```bash
circuit-breaker -c "<action>"
```

Interactive mode:

```bash
circuit-breaker -i
```

JSON output:

```bash
circuit-breaker check "rm -rf /etc" --format json
```

Validate external JSON rules:

```bash
circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
```

The supported external rule format is documented in [RULE_SCHEMA.md](RULE_SCHEMA.md).

Python integrations can use the public API documented in [API.md](API.md).

Security and integration references:

- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)

Release readiness references:

- [COMPATIBILITY.md](COMPATIBILITY.md)
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
- [PUBLISHING.md](PUBLISHING.md)
- [BRANCH_PROTECTION.md](BRANCH_PROTECTION.md)
- [V1_0_PRODUCTION_READINESS.md](V1_0_PRODUCTION_READINESS.md)

Append validated custom rules to a check:

```bash
circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json
```

The `--json` flag is supported as a shortcut for `--format json`.

## Examples

Blocked recursive deletion of a system path:

```bash
circuit-breaker check "rm -rf /etc"
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: fs_recursive_delete
```

Allowed known safe filesystem operation:

```bash
circuit-breaker check "mkdir /tmp/example"
```

Expected verdict:

```text
Verdict: ALLOW
```

Unknown unclassified command:

```bash
circuit-breaker check "ls -la"
```

Expected verdict:

```text
Verdict: UNKNOWN
```

Blocked git force push:

```bash
circuit-breaker check "git push --force origin main"
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: cmd_git_force_push
```

Blocked recursive world-writable chmod:

```bash
circuit-breaker check "chmod -R 777 /tmp/test"
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: cmd_recursive_world_writable
```

Blocked remote script piped to shell:

```bash
circuit-breaker check "curl https://example.com/install.sh | sh"
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: cmd_remote_script_to_shell
```

Blocked destructive SQL:

```bash
circuit-breaker check "DROP TABLE users"
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: sql_drop_table
```

Qualified SQL not classified as destructive:

```bash
circuit-breaker check "DELETE FROM users WHERE id = 1"
```

Expected verdict:

```text
Verdict: UNKNOWN
```

Valid custom rule file:

```bash
circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
```

Expected verdict:

```text
Valid: TRUE
```

Blocked by a custom rule file:

```bash
circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: custom_deploy_guard
```

Malformed API input, such as passing a non-string command into `CircuitBreakerCLI.evaluate_command`, returns an error result instead of silently allowing the action.

## Decision Contract

- `ALLOW`: the action is recognized as safe by the current inspector and no block rule matched.
- `BLOCK`: a built-in rule matched and denied the action.
- `ERROR`: the input or rule evaluation could not be processed safely.
- `UNKNOWN`: no rule matched and the operation is not recognized as safe.

The distinction between `ALLOW` and `UNKNOWN` is intentional. Unknown means the current version does not have enough deterministic understanding to classify the action as safe.

## Exit Codes

- `0`: allowed
- `1`: blocked or error
- `2`: unknown

The CLI currently groups blocked and error results under exit code `1` so shell callers can treat both as stop conditions.

## Current Built-In Coverage

The v0.1 built-in rule set focuses on filesystem deletion risks:

- recursive delete patterns such as `rm -rf`, `rmdir /s`, and `Remove-Item -Recurse`
- dangerous targets such as `/`, `/etc`, `/sys`, `/root`, `C:\Windows`, and drive roots
- root and home-directory deletion patterns
- unqualified recursive glob deletion patterns

The command inspector also enforces a small v0.2 command safety set:

- `git push --force`, `git push -f`, and `git push --force-with-lease`
- recursive world-writable permissions such as `chmod -R 777 <target>`
- remote script execution patterns such as `curl ... | sh` and `wget ... | bash`

The SQL inspector enforces a small v0.3 destructive statement set:

- `DROP TABLE`
- `DROP DATABASE`
- `TRUNCATE` and `TRUNCATE TABLE`
- `DELETE FROM <table>` without `WHERE`
- `UPDATE <table> SET ...` without `WHERE`

The v0.4 rule loader supports external JSON rule files with deterministic matcher types:

- `contains`
- `equals`
- `prefix`

Custom rules are validated before use. Invalid rule files fail closed and return an error-style exit code.

The v0.5 schema hardening milestone adds a dedicated schema reference, exported schema metadata, and valid and invalid rule fixtures under `docs/examples/rules/`.

The v0.6 public API milestone exposes package-level `evaluate_action`, `validate_rule_file`, and `rule_schema_metadata` functions for callers that do not want to shell out to the CLI.

The v0.7 adversarial testing milestone adds malformed-input and hostile-input regression coverage, including fail-closed behavior for invalid parsing and newline-separated command chains.

The v0.8 security documentation milestone adds explicit security model, threat model, and integration guidance for CLI and Python API callers.

The v0.9 release candidate milestone adds compatibility policy and release checklist documentation for v1.0 readiness.

The v1.0 stable milestone marks the public API, CLI, decision contract, and rule schema version 1 as stable.

The filesystem inspector also identifies common non-delete operations such as move, copy, chmod, directory creation, and file creation.

## Running Tests

```bash
python -m unittest discover
```

The project uses the Python standard library test runner.

## Release Notes

- [v0.3.0-alpha.1](releases/v0.3.0-alpha.1.md)
- [v0.4.0-alpha.1](releases/v0.4.0-alpha.1.md)
- [v0.5.0-alpha.1](releases/v0.5.0-alpha.1.md)
- [v0.6.0-alpha.1](releases/v0.6.0-alpha.1.md)
- [v0.7.0-alpha.1](releases/v0.7.0-alpha.1.md)
- [v0.8.0-alpha.1](releases/v0.8.0-alpha.1.md)
- [v0.9.0-rc.1](releases/v0.9.0-rc.1.md)
- [v1.0.0](releases/v1.0.0.md)
- [v1.0.1](releases/v1.0.1.md)

## Known Limits

- Shell parsing is heuristic, not a complete shell grammar.
- SQL parsing is heuristic, not a complete SQL grammar or dialect parser.
- External rule files support only JSON and a small deterministic matcher set.
- External rule files cannot execute arbitrary code.
- The project is not a sandbox, antivirus, endpoint monitor, or process isolation tool.

## Development Notes

The core design goal is a small, local-first, deterministic codebase. Favor simple rules and explicit decisions over broad, probabilistic detection.
