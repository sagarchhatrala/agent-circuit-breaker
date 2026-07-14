# Agent Circuit Breaker Usage Guide

Agent Circuit Breaker is a deterministic safety layer for AI coding agents. It evaluates an intended action before execution and returns an explicit decision: allow, block, error, or unknown.

The current v0.1 scope focuses on filesystem safety: recursive deletion, dangerous filesystem targets, and safe handling of malformed or unrecognized input.

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

The filesystem inspector also identifies common non-delete operations such as move, copy, chmod, directory creation, and file creation.

## Running Tests

```bash
python -m unittest discover
```

The project uses the Python standard library test runner.

## Known Limits

- Shell parsing is heuristic, not a complete shell grammar.
- Custom rule loading is planned but not implemented yet.
- SQL and command inspectors are planned for later milestones.
- The project is not a sandbox, antivirus, endpoint monitor, or process isolation tool.

## Development Notes

The core design goal is a small, local-first, deterministic codebase. Favor simple rules and explicit decisions over broad, probabilistic detection.
