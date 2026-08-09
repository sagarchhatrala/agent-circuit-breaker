# Architecture

Agent Circuit Breaker is organized around a small deterministic pipeline:

```text
Action -> Inspector(s) -> Rules -> Engine -> Decision -> Typed Result -> CLI/API result
```

The implementation intentionally separates domain analysis from policy evaluation.

## Modules

### Engine

File: `agent_circuit_breaker/engine.py`

The engine owns deterministic rule evaluation. It receives:

- one action string
- one list of `Rule` objects

It returns:

- a `Decision`
- the matching `Rule`, when one matched

The engine does not contain filesystem detection logic. It only validates inputs, evaluates rules in order, and returns an explicit result.

### Rules

File: `agent_circuit_breaker/rules/builtin_rules.py`

Rules describe policy. Each rule has:

- `id`
- `title`
- `severity`
- `response`
- `matcher`
- optional `metadata`

Rules remain Python dataclasses in v0.1. This keeps the trusted surface small and avoids adding a config parser before the rule model is stable.

### Filesystem Inspector

File: `agent_circuit_breaker/inspectors/filesystem.py`

The filesystem inspector performs domain-specific analysis. It currently handles:

- path normalization
- dangerous target detection
- operation classification
- recursive and force flag detection
- quoted target extraction

The inspector returns structured analysis that the CLI can expose and rules can reuse.

### CLI

File: `agent_circuit_breaker/cli.py`

The CLI is the current user-facing interface. It supports:

- `agent-circuit-breaker check <action>`
- `agent-circuit-breaker -c <action>`
- interactive mode
- text and JSON output

The CLI combines inspector analysis and engine rule evaluation into a user-facing result.

### Typed Results

File: `agent_circuit_breaker/core/results.py`

v1.6.0 adds typed result primitives:

- `EvaluationRequest`
- `DecisionResult`
- `Finding`

The typed model records stable decision evidence for future policy packs and
integration adapters. It does not change the stable v1.x CLI or API dictionary
contract. Public results can be converted into typed results and then converted
back to the existing dictionary shape.

## Decision Flow

1. CLI receives an action.
2. CLI rejects non-string input as `ERROR`.
3. Filesystem inspector analyzes the action.
4. Engine evaluates the action against built-in rules.
5. If a rule matches, the engine returns that rule's response.
6. If no rule matches and the inspectors prove a single-segment known-safe operation, the CLI reports `ALLOW`.
7. If no rule matches and the operation is not recognized as safe, the CLI reports `UNKNOWN`.
8. Public API evaluation converts the result into a typed internal `DecisionResult`.
9. The API returns the stable v1.x dictionary; the CLI returns the stable text or JSON output.

This preserves the engine's simple contract while allowing the CLI to provide a useful allow decision for known safe filesystem operations.

## Why Known Safe Operations Are Mapped In The CLI

The engine returns `UNKNOWN` when no rule matches. That is the correct low-level behavior because absence of a matching rule is not the same thing as proof of safety.

The CLI has additional context from the inspectors. If the filesystem inspector
recognizes a non-dangerous operation such as `mkdir`, `mv`, `cp`, `chmod`, or
`touch`, and command/SQL inspection proves the action is a single complete
segment with no operators or risk flags, the CLI maps that result to `ALLOW`.

v1.6.2 records this in `inspection_coverage` and validates the final decision in
`decision_validation`. Incomplete mandatory inspection cannot produce `ALLOW`.
v1.6.3 extends the same fail-secure direction by blocking dangerous payloads
hidden behind common shell/interpreter execution flags and by adding validation
metadata to the async pipeline SDK.

This keeps policy layers explicit:

- engine: rule matching only
- inspector: domain understanding
- CLI: user-facing verdict composition

## Current Decision Values

- `ALLOW`: action is recognized as safe and no block rule matched
- `BLOCK`: a block rule matched
- `ERROR`: malformed input or evaluation failure
- `UNKNOWN`: no rule matched and no safe classification exists

## Error Handling

Malformed engine inputs return `Decision.ERROR`. Matcher exceptions are caught and also return `Decision.ERROR`.

The CLI returns a structured error result for malformed command input. This avoids silent allow behavior when input cannot be evaluated.

## Extension Points

The architecture is designed for more inspectors without changing the engine:

- command inspector for shell semantics and command-specific hazards
- SQL inspector for destructive statements
- rule loading and validation for external rule files
- log analyzer for retrospective safety checks

Future extensions should preserve the same boundary: inspectors understand domains, rules describe policy, and the engine combines rule outcomes deterministically.
