# Design Decisions

This document records the main v0.1 design choices and the tradeoffs behind them.

## Deterministic Rules Over AI Judgment

Decision: use explicit rules and inspectors instead of an LLM safety judgment.

Reasoning:

- Safety decisions must be repeatable.
- Users need explainable outcomes.
- A small deterministic rule can be tested directly.
- LLM output can vary across runs and model versions.

Tradeoff:

- Deterministic rules will miss some nuanced cases.
- The project accepts this in exchange for predictability and low operational surprise.

## Explicit Unknown Decision

Decision: return `UNKNOWN` when no rule matches and the operation is not recognized as safe.

Reasoning:

- "No block rule matched" is not proof that an action is safe.
- Unknown preserves honesty about the current coverage.
- Callers can decide whether unknown should stop execution or defer to another approval path.

Tradeoff:

- Users may need to handle an additional state.
- The benefit is avoiding false confidence.

## Engine Does Not Contain Detection Logic

Decision: keep detection logic out of the engine.

Reasoning:

- The engine should be small and easy to audit.
- Filesystem, shell, and SQL logic have different parsing needs.
- Inspectors can evolve independently without changing the rule combiner.

Tradeoff:

- The CLI currently has to compose engine and inspector outputs.
- This is acceptable because the CLI is the presentation layer, not the trusted rule core.

## Dataclass Rules Instead Of YAML In v0.1

Decision: rules are Python dataclasses with callable matchers.

Reasoning:

- No external parser dependency is required.
- Rule construction can be validated with normal Python tests.
- The model is still evolving; locking in a public YAML schema too early would create churn.

Tradeoff:

- Users cannot yet provide custom rule files.
- External rule loading remains planned for a later milestone once validation semantics are clearer.

## Filesystem First

Decision: start with filesystem operations.

Reasoning:

- Recursive deletion is one of the clearest catastrophic agent risks.
- The domain is narrow enough for a v0.1 milestone.
- Tests can cover many real-world false-positive and false-negative cases.

Tradeoff:

- The project does not yet cover SQL, git, cloud, or full shell semantics.
- Those domains are deferred until the filesystem path proves the architecture.

## Minimal Dependencies

Decision: use Python standard library only for the core package.

Reasoning:

- The trusted codebase stays small.
- Installation is simple in local agent environments.
- Tests can run without network access or dependency resolution.

Tradeoff:

- Shell parsing and path handling are more limited than specialized libraries.
- The project favors small, targeted heuristics over broad parsing until a dependency is clearly justified.

## CLI Allows Known Safe Operations

Decision: the CLI maps recognized safe operations to `ALLOW` when no block rule matches.

Reasoning:

- The engine correctly returns `UNKNOWN` when no rule matches.
- The CLI has inspector context and can classify common safe operations such as `mkdir`, `mv`, `cp`, `chmod`, and file creation.
- This keeps user-facing behavior practical without weakening the engine contract.

Tradeoff:

- The allow decision currently depends on inspector coverage.
- Unknown remains available for commands outside current deterministic understanding.

## Block And Error Share Exit Code 1

Decision: CLI exit code `1` represents both blocked and error outcomes.

Reasoning:

- Shell callers usually need both outcomes to stop execution.
- The formatted output still distinguishes `BLOCK` from `ERROR`.
- JSON output includes the exact verdict.

Tradeoff:

- Exit code alone is not enough to distinguish block from error.
- Callers that need the distinction should use `--format json`.

## Non-Goals

The project is not trying to be:

- a sandbox
- an antivirus product
- endpoint monitoring
- behavioral AI detection
- cloud security posture management

Keeping these non-goals explicit helps preserve the small deterministic architecture.
