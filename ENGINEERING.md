# Agent Circuit Breaker — Engineering Constitution

This document establishes the project's engineering principles, architecture, coding standards, constraints, and collaboration style.

Treat everything below as the project's source of truth unless explicitly changed.

---

## Project Goal

Modern AI coding agents can execute commands, modify files, write scripts, and interact with databases.

The goal of Agent Circuit Breaker is to place a deterministic safety layer between an AI agent and the operating system.

Instead of trusting an LLM to decide whether something is dangerous, the circuit breaker performs explicit rule evaluation before an action executes.

The objective is to stop catastrophic mistakes while keeping false positives extremely low.

### Examples of Protected Against

* recursive filesystem deletion
* destructive SQL
* accidental production access
* force pushes
* infrastructure-wide destructive commands
* secret exfiltration
* indirect execution of generated malicious scripts

The project intentionally favors deterministic inspection over probabilistic AI reasoning.

---

## Design Philosophy

These principles are more important than adding features.

1. **Deterministic over AI** — Explicit rule evaluation beats probabilistic reasoning.
2. **Fail secure by default** — When in doubt, block or error.
3. **False positives are more dangerous than missing niche attacks** — Users disable safety if it blocks too often.
4. **Simplicity beats cleverness** — One developer must understand everything.
5. **Every rule must be explainable** — No black boxes.
6. **Small trusted codebase** — Minimal surface area.
7. **Minimal dependencies** — Python stdlib first.
8. **Everything should be testable** — Including edge cases and malformed input.
9. **Local-first** — No cloud dependencies assumed.
10. **Security decisions should never silently fail** — Explicit allow/block/error/unknown.

Whenever there is uncertainty, choose the simpler implementation.

---

## Core Principles

Always assume:

* malformed input exists
* partially parsed commands exist
* malformed configuration exists
* corrupted rules exist
* unexpected operating systems exist

The system should never silently allow dangerous behavior because parsing failed.

If uncertainty exists, return an explicit decision instead of guessing.

---

## Non-Goals

Do NOT attempt to build:

* antivirus
* EDR
* sandbox
* endpoint monitoring
* behavioral AI
* cloud security platform
* telemetry platform
* orchestration framework

Keep the project narrowly focused.

---

## Architecture

The architecture should remain modular.

High-level modules:

* **Engine** — Decision logic combiner (not detection logic)
* **Inspectors** — Domain-specific analysis (filesystem, command, SQL)
* **Rules** — Policy description (declarative, human-readable)
* **CLI** — User interface
* **Tests** — Comprehensive test coverage
* **Fixtures** — Test data and examples
* **Documentation** — Design, rationale, and usage

The engine should not contain detection logic.

Detection logic belongs inside inspectors.

Rules describe policy.

Inspectors understand data.

The engine combines both.

---

## Rule Philosophy

Rules should be declarative.

Rules describe:

* identifier
* title
* severity
* response
* metadata
* matching requirements

Rules should remain human readable.

Avoid embedding complicated logic inside rule files.

Complex logic belongs in inspector code.

---

## Engine Philosophy

The engine receives:

* one action
* one rule set

The engine returns a deterministic decision.

### Possible Outcomes

* **allow** — Action permitted
* **block** — Action denied
* **error** — Malformed input, cannot evaluate
* **unknown** — No applicable rules, decision deferred

Never silently fall through.

Never silently ignore malformed input.

---

## Inspectors

Inspectors should perform domain-specific analysis.

### Filesystem Inspector

* normalize paths
* detect dangerous targets
* canonicalize paths
* identify recursive operations
* detect unqualified bulk operations

### Command Inspector

* tokenize commands
* resolve shell semantics where practical
* identify dangerous operations
* detect credential leakage patterns

### SQL Inspector

* detect destructive statements
* distinguish qualified vs unqualified operations
* detect injection patterns

Future inspectors may exist, but only when justified.

---

## Milestone Strategy

The project should evolve in small milestones.

Every milestone should produce:

* working code
* tests
* documentation
* rationale

Do not jump ahead.

Finish one milestone before proposing another.

---

## Coding Standards

Prefer:

* Python standard library
* Type hints
* Docstrings
* Readable code over clever code
* Avoid unnecessary abstraction
* Avoid frameworks unless compelling reason

Every dependency must justify its existence.

Optional dependencies acceptable only when isolated behind optional installation extras.

---

## Testing Philosophy

Every feature should include tests.

Prefer:

* unit tests
* regression tests
* edge cases
* malformed input tests
* adversarial input tests
* false-positive testing

Security claims should be verified by tests whenever practical.

---

## Documentation

Maintain documentation continuously.

Important engineering decisions should explain:

* what changed
* why it changed
* alternatives considered
* tradeoffs accepted

Track deferred ideas separately.

Do not quietly expand project scope.

---

## Collaboration Style

Act as a senior engineer, not an autonomous coder.

For meaningful design decisions:

1. Present options.
2. Recommend one option and explain why.
3. Wait for approval.
4. Implement only after approval.

Do not redesign the architecture without discussing it first.

Ask small batches of questions.

Avoid overwhelming discussions.

Challenge assumptions respectfully.

Point out security risks.

Point out maintainability risks.

Point out false-positive risks.

Prefer honesty over optimism.

---

## Constraints

Assume:

* local development
* VS Code
* Windows
* Git
* Python

The project should remain fully usable locally.

Do not assume cloud services.

Do not assume internet connectivity.

Do not assume CI/CD.

Do not assume remote repositories.

Keep everything runnable by one developer.

---

## Quality Expectations

Every implementation should prioritize:

* **correctness** — First and foremost
* **clarity** — Readable without explanation
* **maintainability** — Easy to modify
* **testability** — Verifiable behavior
* **predictability** — Deterministic outcomes

Security should never rely on hidden behavior.

The implementation should be understandable months later without extensive explanation.

---

## Future Development

Help build this project incrementally.

Avoid trying to solve every future problem today.

When introducing new features:

* explain why they belong
* identify tradeoffs
* discuss false-positive impact
* discuss performance impact
* discuss maintenance cost

Do not over-engineer.

The simplest correct solution is usually the best one.

---

## End of Constitution

This document is the project's engineering source of truth unless explicitly changed by the project lead.
