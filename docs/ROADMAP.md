# Roadmap

This roadmap tracks planned milestones without expanding the v0.1 scope beyond the current safety layer.

## v0.1: Filesystem Safety Alpha

Status: in progress.

Current completed work:

- core engine
- rule dataclass validation
- built-in filesystem rules
- filesystem inspector
- CLI check command
- text and JSON output
- test suite with 100+ tests
- README and quickstart alignment

Remaining v0.1 work:

- finish documentation set
- review public method docstrings and type hints
- clarify package release readiness
- update `PLAN.md` to reflect actual implementation status
- tag and push `v0.1.0-alpha.1`

Exit criteria:

- all tests pass with `python -m unittest discover`
- docs accurately describe current behavior
- no README claims unsupported features
- examples work locally
- GitHub `main` is current

## v0.2: Command Inspector

Goal: inspect command-level hazards beyond basic filesystem heuristics.

Detailed plan: [V0_2_COMMAND_INSPECTOR.md](V0_2_COMMAND_INSPECTOR.md)

Candidate coverage:

- command tokenization
- shell operator awareness for `&&`, `||`, pipes, and command chains
- dangerous git operations such as force pushes
- credential exfiltration patterns
- script execution patterns
- safer handling of quoted and escaped shell arguments

Design questions:

- How much shell parsing can be implemented safely without external dependencies?
- Which shell dialects are in scope first?
- Should Windows PowerShell and POSIX shells be separate inspectors?

## v0.3: SQL Inspector

Goal: detect destructive SQL statements before execution.

Candidate coverage:

- `DROP TABLE`
- `DROP DATABASE`
- `TRUNCATE`
- unqualified `DELETE`
- unqualified `UPDATE`
- migration commands with destructive statements

Design questions:

- Is a small SQL tokenizer enough for v0.3?
- Which SQL dialects are in scope?
- How should the inspector distinguish test databases from production-like targets?

## v0.4: Rule Loading And Validation

Goal: support external rule files safely.

Candidate work:

- JSON rule format
- rule validation CLI
- schema documentation
- clear errors for malformed rules
- fixture-based rule examples

Design questions:

- Should YAML wait until an optional dependency is justified?
- How should callable logic be represented declaratively?
- What rule features are intentionally unsupported?

## v1.0: Production Readiness

Goal: make the project reliable enough for real agent integration.

Candidate requirements:

- stable public API
- documented rule schema
- versioned built-in rule set
- compatibility policy
- clear security model
- release checklist
- complete documentation
- broader adversarial test suite

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
