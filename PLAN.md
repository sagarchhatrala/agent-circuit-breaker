# Agent Circuit Breaker v0.1 Alpha Plan

Project goal: build a deterministic safety layer between AI coding agents and the operating system.

The current release target is `v0.1.0-alpha.1`. This alpha proves the core architecture with filesystem safety checks, a CLI, tests, and documentation.

## Current Status

Completed:

- Core decision engine
- Rule dataclass and validation
- Built-in filesystem rules
- Filesystem inspector
- CLI command: `circuit-breaker check <action>`
- Text and JSON CLI output
- Standard-library test suite
- Usage, architecture, design decision, and roadmap docs
- GitHub `main` push workflow

Remaining before tagging `v0.1.0-alpha.1`:

- Release-readiness cleanup
- Editable install verification
- CLI smoke test
- Full test run
- Git tag and push

## Repository Structure

```text
agent-circuit-breaker/
|-- agent_circuit_breaker/
|   |-- __init__.py
|   |-- engine.py
|   |-- cli.py
|   |-- inspectors/
|   |   `-- filesystem.py
|   `-- rules/
|       `-- builtin_rules.py
|-- docs/
|   |-- README.md
|   |-- ARCHITECTURE.md
|   |-- DESIGN_DECISIONS.md
|   `-- ROADMAP.md
|-- tests/
|   |-- test_cli.py
|   |-- test_engine.py
|   `-- test_filesystem_inspector.py
|-- ENGINEERING.md
|-- QUICKSTART.md
|-- README.md
|-- setup.py
`-- requirements.txt
```

## v0.1 Alpha Scope

In scope:

- Deterministic rule evaluation
- Explicit decisions: allow, block, error, unknown
- Filesystem operation analysis
- Dangerous path detection
- Recursive delete detection
- CLI usage through `check <action>`
- JSON output for machine-readable results
- Local-first operation with no runtime dependencies

Out of scope:

- Custom rule file loading
- Complete shell grammar parsing
- SQL inspection
- Git-specific command inspection
- Cloud platform inspection
- Sandboxing or process isolation
- Telemetry

## Success Criteria

- `python -m unittest discover` passes
- `pip install -e .` succeeds
- `circuit-breaker check "rm -rf /"` returns `BLOCK`
- `circuit-breaker check "mkdir /tmp/example"` returns `ALLOW`
- `circuit-breaker check "ls -la"` returns `UNKNOWN`
- Documentation describes only currently supported behavior
- `main` is pushed to GitHub
- `v0.1.0-alpha.1` tag is pushed to GitHub

## Next Milestones

After `v0.1.0-alpha.1`, continue with:

- v0.2: command inspector
- v0.3: SQL inspector
- v0.4: custom rule loading and validation
- v1.0: stable API, release process, and production-readiness review

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.
