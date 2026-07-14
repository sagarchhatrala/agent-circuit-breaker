# Quick Start

## Local Setup

```bash
pip install -e .
```

## Run The Test Suite

```bash
python -m unittest discover
```

## Run The CLI

```bash
circuit-breaker check "rm -rf /"
# Verdict: BLOCK

circuit-breaker check "mkdir /tmp/example"
# Verdict: ALLOW

circuit-breaker check "ls -la"
# Verdict: UNKNOWN

circuit-breaker check "rm -rf /etc" --format json
# JSON output
```

## Historical Checklist

## Pre-Development Setup

- [ ] Review `ENGINEERING.md` — Understand the project constitution
- [ ] Review `PLAN.md` — Understand the 2-week milestone roadmap
- [ ] Initialize Git: `git init`
- [ ] Create initial commit: `git add . && git commit -m "Initial project structure"`

## Phase 1: Foundation (Days 1-3)

- [ ] Implement `agent_circuit_breaker/engine.py`
  - [ ] `Decision` class (allow, block, error, unknown)
  - [ ] `Rule` dataclass
  - [ ] `Engine` class with `evaluate()` method
- [ ] Implement `agent_circuit_breaker/rules/builtin_rules.py`
  - [ ] Define 3-5 filesystem safety rules
- [ ] Create `tests/test_engine.py`
  - [ ] Test valid rule acceptance
  - [ ] Test malformed rule rejection
  - [ ] Test deterministic decisions
  - [ ] Target: 10+ passing tests

## Phase 2: Filesystem Inspector (Days 4-6)

- [ ] Implement `agent_circuit_breaker/inspectors/filesystem.py`
  - [ ] `normalize_path()` method
  - [ ] `is_dangerous_target()` method
  - [ ] `analyze_operation()` method
- [ ] Create `tests/test_filesystem_inspector.py`
  - [ ] Test path normalization
  - [ ] Test dangerous target detection
  - [ ] Test operation detection
  - [ ] Target: 30+ passing tests

## Phase 3: CLI + Rules (Days 7-9)

- [ ] Implement `agent_circuit_breaker/cli.py`
  - [ ] `circuit-breaker check <action>` command
  - [ ] `--verbose`, `--rules`, `--format` options
  - [ ] Proper exit codes
- [ ] Populate `agent_circuit_breaker/rules/builtin_rules.py` with full rule set
- [ ] Create `tests/test_cli.py`
  - [ ] Test CLI invocation
  - [ ] Test output parsing
  - [ ] Test all decision types

## Phase 4: Documentation + Polish (Days 10-14)

- [ ] Write `docs/README.md`
- [ ] Write `docs/ARCHITECTURE.md`
- [ ] Write `docs/DESIGN_DECISIONS.md`
- [ ] Write `docs/ROADMAP.md`
- [ ] Add docstrings and type hints to all code
- [ ] All tests passing
- [ ] Code follows PEP 8
- [ ] Create `LICENSE` file (MIT or Apache 2.0)
- [ ] Git tag: `git tag v0.1.0`
- [ ] Ready for GitHub push

## Installation & Testing

```bash
# Install in development mode
pip install -e .

# Run tests
python -m unittest discover

# Run CLI
circuit-breaker check "rm -rf /"
```

## Repository Status

The GitHub repository already exists at `sagarchhatrala/agent-circuit-breaker`.

Historical setup commands:

   ```bash
   git remote add origin https://github.com/sagarchhatrala/agent-circuit-breaker.git
   git branch -M main
   git push -u origin main
   git push --tags
   ```

## Success Indicators

- ✅ All 100+ tests passing
- ✅ No silent failures in engine
- ✅ CLI responds deterministically
- Documentation in progress
- ✅ Code is readable and maintainable
- ✅ Ready for public GitHub release
