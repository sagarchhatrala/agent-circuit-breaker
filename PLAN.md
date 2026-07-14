# Agent Circuit Breaker — 2-Week Milestone Plan

**Project Goal**: Build a deterministic safety layer for AI agents.

**v0.1 Timeline**: 2 weeks (by 2026-07-28)

**v0.1 Scope**: Engine + Filesystem Inspector + CLI + Full Documentation

---

## Repository Structure

```
agent-circuit-breaker/
├── agent_circuit_breaker/          # Main package
│   ├── __init__.py
│   ├── engine.py                   # Core decision engine
│   ├── inspectors/
│   │   ├── __init__.py
│   │   └── filesystem.py           # Filesystem safety inspector
│   ├── rules/
│   │   ├── __init__.py
│   │   └── builtin_rules.py        # Built-in rule set
│   └── cli.py                      # CLI interface
├── tests/                          # Test suite
│   ├── __init__.py
│   ├── test_engine.py
│   ├── test_filesystem_inspector.py
│   └── test_cli.py
├── docs/                           # Documentation
│   ├── README.md                   # Project overview
│   ├── ARCHITECTURE.md             # Design deep-dive
│   ├── DESIGN_DECISIONS.md         # Rationale for key choices
│   └── ROADMAP.md                  # Future milestones
├── projects/                       # Companion products
│   ├── README.md
│   └── (TBD)
├── setup.py                        # Package configuration
├── requirements.txt                # Dependencies
├── PLAN.md                         # This file
├── ENGINEERING.md                  # Copied from handoff document
└── .gitignore
```

---

## v0.1 Feature Breakdown

### Phase 1: Foundation (Days 1-3)

**Goal**: Core engine working, rule format defined, basic test structure in place.

#### Tasks:

1. **Project Setup**
   - Create `setup.py` with minimal dependencies (Python 3.11+ only)
   - Create `.gitignore` for Python
   - Create `requirements.txt` (should be empty or minimal)
   - Initialize Git repo locally

2. **Engine Core** (`agent_circuit_breaker/engine.py`)
   - Implement `Decision` class (allow, block, error, unknown)
   - Implement `Rule` class (dataclass with id, title, severity, response, metadata, matchers)
   - Implement `Engine` class with single method: `evaluate(action, rules) -> Decision`
   - No complex logic — just rule matching
   - Document decision logic clearly

3. **Rule Format**
   - Define rule structure as Python dataclass
   - Create 3-5 built-in Filesystem safety rules (examples below)
   - Keep rules human-readable

4. **Test Framework**
   - Create test structure with descriptive names
   - First test: engine accepts valid rule, rejects malformed rule
   - First test: engine returns deterministic decision

**Expected deliverable**: Engine passes 10+ tests, rule format documented.

---

### Phase 2: Filesystem Inspector (Days 4-6)

**Goal**: Filesystem inspector detects dangerous operations with high precision.

#### Tasks:

1. **Filesystem Inspector** (`agent_circuit_breaker/inspectors/filesystem.py`)
   - Implement `FilesystemInspector` class
   - Methods:
     - `normalize_path(path)` — canonicalize paths (handle `..`, `.`, symlinks)
     - `is_dangerous_target(path)` — detect system directories
     - `analyze_operation(action)` — tokenize action, identify operation (delete, write, etc.)
   - Operations to detect:
     - Recursive deletion (`rm -rf`, `rmdir /s`, `Remove-Item -Recurse`)
     - Deletion of system paths (`/`, `/System`, `C:\Windows`, etc.)
     - Unqualified bulk operations
   - Return structured analysis (operation_type, target_path, risk_level)

2. **Integration with Engine**
   - Engine loads inspectors
   - Inspectors are called before rule matching
   - Inspectors provide context to rules

3. **Comprehensive Tests**
   - Test path normalization (symlinks, `..`, `.`)
   - Test dangerous target detection across OS
   - Test operation detection (recursive delete, force delete, etc.)
   - Test edge cases (empty paths, special characters, Unicode)
   - Test malformed input (null, very long paths, invalid escape sequences)

**Expected deliverable**: Filesystem inspector passes 30+ tests, detects common dangerous patterns.

---

### Phase 3: CLI + Built-in Rules (Days 7-9)

**Goal**: End-to-end pipeline working, users can run safety checks from command line.

#### Tasks:

1. **CLI Interface** (`agent_circuit_breaker/cli.py`)
   - Command: `circuit-breaker check <action> [--rules <rule-file>]`
   - Output: `ALLOW | BLOCK | ERROR | UNKNOWN` with rationale
   - Options:
     - `--verbose` — show rule matching details
     - `--rules` — custom rule file (JSON or YAML)
     - `--format` — output format (text, json)
   - Exit codes: 0=allow, 1=block, 2=error, 3=unknown

2. **Built-in Rules** (`agent_circuit_breaker/rules/builtin_rules.py`)
   - Example rules:
     ```
     1. id=fs_recursive_delete
        title=Recursive filesystem deletion detected
        severity=CRITICAL
        response=BLOCK
        matcher: operation_type == 'recursive_delete'
     
     2. id=fs_system_path
        title=Attempt to delete system directory
        severity=CRITICAL
        response=BLOCK
        matcher: target_path in ['/root', 'C:\Windows', '/System', ...]
     
     3. id=fs_bulk_unqualified
        title=Bulk deletion without qualification
        severity=HIGH
        response=BLOCK
        matcher: operation_type == 'bulk_delete' AND not qualified
     ```

3. **Tests**
   - CLI accepts valid actions, rejects malformed
   - CLI outputs deterministic decisions
   - Exit codes correct for each decision type
   - Rule loading from file works

**Expected deliverable**: CLI works end-to-end, users can run checks.

---

### Phase 4: Documentation + Polish (Days 10-14)

**Goal**: Project is ready for public release, fully documented, all tests passing.

#### Tasks:

1. **README.md** (`docs/README.md`)
   - Project goal (one paragraph)
   - Why it matters
   - Quick start (install, basic usage)
   - Example: block recursive delete
   - Installation instructions
   - Contributing guidelines

2. **ARCHITECTURE.md** (`docs/ARCHITECTURE.md`)
   - System design overview (engine, inspectors, rules)
   - Data flow diagram (textual)
   - Decision flow (allow/block/error/unknown)
   - Why this architecture?
   - Future extensibility points

3. **DESIGN_DECISIONS.md** (`docs/DESIGN_DECISIONS.md`)
   - Why deterministic over AI?
   - Why dataclass rules instead of YAML?
   - Why filesystem first?
   - Why no dependencies?
   - Alternatives considered for each major decision

4. **ROADMAP.md** (`docs/ROADMAP.md`)
   - v0.1 complete
   - v0.2: Command Inspector
   - v0.3: SQL Inspector
   - v1.0: Production readiness
   - Companion products roadmap

5. **ENGINEERING.md** (`ENGINEERING.md`)
   - Copy the project handoff document here for reference

6. **Code Quality**
   - Docstrings for all public methods
   - Type hints throughout
   - README for each module
   - All tests passing
   - Code follows PEP 8 style

7. **Public Release Prep**
   - Create `.gitignore` (Python)
   - Add `LICENSE` (recommend: MIT or Apache 2.0)
   - Tag v0.1 in Git
   - Ready for GitHub push

**Expected deliverable**: Fully documented, public-ready v0.1.

---

## Success Criteria for v0.1

- [ ] Engine accepts and rejects rules deterministically
- [ ] Filesystem inspector detects 10+ dangerous patterns
- [ ] CLI runs `circuit-breaker check <action>` successfully
- [ ] All tests passing (target: 60+ tests)
- [ ] Zero silent failures
- [ ] All public methods documented
- [ ] README explains project goal and quick start
- [ ] ARCHITECTURE.md explains design
- [ ] DESIGN_DECISIONS.md documents tradeoffs
- [ ] Code is readable without external explanation
- [ ] Ready to push to GitHub as public v0.1

---

## Companion Products (Parallel Development)

**Strategy**: These develop independently but inform main product.

### Product 1: Rule Validator CLI
- Input: Rule file (JSON/YAML)
- Output: Validation report (well-formed? semantically sound?)
- Purpose: Help users write safe rules
- Timeline: Start after Phase 2 (needs inspector context)

### Product 2: Log Analyzer
- Input: Agent action logs
- Output: Which actions would have been blocked?
- Purpose: Retrospective safety audit
- Timeline: Start after Phase 3 (needs full pipeline)

### Product 3: Rule Library
- Collection of community-contributed rules
- Starter templates (filesystem, command, SQL)
- Versioned, documented, indexed
- Timeline: Start after v0.1 release

---

## Daily Breakdown (Recommended)

**Week 1**:
- **Day 1 (Mon)**: Phase 1 tasks (engine core, rule format, test structure)
- **Day 2 (Tue)**: Phase 1 continued (finish engine, write first 10 tests)
- **Day 3 (Wed)**: Phase 2 start (filesystem inspector basics)
- **Day 4 (Thu)**: Phase 2 continued (path normalization, dangerous target detection)
- **Day 5 (Fri)**: Phase 2 finish (operation detection, 30+ tests passing)

**Week 2**:
- **Day 6 (Mon)**: Phase 3 start (CLI basics, built-in rules)
- **Day 7 (Tue)**: Phase 3 continued (CLI full integration, end-to-end testing)
- **Day 8 (Wed)**: Phase 4 start (README, ARCHITECTURE, code quality)
- **Day 9 (Thu)**: Phase 4 continued (DESIGN_DECISIONS, ROADMAP, polish)
- **Day 10 (Fri)**: Phase 4 finish (final tests, code review, Git tag v0.1)

---

## Deferred Ideas (Post-v0.1)

These are good ideas but explicitly NOT in v0.1:

- Rule signing/verification
- Remote rule fetching
- Telemetry or logging
- Integration with specific IDEs
- Windows-specific hardening
- Machine learning for detection
- Cloud platform support
- Sandboxing or containerization
- Rule composition/inheritance
- Performance benchmarking

---

## Key Constraints

- **No external dependencies** for core engine (only Python stdlib)
- **Local-first**: Everything runs locally, no cloud assumed
- **One developer**: Everything must be runnable and understandable by one person
- **Deterministic**: Every decision is explicit and repeatable
- **Fail secure**: When in doubt, block or error, never silently allow

---

## Next Step

Approve this plan, then we proceed to Phase 1 setup immediately.

Any changes needed before we start?
