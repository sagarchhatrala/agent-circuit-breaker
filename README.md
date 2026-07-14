# Agent Circuit Breaker

**Deterministic safety layer for AI coding agents.**

## Goal

Place an explicit safety checkpoint between AI agents and the operating system.

Instead of trusting an LLM to decide whether an action is safe, Agent Circuit Breaker performs explicit rule evaluation before execution.

**Objective**: Stop catastrophic mistakes (recursive deletion, destructive SQL, accidental production access) while keeping false positives extremely low.

---

## Quick Start

### Installation

```bash
pip install agent-circuit-breaker
```

### Usage

```bash
circuit-breaker check "rm -rf /etc"
# Verdict: BLOCK

circuit-breaker check "mkdir /tmp/example"
# Verdict: ALLOW

circuit-breaker check "ls /home"
# Verdict: UNKNOWN

circuit-breaker check "rm -rf /" --format json
# JSON result with verdict, decision, matched rule, and operation analysis
```

---

## Why This Matters

Modern AI coding agents can:
- Execute shell commands
- Modify files
- Write scripts
- Interact with databases

Without a deterministic safety layer, an LLM hallucination or misalignment can cause:
- Data loss (recursive filesystem deletion)
- Security breaches (credential exfiltration)
- Downtime (infrastructure-wide destructive commands)

**Agent Circuit Breaker** catches these before they execute.

---

## Design Philosophy

1. **Deterministic over AI** - Explicit rules beat probabilistic reasoning
2. **Fail secure** - When in doubt, block
3. **Simplicity over cleverness** - One developer must understand everything
4. **No silent failures** - Always explicit (allow/block/error/unknown)
5. **Minimal dependencies** - Python stdlib only

---

## Architecture

```
Action -> Inspector(s) -> Rules -> Engine -> Decision (allow/block/error/unknown)
```

- **Inspector**: Domain-specific analysis (filesystem, command, SQL)
- **Rule**: Declarative policy
- **Engine**: Rule matcher

---

## v0.1 Scope

- Core engine with deterministic decision logic
- Filesystem inspector (dangerous paths, recursive delete, bulk operations)
- 5+ built-in safety rules
- CLI interface
- 100+ tests
- Documentation in progress

See [PLAN.md](PLAN.md) for milestone breakdown.

---

## Documentation

- **[PLAN.md](PLAN.md)** - alpha release plan
- **[ENGINEERING.md](ENGINEERING.md)** - project constitution and principles
- **[docs/README.md](docs/README.md)** - usage guide
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - system design
- **[docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md)** - rationale
- **[docs/ROADMAP.md](docs/ROADMAP.md)** - future milestones

---

## Contributing

Contributions welcome! See [ENGINEERING.md](ENGINEERING.md) for collaboration style.

Pull requests should:
- Include tests
- Follow PEP 8
- Update documentation
- Explain rationale

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Companion Products

See [projects/README.md](projects/README.md) for planned companion tools:
- Rule Validator CLI
- Log Analyzer
- Rule Library

---

## Status

**Current**: v0.1.0-alpha.1

**Next**: finish v0.1 documentation and CLI polish

---

## Author

Sagar Chhatrala - [GitHub](https://github.com/sagarchhatrala)

---

**This is an experimental project focused on deterministic safety for AI agents.**
