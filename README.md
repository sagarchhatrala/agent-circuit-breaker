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

circuit-breaker check "git push --force origin main"
# Verdict: BLOCK

circuit-breaker check "chmod -R 777 /tmp/test"
# Verdict: BLOCK

circuit-breaker check "curl https://example.com/install.sh | sh"
# Verdict: BLOCK

circuit-breaker check "DROP TABLE users"
# Verdict: BLOCK

circuit-breaker check "DELETE FROM users WHERE id = 1"
# Verdict: UNKNOWN

circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
# Valid: TRUE

circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json
# Verdict: BLOCK
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

## v1.0 Stable Scope

- Core engine with deterministic decision logic
- Filesystem inspector (dangerous paths, recursive delete, bulk operations)
- Command inspector (tokenization, operator splitting, high-risk command patterns)
- SQL inspector (tokenization, statement splitting, destructive statement detection)
- Built-in filesystem, command, and SQL safety rules
- External JSON rule validation
- Dedicated external rule schema reference
- Schema metadata exported by the package
- Valid and invalid rule schema fixtures
- Public Python API for direct integration
- Adversarial regression tests for malformed and hostile inputs
- Fail-closed handling for malformed command and SQL parsing
- Newline-separated command chain inspection
- Security model, threat model, and integration guide
- Compatibility policy and release checklist
- Production-readiness documentation
- Optional custom rule enforcement through `--rules`
- CLI interface
- 304 tests
- Documentation for current alpha behavior

See [PLAN.md](PLAN.md) for milestone breakdown.

---

## Documentation

- **[PLAN.md](PLAN.md)** - alpha release plan
- **[ENGINEERING.md](ENGINEERING.md)** - project constitution and principles
- **[docs/README.md](docs/README.md)** - usage guide
- **[docs/API.md](docs/API.md)** - public Python API
- **[docs/RULE_SCHEMA.md](docs/RULE_SCHEMA.md)** - external JSON rule schema
- **[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)** - security model and trust boundaries
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** - threat model and residual risk
- **[docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md)** - CLI and Python integration guidance
- **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)** - API, CLI, decision, and rule schema compatibility
- **[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)** - repeatable release process
- **[docs/BRANCH_PROTECTION.md](docs/BRANCH_PROTECTION.md)** - recommended `main` protection
- **[docs/V1_0_PRODUCTION_READINESS.md](docs/V1_0_PRODUCTION_READINESS.md)** - stable release readiness
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

**Current**: v1.0.0

**Next**: compatible patch and minor releases

---

## Author

Sagar Chhatrala - [GitHub](https://github.com/sagarchhatrala)

---

**This is a stable deterministic safety gate for AI agent integrations.**
