# Agent Circuit Breaker Documentation

Agent Circuit Breaker is a local-first safety runtime for AI coding agents. It evaluates proposed shell commands, filesystem operations, SQL text, and MCP tool-call arguments before execution.

## Start Here

- [Main README](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/main/README.md)
- [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [LONG_HORIZON_AGENT_SAFETY.md](LONG_HORIZON_AGENT_SAFETY.md)
- [JSON_OUTPUT_CONTRACT.md](JSON_OUTPUT_CONTRACT.md)
- [API.md](API.md)

## Policy And Rules

- [Rule schema](RULE_SCHEMA.md)
- [ALLOWLIST_PATTERN.md](ALLOWLIST_PATTERN.md)
- [Example rule packs](examples/rules/)
- [COMPATIBILITY.md](COMPATIBILITY.md)

## Operations

- [PUBLISHING.md](PUBLISHING.md)
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
- [BRANCH_PROTECTION.md](BRANCH_PROTECTION.md)
- [V1_0_PRODUCTION_READINESS.md](V1_0_PRODUCTION_READINESS.md)
- [V1_1_PLAN.md](V1_1_PLAN.md)
- [ANNOUNCEMENT.md](ANNOUNCEMENT.md)

## Design

- [Architecture](ARCHITECTURE.md)
- [Design decisions](DESIGN_DECISIONS.md)
- [Roadmap](ROADMAP.md)

## Current Coverage

The current stable package includes:

- deterministic core engine.
- filesystem, command, and SQL inspectors.
- built-in safety rules for destructive filesystem, command, infrastructure, permission, and SQL patterns.
- `ALLOW`, `BLOCK`, `UNKNOWN`, `ERROR`, and `PENDING_APPROVAL` decisions.
- external JSON rules with scalar, regex, and boolean composite matchers.
- safety profiles and strict/advisory/approval modes.
- local approval queue.
- `explain` command with risk scores and safer alternatives.
- static `scan` mode and SARIF output.
- tamper-evident audit timeline.
- central policy loading.
- signed policy/rule-pack verification.
- plugin discovery.
- pre-commit hook manifest.
- stdio JSON-RPC MCP proxy that inspects all string-valued tool-call arguments.
- HMAC-backed policy/rule-pack signatures for authenticity checks.
- trajectory JSON evaluation for long-running agent run contracts.
- optional stateful MCP trajectory enforcement across multiple tool calls.
- contextual trajectory approvals and replayable local run ledger.
- deterministic trajectory findings for secret/data egress flows.
- trusted publishing workflow for TestPyPI and PyPI.

## Release Notes

- [v1.4.6](releases/v1.4.6.md)
- [v1.4.5](releases/v1.4.5.md)
- [v1.4.4](releases/v1.4.4.md)
- [v1.4.3](releases/v1.4.3.md)
- [v1.4.2](releases/v1.4.2.md)
- [v1.4.1](releases/v1.4.1.md)
- [v1.4.0](releases/v1.4.0.md)
- [v1.3.0](releases/v1.3.0.md)
- [v1.2.0](releases/v1.2.0.md)
- [v1.1.2](releases/v1.1.2.md)
- [v1.1.1](releases/v1.1.1.md)
- [v1.1.0](releases/v1.1.0.md)
- [v1.0.1](releases/v1.0.1.md)
- [v1.0.0](releases/v1.0.0.md)

Historical pre-1.0 milestone notes remain in this directory for project archaeology, but the files above describe the supported v1.x behavior.
