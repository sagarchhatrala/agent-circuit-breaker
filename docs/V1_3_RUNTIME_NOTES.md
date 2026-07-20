# v1.3 Runtime Notes

v1.3.0 is a single release, but it is built as controlled batches around one product direction: a local-first safety runtime for AI coding agents.

## Production-Ready in v1.3

- Backward-compatible `check` behavior.
- Safety profiles and policy modes.
- `PENDING_APPROVAL` result support.
- Local approval queue.
- `explain` mode.
- `scan` mode and SARIF output.
- Tamper-evident audit timeline.
- Central policy loading from file or explicit URL.
- Plugin discovery and optional rule-provider loading.
- Extended external rule schema with regex and boolean matchers.
- Hook scaffold generation.

## Scoped as Scaffold in v1.3

### MCP Proxy

The `agent_circuit_breaker_mcp` package is a minimal JSON-lines proxy scaffold. It is useful for integration experiments and tests, but it is not yet a complete MCP transport proxy. The next hardening step is a full MCP JSON-RPC proxy with request/response forwarding, tool inventory, policy binding, and audit correlation.

### Enterprise Policy Signing

The v1.3 policy loader supports central files and explicit URLs, but cryptographic policy-pack signing is not enabled yet. This is intentionally deferred because a correct implementation needs a real trust model: identity, key rotation, signature format, revocation, and CI/release integration. Until then, policy loading remains data-only and deterministic, and signature verification should be enforced by the deployment system around the policy file.

## Compatibility

Existing v1.2 integrations remain compatible by default. New behavior is opt-in through new commands, profiles, modes, policy files, plugins, or approval-response rules.
