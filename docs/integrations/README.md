# Integration quickstart

ACB has two different boundaries: native hooks return a decision to a host;
mediated tools execute inside ACB's trusted dispatcher. Protecting mediated tools
does not protect the host's native shell, hosted tools, or other MCP servers.

| Product | Path | Validation for v1.7.0 |
|---|---|---|
| [Claude Code](claude-code.md) | Native `PreToolUse`; stdio MCP | Documented payload/config fixtures; native host unavailable |
| [Cursor](cursor.md) | Separate shell/MCP hooks; stdio MCP | Documented desktop payload/config fixtures; desktop/CLI unavailable |
| [OpenAI API](openai-api.md) | Responses function dispatcher | Real offline execution; SDK imported; live API opt-in, not run |
| [Codex](codex.md) | Project `.codex/config.toml` MCP | CLI override parsing and MCP SDK calls; project discovery/native invocation unverified |

Generated commands use a fixed installed interpreter with Python `-I` isolation,
so a project-local shadow module or `PYTHONPATH` cannot replace the adapter. The
package must be installed in that interpreter; source-only module lookup is not
a supported host setup.

All examples use synthetic fixtures. The core has no third-party runtime
requirements. Python 3.11+ is required. Typed file workflows additionally require
POSIX no-follow directory descriptors. Generic evaluation remains portable.

## Create the common fixture

```bash
python3 -m venv /tmp/acb-integration-venv
/tmp/acb-integration-venv/bin/pip install agent-circuit-breaker==1.7.0
. /tmp/acb-integration-venv/bin/activate
/tmp/acb-integration-venv/bin/agent-circuit-breaker demo --fixture-project /tmp/acb-integration-workspace
```

Use a new directory name if that path exists. The command refuses overwriting an
existing workspace. `policy.json` includes exact source hashes, trusted sensitivity
labels, principal, report directory and allowed destination. Read it before use.
The prose goal is explanatory metadata, not automatically understood intent.

A trusted service must protect its policy, Python installation, state/key directory
and control channel from the agent. A project-local config is convenient and
reviewable; it is not tamper-proof against a host agent allowed to edit it. Separate
OS identities or an appropriate sandbox must supply that boundary in deployment.
The demonstration uses a fixed fixture executor and runs no untrusted process.

## Modern MCP and compatibility

The stdio server supports protocol **2026-07-28** (`server/discover` and per-request
metadata) and legacy initialization revisions through **2025-11-25**. Notifications
never execute tools or receive responses. Cancellation preserves uncertain or
unresolved execution; it does not assert rollback. Requests are bounded, duplicate
IDs are rejected, and logs stay on stderr. The durable run is reused after restart. One MCP server process owns each state
directory for its lifetime; a second process receives a busy error. Use separate
owner-reviewed state directories for independent hosts, never as a way to bypass
a run suspension.
A missing run index alongside existing state requires owner inspection and an
explicit `--run-id`; it never silently resets authority.

The legacy `agent-circuit-breaker-mcp-proxy` remains an inspection/forwarding path.
Its HTTP mode is a custom JSON POST bridge, **not** a complete Streamable HTTP
implementation. The new executor integration is stdio only.

Official sources rechecked November 8, 2026:
[Claude hooks](https://code.claude.com/docs/en/hooks),
[Claude MCP](https://code.claude.com/docs/en/mcp),
[Cursor hooks](https://cursor.com/docs/agent/hooks),
[Cursor MCP](https://cursor.com/docs/context/mcp),
[Responses function calling](https://developers.openai.com/api/docs/guides/function-calling),
[Codex MCP](https://developers.openai.com/codex/mcp),
[MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28),
[MCP versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[MCP stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio).
