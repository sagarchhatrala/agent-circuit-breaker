# OpenAI Codex

Codex is a distinct product from the OpenAI Responses API. ACB uses Codex's supported
MCP registration, not the retired `.codex/hooks.json` scaffold. Only the mediated
ACB tools receive RuntimeGate enforcement; native shell and other tools do not.

Prerequisites: Python 3.11+, ACB 1.7.0, Codex with project MCP configuration support.
Local CLI observed: **codex-cli 0.163.0**. Explicit CLI configuration overrides were parsed without a model request.
Automatic discovery of the disposable project configuration did not succeed in
this environment, even with a project-trust CLI override; it remains unverified.
Native model-driven MCP invocation is also unverified;
actual tool calls were separately tested with MCP Python SDK **2.3.0**, both modern
2026-07-28 and legacy 2025-11-25 protocols.

Create the [common fixture](README.md), then:

```bash
agent-circuit-breaker integrate codex detect --mode mcp
agent-circuit-breaker integrate codex preview --mode mcp --project /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
agent-circuit-breaker integrate codex install --mode mcp --project /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
agent-circuit-breaker integrate codex verify --mode mcp --project /tmp/acb-integration-workspace
```

Complete project `.codex/config.toml`:

```toml
[mcp_servers.acb]
command = "/tmp/acb-integration-venv/bin/python"
args = ["-I", "-m", "agent_circuit_breaker_mcp.workflow_server", "--workspace", "/tmp/acb-integration-workspace", "--state", "/tmp/acb-integration-state", "--policy", "/tmp/acb-integration-workspace/policy.json"]
```

Trust the disposable project in Codex as appropriate. Run `codex mcp list` and
`codex mcp get acb`; use `/mcp` inside Codex to inspect the connected server.
Ask specifically for `acb.read_file` with `{"path":"incident.txt"}`: expect `ALLOW`,
synthetic content, and an artifact ID. `{"path":"../outside"}` must produce `BLOCK`
without starting an executor. Do not treat `integrate verify` as proof that Codex
loaded or invoked the server.

The official user-level CLI equivalent is:

```bash
codex mcp add acb -- /tmp/acb-integration-venv/bin/python -I -m agent_circuit_breaker_mcp.workflow_server --workspace /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
```

That command may affect user-level configuration; the guided installer above uses
project-scoped configuration instead. Do not run both accidentally.

Troubleshoot project trust, interpreter paths, disabled server entries, startup
logs and private state permissions. Restart retains the run and consumed authority.
Inspect interrupted executions; never delete state as a substitute for reconciliation.

Remove project integration with:

```bash
agent-circuit-breaker integrate codex uninstall --mode mcp --project /tmp/acb-integration-workspace
```

If you deliberately used user-level CLI registration, use `codex mcp remove acb`.
The installer preserves unrelated TOML and restores original bytes when unchanged.
Source: [official Codex MCP documentation](https://developers.openai.com/codex/mcp), checked November 8, 2026.
