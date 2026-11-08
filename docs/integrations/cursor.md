# Cursor

Prerequisites: Python 3.11+, ACB 1.7.0, a Cursor desktop version supporting the
current documented project hooks and `failClosed`. No native Cursor desktop or CLI
was available for this release's local checks. Fixtures target the **desktop agent**;
CLI/cloud support is not claimed. Record your installed version before native tests.

```bash
agent-circuit-breaker integrate cursor detect --mode hooks
agent-circuit-breaker integrate cursor preview --mode hooks
agent-circuit-breaker integrate cursor install --mode hooks
agent-circuit-breaker integrate cursor verify --mode hooks
```

Complete minimal `.cursor/hooks.json` (the installer inserts your interpreter path):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{
      "command": "/tmp/acb-integration-venv/bin/python -I -m agent_circuit_breaker.hooks_native cursor beforeShellExecution",
      "timeout": 10,
      "failClosed": true
    }],
    "beforeMCPExecution": [{
      "command": "/tmp/acb-integration-venv/bin/python -I -m agent_circuit_breaker.hooks_native cursor beforeMCPExecution",
      "timeout": 10,
      "failClosed": true
    }]
  }
}
```

Cursor's MCP input has a **JSON string** `tool_input`, `tool_name` and
`mcp_server_name`. It is not Claude's `tool_input` object. The adapter validates each
format separately and emits `permission`, `user_message` and `agent_message`.
It never interprets the MCP launch `command` as the tool's proposed shell command.

Fixture-only checks, which do not execute their command strings:

```bash
printf '%s' '{"command":"mkdir /tmp/acb-hook-fixture","cwd":"/tmp"}' | agent-circuit-breaker hook cursor beforeShellExecution
printf '%s' '{"command":"rm -rf /","cwd":"/tmp"}' | agent-circuit-breaker hook cursor beforeShellExecution
```

Expect `permission: "allow"`, then `"deny"`. All non-ALLOW outcomes deny. Generic
MCP calls without a trusted adapter return `UNKNOWN` and deny. Use mediated MCP as
a separate integration path. These hooks permit host-owned execution; they do not
provide RuntimeGate consumption/outcome evidence.

Native walkthrough: in an empty project, ask Cursor to create a disposable
directory, then recursively remove it. The second action should be denied and the
directory remain. Test a missing hook executable and a timeout: `failClosed: true`
should deny. Current documentation says crashes/timeouts otherwise fail open.
Enable “Block until hooks are ready” where applicable and check Cursor's Hooks logs.
Do not infer cloud-agent behavior from desktop fixtures.

## Mediated MCP

Create the [common fixture](README.md), then:

```bash
agent-circuit-breaker integrate cursor preview --mode mcp --project /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
agent-circuit-breaker integrate cursor install --mode mcp --project /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
agent-circuit-breaker integrate cursor verify --mode mcp --project /tmp/acb-integration-workspace
```

Complete `.cursor/mcp.json`:

```json
{"mcpServers":{"acb":{"command":"/tmp/acb-integration-venv/bin/python","args":["-I","-m","agent_circuit_breaker_mcp.workflow_server","--workspace","/tmp/acb-integration-workspace","--state","/tmp/acb-integration-state","--policy","/tmp/acb-integration-workspace/policy.json"]}}}
```

Enable the server in Cursor's MCP settings. `read_file({"path":"incident.txt"})`
returns an actual artifact with `ALLOW`; `read_file({"path":"../outside"})` returns
`BLOCK` without starting an executor. The same dispatcher was tested with the MCP
Python SDK; native Cursor tool invocation remains unverified.

Troubleshoot wrong interpreter paths, disabled project servers and unsupported
hook options. Run `demo --doctor` to check the package independently of Cursor.
Remove with `agent-circuit-breaker integrate cursor uninstall --mode hooks`, or
`--mode mcp --project /tmp/acb-integration-workspace`. Unrelated configuration is
preserved; private backups are in `.acb-integrations/`. Restart/reload Cursor.
