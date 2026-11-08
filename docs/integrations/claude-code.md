# Claude Code

Prerequisites: Python 3.11+, ACB 1.7.0, Claude Code **2.1.295 or later** for
`onFailure: "block"`. The native host was unavailable during local validation;
input/output and installation fixtures passed. This is not a native-host test.

## Native hook

From your disposable project:

```bash
agent-circuit-breaker integrate claude detect --mode hooks
agent-circuit-breaker integrate claude preview --mode hooks
agent-circuit-breaker integrate claude install --mode hooks
agent-circuit-breaker integrate claude verify --mode hooks
```

The installer merges `.claude/settings.json`, preserves unrelated settings and
keeps a private restoration receipt in `.acb-integrations/`. Repeating installation
is idempotent. Minimal configuration (use your installed Python's absolute path):

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|mcp__.*",
      "hooks": [{
        "type": "command",
        "command": "/tmp/acb-integration-venv/bin/python -I -m agent_circuit_breaker.hooks_native claude PreToolUse",
        "timeout": 10,
        "onFailure": "block"
      }]
    }]
  }
}
```

These fixture checks evaluate text; they never execute the enclosed command:

```bash
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"mkdir /tmp/acb-hook-fixture"}}' | agent-circuit-breaker hook claude PreToolUse
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | agent-circuit-breaker hook claude PreToolUse
```

Expect `hookSpecificOutput.permissionDecision` to be `allow`, then `deny`.
`UNKNOWN`, `PENDING_APPROVAL` and `ERROR` all emit denial with the original ACB
outcome in the reason. Diagnostics go to stderr. Arbitrary MCP schemas abstain.

For native validation, restart Claude Code in the disposable project, inspect
`/hooks`, and ask it to create a disposable directory. Then ask it to recursively
remove that same directory: ACB should deny, leaving it present. Test a deliberately
missing hook executable too: `onFailure: "block"` must stop the tool. Do not use
valuable files as denied-operation test targets. Record your actual host version.

The host owns execution after a permit. This hook cannot attest completion, prevent
execution if disabled, or protect unrelated events. Old host versions may fail open
on missing/crashed hooks. Post-execution callbacks cannot prevent earlier effects.

## ACB-owned MCP tools

Create the [common fixture](README.md), then:

```bash
agent-circuit-breaker integrate claude preview --mode mcp --project /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
agent-circuit-breaker integrate claude install --mode mcp --project /tmp/acb-integration-workspace --state /tmp/acb-integration-state --policy /tmp/acb-integration-workspace/policy.json
agent-circuit-breaker integrate claude verify --mode mcp --project /tmp/acb-integration-workspace
```

Minimal `.mcp.json`:

```json
{"mcpServers":{"acb":{"command":"/tmp/acb-integration-venv/bin/python","args":["-I","-m","agent_circuit_breaker_mcp.workflow_server","--workspace","/tmp/acb-integration-workspace","--state","/tmp/acb-integration-state","--policy","/tmp/acb-integration-workspace/policy.json"]}}}
```

Approve the project MCP configuration in Claude Code when prompted. Call `read_file`
with `{"path":"incident.txt"}`: expect `ALLOW`, actual text and artifact identity.
Call it with `{"path":"../outside"}`: expect `BLOCK`, executor not started.
Generic native MCP hooks currently abstain; use the mediated path separately rather
than layering a generic deny hook over it. Native tools remain outside its boundary.

Troubleshooting: check executable paths, Python version, project trust, state mode
0700, and stderr. `integrate verify` checks configuration/fixtures, not host loading.
Inspect a blocked or interrupted run with `runtime-inspect STATE/runtime.sqlite3 RUN_ID`.
Do not delete state to retry an uncertain publication.

Remove either integration with `agent-circuit-breaker integrate claude uninstall
--mode hooks` or `--mode mcp --project /tmp/acb-integration-workspace`. Uninstall
restores original bytes if unchanged and preserves later unrelated edits; managed
conflicts stop for manual restoration. Restart the host afterward.
