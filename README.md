# Agent Circuit Breaker

Agent Circuit Breaker (ACB) puts explicit permission checks before an AI agent's
execution. Its trusted adapters bind actions to resources, artifact versions,
principals and single-use approvals, then record whether execution started and how
it ended. The core is local-first and uses Python's standard library.

[![ACB local demo: an unauthorized export cannot start](https://raw.githubusercontent.com/sagarchhatrala/agent-circuit-breaker/v1.7.0/docs/assets/acb-demo.png)](https://github.com/sagarchhatrala/agent-circuit-breaker/releases/tag/v1.7.0)

[Watch the demo / download captions](https://github.com/sagarchhatrala/agent-circuit-breaker/releases/tag/v1.7.0)
· [Run it offline](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/DEMO.md)

## Install and try it

Python 3.11+. The typed local workflow executor requires POSIX (Linux/macOS).

```bash
python -m pip install agent-circuit-breaker==1.7.2
agent-circuit-breaker demo
```

Open the private loopback URL. Read synthetic incident logs, create a real report,
compare an unprotected export with a denied proposal, and see approval replay and
restart protection. Proposals are labeled offline; execution and collector receipts
are fresh. No API key is needed, and all UI assets are included in the wheel.

```bash
agent-circuit-breaker demo --doctor
agent-circuit-breaker demo --replay --output /tmp/acb-replay.json
python -m agent_circuit_breaker.responses_example
```

## v1.7.2: useful operations behind a separate owner

The new owner service holds files, database access, policy and credentials behind
an authenticated Unix socket. Agents can create reports, request an approved
SQLite change, or publish an exact artifact to an owner-registered S3 destination.
The owner reviews the exact resource, bytes/rows and cumulative budget before
approving; replay, changed data and unresolved execution cannot silently retry.

```bash
agent-circuit-breaker owner init /tmp/acb-owner-example
agent-circuit-breaker owner --help
```

[Run the owner workflow](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/OWNER_SERVICE.md)
· [Separate owner/agent containers](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/examples/owner/README.md)
· [Release notes](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/releases/v1.7.2.md)
· [Execution evidence](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/validation/v1.7.2-results.md)

Cumulative row/file/export-byte budgets survive restart. Supported transforms
preserve sensitivity labels; only the owner can declassify reviewed bytes.
Signed, paginated evidence can be retained independently. Same-UID development
mode is for rehearsal; protected deployment requires OS isolation and removal of
alternate access to the resources. SQLite support is deliberately bounded.

## Integrations

| Product | Integration | Verification scope |
|---|---|---|
| [Claude Code](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/integrations/claude-code.md) | Native PreToolUse adapter; mediated MCP | Configuration/event fixtures; native host unverified |
| [Cursor](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/integrations/cursor.md) | Separate shell/MCP hooks; mediated MCP | Desktop-targeted fixtures; native host unverified |
| [OpenAI API](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/integrations/openai-api.md) | Responses function dispatcher | Real offline executor; live API opt-in |
| [Codex](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/integrations/codex.md) | Project-scoped MCP configuration | CLI overrides and MCP SDK; project discovery/native invocation unverified |

Guided commands provide detection, preview, merge, verification and uninstall.
[Integration quickstart and tested versions](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/integrations/README.md).

## Decisions and the boundary

Only `ALLOW` authorizes execution. `BLOCK`, `UNKNOWN`, `PENDING_APPROVAL`, and `ERROR`
remain distinct and cannot silently start a protected executor. A natural-language
goal, tool description, model opinion or low risk score never grants permission.

**ACB protects its trusted execution path.** It is not an OS sandbox and cannot
protect tools that bypass it, disabled hooks, or owner policy/state the agent can
modify. Native hooks permit host-owned execution; mediated tools own the full
RuntimeGate lifecycle. Provenance covers the supported typed transformations, not
arbitrary shell/Python/model information flow.

[Verified scenarios and limitations](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/validation/v1.7.0-independent-review.md)
· [Security model](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/WORKFLOW_SECURITY.md)
· [Enforcement matrix](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/ADAPTER_ENFORCEMENT_MATRIX.md)
· [Runtime API](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/API.md)
· [Release notes](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/releases/v1.7.2.md)
· [Compatibility](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/docs/COMPATIBILITY.md)
· [Support](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/SUPPORT.md)
· [MIT license](https://github.com/sagarchhatrala/agent-circuit-breaker/blob/v1.7.2/LICENSE)
