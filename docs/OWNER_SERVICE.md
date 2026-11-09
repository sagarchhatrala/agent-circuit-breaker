# Owner-mediated execution (v1.7.2)

Use the owner service when an agent should propose operations while a separate
process holds the resources, policy, credentials and approval authority. Its Unix
agent socket exposes typed tools; its private control socket exposes owner review.
Both routes use the existing RuntimeGate and durable SQLite start/outcome records.
The package has no required third-party runtime dependencies.

## Try a real local workflow

Linux/macOS, Python 3.11+. These commands create **synthetic** data in a new
directory. Use a short absolute path for Unix sockets. On macOS, use the resolved
paths printed by `init` (usually `/private/tmp/...`).

```bash
python -m pip install agent-circuit-breaker==1.7.2
agent-circuit-breaker owner init /tmp/acb-owner-example
```

The JSON result supplies `workspace`, `state`, `config`, `agent_socket` and
`control_socket`. Substitute those exact values below. In terminal one:

```bash
agent-circuit-breaker owner serve \
  --workspace /tmp/acb-owner-example/workspace \
  --state /tmp/acb-owner-example/state \
  --config /tmp/acb-owner-example/owner.json \
  --socket /tmp/acb-owner-example/socket/agent.sock \
  --agent-uid "$(id -u)" --development
```

In terminal two, use the actual paths printed by `init`:

```bash
agent-circuit-breaker owner verify \
  --socket /tmp/acb-owner-example/socket/agent.sock \
  --control-socket /tmp/acb-owner-example/state/control.sock \
  --report reports/verified.json
```

This reads the source, writes a new report file, independently inspects its bytes
through the owner socket, and attempts a denied traversal. It consumes one file
from the example's budget; reruns require a new report filename.

`--development` permits the same UID for both roles and **does not isolate an
agent**. For protected resources use the [Linux container recipe](../examples/owner/README.md).
Without that flag, the service requires distinct UIDs. On Linux it authenticates
socket peers with `SO_PEERCRED`; macOS uses `getpeereid`. Agent requests cannot
supply a principal, capability, effects measurement or owner approval.

## Review and execute a database change

The generated database contains three synthetic tickets. Its registered
`close_ticket` operation permits one row per call and two rows cumulatively:

```bash
agent-circuit-breaker owner call database_change \
  --socket /tmp/acb-owner-example/socket/agent.sock \
  --arguments '{"operation":"close_ticket","parameters":{"id":1,"status":"closed"}}'
```

This returns `PENDING_APPROVAL` and a `review_id`, with no source database change.
The CLI exits 3 for pending, 2 for unknown, 1 for block/error, and 0 for success.
Read the decision and `outcome`; a successful review command is not execution.

As the owner, inspect the review ID. The response includes the exact action
fingerprint, registered SQL, bound parameters, row count, before/after hashes,
up to ten changed rows, resource, budgets and policy fingerprint:

```bash
agent-circuit-breaker owner inspect REVIEW_ID --socket /tmp/acb-owner-example/state/control.sock
agent-circuit-breaker owner approve REVIEW_ID \
  --socket /tmp/acb-owner-example/state/control.sock \
  --fingerprint EXACT_INSPECTED_FINGERPRINT --ttl-seconds 300
agent-circuit-breaker owner commit REVIEW_ID --socket /tmp/acb-owner-example/socket/agent.sock
```

Use `owner reject REVIEW_ID --socket CONTROL_SOCKET` to reject/revoke an active
review. A changed plan, expired approval or consumed approval cannot execute.
Concurrent commit requests cannot consume the approval twice. Restart reuses the
same run and review store; it does not reset budgets or revive approvals.

Only the owner registers SQL. This release supports parameterized SQLite UPDATE
and DELETE on one regular rowid table. Parameters are scalar JSON values; SQL
fragments and additional parameter names are refused. Preview executes on a
private in-memory backup, not the live database. Execution uses `BEGIN IMMEDIATE`,
revalidates the full table/schema snapshot, checks the actual rows/result, then
commits. Changed data requires a fresh review.

The bounded profile limits the database preview to 64 MiB, the target table to
10,000 rows/1 MiB, parameters to 32 names and strings to 4,096 characters. Triggers,
views, virtual tables, shadowed row identities, WITHOUT ROWID tables, non-JSON
values, cross-table effects, attached databases and arbitrary functions are
unsupported. Foreign-key operations that require another table are refused by the
authorizer. Registering a table also permits agents to see its preview samples;
do not register data they must not read. This is not a universal SQL/ORM firewall.

## Tools and provenance

`owner tools --socket AGENT_SOCKET` returns JSON schemas. The owner route has:

| Tool | Actual operation |
|---|---|
| `read_file` | Read an owner-pinned file version and classify an artifact |
| `copy_artifact` | Create a new file with exactly the source bytes |
| `encode_artifact` | Create a Base64 file, preserving labels |
| `write_report` | Render a fixed incident report from source artifacts |
| `repository_status` | Bounded status from a sanitized local Git metadata snapshot |
| `publish_artifact` | Approved, conditional S3-compatible PUT to a registered destination |
| `json_artifact` | Canonicalize JSON, preserving labels |
| `redact_artifact` | Apply existing secret-pattern redaction, preserving labels |
| `database_change` | Preview/approve/execute a registered SQLite operation (if configured) |
| `review_operation` | MCP preview of a named operation without execution |
| `execute_review` | MCP execution of an owner-approved review ID |

No tool can run arbitrary shell code, supply raw SQL or lower an artifact's labels.
Output files are created without overwriting existing files. The original six-tool
Workflow API remains available with its existing catalog and publisher callback.

Pattern redaction is imperfect: **it never automatically declassifies data**.
The owner can inspect `owner artifact --socket CONTROL_SOCKET --json
'{"artifact_id":"ID"}'`, review the actual bytes, then deliberately create a new
artifact with reviewed labels:

```bash
agent-circuit-breaker owner declassify --socket CONTROL_SOCKET --json \
  '{"artifact_id":"ID","sha256":"REVIEWED_SHA256","path":"reports/public.json","labels":["public"],"reason":"Reviewed redacted output for this destination"}'
```

The exact hash must still match. Declassification is logged as an owner action,
consumes a file budget and is unavailable on the agent socket or MCP catalog.
Copying/encoding/redacting alone cannot bypass a destination's label restriction.

## Owner configuration and S3

Start from the generated `owner.json`. Keep it and the resources inaccessible to
the agent. A minimal S3 addition is:

```json
{
  "workflow": {
    "principal": "maintenance-agent",
    "read_paths": {"incident.json": {"sha256": "OWNER_COMPUTED_HASH", "labels": ["internal"]}},
    "report_directory": "reports",
    "destinations": {"archive": ["internal", "public"]}
  },
  "s3_destinations": {
    "archive": {
      "endpoint": "https://s3.us-east-1.amazonaws.com",
      "region": "us-east-1",
      "bucket": "your-existing-bucket",
      "prefix": "reviewed-reports",
      "access_key_env": "ACB_ARCHIVE_ACCESS_KEY",
      "secret_key_env": "ACB_ARCHIVE_SECRET_KEY",
      "session_token_env": "ACB_ARCHIVE_SESSION_TOKEN"
    }
  },
  "effect_limits": {"files_written": 10, "export_bytes": 1048576, "database_rows": 2},
  "max_actions": 500,
  "ttl_seconds": 86400
}
```

Supply credentials only to the owner environment; omit `session_token_env` when
not using temporary credentials. Use least-privilege bucket/prefix permissions.
Each workflow destination must have exactly one S3 registration. Destination
endpoint, region, bucket, prefix and artifact path are owner-bound. The agent
cannot substitute a URL/key. The key is `prefix/artifact-path`.

PUT uses SigV4, SHA-256 payload/checksum headers and `If-None-Match: *`. HTTPS is
required by default. Redirects and environment proxies are disabled. There are no
automatic retries. Timeouts, ambiguous responses and post-dispatch failures hold
the reservation and require owner reconciliation. A receipt establishes server
acceptance, not independent durable-retention proof. Release checks use Moto and
MinIO, including actual object retrieval and wrong-signature rejection; they do
not establish certification against every S3 implementation or live AWS account.
`allow_http_for_testing: true` exists for explicitly configured disposable fixtures.

## Budgets, restart and uncertain outcomes

Reservations are charged at atomic execution start. Trusted executors return
measured effects no greater than the reservation; unused reservation can then be
released. A failed, interrupted or uncertain execution conservatively retains its
reservation until an owner supplies explicit measured reconciliation evidence.
An agent-declared byte/row count is never a trusted measurement.

For this adapter, `files_written` counts created output artifacts;
`database_rows` counts SQLite rows affected (including matched no-op updates);
`export_bytes` counts S3 payload bytes. File reads, database previews, MCP replies,
protocol overhead, monetary spend and arbitrary external tools are **not** charged
to `export_bytes`. Additional metrics require a trusted adapter. Generic RuntimeGate
integrations opt in with `RunContract.effect_limits`, `RuntimeAction.metadata.effects`
and `EffectResult` from `agent_circuit_breaker.effects`.

Use `owner status` to see limits/usage. The owner has one active durable run per
state directory. Exhaustion/expiry does not create fresh authority automatically.
Stop the service, retain/export and review the old state, then initialize a new
state directory only when deliberately granting a new budget. Configuration or
database inode changes also require deliberate new authority; deleting the run
pointer does not reset existing authority. No multi-host failover is provided.

For an uncertain operation, independently inspect the exact destination and find
its authorization/action fingerprint in exported evidence. Only the control
socket accepts `reconcile` with those identifiers, an outcome and evidence:

```bash
agent-circuit-breaker owner reconcile --socket CONTROL_SOCKET --json \
  '{"authorization_id":"ID","action_fingerprint":"HASH","outcome":"executed","evidence":{"observation":"Independently retrieved the exact reviewed object","effects":{"export_bytes":123}}}'
```

Do not infer failure from a lost response. Reconciliation does not revive a
consumed approval or automatically retry an operation. Retry IDs are supported by
the socket `call`/`commit` `request_id` field (CLI `--json`); reusing an ID with new
arguments is refused. An interrupted request stays uncertain even after restart.

## Retain and verify evidence

```bash
agent-circuit-breaker owner export --socket CONTROL_SOCKET --output page-0.json --limit 25
agent-circuit-breaker owner verify-evidence page-0.json --key-file /protected/state/provenance.key
```

Repeat with `--from-sequence NEXT_SEQUENCE` until `next_sequence` is null. Each
page is HMAC-authenticated and includes run ID, policy fingerprint, state version,
total event count and sequence boundaries. Retain every page and the verification
key separately from agent-writable storage. For a consistent snapshot, stop agent
requests while exporting and ensure the same state version across pages. If a
response is too large, lower `--limit` (minimum one event). Individual request and
response limits are 1 MiB. Redaction minimizes recognized secrets in exported
records; review exports before sharing them.

HMAC detects modification without the key. A compromised owner/key holder can
forge evidence, and deleting all local evidence cannot be detected without an
independently retained checkpoint. This is not immutable or publicly verifiable
storage. Service request/review records are local owner-protected state, not an
unbounded production archival service; monitor storage and rotate runs deliberately.

## Connect an MCP client

Run the owner separately, then generate project configuration:

```bash
agent-circuit-breaker integrate claude preview --mode mcp --owner-socket /absolute/socket/agent.sock
agent-circuit-breaker integrate claude install --mode mcp --owner-socket /absolute/socket/agent.sock
```

Use `cursor` or `codex` for their configuration formats. The generated command runs
`python -I -m agent_circuit_breaker_mcp.owner_client --socket ...`. Give that process
only the agent socket; no private state, database, bucket credentials or direct
resource mounts. `integrate verify` verifies configuration, while `owner verify`
executes a real route. MCP SDK tests cover modern and legacy stdio protocols.
Configuring this server does not mediate native shell tools or other MCP servers.

## Reproduce the execution checks

From a checkout with the installed package:

```bash
python -I scripts/owner_smoke.py
python -m pip install 'mcp==2.3.0' 'moto[server]' boto3
python -I scripts/mcp_sdk_smoke.py
python -I scripts/verify_owner_workflows.py --seed 172 --output /tmp/owner-results.json
python scripts/verify_owner_isolation.py --wheel dist/agent_circuit_breaker-1.7.2-py3-none-any.whl
```

The last command requires Linux Docker. The scenario runner measures real effects,
replay, mutation, concurrent commits, budgets and crash recovery, with request
p50/p95 latency. It is a seeded synthetic acceptance corpus, not evidence of market
superiority or broad prompt-injection recall. See the [release validation](validation/v1.7.2-results.md).
