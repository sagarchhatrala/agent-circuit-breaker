# Historical pre-v1.7.1 snapshot

This report records the initial 9 November verification of v1.7.0 and its first
local fixes. For the subsequently fixed SQL/MCP/ledger gaps and released behavior,
see [v1.7.1 verification](v1.7.1-results.md). Counts and limitations below describe
that earlier snapshot and are retained as evidence.

# AppSec Days India 2026: local execution verification

Verified on 9 November 2026, starting from commit `d6dd54531652853db5b34b24938fb6d3f1b70dc3` (v1.7.0).

**The conference demonstrations work with the local fixes described below. The published v1.7.0 release still reproduces defects.** This is a scoped engineering verification, not evidence that arbitrary agent actions are safe.

The independent rehearsal exercises 126 checks: 121 functional checks and five explicit observations of coverage limits. The published package failed 20 checks. The patched wheel passed all 126 outside the checkout on Python 3.11.18, 3.12.16, and 3.14.8 (macOS ARM64). Those 20 failures include multiple demonstrations of the same defects; they are not 20 independent vulnerabilities.

The pre-existing suite passed before these defects were found: 679 tests and 380 subtests. With seven new regression tests, the suite passes 686 tests and 422 subtests on Python 3.14.8. The CI configuration now includes the new rehearsal separately from the unit suite; that workflow change has not run remotely yet.

## What actually ran

All destructive payloads went through real ACB evaluation or a real proxy process. The independent shell executor only executes a fixed set of harmless fixture commands. Any other command that unexpectedly passes can reach a recorder but cannot run. This keeps the exercise safe independently of ACB's correctness.

- Real `touch` commands through `RuntimeGate` and `RuntimeToolExecutor`, with files checked afterward. The original scope escape actually created an out-of-scope file inside a temporary directory; the patched gate never calls the executor for it.
- Real SQLite databases with three fixture rows. A permitted qualified delete removes exactly one row; denied DROP, bulk DELETE, tautological UPDATE, and stacked statements leave the table and data intact.
- A real synthetic `.env` read, a real SQLite export, and real `curl` requests to a loopback-only HTTP collector. The public upload arrives. Secret and export uploads are denied before the upload executor starts.
- Real stdio MCP proxy subprocesses and HTTP MCP proxy requests, with an independent upstream recording every received request. Denied calls are verified absent from that record.
- Real MCP SDK 2.3.0 clients using both supported protocol modes in `scripts/mcp_sdk_smoke.py`. The guarded workflow server creates an actual report, denies a traversal request without starting execution, and reuses its durable run after restart.
- SQLite runtime persistence and a consumed authorization replay. Restart retains the authorization state; a second execution attempt raises before calling the executor.
- Real audit/ledger files, deliberate edits, public-hash recomputation, truncation, verification, checkpoint validation, and replay.
- Real generated pre-command hooks and the real pre-commit runner in a temporary Git repository. The pre-commit check uses the shipped manifest's entry with the installed package; it does not fetch or publish a repository.
- A built wheel installed with `--no-index` into a fresh environment, exercised from `/tmp` using Python isolated mode. Wheel/sdist metadata checks and the existing package smoke and demo doctor also pass.

Cloud, Kubernetes, Docker deletion, package publication, fork bombs, and system-path deletion were evaluated as proposed commands and never executed. No real credentials, production resources, package uploads, Slack messages, GitHub writes, or external exfiltration endpoints were used.

## Claim-by-claim results

| Conference claim | Verified behavior and limits |
| --- | --- |
| NFKC, format/zero-width stripping, homoglyph translation | ASCII, zero-width, Cyrillic `м`, fullwidth characters, and a format-character variant all normalize to `rm -rf /` and match `fs_recursive_delete`. This is inspection normalization; it does not rewrite execution text or prove a shell interprets a visual lookalike as ASCII. |
| Filesystem protection | Recursive deletion and system-path deletion return BLOCK. Real denied fixture deletion never reaches the executor and leaves its sentinel intact. |
| Shell risk flags | Force push, remote script pipe, destructive Docker, AWS/Azure/GCP deletion, forceful Kubernetes deletion, context-free npm publication, and fork-bomb samples return BLOCK with the expected rule. |
| SQL protection | DROP TABLE/DATABASE, TRUNCATE, unqualified DELETE/UPDATE, simple tautologies, comments, and stacked statements match their rules. SQLite verifies the protected table remains intact. Detection is a finite heuristic, not full SQL semantics. |
| Ordered rules | Direct engine calls confirm first-match-wins. A custom allow appended through the public API cannot override an earlier built-in block. |
| All five outcomes | CLI/API exercises ALLOW, BLOCK, PENDING_APPROVAL, UNKNOWN, and ERROR. Only ALLOW produces a successful gate exit. Malformed rule files produce validation diagnostics and a nonzero exit. |
| Matcher failures | An intentionally failing matcher returns ERROR and prevents a later allow rule from taking effect. |
| Trajectory accumulation | Repeated blocked attempts, unknown volume, forbidden target boundaries, write scopes, output channels, direct/sequential secret egress, data-export egress, and download-then-execute all produce their corresponding findings. |
| Pre-execution runtime | Actual file, database, and loopback side effects happen only after authorization through the tested wrapper. PENDING_APPROVAL, UNKNOWN, malformed actions, and BLOCK do not call its executor. |
| MCP guarding | Real stdio and legacy HTTP transports stop tested dangerous argument strings. Nested arguments, unknown actions, malformed envelopes, approval, and cross-call trajectory cases are covered. Generic tool semantics remain a limitation below. |
| SARIF | Actual scan output contains filesystem and SQL findings with locations; the generated file validates against the full SARIF 2.1.0 schema. |
| GitHub Code Scanning | Historical workflow evidence confirms a real successful upload and completed processing. No new workflow or upload was triggered for these uncommitted changes. |
| Hooks | Generated pre-command hook permits the safe fixture and stops blocked/unknown inputs. Corrected pre-commit entry permits a safe file and rejects a dangerous file. |
| Auditability | Hash edits are detected; HMAC detects a forged hash chain; a separately retained checkpoint detects truncation. Ledger verification and replay work, subject to the limits below. |
| Local-first, no model dependency | The core wheel installs without runtime dependencies. All rehearsal decisions and executors run locally without an LLM. Optional development/MCP SDK packages were installed only as test tooling. |

## Defects reproduced and fixed locally

| Reproduction | Before | After |
| --- | --- | --- |
| `touch reports/../outside.txt` with `allowed_scopes=["reports/"]` | ALLOW; real file created outside reports | BLOCK before executor; dot segments canonicalized |
| `touch outside` with the same policy | ALLOW; extensionless target missed | BLOCK; command operands are inspected |
| `touch -- -outside` / `touch outside > reports/log.txt` | ALLOW; dash-prefixed operand dropped, or redirection hid the main write target | BLOCK; operands and redirect destinations are both checked |
| Absolute, hidden, sibling-prefix, and quoted path variants | Normalization could erase meaningful prefixes; regex missed some operands | Path identity and segment boundaries preserved; regression controls cover allowed and denied cases |
| HTTP `tools/call` notification containing `rm -rf /` | Forwarded because rejection had no JSON-RPC response object | Suppressed; empty HTTP 204 response; no upstream receipt |
| HTTP proxy with `--trajectory` | Flag-created guard was never passed to HTTP transport; read-then-egress forwarded | Guard and configured security state passed through; requests serialized for this single-run endpoint |
| Quarantined MCP tool | Counted as forwarded before the later catalog denial | Forwarded count changes only after security checks permit it |
| `docker system prune -af` / `docker rm -fv fixture` | UNKNOWN; equivalent short flags missed | BLOCK with Docker rule |
| `kubectl delete pods --grace-period 0` | UNKNOWN; only equals form detected | BLOCK; separated value and explicit force/now true forms recognized |
| `curl -dhello`, `-XPOST`, `-F`, `-T` | Output-channel finding missed | HTTP output recognized; case-sensitive short options preserved |
| S3 upload with trailing `--quiet` | Destination incorrectly assumed to be final token | Upload destination extracted from operands; download control remains unflagged |
| `max_blocked_attempts=0` | Coerced to 1 | Zero preserved in trajectory and runtime contracts |
| Boolean numeric limit | `True` accepted as an integer | Malformed contract rejected |
| Shipped pre-commit entry | `Executable circuit-breaker not found` for both safe and dangerous files | Uses installed `agent-circuit-breaker` executable |

The HTTP implementation remains a minimal legacy JSON request/response proxy representing one shared run. Serializing its state does not make it a general multi-session Streamable HTTP gateway.

## Corrections needed in the talk

Use the actual finding identifiers when showing JSON:

| Submitted identifier | Current implementation |
| --- | --- |
| `traj_allowed_scope` | `traj_scope_violation` |
| `traj_output_channel` | `traj_output_channel_drift` |
| `traj_secret_egress` | `traj_secret_then_egress` |
| `traj_direct_secret_egress` | `traj_secret_in_egress_action` |
| `traj_data_export_egress` | `traj_data_export_then_egress` |

Describe `allowed_scopes` as **lexical scope checks on recognized write operations**, rather than restricting every filesystem access. Reads such as `cat /etc/hosts` are not scope-enforced by this legacy trajectory heuristic. Symlinks, working-directory changes, arbitrary scripts, and OS-level containment require a trusted executor or a more specific adapter. The tested v1.7 workflow server has its own typed workspace controls; do not attribute those controls to generic shell inspection.

Empty scope/output lists disable their respective restrictions; they do not mean “deny everything.” Forbidden-target token boundaries were verified for simple names such as `main` versus `domain`; complex target strings currently use substring matching.

Describe generic MCP protection as **inspection of argument strings plus optional trajectory/catalog/taint checks**. An inert test call named `delete_everything_fixture` with `{}` arguments is forwarded. There are no strings to inspect, and the generic proxy cannot infer the operation from arbitrary tool semantics. Tools whose meaning lives in their names, numeric IDs, or server implementation need explicit adapters/capabilities. `--allow-unknown` deliberately weakens the default stop behavior; it is used only in the inert trajectory proxy demonstration to let the first unmatched read proceed.

Describe SQL coverage as **recognition of specific dangerous shapes with UNKNOWN stopped by default**. Real SQLite proves `WITH x AS (SELECT 1) DELETE FROM demo` and `DELETE FROM demo WHERE 2>1` delete every fixture row without a gate; they currently evaluate as UNKNOWN rather than matching a SQL block rule. The gated runs correctly refuse them. Conversely, `DELETE FROM demo WHERE id=1 AND 1=1` is overblocked even though SQLite changes one row. This false positive remains a documented inspector limitation. A normal SELECT or qualified DELETE also needs an explicit allow rule in this API; “not dangerous” does not automatically mean ALLOW.

Describe audit guarantees precisely: `RunLedger` is an **unsigned hash chain**. A writer can alter an entry and recompute the hashes successfully; the rehearsal demonstrates this. `AuditLog` supports HMAC when the key is configured and protected. A valid prefix still verifies after truncation, so detecting lost tail entries needs an independently retained checkpoint. Neither file is immutable, and concurrent writers/host compromise were not certified here.

The Python evaluation APIs return decisions; enforcement exists only where the trusted host actually gates its executor. The project is not an OS sandbox. The rehearsal verifies the specific wrapped paths, not agents with an alternate route to the shell/database/server.

## Evidence and reproduction

- [Rehearsal runner](../../scripts/verify_appsec_demo.py)
- [Regression tests](../../tests/test_appsec_regressions.py)
- [Patched wheel results](appsec-2026-results.json)
- [Published v1.7.0 results](appsec-2026-pypi-results.json)
- [Validation environment and artifact checksums](appsec-2026-environment.json)
- [Successful existing Code Scanning run](https://github.com/sagarchhatrala/agent-circuit-breaker/actions/runs/42477444434): logs on 8 November say “Successfully uploaded results” and “Analysis upload status is complete.” This run predates the local changes.
- [Successful existing CI for the starting commit](https://github.com/sagarchhatrala/agent-circuit-breaker/actions/runs/42477284061), also predating these changes.

From the patched checkout:

```bash
python3 -m venv /tmp/acb-appsec-rehearsal
/tmp/acb-appsec-rehearsal/bin/python -m pip install -e . pytest pre-commit
/tmp/acb-appsec-rehearsal/bin/python scripts/verify_appsec_demo.py --output /tmp/acb-appsec-results.json
/tmp/acb-appsec-rehearsal/bin/python -m pytest -q
```

The runner creates and cleans temporary data, starts only loopback services, and writes its JSON results plus a companion `.sarif` file. A failed expectation gives a nonzero exit. The five limitation observations are deliberately recorded as expected behavior, not advertised as security guarantees. The runner needs a POSIX host with Git, `touch`, `cat`, and `curl`; native Windows execution was not verified.

For MCP SDK interoperability:

```bash
/tmp/acb-appsec-rehearsal/bin/python -m pip install 'mcp==2.3.0'
/tmp/acb-appsec-rehearsal/bin/python scripts/mcp_sdk_smoke.py
```

These fixes are local and unreleased. The version remains 1.7.0 in this working tree. Rehearse from the patched checkout or its exact wheel; a plain PyPI installation currently retrieves the release with the reproduced defects.
