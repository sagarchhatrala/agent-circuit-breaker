# Changelog

All notable changes to Agent Circuit Breaker are tracked here.

This project follows semantic versioning after `v1.0.0`.

## [1.6.7] - 2026-08-24

### Security

- Added OpenSSF Baseline Level 1 evidence tracking and GitHub security
  configuration documentation.
- Enabled and documented repository vulnerability management controls,
  including private vulnerability reporting and Dependabot security updates.

### Added

- Root `CONTRIBUTING.md` with setup, review, testing, security-sensitive
  contribution, and generated-artifact guidance.
- `docs/GETTING_STARTED.md` for a concise first-use guide.
- `docs/OPENSSF_BASELINE_1.md` evidence matrix for Baseline Level 1 criteria.
- `docs/GITHUB_SECURITY_CONFIGURATION.md` with verified repository settings
  and manual account/organization actions.
- Dependabot update configuration for GitHub Actions and Python packaging.

### Compatibility

- No runtime CLI, Python API, MCP, pipeline, policy, rule, audit, approval, or
  ledger behavior changes are intended in this release.
- Workflow source changes are limited to adding Dependabot update
  configuration; existing CI and publish entry points are unchanged.

## [1.6.6] - 2026-08-17

### Security

- Expanded nested interpreter detection to cover encoded PowerShell payloads and
  common `system(...)`, `exec(...)`, and `execSync(...)` command literals in
  Python, Perl, Node.js, Ruby, and similar interpreter wrappers.
- Expanded persisted-record redaction for common credential shapes including
  AWS-style secret assignments, GitHub token prefixes, `curl -u` basic auth,
  `mysql -p...`, and URL userinfo passwords.

### Changed

- Rule-provider plugins may now return validated declarative rule dictionaries
  using the same rule schema as JSON rule files, in addition to returning
  `Rule` objects.
- Invalid plugin providers now fail closed with entry-point-specific diagnostic
  errors instead of surfacing as opaque engine errors.

### Compatibility

- Existing v1.x CLI/API result fields and schemas keep their meaning.
- Some interpreter-wrapped destructive commands that previously returned
  `UNKNOWN` now return `BLOCK`.
- Plugin providers that already return `Rule` objects continue to work.

## [1.6.5] - 2026-08-09

### Changed

- MCP proxy forwarding now stops `UNKNOWN` tool-call inspections by default.
- Pipeline SDK facade evaluations now treat core evaluator `UNKNOWN` results as
  applicable unknowns by default, preventing unrelated guard allows from making
  an unclassified action executable.
- Added explicit compatibility opt-ins: `agent-circuit-breaker-mcp-proxy
  --allow-unknown`, `MCPRunGuard(allow_unknown=True)`, and
  `AgentCircuitBreaker(allow_core_unknown=True)`.
- Documentation now clarifies the difference between preserving `UNKNOWN` in
  low-level results and stopping `UNKNOWN` in executable adapter paths.

### Security

- Hardens cross-adapter execution semantics so `ALLOW` remains the only default
  executable state for MCP and pipeline integrations.
- Adds regression coverage for default MCP UNKNOWN blocking, explicit MCP
  UNKNOWN forwarding opt-in, default pipeline UNKNOWN blocking, explicit
  pipeline UNKNOWN allow opt-in, and interpreter-wrapper UNKNOWN handling.

### Compatibility

- Existing v1.x CLI/API result fields and schemas keep their meaning.
- Low-level `check` behavior still reports `UNKNOWN` for unclassified actions.
- Callers that intentionally relied on previous MCP or pipeline UNKNOWN
  forwarding can opt in explicitly.

## [1.6.4] - 2026-08-09

### Added

- Added an internal canonical decision contract for audit, ledger, approval, trajectory, and adapter consistency.
- Added cross-adapter security corpus tests for allow, block, unknown, nested command, and SQL decisions.
- Added approval revalidation against a freshly evaluated action result.
- Added trajectory `run_fingerprint` based on canonical JSON serialization.
- Added MCP attempted-versus-forwarded trajectory state and security-relevance coverage metadata.

### Changed

- `http://` remote policy URLs are rejected by default; callers must explicitly opt in with `--allow-insecure-remote-policy`.
- Audit events and run-ledger replay include compact canonical decision summaries.
- Documentation now clarifies canonical decision semantics, approval revalidation, MCP coverage, and remote policy transport behavior.

### Compatibility

- Existing v1.x CLI/API result fields keep their meaning.
- Existing `run_id` remains present; `run_fingerprint` is additive.
- The default install remains dependency-free.

## [1.6.2] - 2026-08-09

### Added

- Added `inspection_coverage` to action results so integrations can see which mandatory inspectors ran and whether coverage was complete.
- Added `decision_validation` to action results to make unsafe `ALLOW` states fail closed.
- Added MCP argument inspection coverage metadata, including inspected field paths and fail-closed depth errors.
- Added approval ID scoping for policy source, policy trust, policy signature, inspection coverage, and decision validation context.
- Added audit event summaries for inspection coverage and decision validation.
- Added regression tests for chained-command auto-allow bypasses, MCP coverage, approval scoping, audit summaries, and schema metadata.

### Changed

- Known-safe filesystem auto-allow now requires a single complete command segment with no shell operators, no command risk flags, and clean SQL inspection.
- Public decision and audit schemas now include v1.6.2 evidence fields.
- Updated documentation and release notes for the v1.6.2 fail-secure inspection contract.

### Fixed

- Fixed a bypass where a safe first filesystem segment could cause a chained command to be allowed before all command segments were considered.
- Updated the GitHub scan workflow to use `agent-circuit-breaker` instead of the old short command name.

### Compatibility

- Existing JSON fields keep their v1.x meaning.
- New result fields are additive.
- Safe single-segment filesystem operations such as `mkdir /tmp/example` still return `ALLOW`.
- Chained or multi-segment actions that do not match a block rule remain explicit as `UNKNOWN` unless strict or approval policy mode changes them.
- The default install remains dependency-free.

## [1.6.1] - 2026-08-09

### Added

- Added policy source trust metadata for loaded policies.
- Added fail-secure validation for auto-discovered repository policies.
- Added `--trust-repository-policy` for explicitly trusting repository policy that can weaken inherited controls.
- Added regression tests for repository policy strengthening, weakening rejection, and trusted override behavior.

### Changed

- Updated the console command names, documentation, tests, and examples to use `agent-circuit-breaker` and `agent-circuit-breaker-mcp-proxy`.
- Auto-discovered repository policy may strengthen enforcement by default, but cannot add allow rules, select advisory mode, select the solo profile, or disable strict mode unless explicitly trusted.

### Compatibility

- Explicit `--policy` paths and `ACB_POLICY` remain caller-selected policy sources.
- Built-in blocks still take precedence over custom allow rules.
- The default install remains dependency-free.

## [1.6.0] - 2026-08-06

### Added

- Added dependency-free `EvaluationRequest`, `DecisionResult`, and `Finding` dataclasses.
- Added deterministic conversion from stable v1.x public result dictionaries into typed decision results.
- Added stable typed findings for matched rules and fail-secure evaluation errors.
- Added deterministic short evaluation IDs for typed decisions.
- Added regression coverage for typed block, unknown, error, and legacy round-trip behavior.

### Compatibility

- Existing CLI output remains unchanged.
- `evaluate_action(...)` continues to return the same v1.x dictionary shape.
- Typed results are additive and can round-trip back to legacy dictionaries.
- The default install remains dependency-free.

## [1.5.2] - 2026-07-31

### Added

- Added versioned JSON schema artifacts and `agent-circuit-breaker schemas [NAME]`.
- Added fixture-based custom rule tests with `agent-circuit-breaker rules test <PATH>`.
- Added generated built-in rule catalog output with `agent-circuit-breaker catalog`.
- Added architecture boundary tests for core package isolation.
- Added explicit resource limits for command text, rule files, policy files, trajectory inputs, approval payloads, and MCP traversal.
- Added default redaction for common secret-like values in audit, approval, and ledger persistence.

### Compatibility

- Existing public CLI and API fields remain additive.
- The default install remains dependency-free.
- Raw persisted record retention is still possible with explicit `ACB_RETAIN_RAW_RECORDS=1`.

## [1.5.1] - 2026-07-28

### Fixed

- Fixed a pipeline SDK bypass where guards only inspected conventional argument keys such as `command`, `path`, or `url`.
- `AgentContext.action_text()` now includes all nested string-valued tool arguments, regardless of schema field name.
- Filesystem and network guards now inspect arbitrary string-valued arguments for path and endpoint shapes.
- `NetworkEgressGuard` no longer performs live DNS resolution during evaluation.
- Approval records no longer reset a prior `approved` or `denied` decision back to `pending` when the same action is evaluated again.

### Compatibility

- The default install remains dependency-free and local-first.
- Hostname-based private-network detection is intentionally DNS-free; literal private IPs, loopback, link-local, reserved, multicast, unspecified, and configured metadata hosts remain blocked.

## [1.5.0] - 2026-07-28

### Added

- Added optional Redis-backed circuit state with atomic Lua-script transitions for distributed agent fleets.
- Added optional OpenTelemetry and Prometheus exporters while keeping the default install dependency-free.
- Added a `PipelineBenchmark` helper for measuring pipeline overhead in caller-owned workloads.
- Added package-install policy support for resolved dependency metadata and lockfile inputs.

### Changed

- Pipeline guard scheduling now uses `asyncio.TaskGroup` with fail-fast cancellation when a guard denies.
- Package metadata now exposes optional extras: `redis`, `otel`, `prometheus`, and `enterprise`.
- Documentation now separates the dependency-free core from optional enterprise integrations.

### Compatibility

- The default install still has no runtime dependencies.
- Pydantic DTOs, AST write blocking, and editor/filesystem write interception remain out of scope for this release.

## [1.4.9] - 2026-07-27

### Added

- Added a dependency-free async `PipelineEngine` for concurrent guard evaluation with fail-closed aggregation.
- Added immutable `AgentContext`, `GuardResult`, and `PipelineResult` DTOs using stdlib dataclasses.
- Added protocol contracts for guards, state stores, hooks, and exporters.
- Added `AgentCircuitBreaker` SDK facade with async and outer-layer sync APIs.
- Added `StateManager`, `InMemoryStore`, and SQLite-backed persistent circuit state.
- Added deterministic pipeline guards for shell commands, filesystem path policy, network egress/SSRF, package installs, sequence repetition, context-window limits, and tool-call volume.
- Added a legacy guard that bridges the existing battle-tested evaluator into the new pipeline.
- Added dependency-free pipeline events and a logging exporter.

### Changed

- Package exports now include the pipeline SDK primitives while preserving existing `evaluate_action` and `evaluate_trajectory` behavior.
- Documentation now separates SDK-routed file-write validation from OS-level write interception, which remains out of scope without sandboxing or a filesystem proxy.

### Compatibility

- No runtime dependencies were added.
- Redis, OTel, Prometheus, and AST write blocking were intentionally not added to this patch.

## [1.4.8] - 2026-07-21

### Fixed

- Fixed `allowed_outputs` false positives for inbound network reads such as `curl` health checks, `wget` downloads, `git clone`, and S3 downloads.
- Output-channel drift now focuses on outbound publication actions such as GitHub PRs/pushes, HTTP POST/upload-style commands, Slack posts, and cloud-storage uploads.

### Added

- Added approval-record security metadata that warns when `ACB_APPROVAL_TOKEN` is not configured.
- Added regression coverage for inbound network reads, outbound output drift, S3 upload/download direction, and approval-token warning metadata.

### Changed

- Release publishing now sends GitHub Release workflows through TestPyPI before PyPI.

## [1.4.7] - 2026-07-21

### Fixed

- Fixed trajectory secret-egress bypasses for unlisted but common egress shapes such as `ssh` and custom upload/exfil scripts.
- Fixed `forbidden_targets` false positives caused by unanchored substring matching, such as `main` matching `domain` or `maintenance`.
- Fixed trajectory scope enforcement misses for common write patterns such as `tee`, `curl -o`, and `wget -O`.
- Fixed scope checking blind spot where absolute paths were skipped instead of treated as outside relative allowed scopes.

### Added

- Added optional `ACB_APPROVAL_TOKEN` / `--approval-token` gate for local approval decisions.
- Added adversarial regressions for the reported long-horizon bypass cases.

### Changed

- Documentation now clarifies that local approvals are an audit/review workflow unless the approval decision path is separated from the agent runtime.

## [1.4.6] - 2026-07-21

### Added

- Added trajectory detection for direct secret-like material in egress actions.
- Added trajectory detection for data exports followed by external egress.
- Expanded deterministic egress channel coverage to include netcat-style sends, rclone, Azure/GCP storage uploads, GitHub gists, HTTPie-style commands, and paste/webhook patterns.
- Expanded sensitive-reference coverage for common credential files such as `.npmrc`, `.pypirc`, kubeconfig, and private key material.

### Compatibility

- Single-action `check` behavior remains unchanged.
- New egress findings apply only to trajectory evaluation and stateful MCP trajectory mode.

## [1.4.5] - 2026-07-21

### Added

- Added contextual approval summaries for trajectory results.
- Added `--ledger` for `agent-circuit-breaker trajectory` to persist full trajectory results in a local hash-chained run ledger.
- Added `agent-circuit-breaker ledger`, `agent-circuit-breaker ledger <RUN_ID>`, and `agent-circuit-breaker ledger --verify`.
- Added `RunLedger` for local replay of stored trajectory runs.

### Compatibility

- Existing approval records remain readable. New records include an additive `context` object.
- The run ledger is opt-in and local-only.

## [1.4.4] - 2026-07-21

### Added

- Added optional stateful MCP trajectory enforcement through `agent-circuit-breaker-mcp-proxy --trajectory`.
- Added `--trajectory-policy <path>` for supplying an MCP run contract with trajectory fields such as `allowed_outputs`, `allowed_scopes`, and `forbidden_targets`.
- Added programmatic `MCPRunGuard` support for integrations that want to keep trajectory state outside the stdio proxy.
- Added MCP JSON-RPC error metadata for trajectory verdicts and trajectory finding IDs.

### Compatibility

- MCP proxy behavior remains stateless by default unless `--trajectory`, `--trajectory-policy`, or an explicit `MCPRunGuard` is used.

## [1.4.3] - 2026-07-21

### Added

- Added trajectory-level analysis for long-running agent runs through `evaluate_trajectory(...)`.
- Added `agent-circuit-breaker trajectory <run.json>` for evaluating JSON action sequences and optional run contracts.
- Added deterministic trajectory findings for repeated blocked actions, forbidden targets, write-like actions outside allowed scopes, output-channel drift, unknown-action volume, and secret-like reads followed by egress.

### Changed

- Package exports now include `evaluate_trajectory` as an additive public API.
- JSON/API documentation now describes trajectory output fields and finding IDs.

### Compatibility

- Existing `check`, `scan`, MCP proxy, policy, approval, and audit behavior is unchanged.

## [1.4.2] - 2026-07-21

### Fixed

- Fixed MCP proxy inspection bypasses caused by arbitrary third-party argument names such as `input`, `code`, `payload`, or `value`.
- Fixed MCP proxy inspection for raw string `arguments` payloads.
- Fixed misleading `--require-signature` semantics by rejecting checksum-only SHA-256 documents as required signatures.

### Changed

- `agent-circuit-breaker-mcp-proxy` now inspects every string-valued tool-call argument recursively instead of only a short key allowlist.
- `--require-signature` now requires an authenticity-providing algorithm, currently `hmac-sha256`.
- Plain SHA-256 is treated as checksum-only integrity metadata, not an authenticity signature.

## [1.4.1] - 2026-07-21

### Changed

- Rewrote the top-level README for a mature open-source project presentation.
- Replaced stale milestone-heavy README sections with current quickstart, coverage, integration, enterprise-control, and limitation sections.
- Updated PyPI/TestPyPI-facing package metadata through the README long description.
- Updated documentation links to use valid GitHub/PyPI/TestPyPI URLs where the README is rendered outside GitHub.
- Simplified the docs index around current v1.x behavior and moved historical notes out of the primary path.

## [1.4.0] - 2026-07-21

### Added

- Added a dependency-free stdio JSON-RPC MCP proxy entry point: `agent-circuit-breaker-mcp-proxy`.
- Added MCP `tools/call` argument inspection with JSON-RPC error responses for blocked, pending, or error verdicts.
- Added optional JSON policy/rule-pack signature verification with deterministic `sha256` and `hmac-sha256` support.
- Added `--require-signature` for policy and rule-file loading.

### Changed

- `--mode strict` now actively blocks `UNKNOWN` verdicts instead of acting as metadata only.
- `team` and `prod` profiles now route `UNKNOWN` verdicts to `PENDING_APPROVAL`.
- CI workflows use newer GitHub Action majors for Node 24-era runner compatibility.

### Fixed

- `scan` command extraction now recognizes capitalized markers such as `Run:` and `- Run:`.
- Ambient `.agent-circuit-breaker/policy.json` can now contain inline `rules` without breaking `check`.
- Policy rule-file paths now resolve relative to the policy file location.
- Rule-file validation preserves existing schema errors for non-object JSON while adding signature checks for object documents.

## [1.3.0] - 2026-07-20

### Added

- Added safety profiles (`solo`, `repo`, `team`, `prod`) and policy modes (`strict`, `advisory`, `approval`).
- Added additive `PENDING_APPROVAL` decision support for policy-driven human approval flows.
- Added local approval queue commands: `approvals list`, `approvals approve <id>`, and `approvals deny <id>`.
- Added `explain` mode with safer-alternative suggestions for risky actions.
- Added `scan` mode for static inspection of scripts, docs, CI files, and SQL snippets.
- Added SARIF output for scan findings and a GitHub Action scaffold for code scanning upload.
- Added opt-in tamper-evident audit logging with hash-chained JSONL entries and `timeline --verify`.
- Added central policy loading from local files or explicit URLs with CLI override precedence.
- Added plugin discovery and optional rule-provider loading through Python entry points.
- Added external rule matchers for `regex`, `all_of`, `any_of`, and `not`.
- Added hook scaffold generation through `install-hooks`.
- Added a minimal optional MCP-style JSON-lines proxy scaffold outside the core engine package.
- Added `.pre-commit-hooks.yaml`.

### Changed

- Repositioned the package from a one-shot command checker toward a local-first safety runtime while keeping the core dependency-free.
- Expanded the public rule schema metadata to include approval responses and composite matchers.

### Compatibility

- Existing `check`, `validate-rules`, JSON fields, and documented v1.2 decisions remain compatible by default.
- `PENDING_APPROVAL` appears only when a rule or selected policy mode requests approval behavior.

## [1.2.0] - 2026-07-20

### Added

- Added additive `risk_score` output fields at the top level and inside command/SQL analyses without changing existing verdicts, decisions, exit codes, or rule IDs.
- Added Unicode normalization before matching, including zero-width character removal and a narrow Cyrillic/Greek homoglyph map for risky ASCII tokens.
- Added a structured Phase 1 bug log for sandbox findings and fixed reproductions.
- Added adversarial regressions for quote-splitting, Unicode smuggling, false-positive probes, deterministic fuzz-style inputs, and large-input latency.

### Changed

- Switched shell tokenization to Python stdlib POSIX `shlex` parsing for quote removal, quote concatenation, and backslash handling.
- Normalized external rule matcher inputs before evaluation while preserving the existing schema version and matcher types.

### Fixed

- Blocked quote-split command tokens such as `r''m -r''f /etc`, `g'it' push --for''ce origin main`, and `ch''mod -R ugo+r''wx /tmp`.
- Blocked zero-width and homoglyph smuggling such as `r\u200bm -rf /etc`, `rм -rf /etc`, `DRОP TABLE users`, and `DRO\u200bP TABLE users`.
- Preserved false-positive behavior for unrelated commands such as `transform -rf image.png`, `terraform -rf apply`, `confirm -rf change`, `dropbox table users`, and `findings /etc/ -delete`.

## [1.1.2] - 2026-07-16

### Fixed

- Blocked renamed shell fork-bomb variants such as `f(){ f|f& };f` and `bomb(){ bomb|bomb& };bomb`.
- Blocked `find -delete` rooted at protected path children and trailing-slash variants such as `find /etc/ -delete` and `find /home/someuser -delete`.
- Blocked AWS S3 bucket removal through `aws s3 rb`.
- Blocked comma-separated and grouped symbolic recursive world-writable chmod modes such as `u+rwx,g+rwx,o+rwx` and `ugo+rwx`.

## [1.1.1] - 2026-07-16

### Fixed

- Replaced substring-based recursive delete matching with tokenized filesystem operation analysis.
- Fixed false positives for non-delete commands containing `rm`, such as `transform -rf`.
- Blocked split and long-form recursive delete flags such as `rm -r -f /etc` and `rm --recursive --force /etc`.
- Blocked unquoted system path deletion targets such as `rm /etc/passwd`.
- Blocked symbolic recursive world-writable chmod such as `chmod -R a+rwx /tmp`.
- Blocked AWS S3 recursive removal through `aws s3 rm --recursive`.
- Blocked simple SQL tautological bulk mutations such as `WHERE 1=1`.
- Fixed SQL block comments between keywords, such as `DROP/**/TABLE`.
- Added catastrophic command coverage for disk overwrite/format, root-level `find -delete`, and shell fork bomb patterns.

## [1.1.0] - 2026-07-15

### Added

- Built-in command rules for package publish commands without explicit release context.
- Built-in command rules for destructive Docker command shapes.
- Built-in command rules for cloud resource deletion command shapes.
- Built-in command rules for forceful Kubernetes deletion command shapes.
- Detailed JSON output contract documentation.
- Local allowlist pattern documentation and examples.

### Changed

- Known dangerous command rules can block before unrelated heuristic SQL parser errors.

## [1.0.1] - 2026-07-15

### Added

- `pyproject.toml` build-system declaration.
- Publishing guide for TestPyPI and PyPI.
- Release checklist publishing steps.

### Changed

- Package metadata now includes README long description and project URLs.
- Published wheel excludes the test suite package.

## [1.0.0] - 2026-07-15

### Added

- CI and release hygiene:
  - GitHub Actions workflow for Python 3.11 and 3.12.
  - PR and issue templates.
  - Security policy.
  - Branch protection documentation.
- Stable public Python API.
- Stable CLI commands and exit codes.
- External JSON rule schema version 1.
- Filesystem, command, and SQL safety inspectors.
- Built-in rules for recursive deletion, dangerous filesystem paths, git force pushes, recursive chmod 777, remote scripts piped to shells, destructive SQL, and unqualified SQL mutations.
- External rule validation and custom rule enforcement.
- Adversarial and documentation regression tests.
- Security model, threat model, integration guide, compatibility policy, and release checklist.

### Changed

- Package metadata is marked production/stable.

### Verification

- `python -m unittest discover`
- `git diff --check`
- CLI smoke checks
- Python API smoke checks
