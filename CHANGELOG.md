# Changelog

All notable changes to Agent Circuit Breaker are tracked here.

This project follows semantic versioning after `v1.0.0`.

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
- Added `--ledger` for `circuit-breaker trajectory` to persist full trajectory results in a local hash-chained run ledger.
- Added `circuit-breaker ledger`, `circuit-breaker ledger <RUN_ID>`, and `circuit-breaker ledger --verify`.
- Added `RunLedger` for local replay of stored trajectory runs.

### Compatibility

- Existing approval records remain readable. New records include an additive `context` object.
- The run ledger is opt-in and local-only.

## [1.4.4] - 2026-07-21

### Added

- Added optional stateful MCP trajectory enforcement through `circuit-breaker-mcp-proxy --trajectory`.
- Added `--trajectory-policy <path>` for supplying an MCP run contract with trajectory fields such as `allowed_outputs`, `allowed_scopes`, and `forbidden_targets`.
- Added programmatic `MCPRunGuard` support for integrations that want to keep trajectory state outside the stdio proxy.
- Added MCP JSON-RPC error metadata for trajectory verdicts and trajectory finding IDs.

### Compatibility

- MCP proxy behavior remains stateless by default unless `--trajectory`, `--trajectory-policy`, or an explicit `MCPRunGuard` is used.

## [1.4.3] - 2026-07-21

### Added

- Added trajectory-level analysis for long-running agent runs through `evaluate_trajectory(...)`.
- Added `circuit-breaker trajectory <run.json>` for evaluating JSON action sequences and optional run contracts.
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

- `circuit-breaker-mcp-proxy` now inspects every string-valued tool-call argument recursively instead of only a short key allowlist.
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

- Added a dependency-free stdio JSON-RPC MCP proxy entry point: `circuit-breaker-mcp-proxy`.
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
