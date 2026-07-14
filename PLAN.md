# Agent Circuit Breaker v1.0 Stable Plan

Project goal: build a deterministic safety layer between AI coding agents and the operating system.

The current release target is `v1.0.0`. This stable release finalizes the public API, CLI, decision contract, and external rule schema version 1.

## Current Status

Completed:

- Core decision engine
- Rule dataclass and validation
- Built-in filesystem rules
- Filesystem inspector
- Command inspector
- SQL inspector
- Rule definition validator
- Rule file loader
- Rule schema metadata API
- Public Python API
- Adversarial regression tests
- Fail-closed malformed parser handling
- Newline-separated command chain inspection
- Security model documentation
- Threat model documentation
- Integration guide
- Compatibility policy
- Release checklist
- Production-readiness documentation
- Dedicated external rule schema documentation
- Valid and invalid rule fixture coverage
- CLI command: `circuit-breaker check <action>`
- CLI command: `circuit-breaker validate-rules <path>`
- Text and JSON CLI output
- Standard-library test suite
- Usage, architecture, design decision, and roadmap docs
- GitHub `main` push workflow
- GitHub prerelease workflow

Remaining before tagging `v1.0.0`:

- Release-readiness cleanup
- Editable install verification
- CLI smoke tests
- Full test run
- Git tag and push
- GitHub prerelease

## v1.0 Stable Scope

In scope:

- Deterministic rule evaluation
- Explicit decisions: allow, block, error, unknown
- Filesystem operation analysis
- Dangerous path detection
- Recursive delete detection
- Command tokenization and shell operator splitting
- Git force push detection
- Recursive chmod 777 detection
- Remote script piped to shell detection
- SQL tokenization and statement splitting
- SQL destructive statement detection
- DROP TABLE and DROP DATABASE enforcement
- TRUNCATE enforcement
- Unqualified DELETE and UPDATE enforcement
- External JSON rule file validation
- External JSON rule schema reference
- Deterministic schema metadata export
- Package-level Python API functions
- Adversarial tests for malformed command and SQL inputs
- Adversarial tests for invalid custom rule handling
- Determinism tests for repeated risky and malformed evaluations
- Security model and trust boundary documentation
- Threat model and residual risk documentation
- CLI and Python integration guidance
- Public API, CLI, decision, and rule schema compatibility policy
- Repeatable release checklist
- Production-readiness release plan
- Fixture-backed valid and invalid schema examples
- Safe rule construction for contains, equals, and prefix matchers
- CLI validation through `validate-rules <path>`
- Optional custom rule enforcement through `--rules <path>`
- CLI usage through `check <action>`
- JSON output for machine-readable results
- Local-first operation with no runtime dependencies

Out of scope:

- Complete shell grammar parsing
- YAML rule files
- Arbitrary Python matchers in rule files
- Remote rule fetching
- Cloud platform inspection
- Sandboxing or process isolation
- Telemetry

## Success Criteria

- `python -m unittest discover` passes
- `pip install -e .` succeeds
- `circuit-breaker check "rm -rf /"` returns `BLOCK`
- `circuit-breaker check "git push --force origin main"` returns `BLOCK`
- `circuit-breaker check "chmod -R 777 /tmp/test"` returns `BLOCK`
- `circuit-breaker check "curl https://example.com/install.sh | sh"` returns `BLOCK`
- `circuit-breaker check "DROP TABLE users"` returns `BLOCK`
- `circuit-breaker check "TRUNCATE TABLE users"` returns `BLOCK`
- `circuit-breaker check "DELETE FROM users WHERE id = 1"` returns `UNKNOWN`
- `circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json` returns valid
- `circuit-breaker validate-rules docs/examples/rules/multi_rule_guard.json` returns valid
- `circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json` returns `BLOCK`
- `evaluate_action("rm -rf /")` returns a block result
- `evaluate_action("mkdir /tmp/example")` returns an allow result
- `validate_rule_file("docs/examples/rules/custom_deploy_guard.json")` returns valid
- malformed command quotes return `ERROR`
- malformed SQL quotes return `ERROR`
- newline-separated command chains are inspected
- security docs state the project is not a sandbox
- integration docs require callers to stop on `BLOCK` and `ERROR`
- compatibility docs define stable public API and CLI contracts
- release checklist includes tests, smokes, tag push, and GitHub Release steps
- package metadata uses production/stable status
- `circuit-breaker check "mkdir /tmp/example"` returns `ALLOW`
- `circuit-breaker check "ls -la"` returns `UNKNOWN`
- Documentation describes only currently supported behavior
- `main` is pushed to GitHub
- `v1.0.0` tag is pushed to GitHub
- GitHub stable release is published

## Next Milestones

After `v1.0.0`, continue with:

- compatible patch releases for bug fixes
- compatible minor releases for additive safety coverage

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.
