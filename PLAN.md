# Agent Circuit Breaker v0.5 Alpha Plan

Project goal: build a deterministic safety layer between AI coding agents and the operating system.

The current release target is `v0.5.0-alpha.1`. This alpha hardens the external JSON rule schema on top of the v0.4 rule loading foundation.

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
- Dedicated external rule schema documentation
- Valid and invalid rule fixture coverage
- CLI command: `circuit-breaker check <action>`
- CLI command: `circuit-breaker validate-rules <path>`
- Text and JSON CLI output
- Standard-library test suite
- Usage, architecture, design decision, and roadmap docs
- GitHub `main` push workflow
- GitHub prerelease workflow

Remaining before tagging `v0.5.0-alpha.1`:

- Release-readiness cleanup
- Editable install verification
- CLI smoke tests
- Full test run
- Git tag and push
- GitHub prerelease

## v0.5 Alpha Scope

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
- `circuit-breaker check "mkdir /tmp/example"` returns `ALLOW`
- `circuit-breaker check "ls -la"` returns `UNKNOWN`
- Documentation describes only currently supported behavior
- `main` is pushed to GitHub
- `v0.5.0-alpha.1` tag is pushed to GitHub
- GitHub prerelease is published

## Next Milestones

After `v0.5.0-alpha.1`, continue with:

- v0.6: public API alpha
- v0.7: adversarial test alpha
- v0.8: security documentation alpha
- v0.9: release candidate
- v1.0: stable API, release process, and production-readiness review

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.
