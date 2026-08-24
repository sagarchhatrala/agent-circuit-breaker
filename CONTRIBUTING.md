# Contributing

Agent Circuit Breaker is a deterministic, fail-secure runtime safety layer for
AI-agent actions. Contributions should preserve that direction: explicit
security decisions, explainable rules, no LLM authority in the enforcement
path, and no required network service in the core package.

## Development Setup

```bash
git clone https://github.com/sagarchhatrala/agent-circuit-breaker.git
cd agent-circuit-breaker
python -m pip install -e .
python -m unittest discover
```

The core package intentionally has no required third-party runtime
dependencies. Optional integrations are declared in `setup.py`.

## Contribution Process

1. Open an issue or pull request describing the problem and the intended change.
2. Keep changes narrowly scoped to the behavior being improved.
3. Add or update tests for security-sensitive behavior.
4. Run the full test suite and whitespace check before requesting review:

```bash
python -m unittest discover
git diff --check
```

Pull requests to `main` are expected to pass CI and be reviewed before merge.
Do not include generated build outputs such as `dist/`, wheels, or egg-info
directories in commits.

## Security-Sensitive Contributions

Security changes should include regression coverage for the invariant they
protect. Useful examples include:

- `UNKNOWN` does not execute through executable adapters by default.
- blocked MCP tool calls are not forwarded.
- invalid policy, rule, plugin, or signature inputs fail closed.
- approval decisions are bound to the evaluated action/context.
- persisted audit, approval, and ledger records redact common secret shapes.

Do not open a public issue for a suspected vulnerability. Follow
`SECURITY.md` instead.

## Rules And Policies

Declarative rule files should use the documented schema in
`docs/RULE_SCHEMA.md`. Built-in deny rules run before custom allow rules, so a
custom rule must not be used to bypass a deterministic built-in block.

## License

By contributing, you agree that your contribution is provided under the MIT
License used by this repository.
