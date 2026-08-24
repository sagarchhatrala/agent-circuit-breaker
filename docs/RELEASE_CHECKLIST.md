# Release Checklist

Use this checklist before tagging a release.

## Version And Docs

- Update `agent_circuit_breaker/__init__.py`.
- Update `setup.py`.
- Update `README.md`.
- Update `QUICKSTART.md`.
- Update `docs/README.md`.
- Update `docs/OPENSSF_BASELINE_1.md` when governance, CI/CD, security, dependency, or release controls change.
- Update `docs/GITHUB_SECURITY_CONFIGURATION.md` when repository security settings or required manual actions change.
- Update `docs/ROADMAP.md`.
- Update `PLAN.md`.
- Add release notes under `docs/releases/`.

## Validation

Run:

```bash
python -m build
python -m twine check dist/agent_circuit_breaker-<version>.tar.gz dist/agent_circuit_breaker-<version>-py3-none-any.whl
python -m unittest discover
git diff --check
```

Review OpenSSF/security hygiene before release:

```bash
git ls-files | rg -i '\.(exe|dll|so|dylib|bin|pyd|zip|tar|gz|whl|jar)$'
rg -n "password|secret|token|api[_-]?key|AKIA|ghp_|BEGIN (RSA|OPENSSH|PRIVATE)|pypi-|sk-"
```

Expected:

- no tracked generated executables or opaque release artifacts.
- no real credentials in source, docs, examples, tests, or workflows.

Run focused tests for the release area when applicable:

```bash
python -m unittest tests.test_api
python -m unittest tests.test_adversarial
python -m unittest tests.test_docs
```

## CLI Smokes

Run:

```bash
python -m agent_circuit_breaker.cli check "rm -rf /"
python -m agent_circuit_breaker.cli check "git push --force origin main"
python -m agent_circuit_breaker.cli check "DROP TABLE users"
python -m agent_circuit_breaker.cli check "mkdir /tmp/example"
python -m agent_circuit_breaker.cli validate-rules docs/examples/rules/custom_deploy_guard.json
python -m agent_circuit_breaker.cli validate-rules docs/examples/rules/multi_rule_guard.json
python -m agent_circuit_breaker.cli schemas rule-file
python -m agent_circuit_breaker.cli catalog --format json
```

Expected:

- destructive examples return `BLOCK`.
- `mkdir /tmp/example` returns `ALLOW`.
- valid rule files return `Valid: TRUE`.
- schema and catalog commands return JSON.

## Python API Smokes

Run:

```bash
python -c "from agent_circuit_breaker import evaluate_action; r=evaluate_action('rm -rf /'); print(r['verdict'], r['matched_rule'])"
python -c "from agent_circuit_breaker import validate_rule_file; r=validate_rule_file('docs/examples/rules/custom_deploy_guard.json'); print(r['is_valid'])"
```

Expected:

- recursive delete returns `block fs_recursive_delete`.
- rule validation returns `True`.

## Git And GitHub

- Commit release prep.
- Push `main`.
- Create the release tag.
- Push the release tag.
- Create the GitHub Release from `docs/releases/<version>.md`.
- Verify the release appears in the GitHub Releases tab.
- Verify `git status --short` is clean.

## Package Publishing

- Build artifacts with `python -m build`.
- Validate artifacts with explicit source distribution and wheel filenames.
- Confirm the GitHub Release `Publish` workflow publishes to TestPyPI first.
- Confirm the same workflow publishes to PyPI after TestPyPI succeeds.
- Verify `pip install agent-circuit-breaker==<version>` works.

## Release Notes

Release notes should include:

- title.
- added features.
- changed behavior.
- verification commands.
- compatibility or safety notes.
