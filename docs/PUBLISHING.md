# Publishing

Use TestPyPI before publishing to PyPI.

Project links:

- PyPI: https://pypi.org/project/agent-circuit-breaker/
- TestPyPI: https://test.pypi.org/project/agent-circuit-breaker/
- GitHub Releases: https://github.com/sagarchhatrala/agent-circuit-breaker/releases
- Publish workflow: https://github.com/sagarchhatrala/agent-circuit-breaker/actions/workflows/publish.yml

## Prerequisites

- `build`
- `twine`
- TestPyPI API token
- PyPI API token

For GitHub Actions publishing, prefer trusted publishing over local token files.

## Trusted Publishing

Recommended GitHub environments:

- `testpypi`
- `pypi`

Configure trusted publishers in TestPyPI and PyPI for this repository:

- owner: `sagarchhatrala`
- repository: `agent-circuit-breaker`
- workflow: `publish.yml`
- environment: `testpypi` or `pypi`

The workflow is defined in `.github/workflows/publish.yml`.

Release publishing:

1. Publish a GitHub Release.
2. The `Publish` workflow builds once, publishes to TestPyPI, then publishes the same artifacts to PyPI.
3. Verify install from PyPI.

Manual publishing:

1. Open the `Publish` workflow in GitHub Actions.
2. Run workflow with `repository` set to `testpypi` for TestPyPI-only validation.
3. Run workflow with `repository` set to `pypi` to publish through TestPyPI first, then PyPI.

Recommended local install:

```bash
python -m pip install --upgrade build twine
```

## Build

```bash
python -m build
python -m twine check dist/*
```

Expected artifacts:

- source distribution: `dist/agent_circuit_breaker-<version>.tar.gz`
- wheel: `dist/agent_circuit_breaker-<version>-py3-none-any.whl`

## TestPyPI

Upload:

```bash
python -m twine upload --repository testpypi dist/*
```

Install verification:

```bash
python -m pip install --index-url https://test.pypi.org/simple/ --no-deps agent-circuit-breaker==<version>
python -c "from agent_circuit_breaker import evaluate_action; print(evaluate_action('rm -rf /')['verdict'])"
```

## PyPI

After TestPyPI verification:

```bash
python -m twine upload dist/*
```

Install verification:

```bash
python -m pip install --no-deps agent-circuit-breaker==<version>
python -c "from agent_circuit_breaker import evaluate_action; print(evaluate_action('rm -rf /')['verdict'])"
```

## Notes

- Do not upload a version twice. PyPI and TestPyPI reject duplicate files.
- Store local fallback tokens outside the repository.
- Keep `dist/` untracked.
