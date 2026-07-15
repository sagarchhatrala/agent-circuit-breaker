# Publishing

Use TestPyPI before publishing to PyPI.

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

Manual TestPyPI publishing:

1. Open the `Publish` workflow in GitHub Actions.
2. Run workflow with `repository` set to `testpypi`.
3. Verify install from TestPyPI.

PyPI publishing:

1. Publish a GitHub Release, or run the workflow manually with `repository` set to `pypi`.
2. Verify install from PyPI.

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
python -m pip install --index-url https://test.pypi.org/simple/ --no-deps agent-circuit-breaker==1.1.0
python -m agent_circuit_breaker.cli check "rm -rf /"
```

## PyPI

After TestPyPI verification:

```bash
python -m twine upload dist/*
```

## Notes

- Do not upload a version twice. PyPI and TestPyPI reject duplicate files.
- Store local fallback tokens outside the repository.
- Keep `dist/` untracked.
