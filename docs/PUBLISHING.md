# Publishing

Use TestPyPI before publishing to PyPI.

## Prerequisites

- `build`
- `twine`
- TestPyPI API token
- PyPI API token

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
python -m pip install --index-url https://test.pypi.org/simple/ --no-deps agent-circuit-breaker==1.0.1
python -m agent_circuit_breaker.cli check "rm -rf /"
```

## PyPI

After TestPyPI verification:

```bash
python -m twine upload dist/*
```

## Notes

- Do not upload a version twice. PyPI and TestPyPI reject duplicate files.
- Store tokens outside the repository.
- Keep `dist/` untracked.
