# Publishing

Use TestPyPI before publishing to PyPI. Existing trusted publishing identities are
bound to this repository, `.github/workflows/publish.yml`, and the `testpypi` and
`pypi` GitHub environments. No source tokens or local credential files are needed.

## Authoritative release path

1. Check GitHub, PyPI and TestPyPI for the version. Never overwrite a tag or reuse
   a version for different bytes. Complete the [release checklist](RELEASE_CHECKLIST.md).
2. Merge the release PR through protected main after required Python 3.11/3.12
   checks. Create and push the version tag once, pointing to that merged revision.
3. Dispatch from that tag: `gh workflow run publish.yml --ref v1.7.1 -f repository=pypi`.
4. Wait for every job, including public PyPI fresh-install verification. Download
   `release-provenance` and `python-package-distributions` from that workflow run.
5. Create the stable GitHub release with versioned notes, reviewed synthetic media,
   and authoritative checksums/manifest. Check public links.

The workflow checks tag/version equality and main ancestry, reruns the security
suite, then performs one authoritative build using `python -m build`. The wheel is
built from the sdist. Both distributions pass metadata/content inspection, and the
exact wheel runs in a clean environment outside the checkout.

Those original files are uploaded to TestPyPI. Both indexed wheel and sdist are
fetched and compared against the authoritative SHA-256 manifest; the wheel is
installed and executes release-critical scenarios in another clean environment.
Only then do the same original bytes reach PyPI. Public PyPI bytes, fresh installed
CLI, packaged assets and real execution are checked again.

There is no `skip-existing`. Publishing a GitHub release cannot trigger duplicate
uploads. After a partial successful upload, rerun only failed downstream jobs and
retain the original successful build/artifacts. Do not rerun the entire workflow
and substitute another build. An immutable version conflict requires provenance
comparison and a maintainer decision.

`repository=testpypi` supports deliberate TestPyPI-only publishing. Do not use it as
a separate rehearsal for the same stable version: a later all-jobs dispatch would
reuse that immutable version. The stable path already contains its TestPyPI gate.

## Local preparation

Local builds are development evidence, not proof that CI release bytes passed:

```bash
python -m pip install build twine pytest
python -m pytest -q
python -m build
python -m twine check dist/agent_circuit_breaker-<version>.tar.gz dist/agent_circuit_breaker-<version>-py3-none-any.whl
```

Inspect contents, install the exact wheel into a fresh environment, and run
`python -I /path/to/scripts/package_smoke.py` outside the checkout. Optional SDK
checks use `scripts/mcp_sdk_smoke.py` with `mcp==2.3.0`. Keep raw recordings, private
state and generated build/provenance outputs untracked.

[PyPI](https://pypi.org/project/agent-circuit-breaker/) ·
[TestPyPI](https://test.pypi.org/project/agent-circuit-breaker/) ·
[Workflow](https://github.com/sagarchhatrala/agent-circuit-breaker/actions/workflows/publish.yml) ·
[Releases](https://github.com/sagarchhatrala/agent-circuit-breaker/releases)
