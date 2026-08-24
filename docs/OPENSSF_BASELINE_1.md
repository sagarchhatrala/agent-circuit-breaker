# OpenSSF Baseline Level 1 Evidence

This matrix maps Agent Circuit Breaker to the Open Source Project Security
Baseline Level 1 assessment requirements, criteria version 2026.02.19:

- https://baseline.openssf.org/versions/2026-02-19.html
- https://www.bestpractices.dev/en

Evidence is based on repository files and GitHub API checks performed on
2026-08-24.

Statuses use only `Met`, `Unmet`, `N/A`, or `?`.

| ID | Status | Evidence | Location | Manual action |
| -- | ------ | -------- | -------- | ------------- |
| OSPS-AC-01.01 | ? | Repository files cannot prove account-level MFA/passkey enforcement for every privileged account. | GitHub account/org settings | Confirm MFA or passkeys are enforced for every account with admin, maintainer, or push access. |
| OSPS-AC-02.01 | Met | Current collaborator list contains one admin account; collaborator access is manually assigned in GitHub and least-privilege expectations are documented. | GitHub collaborators API; `docs/GITHUB_SECURITY_CONFIGURATION.md` | Keep future collaborators least-privilege. |
| OSPS-AC-03.01 | Met | `main` branch protection prevents direct commits by requiring PRs, strict status checks, conversation resolution, and administrator enforcement before merge. | GitHub branch protection API; `docs/GITHUB_SECURITY_CONFIGURATION.md` | Add a required approving review only when a second real write-access reviewer exists. |
| OSPS-AC-03.02 | Met | `main` branch protection has force pushes and branch deletion disabled. | GitHub branch protection API; `docs/GITHUB_SECURITY_CONFIGURATION.md` | None. |
| OSPS-BR-01.01 | Met | Workflows do not pass untrusted issue/PR titles, branch names, or user-controlled metadata into shell commands. Workflow dispatch uses a typed choice input. | GitHub workflow files | None. |
| OSPS-BR-01.02 | N/A | This requirement is retired in the upstream baseline source. | OpenSSF `OSPS-BR.yaml` | None. |
| OSPS-BR-01.03 | Met | PR workflows have no package-publishing credentials. Repository Actions default token permissions are read-only, fork PRs require first-time contributor approval, and publishing runs only on release/manual dispatch with OIDC. | GitHub Actions permissions API; `.github/workflows/ci.yml`, `.github/workflows/agent-circuit-breaker-scan.yml`, `.github/workflows/publish.yml` | Pin third-party Actions and split SARIF upload after refreshing the maintainer token with `workflow` scope. |
| OSPS-BR-03.01 | Met | Official project channels in package metadata and docs use HTTPS URLs. Cleartext remote policy loading is rejected by default. | `setup.py`, `README.md`, `docs/SECURITY_MODEL.md` | None. |
| OSPS-BR-03.02 | Met | Official distribution channels are PyPI, TestPyPI, and GitHub Releases over HTTPS; release publishing uses OIDC trusted publishing. | `setup.py`, `README.md`, `.github/workflows/publish.yml`, `docs/PUBLISHING.md` | None. |
| OSPS-BR-07.01 | Met | Secret scanning and push protection are enabled; `.gitignore` excludes environment files and build artifacts; repository scans found no obvious committed secrets. | GitHub repository API; `.gitignore`; `SECURITY.md` | Keep scanning and push protection enabled. |
| OSPS-DO-01.01 | Met | User guides cover installation, quick start, CLI/API use, policies/rules, MCP, pipeline SDK, and security model. | `README.md`, `QUICKSTART.md`, `docs/GETTING_STARTED.md`, `docs/INTEGRATION_GUIDE.md` | None. |
| OSPS-DO-02.01 | Met | Defect reporting is documented through issue templates and contribution/security docs. | `.github/ISSUE_TEMPLATE/`, `CONTRIBUTING.md`, `SECURITY.md` | None. |
| OSPS-GV-02.01 | Met | Public issues are enabled and issue templates support public discussion of bugs/features and usage obstacles. | GitHub repository API; `.github/ISSUE_TEMPLATE/` | None. |
| OSPS-GV-03.01 | Met | Contribution process, tests, review expectations, generated-artifact policy, and security-sensitive contribution guidance are documented. | `CONTRIBUTING.md` | None. |
| OSPS-LE-02.01 | Met | Source code license is MIT, an OSI-approved open source license. | `LICENSE`, GitHub license API, `setup.py` | None. |
| OSPS-LE-02.02 | Met | Released package metadata declares MIT and includes the license file in built distributions. | `setup.py`, `LICENSE`, package build verification | None. |
| OSPS-LE-03.01 | Met | The repository root contains a `LICENSE` file. | `LICENSE` | None. |
| OSPS-LE-03.02 | Met | Release source and Python distributions include the `LICENSE` file. | `LICENSE`, `setup.py`, package build verification | None. |
| OSPS-QA-01.01 | Met | Source code repository is public at a stable HTTPS GitHub URL. | GitHub repository API; `setup.py` | None. |
| OSPS-QA-01.02 | Met | Git stores a public change history with commit metadata; GitHub exposes commits and tags. | Git history; GitHub repository | None. |
| OSPS-QA-02.01 | Met | Direct runtime dependencies and optional extras are declared in the packaging metadata; core runtime has no required third-party dependencies. | `setup.py`, `requirements.txt` | None. |
| OSPS-QA-04.01 | N/A | ACB is maintained in a single authoritative repository; no separate codebase repositories are part of the project. | Repository structure; `projects/README.md` | Update this if the project adds additional codebase repositories. |
| OSPS-QA-05.01 | Met | No generated executable artifacts are tracked in Git. Local build output is ignored. | `git ls-files`; `.gitignore` | None. |
| OSPS-QA-05.02 | Met | No unreviewable binary artifacts are tracked in Git; the README hero is a text SVG. | `git ls-files`; `docs/assets/agent-circuit-breaker-readme-hero.svg` | None. |
| OSPS-VM-02.01 | Met | Security contacts and private vulnerability reporting instructions are documented. | `SECURITY.md`; GitHub private vulnerability reporting API | None. |

## Copy-Paste Justifications For Met Criteria

- OSPS-AC-02.01: GitHub collaborator access is manually assigned, the current collaborator set is limited to the owner/admin account, and least-privilege collaborator expectations are documented.
- OSPS-AC-03.01: The `main` branch is protected against direct commits by requiring pull requests, strict CI status checks, conversation resolution, and administrator enforcement.
- OSPS-AC-03.02: The `main` branch protection disallows force pushes and branch deletion.
- OSPS-BR-01.01: GitHub Actions workflows do not inject untrusted repository metadata into shell commands; manual inputs use constrained choice values.
- OSPS-BR-01.03: Pull request workflows do not receive package-publishing credentials; GitHub Actions default token permissions are read-only, fork PRs require first-time contributor approval, and privileged publishing is isolated to release/manual workflows using OIDC.
- OSPS-BR-03.01: Official project URLs are HTTPS, and cleartext remote policy URLs are rejected by default.
- OSPS-BR-03.02: Official distribution channels are HTTPS-protected PyPI/TestPyPI/GitHub Releases and use trusted publishing.
- OSPS-BR-07.01: GitHub secret scanning and push protection are enabled, ignored local files include environment/build outputs, and repository scans did not find obvious committed secrets.
- OSPS-DO-01.01: The repository includes installation, quick-start, integration, rule/policy, API, and security model documentation.
- OSPS-DO-02.01: Public defect reporting is documented through GitHub issue templates, `CONTRIBUTING.md`, and `SECURITY.md`.
- OSPS-GV-02.01: GitHub Issues are enabled for public discussion of bugs, changes, and usage obstacles.
- OSPS-GV-03.01: `CONTRIBUTING.md` documents setup, tests, review expectations, generated-artifact policy, and security contribution rules.
- OSPS-LE-02.01: The source code is licensed under MIT.
- OSPS-LE-02.02: Released Python assets declare MIT and include the license file.
- OSPS-LE-03.01: The source repository includes a root `LICENSE` file.
- OSPS-LE-03.02: The release source and built package include the license file.
- OSPS-QA-01.01: The repository is publicly readable at the stable GitHub URL.
- OSPS-QA-01.02: Git/GitHub provide a public change history with author and timestamp metadata.
- OSPS-QA-02.01: Direct dependencies and optional extras are declared in `setup.py`; `requirements.txt` documents the dependency-free core runtime.
- OSPS-QA-05.01: No generated executables are tracked in Git.
- OSPS-QA-05.02: No opaque binary artifacts are tracked in Git.
- OSPS-VM-02.01: `SECURITY.md` contains security contacts and private vulnerability reporting instructions.
