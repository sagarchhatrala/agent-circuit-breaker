# Security Policy

## Supported Versions

Security fixes are supported for the latest stable v1.x release. Users should
upgrade to the newest published package before reporting an issue against an
older patch release unless the issue is reproducible on the latest release.

| Version | Supported |
| --- | --- |
| 1.x latest | Yes |
| Older 1.x patch releases | Best effort |
| < 1.0 | No |

## Reporting A Vulnerability

Please do not open a public issue for a vulnerability.

Report suspected vulnerabilities through GitHub private vulnerability
reporting for this repository:

https://github.com/sagarchhatrala/agent-circuit-breaker/security/advisories/new

If private reporting is unavailable, contact the maintainer at the email
address listed in `setup.py`.

Include:

- affected version or commit.
- reproduction steps.
- expected and actual behavior.
- potential impact.
- suggested fix, if known.

## Scope

Relevant security reports include:

- false `ALLOW` results for documented catastrophic patterns.
- fail-open behavior for malformed inputs or invalid rule files.
- bypasses in documented public API or CLI behavior.
- unsafe rule loading behavior.
- credential leakage in persisted audit, approval, or ledger records.
- policy, approval, MCP, or pipeline bypasses that permit execution when ACB
  should return `BLOCK`, `ERROR`, `UNKNOWN`, or `PENDING_APPROVAL`.

Out-of-scope reports include:

- requests for complete shell or SQL grammar support.
- behavior already documented as `UNKNOWN`.
- issues caused by callers ignoring `BLOCK`, `ERROR`, or `UNKNOWN`.
- sandbox, antivirus, endpoint monitor, or process isolation expectations.

## Disclosure Process

- The maintainer will acknowledge reports as soon as practical.
- Confirmed vulnerabilities are fixed in the supported v1.x line.
- Public details should wait until a fix, mitigation, or advisory is available.
- Do not include real credentials, private keys, or third-party secrets in the
  report. Use synthetic examples.
