# Security Policy

## Supported Versions

Security fixes are supported for the latest stable release.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting A Vulnerability

Please do not open a public issue for a vulnerability.

Report suspected vulnerabilities through GitHub's private vulnerability reporting for this repository when available. If private reporting is unavailable, contact the maintainer listed in `setup.py`.

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

Out-of-scope reports include:

- requests for complete shell or SQL grammar support.
- behavior already documented as `UNKNOWN`.
- issues caused by callers ignoring `BLOCK`, `ERROR`, or `UNKNOWN`.
- sandbox, antivirus, endpoint monitor, or process isolation expectations.
