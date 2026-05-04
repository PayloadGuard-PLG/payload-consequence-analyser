# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅        |
| < 1.1   | ❌        |

## Reporting a Vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/security/advisories/new) on this repository.

Do **not** open a public issue for security matters. We aim to respond within 5 business days and to publish a fix within 30 days of a confirmed report.

## Scope

Vulnerabilities in scope:
- Shell injection or expression injection in the GitHub Action
- Output injection into GitHub PR comments or Check Run summaries
- Bypass of PayloadGuard's detection logic via crafted branch names, file names, or content
- Exposure of GitHub App credentials or tokens

Out of scope:
- Denial-of-service via extremely large repositories (mitigated by 1 MB blob cap but acknowledged as a resource constraint)
- Issues in dependencies not controlled by this project
