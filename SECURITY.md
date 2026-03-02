# Security Policy

## Reporting a Vulnerability

ROE Gate is a security-critical tool. We take vulnerability reports seriously.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via email:

**Email:** [rick@greylineinteractive.com](mailto:rick@greylineinteractive.com)

**Subject line:** `[SECURITY] ROE Gate - <brief description>`

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected component (gate service, crypto, executor, etc.)
- Impact assessment (what an attacker could achieve)
- Any suggested fix (optional)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix or mitigation:** Depends on severity, but critical issues are prioritized immediately

### Scope

The following are in scope for security reports:

- Token forgery, replay, or bypass
- Gate evaluation bypass (action executed without valid evaluation)
- ROE specification parsing vulnerabilities
- Judge LLM manipulation that leads to incorrect decisions
- Privilege escalation through MCP tools
- Audit log tampering or evasion

### Out of Scope

- Vulnerabilities in third-party dependencies (report these upstream)
- Issues requiring physical access to the host machine
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
