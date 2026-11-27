# Security Policy

## Supported versions

ZIPMarkdown `0.1.x` beta receives security fixes. Pre-release behavior may change, but vault format compatibility is treated conservatively.

## Reporting a vulnerability

Do **not** disclose a suspected vulnerability, secret-detection bypass, path traversal, vault weakness, or credential in a public issue.

Use [GitHub Private Vulnerability Reporting](https://github.com/javierstampa/ZIPMarkdown/security/advisories/new) (**Security → Report a vulnerability**). Reports submitted there are private and visible only to the maintainers until a coordinated disclosure is agreed.

The maintainer must enable GitHub private vulnerability reporting in **Settings → Security → Code security and analysis** before making the repository public. Verify that the **Report a vulnerability** button is visible from a signed-out or non-maintainer account. If it is unavailable, pause publication; never redirect a reporter to a public issue.

Include the affected version, reproduction steps, expected impact, and a minimal synthetic fixture. Never attach real credentials, a production `.secrets` vault, or customer data. The project aims to acknowledge a report within 3 business days and provide an initial assessment within 7 business days; these are response targets, not a promise of a fix date.

Maintainers will coordinate remediation and disclosure through the private advisory. Credit is offered unless the reporter asks to remain anonymous.

## Security model

ZIPMarkdown is local and has no telemetry. Secret filtering reduces risk but cannot guarantee detection of every secret. Windows vaults use per-user DPAPI; `.secrets` files must never be shared with an AI or committed. Untrusted ZIPs are subject to path, entry-count, size, compression-ratio, encryption, duplicate-entry, and symlink checks.
