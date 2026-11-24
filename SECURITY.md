# Security Policy

## Supported versions

ZIPMarkdown `0.1.x` beta receives security fixes. Pre-release behavior may change, but vault format compatibility is treated conservatively.

## Reporting a vulnerability

Do **not** disclose a suspected vulnerability, secret-detection bypass, path traversal, vault weakness, or credential in a public issue.

Before publishing the repository, the maintainer must enable GitHub private vulnerability reporting or replace the following marker with a private contact channel:

> **TODO (maintainer before public release): configure and document the private security-reporting channel.**

Until that channel exists, stop publication rather than asking reporters to post sensitive details publicly. Include affected version, reproduction steps, and impact, but never attach real credentials or a production vault.

## Security model

ZIPMarkdown is local and has no telemetry. Secret filtering reduces risk but cannot guarantee detection of every secret. Windows vaults use per-user DPAPI; `.secrets` files must never be shared with an AI or committed. Untrusted ZIPs are subject to path, entry-count, size, compression-ratio, encryption, duplicate-entry, and symlink checks.
