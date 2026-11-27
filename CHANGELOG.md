# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses semantic package versions; the first public tag is `v0.1.0b1`.

## [Unreleased]

### Added
- Regression tests for destructive import/export/vault/rebase path aliases and output-extension enforcement.
- Incremental, size-bounded Markdown parsing with limits applied before reading content.
- Optional strict secret mode backed by a clean Gitleaks scan of generated Markdown.
- Private vulnerability-reporting procedure based on GitHub private advisories, with verification and response targets.

### Changed
- Python package version is now the PEP 440 prerelease `0.1.0b1`.
- CI uses immutable action SHAs, enforces at least 80% branch-aware Python coverage, and narrows the Gitleaks allowlist to explicit synthetic marker patterns.
- Beta releases now attach the Python wheel and source distribution alongside the Windows executable and checksum.
- Packaging metadata now uses the SPDX `MIT` license expression and declares the license file with current PyPA metadata.

### Security
- Password literals and explicit Authorization headers no longer bypass reversible redaction solely because they are short or alphabetic.
- Canonical archive keys now combine Unicode NFC normalization and case folding. ZIP, folder, Markdown, and vault-rebase paths reject cross-platform canonical collisions before they can overwrite one another.
- Added regressions for case-only folder collisions and composed/decomposed Unicode ZIP paths.

## [0.1.0] - 2026-11-24

### Added
- Installable `zipmarkdown` CLI with `export`, `import`, and `rebase` commands.
- Injectable vault backend and real Windows DPAPI tests.
- Configurable ZIP/PDF resource limits and centralized portable-path validation.
- Optional `.gitignore` support, Linux/Windows CI, release workflow, community files, and bilingual documentation.
- Exact binary/PDF recovery and complete folder/ZIP round-trip tests.

### Changed
- Secret filtering now uses high and contextual confidence and emits a value-free report.
- Vault creation is lazy; empty vaults are not written.
- Markdown, vault, ZIP, rebase, and package outputs use atomic writes.
- Public branding is consistently ZIPMarkdown; historical `MDTK` vault markers remain readable.

### Security
- Rejects Zip Slip paths, Windows-reserved names, duplicate/encrypted/symlink entries, suspicious compression ratios, and configured resource-limit violations.
- Conservative rebase does not overwrite new real values introduced by an AI.
