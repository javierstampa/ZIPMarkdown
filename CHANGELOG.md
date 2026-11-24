# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses semantic package versions; the first public tag is `v0.1.0-beta`.

## [Unreleased]

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
