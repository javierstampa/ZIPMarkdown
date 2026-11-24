# ZIPMarkdown

**Export a complete project to AI-friendly Markdown, redact secrets locally, let an AI modify the project, and conservatively restore protected values when rebuilding it.**

> **Beta:** package version `0.1.0`; first public pre-release tag `v0.1.0-beta`.

ZIPMarkdown is a local, no-telemetry round-trip tool. Unlike one-way “folder to prompt” converters, it keeps the recovery path in scope: filenames, text, PDFs, binaries, sensitive files, and protected values can be rebuilt after an AI edits the Markdown.

```text
Project/ZIP → Markdown → AI edits → Secret rebase → Rebuilt project
```

## Why it exists

Sending a project to an AI creates two competing risks: omitting important non-text context, or exposing credentials and machine-local files. ZIPMarkdown creates a readable Markdown snapshot while keeping protected recovery material in a local vault. On rebuild, it restores an original secret only where a marker or safe placeholder remains; a new real value introduced by the AI is never overwritten automatically.

## Core properties

- Folder or ZIP → indexed Markdown with stable fenced file blocks.
- Markdown → ZIP or project directory.
- Confidence-based redaction for assignments, provider tokens, authorization values, URLs, and private keys.
- Conservative rebase by marker, path, variable name, and safe unique filename recovery.
- Exact recovery of PDFs, binaries, sensitive files, non-UTF-8 text, and untouched protected files.
- ZIP Slip, absolute path, traversal, Windows reserved-name, duplicate, encrypted-entry, symlink, size, page-count, and compression-ratio defenses.
- Atomic Markdown, vault, ZIP, and rebase outputs.
- Optional `.gitignore` matching; security and dependency exclusions always remain active.
- Local operation with no analytics, sync, API calls, or telemetry.

## Install

Python 3.10–3.12 is supported.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install .
```

For isolated CLI installation:

```bash
pipx install .
```

Development and executable-build tools:

```bash
python -m pip install -e ".[dev]"
```

## CLI

### Export

```bash
zipmarkdown export ./my-project -o project.md
zipmarkdown export project.zip -o project.md
zipmarkdown export ./my-project -o project.md --respect-gitignore --verbose
```

The legacy commands remain available:

```bash
python zip_a_markdown.py ./my-project -o project.md
python zip_a_markdown.py project.zip -o project.md
```

### Let an AI edit the Markdown

Share only the `.md`. **Never share or commit the adjacent `.secrets` file.** Review the Markdown before sharing it; filtering reduces risk but does not guarantee detection of every secret.

### Rebuild

```bash
zipmarkdown import edited.md --secrets project.secrets -o rebuilt.zip
zipmarkdown import edited.md --secrets project.secrets --folder -o rebuilt-project
```

If the Markdown and vault have the same stem and remain adjacent, `--secrets` is optional. To rebuild without applying an adjacent vault:

```bash
zipmarkdown import edited.md --no-vault -o rebuilt.zip
```

### Rebase an AI-provided ZIP or Markdown

```bash
zipmarkdown rebase edited.md --secrets project.secrets -o rebased.zip
zipmarkdown rebase ai-output.zip --secrets project.secrets -o rebased.zip
```

Rebase restores intact internal markers and recognized placeholders such as `YOUR_API_KEY`, `<token>`, and `[REDACTED]`. It uses path and variable name only when the match is safe. Ambiguous matches are reported and left unchanged. New real values are preserved.

## Small end-to-end example

```text
sample/
├── src/app.py
├── assets/logo.bin
└── .env
```

```bash
zipmarkdown export sample -o sample.md
# Give sample.md—not sample.secrets—to the AI.
zipmarkdown import sample-edited.md --secrets sample.secrets -o sample-rebuilt.zip
```

The Markdown contains readable `src/app.py`; `.env` and `assets/logo.bin` remain only in the protected local vault and are restored to the rebuilt ZIP.

## Vault and platform support

The on-disk vault format retains historical `MDTK` markers for compatibility with pre-public builds; the public product name is ZIPMarkdown.

| Capability | Windows | Linux/macOS |
|---|---:|---:|
| Export projects needing no protected recovery data | Yes | Yes |
| Import/rebuild without a vault | Yes | Yes |
| Protected `.secrets` vault | DPAPI, current Windows user | Not yet available |
| Export secrets, PDFs, sensitive files, binaries | Yes | Stops safely unless a backend is supplied by an embedding application |
| Unit-test vault injection | Yes | Yes |
| Tray GUI / EXE | Yes | Not a supported release target |

DPAPI vaults use `CryptProtectData`/`CryptUnprotectData` and can normally be opened only by the same Windows account. Writes are atomic. DPAPI is initialized only if protected recovery data actually exists; an empty `.secrets` file is not created.

### `--no-vault`

`--no-vault` is not plaintext mode. It permits only an export that requires no protected data. If ZIPMarkdown finds a secret, PDF, sensitive file, binary, or byte-preservation case, it stops instead of silently losing recovery data. This is the safe cross-platform beta behavior.

## PDFs and binaries

PDF text is extracted for AI context. The original PDF bytes are stored in the vault and restored exactly. PDFs are bounded by file-size and page-count limits. Other binaries are omitted from Markdown but stored in the vault. Dependency/build trees remain excluded rather than copied into the vault.

## Untrusted input limits

Defaults are centralized in `archive_safety.py` and exposed by CLI flags:

- 10,000 entries;
- 100 MB uncompressed per file;
- 1 GB total uncompressed;
- 1,000 PDF pages;
- compression ratio above 100:1 rejected;
- portable path-length and depth checks.

Encrypted ZIP entries and symlinks are not supported. Empty ZIPs are accepted as an explicit empty snapshot; duplicate names are rejected.

## Optional `.gitignore`

Use `--respect-gitignore` to opt in. Verbose mode reports the rule that excluded each file. The declared `pathspec` dependency implements Git-style rules. A conservative fallback covers common wildcard, rooted, directory, and negation rules in constrained offline environments; unusual Git edge cases may differ. ZIPMarkdown's own security/dependency exclusions are always applied.

## GUI and Windows executable

Run:

```bash
zipmarkdown gui
```

The tray menu exposes:

- **Project or ZIP → Markdown**
- **Markdown → Project or ZIP**
- **Apply vault / Rebase secrets**
- **Open output folder**
- **Last operation report**

Dropping a folder, ZIP, or Markdown onto `ZIPMarkdown.exe` routes it to the appropriate flow. A vault can be selected manually when the Markdown was renamed.

Build reproducibly on Windows:

```bat
build_exe.bat
```

Outputs are `dist\ZIPMarkdown.exe` and `dist\ZIPMarkdown.exe.sha256`. The executable is **not Authenticode-signed**. Windows SmartScreen may warn because the binary is new and unsigned.

## Tests and quality

```bash
python -m compileall -q .
python -m pytest
python -m ruff check .
python -m build
```

Linux CI runs portable logic with an injected test vault. Windows CI runs the same suite plus real DPAPI tests and builds the executable. The release workflow is prepared for `v0.1.0-beta`.

## Security model and limitations

- Secret filtering is defense in depth, not a guarantee. Always review exported Markdown.
- Do not send `.secrets` files to an AI or commit them.
- Rebase intentionally favors false negatives over overwriting an AI's new real value.
- Scanned/image-only PDFs yield a no-text notice; ZIPMarkdown does not perform OCR.
- macOS Keychain, Linux Secret Service, and password-encrypted vaults are roadmap items, not beta features.
- The GUI and real DPAPI/executable smoke tests require Windows.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not put sensitive details in a public issue.

## Contributing, license, roadmap

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), and [SECURITY.md](SECURITY.md). ZIPMarkdown is licensed under the [MIT License](LICENSE).

Roadmap: native macOS/Linux vault backends, optional password-protected portable vaults, OCR hooks, signed Windows releases, and richer dry-run reports.

A future short demo GIF can be placed at `docs/zipmarkdown-demo.gif`; no unverified screenshot is included in this beta.
