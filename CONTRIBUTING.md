# Contributing to ZIPMarkdown

Thank you for improving ZIPMarkdown. The project is security-sensitive: preserve conservative secret restoration, binary fidelity, portable paths, and local-only operation.

## Development setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m build
```

Use Python 3.10–3.12. Add a regression test before changing vault, redaction, archive, PDF, filename-recovery, or rebase behavior. Portable tests belong in `tests/unit` or `tests/integration`; real DPAPI tests belong in `tests/windows`.

## Pull requests

1. Branch from `main`.
2. Keep changes focused and backwards-compatible where practical.
3. Never commit a real `.secrets`, `.env`, credential, private key, or personal path.
4. Describe security and compatibility effects.
5. Confirm tests, Ruff, package build, and secret scanning pass.

Do not open public issues for suspected vulnerabilities; follow [SECURITY.md](SECURITY.md).
