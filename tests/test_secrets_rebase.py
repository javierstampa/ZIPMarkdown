import tempfile
import unittest
import zipfile
from pathlib import Path

import markdown_a_zip
import zip_a_markdown
from local_secrets import load_secrets
from secrets_rebase import rebase_markdown_file, rebase_text_files, rebase_zip_file


class SecretsRebaseTests(unittest.TestCase):
    def test_export_vault_is_encrypted_and_normal_reverse_restores_original_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            markdown = root / "source.md"
            rebuilt = root / "rebuilt.zip"
            original_code = b'API_KEY = "code-secret-value"\r\nprint("ok")\r\n'
            original_env = b"SERVICE_TOKEN=env-secret-value\r\n"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("src/main.py", original_code)
                archive.writestr(".env.production", original_env)

            report = zip_a_markdown.convert(source, markdown)
            vault = report.secrets_file
            self.assertTrue(vault.is_file())
            self.assertNotIn("code-secret-value", markdown.read_text(encoding="utf-8"))
            self.assertNotIn("env-secret-value", markdown.read_text(encoding="utf-8"))
            self.assertNotIn("code-secret-value", vault.read_bytes().decode("latin-1"))
            self.assertEqual(load_secrets(vault)["version"], 1)

            markdown_a_zip.convert(markdown, rebuilt)
            with zipfile.ZipFile(rebuilt) as archive:
                self.assertEqual(archive.read("src/main.py"), original_code)
                self.assertEqual(archive.read(".env.production"), original_env)

    def test_rebase_matches_path_and_key_and_adds_missing_sensitive_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "base.zip"
            markdown = root / "base.md"
            ai_markdown = root / "ai.md"
            output = root / "ai-rebased.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("src/settings.py", 'API_KEY = "local-api-secret"\n')
                archive.writestr(".env", "SERVICE_TOKEN=local-service-secret\n")
            report = zip_a_markdown.convert(source, markdown)
            ai_markdown.write_text(
                '## `src/settings.py`\n\n```python\nAPI_KEY = "YOUR_API_KEY"\n```\n',
                encoding="utf-8",
            )

            result = rebase_markdown_file(ai_markdown, output, report.secrets_file)

            self.assertEqual(result.values_applied, 2)
            self.assertEqual(result.values_unmatched, 0)
            with zipfile.ZipFile(output) as archive:
                self.assertIn("local-api-secret", archive.read("src/settings.py").decode())
                self.assertEqual(archive.read(".env"), b"SERVICE_TOKEN=local-service-secret\n")

    def test_rebase_does_not_overwrite_non_placeholder_values_or_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "base.zip"
            markdown = root / "base.md"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("src/settings.py", 'API_KEY = "local-api-secret"\n')
            report = zip_a_markdown.convert(source, markdown)
            payload = load_secrets(report.secrets_file)

            files, result = rebase_text_files(
                [("src/settings.py", 'API_KEY = "new-value-from-ai"\n')], payload
            )

            self.assertEqual(files[0][1], 'API_KEY = "new-value-from-ai"\n')
            self.assertEqual(result.values_applied, 0)
            self.assertEqual(result.values_unmatched, 1)

    def test_rebase_ai_zip_keeps_other_entries_and_restores_sensitive_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "base.zip"
            markdown = root / "base.md"
            ai_zip = root / "ai.zip"
            output = root / "ai-rebased.zip"
            binary = b"\x00\x01image data"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("src/settings.py", 'API_KEY = "local-api-secret"\n')
                archive.writestr(".env", "SERVICE_TOKEN=local-service-secret\n")
            report = zip_a_markdown.convert(source, markdown)
            with zipfile.ZipFile(ai_zip, "w") as archive:
                archive.writestr("src/settings.py", 'API_KEY = "YOUR_API_KEY"\n')
                archive.writestr("assets/image.bin", binary)

            result = rebase_zip_file(ai_zip, output, report.secrets_file)

            self.assertEqual(result.values_applied, 2)
            self.assertEqual(result.values_unmatched, 0)
            self.assertEqual(result.sensitive_files_added, 1)
            with zipfile.ZipFile(output) as archive:
                self.assertIn("local-api-secret", archive.read("src/settings.py").decode())
                self.assertEqual(archive.read("assets/image.bin"), binary)
                self.assertEqual(archive.read(".env"), b"SERVICE_TOKEN=local-service-secret\n")

    def test_rebase_can_match_redacted_private_key_lines_without_original_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "base.zip"
            markdown = root / "base.md"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "src/key.py",
                    "-----BEGIN PRIVATE KEY-----\nprivate-line-one\nprivate-line-two\n"
                    "-----END PRIVATE KEY-----\n",
                )
            report = zip_a_markdown.convert(source, markdown)
            payload = load_secrets(report.secrets_file)

            files, result = rebase_text_files(
                [
                    (
                        "src/key.py",
                        "-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY]\n"
                        "[REDACTED PRIVATE KEY]\n-----END PRIVATE KEY-----\n",
                    )
                ],
                payload,
            )

            self.assertEqual(result.values_applied, 2)
            self.assertEqual(result.values_unmatched, 0)
            self.assertIn("private-line-one\nprivate-line-two", files[0][1])


if __name__ == "__main__":
    unittest.main()
