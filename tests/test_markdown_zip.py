import contextlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import markdown_a_zip
import zip_a_markdown


class MarkdownZipRoundTripTests(unittest.TestCase):
    def test_filename_underscores_survive_round_trip(self) -> None:
        filename = "Cuantica/caq_gemv_v5.cu"
        content = '#include "caq_gemv_v5.cu"\nint main() {}\n'

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_zip = root / "source.zip"
            markdown = root / "source.md"
            rebuilt_zip = root / "rebuilt.zip"

            with zipfile.ZipFile(original_zip, "w") as archive:
                archive.writestr(filename, content)

            zip_a_markdown.convert(original_zip, markdown)
            extracted = markdown_a_zip.parse_markdown(markdown)
            self.assertEqual(extracted, [(filename, content)])

            markdown_a_zip.convert(markdown, rebuilt_zip)
            with zipfile.ZipFile(rebuilt_zip) as archive:
                self.assertEqual(archive.namelist(), [filename])
                self.assertEqual(archive.read(filename).decode("utf-8"), content)

    def test_plain_heading_keeps_filename_underscores(self) -> None:
        markdown = "## Cuantica/caq_gemv_v5.cu\n\n```cpp\nint main() {}\n```\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.md"
            path.write_text(markdown, encoding="utf-8")
            self.assertEqual(
                markdown_a_zip.parse_markdown(path),
                [("Cuantica/caq_gemv_v5.cu", "int main() {}")],
            )

    def test_recovers_lost_underscores_from_include(self) -> None:
        markdown = (
            "## Cuantica/caqgemvv5.cu\n\n```cpp\nint kernel() {}\n```\n\n"
            "## Cuantica/test.cpp\n\n```cpp\n#include \"caq_gemv_v5.cu\"\n```\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.md"
            path.write_text(markdown, encoding="utf-8")
            extracted = markdown_a_zip.parse_markdown(path)
            self.assertEqual(extracted[0][0], "Cuantica/caq_gemv_v5.cu")

    def test_zip_to_markdown_recovers_name_from_include(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            markdown = root / "source.md"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("Cuantica/caqgemvv5.cu", "int kernel() {}\n")
                archive.writestr(
                    "Cuantica/test.cpp", '#include "caq_gemv_v5.cu"\n'
                )

            zip_a_markdown.convert(source, markdown)
            self.assertIn("## `Cuantica/caq_gemv_v5.cu`", markdown.read_text(encoding="utf-8"))

    def test_folder_to_markdown_skips_git_and_selected_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "src").mkdir()
            (root / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("internal", encoding="utf-8")
            markdown = root / "context.md"

            zip_a_markdown.convert_folder_to_markdown(
                root,
                markdown,
                exclude_paths={markdown},
            )

            files = markdown_a_zip.parse_markdown(markdown)
            self.assertEqual(files, [("src/main.py", "print('ok')\n")])

    def test_zip_to_markdown_skips_secret_files_and_redacts_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            markdown = root / "source.md"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(".env.production", "API_KEY=should-not-appear\n")
                archive.writestr("config/secrets.yaml", "password: should-not-appear\n")
                archive.writestr("src/settings.py", 'OPENAI_API_KEY = "sk-test-verysecretvalue123"\n')
                archive.writestr("src/main.py", "token = os.getenv('TOKEN')\n")
                archive.writestr(".venv/Lib/site-packages/package.py", "third-party code\n")
                archive.writestr("node_modules/package/index.js", "third-party code\n")

            report = zip_a_markdown.convert(source, markdown)

            output = markdown.read_text(encoding="utf-8")
            self.assertNotIn("should-not-appear", output)
            self.assertNotIn("sk-test-verysecretvalue123", output)
            self.assertRegex(
                output,
                r'OPENAI_API_KEY = "\[\[MDTK_SECRET_[a-f0-9]{32}\]\]"',
            )
            self.assertIn("token = os.getenv('TOKEN')", output)
            self.assertEqual(report.included, 2)
            self.assertEqual(report.sensitive_files_skipped, 2)
            self.assertEqual(report.generated_files_skipped, 2)
            self.assertEqual(report.values_redacted, 1)

    def test_folder_to_markdown_filters_secret_paths_and_private_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / ".aws").mkdir()
            (root / ".aws" / "credentials").write_text("secret", encoding="utf-8")
            (root / "node_modules" / "dependency").mkdir(parents=True)
            (root / "node_modules" / "dependency" / "code.js").write_text(
                "third-party code", encoding="utf-8"
            )
            (root / "app.py").write_text(
                "key = \"visible-later-not-this-value\"\n"
                "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            markdown = root / "context.md"

            report = zip_a_markdown.convert_folder_to_markdown(root, markdown)

            output = markdown.read_text(encoding="utf-8")
            self.assertNotIn("private-material", output)
            self.assertNotIn("visible-later-not-this-value", output)
            self.assertRegex(output, r"\[\[MDTK_SECRET_[a-f0-9]{32}\]\]")
            self.assertEqual(report.sensitive_files_skipped, 1)
            self.assertEqual(report.generated_files_skipped, 1)
            self.assertEqual(report.values_redacted, 2)

    def test_private_key_redaction_preserves_every_source_line(self) -> None:
        content = (
            "before()\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "private-material-line-one\n"
            "private-material-line-two\n"
            "-----END PRIVATE KEY-----\n"
            "after()\n"
        )
        redacted, count = zip_a_markdown.redact_secret_values(content)

        self.assertEqual(len(redacted.splitlines()), len(content.splitlines()))
        self.assertNotIn("private-material", redacted)
        self.assertEqual(redacted.splitlines()[0], "before()")
        self.assertEqual(redacted.splitlines()[-1], "after()")
        self.assertEqual(count, 1)

    def test_folder_export_does_not_ingest_existing_output_and_keeps_env_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / ".env.example").write_text(
                "API_KEY=actual-secret-value\n", encoding="utf-8"
            )
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            markdown = root / "context.md"
            markdown.write_text("old export", encoding="utf-8")

            zip_a_markdown.convert_folder_to_markdown(root, markdown)
            files = markdown_a_zip.parse_markdown(markdown)

            self.assertEqual([name for name, _ in files], [".env.example", "main.py"])
            self.assertRegex(
                dict(files)[".env.example"],
                r"API_KEY=\[\[MDTK_SECRET_[a-f0-9]{32}\]\]",
            )

    def test_cli_accepts_a_folder_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "my.project"
            source.mkdir()
            (source / "main.py").write_text("print('ok')\n", encoding="utf-8")
            output = root / "snapshot.md"
            arguments = ["zip_a_markdown.py", str(source), "--output", str(output)]

            with patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                result = zip_a_markdown.main()

            self.assertEqual(result, 0)
            self.assertEqual(
                markdown_a_zip.parse_markdown(output),
                [("main.py", "print('ok')\n")],
            )

    def test_pdf_text_is_extracted_and_restored_in_zip(self) -> None:
        def make_test_pdf(text: str) -> bytes:
            content = f"BT /F1 12 Tf 72 712 Td ({text}) Tj ET"
            content_bytes = content.encode("latin1")
            length = len(content_bytes)
            return (
                b"%PDF-1.4\n"
                b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
                b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
                b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
                b"4 0 obj << /Length " + str(length).encode("ascii") + b" >>\nstream\n"
                + content_bytes + b"\nendstream\nendobj\n"
                b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
                b"xref\n0 6\n0000000000 65535 f \n"
                b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n999\n%%EOF\n"
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_zip = root / "source.zip"
            markdown = root / "source.md"
            rebuilt_zip = root / "rebuilt.zip"
            pdf_data = make_test_pdf("Instrucciones del proyecto en PDF")

            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("docs/instrucciones.pdf", pdf_data)
                archive.writestr("src/main.py", "print('hola')\n")

            report = zip_a_markdown.convert(source_zip, markdown)
            md_text = markdown.read_text(encoding="utf-8")
            self.assertIn("docs/instrucciones.pdf", md_text)
            self.assertIn("Instrucciones del proyecto en PDF", md_text)
            self.assertEqual(report.included, 2)
            self.assertEqual(report.skipped_binary, 0)

            markdown_a_zip.convert(markdown, rebuilt_zip)
            with zipfile.ZipFile(rebuilt_zip) as archive:
                self.assertIn("docs/instrucciones.pdf", archive.namelist())
                self.assertEqual(archive.read("docs/instrucciones.pdf"), pdf_data)

    def test_code_with_token_in_name_is_not_treated_as_sensitive(self) -> None:
        from secret_filter import is_sensitive_path

        self.assertFalse(is_sensitive_path("src/token_service.py"))
        self.assertFalse(is_sensitive_path("auth/password_reset.ts"))
        self.assertFalse(is_sensitive_path("docs/token_instructions.pdf"))
        self.assertTrue(is_sensitive_path("credentials.json"))
        self.assertTrue(is_sensitive_path(".env"))
        self.assertTrue(is_sensitive_path("secrets/keys.txt"))


if __name__ == "__main__":
    unittest.main()
