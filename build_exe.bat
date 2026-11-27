@echo off
setlocal
cd /d "%~dp0"

python -m pip install ".[dev,gui]"
if errorlevel 1 goto :error

if exist "dist\ZIPMarkdown.exe" del /q "dist\ZIPMarkdown.exe"
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name ZIPMarkdown ^
  --icon "%~dp0assets\zipmarkdown.ico" ^
  --add-data "%~dp0assets\zipmarkdown.ico;assets" ^
  --distpath dist ^
  --workpath "%TEMP%\ZIPMarkdown-pyinstaller" ^
  --specpath "%TEMP%\ZIPMarkdown-pyinstaller" ^
  --collect-all pystray ^
  --collect-all pypdf ^
  zip_markdown_app.py
if errorlevel 1 goto :error

powershell -NoProfile -Command "$h=(Get-FileHash -Algorithm SHA256 'dist\ZIPMarkdown.exe').Hash.ToLower(); Set-Content -Path 'dist\ZIPMarkdown.exe.sha256' -Value ($h+'  ZIPMarkdown.exe') -NoNewline -Encoding Ascii"
if errorlevel 1 goto :error
if not exist "dist\ZIPMarkdown.exe.sha256" goto :error

echo Built dist\ZIPMarkdown.exe
echo SHA-256 written to dist\ZIPMarkdown.exe.sha256
exit /b 0

:error
echo ERROR: reproducible build failed. Review the output above.
exit /b 1
