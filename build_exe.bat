@echo off
setlocal
cd /d "%~dp0"

python -c "import PyInstaller, pystray, PIL, pypdf" >nul 2>nul
if errorlevel 1 (
    echo Faltan dependencias. Instalando PyInstaller y dependencias...
    python -m pip install --user pyinstaller pystray Pillow pypdf
    if errorlevel 1 (
        echo ERROR: No se pudo instalar PyInstaller.
        pause
        exit /b 1
    )
)

if not exist "build\ZIPMarkdown" mkdir "build\ZIPMarkdown"

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name ZIPMarkdown ^
    --distpath . ^
    --workpath build\ZIPMarkdown ^
    --specpath build\ZIPMarkdown ^
    --collect-all pystray ^
    --collect-all pypdf ^
    zip_markdown_app.py
if errorlevel 1 (
    echo ERROR: Fallo la creacion del ejecutable.
    pause
    exit /b 1
)

echo.
echo Ejecutable creado en:
echo %~dp0ZIPMarkdown.exe
pause
