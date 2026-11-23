@echo off
setlocal
set "SCRIPT=%~dp0markdown_a_zip.py"
set "INPUT=%~1"

if not exist "%SCRIPT%" (
    echo ERROR: no se encuentra "%SCRIPT%"
    pause
    exit /b 1
)

powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; $f=$env:INPUT; if([string]::IsNullOrWhiteSpace($f)){$d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='Selecciona un Markdown'; $d.Filter='Markdown (*.md)|*.md|Todos (*.*)|*.*'; if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){$f=$d.FileName}else{$f=Read-Host 'Escribe la ruta del Markdown'}}; $f=$f.Trim().Trim([char]34); if([string]::IsNullOrWhiteSpace($f)){exit 0}; $s=New-Object System.Windows.Forms.SaveFileDialog; $s.Title='Guardar ZIP como'; $s.Filter='Archivos ZIP (*.zip)|*.zip|Todos (*.*)|*.*'; $s.DefaultExt='zip'; $s.AddExtension=$true; $s.InitialDirectory=[IO.Path]::GetDirectoryName($f); $s.FileName=([IO.Path]::GetFileNameWithoutExtension($f)+'.zip'); if($s.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){$o=$s.FileName}else{$o=Read-Host 'Ruta de salida (vacio = predeterminada)'}; $o=$o.Trim().Trim([char]34); if([string]::IsNullOrWhiteSpace($o)){& python $env:SCRIPT $f}else{& python $env:SCRIPT $f --output $o}; exit $LASTEXITCODE"
set "RESULT=%ERRORLEVEL%"

:finish
if not "%RESULT%"=="0" echo Conversion failed with exit code %RESULT%.
pause
exit /b %RESULT%
