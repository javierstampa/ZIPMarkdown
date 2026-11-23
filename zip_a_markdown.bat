@echo off
setlocal
set "SCRIPT=%~dp0zip_a_markdown.py"
set "INPUT=%~1"

if not exist "%SCRIPT%" (
    echo ERROR: no se encuentra "%SCRIPT%"
    pause
    exit /b 1
)

powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; $f=$env:INPUT; if([string]::IsNullOrWhiteSpace($f)){$choice=[Windows.Forms.MessageBox]::Show('¿Quieres seleccionar una carpeta? Pulsa No para elegir un ZIP.','Elegir origen','YesNoCancel'); if($choice -eq 'Yes'){$d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='Selecciona una carpeta de proyecto'; if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){$f=$d.SelectedPath}} elseif($choice -eq 'No'){$d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='Selecciona un ZIP'; $d.Filter='Archivos ZIP (*.zip)|*.zip|Todos (*.*)|*.*'; if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){$f=$d.FileName}}}; $f=$f.Trim().Trim([char]34); if([string]::IsNullOrWhiteSpace($f)){exit 0}; $s=New-Object System.Windows.Forms.SaveFileDialog; $s.Title='Guardar Markdown como'; $s.Filter='Markdown (*.md)|*.md|Todos (*.*)|*.*'; $s.DefaultExt='md'; $s.AddExtension=$true; $s.InitialDirectory=[IO.Path]::GetDirectoryName($f); if(Test-Path -LiteralPath $f -PathType Container){$s.FileName=([IO.Path]::GetFileName($f)+'.md')}else{$s.FileName=([IO.Path]::GetFileNameWithoutExtension($f)+'.md')}; if($s.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){$o=$s.FileName}else{$o=Read-Host 'Ruta de salida (vacio = predeterminada)'}; $o=$o.Trim().Trim([char]34); if([string]::IsNullOrWhiteSpace($o)){& python $env:SCRIPT $f}else{& python $env:SCRIPT $f --output $o}; exit $LASTEXITCODE"
set "RESULT=%ERRORLEVEL%"

:finish
if not "%RESULT%"=="0" echo Conversion failed with exit code %RESULT%.
pause
exit /b %RESULT%
