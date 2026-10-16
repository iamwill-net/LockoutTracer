# Builds LockoutTracer.exe with the C# compiler that ships with .NET Framework 4.x (no SDK needed).
$ErrorActionPreference = 'Stop'
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$src = Join-Path $PSScriptRoot 'src'
$out = Join-Path $PSScriptRoot 'LockoutTracer.exe'

& $csc /nologo /target:winexe /optimize+ /platform:anycpu "/out:$out" "/win32manifest:$src\app.manifest" "/win32icon:$src\app.ico" `
    /r:System.dll /r:System.Core.dll /r:System.Data.dll /r:System.Xml.dll /r:System.Drawing.dll `
    /r:System.Windows.Forms.dll /r:System.DirectoryServices.dll `
    "$src\Engine.cs" "$src\MainForm.cs" "$src\Theme.cs"
if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE)" }
Get-Item $out | Select-Object Name, Length, LastWriteTime
