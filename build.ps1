# Builds AtlasCoordinatorService.exe with the .NET Framework C# compiler.
# Output goes to .\bin, which is not part of the repository.
$ErrorActionPreference = 'Stop'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe not found at $csc" }

$root = $PSScriptRoot
$out  = Join-Path $root 'bin'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$exeOut = Join-Path $out 'AtlasCoordinatorService.exe'
$source = Join-Path $root 'AtlasCoordinatorService.cs'

& $csc /nologo /target:exe "/out:$exeOut" /r:System.ServiceProcess.dll /r:System.Web.Extensions.dll /r:System.Core.dll "$source"

if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE" }
Write-Host "Built $(Join-Path $out 'AtlasCoordinatorService.exe')"
