# ==============================================================================
# AegisKey - PIPELINE autonomo: build-all -> flash S3+classic -> valida boot
# Uso: .\scripts\pipeline.ps1 [-SkipApk] [-SkipTests] [-SkipFlash]
# Chama os builds (paralelo interno) em vez de repetir comandos um a um.
# ==============================================================================
[CmdletBinding()]
param(
    [switch]$SkipApk,
    [switch]$SkipTests,
    [switch]$SkipFlash,
    [string]$PortS3 = "COM7",
    [string]$PortClassic = "COM8"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

Write-Host "=== [1/3] BUILD-ALL ===" -ForegroundColor Cyan
$flags = @()
if ($SkipApk) { $flags += "-SkipApk" }
if ($SkipTests) { $flags += "-SkipTests" }
& (Join-Path $PSScriptRoot "build-all.ps1") @flags
if ($LASTEXITCODE -ne 0) { Write-Host "PIPELINE ABORTADO no build." -ForegroundColor Red; exit 1 }

if ($SkipFlash) { Write-Host "PIPELINE OK (sem flash)." -ForegroundColor Green; exit 0 }

Write-Host "=== [2/3] FLASH ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "build-esp32s3-devkitc.ps1") -OnlyFlash -Port $PortS3
if ($LASTEXITCODE -ne 0) { Write-Host "PIPELINE ABORTADO no flash S3." -ForegroundColor Red; exit 1 }
& (Join-Path $PSScriptRoot "build-esp32-ttgo.ps1") -OnlyFlash -Port $PortClassic
if ($LASTEXITCODE -ne 0) { Write-Host "PIPELINE ABORTADO no flash classic." -ForegroundColor Red; exit 1 }

Write-Host "=== [3/3] PORTAS ===" -ForegroundColor Cyan
Get-PnpDevice -Class Ports -Status OK | Select-Object FriendlyName | Format-Table -AutoSize
Write-Host "PIPELINE OK. Valide o boot: .\scripts\flash.ps1 -Monitor (ou live_monitor na COM)." -ForegroundColor Green
exit 0
