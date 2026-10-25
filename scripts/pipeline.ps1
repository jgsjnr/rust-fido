# ==============================================================================
# AegisKey - PIPELINE autonomo: test-all -> build-freertos-s3 -> flash S3 -> valida boot
# Uso: .\scripts\pipeline.ps1 [-SkipTests] [-SkipFlash] [-PortS3 COM7]
# Lane suportada: somente FreeRTOS (build-freertos-s3* + flash.ps1 via esptool).
# Legado (build-all / build-esp32-*) = NAO USAR, ver scripts/README.md.
# ==============================================================================
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipFlash,
    [string]$PortS3 = "COM7"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

if (-not $SkipTests) {
    Write-Host "=== [1/3] TESTES ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "test-all.ps1")
    if ($LASTEXITCODE -ne 0) { Write-Host "PIPELINE ABORTADO nos testes." -ForegroundColor Red; exit 1 }
} else {
    Write-Host "=== [1/3] TESTES (pulados) ===" -ForegroundColor Gray
}

Write-Host "=== [2/3] BUILD FREERTOS S3 ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "build-freertos-s3.ps1")
if ($LASTEXITCODE -ne 0) { Write-Host "PIPELINE ABORTADO no build." -ForegroundColor Red; exit 1 }

if ($SkipFlash) { Write-Host "PIPELINE OK (sem flash)." -ForegroundColor Green; exit 0 }

Write-Host "=== [3/3] FLASH + PORTAS ===" -ForegroundColor Cyan
$bin = Join-Path $global:TargetDir "aegis-app-freertos-s3.bin"
& (Join-Path $PSScriptRoot "flash.ps1") -Chip esp32s3 -Port $PortS3 -BinPath $bin
if ($LASTEXITCODE -ne 0) { Write-Host "PIPELINE ABORTADO no flash S3." -ForegroundColor Red; exit 1 }

Get-PnpDevice -Class Ports -Status OK | Select-Object FriendlyName | Format-Table -AutoSize
Write-Host "PIPELINE OK. Valide o boot: .\scripts\flash.ps1 -Monitor (ou live_monitor na COM)." -ForegroundColor Green
exit 0
