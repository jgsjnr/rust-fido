# ==============================================================================
# AegisKey S3 - Build & Flash para ESP32-S3 DevKitC-1 (USB Nativo + WS2812 LED)
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$Test,
    [switch]$Flash,
    [string]$Port,
    [switch]$Monitor,
    [switch]$Clean,
    [switch]$OnlyBuild,
    [switch]$OnlyFlash
)

. (Join-Path $PSScriptRoot "common.ps1")

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " [AEGISKEY] ESP32-S3 DevKitC-1 (USB Nativo + WS2812 LED)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$chip = "esp32s3"
$target = "xtensa-esp32s3-espidf"
$feature = "board-devkitc"
$binName = "aegis-app-esp32s3-devkitc.bin"

if ($Test) {
    Invoke-FirmwareTest
}

if (-not $OnlyFlash) {
    Invoke-FirmwareBuild -Target $target -Feature $feature -Clean:$Clean
    $binPath = Invoke-FirmwareElf2Image -Chip $chip -Target $target -OutBinName $binName
} else {
    $binPath = Join-Path $global:TargetDir $binName
}

if ($Flash -or $OnlyFlash) {
    $usedPort = Invoke-FirmwareFlash -Chip $chip -BinPath $binPath -Port $Port
    if ($Monitor) {
        Invoke-SerialMonitor -Port $usedPort
    }
} else {
    Write-Host "`nPara gravar na placa, execute:" -ForegroundColor Yellow
    Write-Host "  .\scripts\build-esp32s3-devkitc.ps1 -Flash" -ForegroundColor White
    Write-Host "  .\scripts\build-esp32s3-devkitc.ps1 -Flash -Monitor" -ForegroundColor White
}
