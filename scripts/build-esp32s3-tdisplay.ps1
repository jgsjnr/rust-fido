# ==============================================================================
# AegisKey S3 - Build & Flash para LilyGO T-Display-S3 (ESP32-S3 + Tela 170x320)
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
Write-Host " [AEGISKEY] LilyGO T-Display-S3 (ESP32-S3 + LCD 170x320)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$chip = "esp32s3"
$target = "xtensa-esp32s3-espidf"
$feature = "board-t-display"
$binName = "aegis-app-esp32s3-tdisplay.bin"

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
    Write-Host "  .\scripts\build-esp32s3-tdisplay.ps1 -Flash" -ForegroundColor White
    Write-Host "  .\scripts\build-esp32s3-tdisplay.ps1 -Flash -Monitor" -ForegroundColor White
}
