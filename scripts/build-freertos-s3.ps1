# ==============================================================================
# AegisKey - Build device ESP32-S3 da variante FreeRTOS + proximity
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3.ps1
# Reusa common.ps1 (env ESP, sync de componentes C, elf->bin). Exit 0 = ELF ok.
# ==============================================================================
[CmdletBinding()]
param([switch]$Clean)

. (Join-Path $PSScriptRoot "common.ps1")

Invoke-FirmwareBuild -Target "xtensa-esp32s3-espidf" -Feature "board-devkitc,freertos,proximity" -Clean:$Clean
$bin = Invoke-FirmwareElf2Image -Chip "esp32s3" -Target "xtensa-esp32s3-espidf" -OutBinName "aegis-app-freertos-s3.bin"
Write-Host ("[OK] bin em {0}" -f $bin) -ForegroundColor Green
