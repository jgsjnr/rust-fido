# ==============================================================================
# AegisKey S3 - Utilitário Rápido de Gravação (Flash)
# ==============================================================================

[CmdletBinding()]
param(
    [string]$BinPath,
    [string]$Chip = "esp32",
    [string]$Port,
    [int]$Baud = 921600,
    [switch]$Monitor
)

. (Join-Path $PSScriptRoot "common.ps1")

Initialize-EspEnvironment

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " ⚡ AegisKey: Gravador Rápido de Firmware ESP32" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Se nenhum binário foi passado, procurar na pasta target
if (-not $BinPath) {
    $bins = Get-ChildItem -Path $script:TargetDir -Filter "*.bin" -ErrorAction SilentlyContinue
    if (-not $bins -or $bins.Count -eq 0) {
        throw "Nenhum binário .bin encontrado em $script:TargetDir. Execute um dos scripts de build primeiro."
    }

    Write-Host "Binários disponíveis em $script:TargetDir:" -ForegroundColor Gray
    for ($i = 0; $i -lt $bins.Count; $i++) {
        Write-Host "  [$($i+1)] $($bins[$i].Name) ($([math]::Round($bins[$i].Length / 1KB, 1)) KB)" -ForegroundColor Yellow
    }

    $idx = Read-Host "Selecione o binário para gravar [1-$($bins.Count)]"
    if (-not $idx) { $idx = 1 }
    $selectedBin = $bins[[int]$idx - 1]
    $BinPath = $selectedBin.FullName

    if ($selectedBin.Name -match "esp32s3") {
        $Chip = "esp32s3"
    } else {
        $Chip = "esp32"
    }
}

$usedPort = Invoke-FirmwareFlash -Chip $Chip -BinPath $BinPath -Port $Port -Baud $Baud

if ($Monitor) {
    Invoke-SerialMonitor -Port $usedPort
}
