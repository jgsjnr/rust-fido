# ==============================================================================
# AegisKey S3 - Utilitário Rápido de Gravação (Flash)
# ==============================================================================

[CmdletBinding()]
param(
    [string]$BinPath,
    [string]$Chip = "esp32",
    [string]$Port,
    [int]$Baud = 921600,
    [switch]$Monitor,
    [switch]$MonitorOnly
)

. (Join-Path $PSScriptRoot "common.ps1")

Initialize-EspEnvironment

if ($MonitorOnly) {
    if (-not $Port) {
        $ports = Get-EspPorts
        if (-not $ports -or $ports.Count -eq 0) {
            throw "Nenhuma porta serial ESP32 conectada encontrada."
        }
        $Port = $ports[0].Port
    }
    & (Join-Path $PSScriptRoot "monitor.ps1") -Port $Port
    return
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " ⚡ AegisKey: Gravador Rápido de Firmware ESP32" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Se nenhum binário foi passado, procurar na pasta target
if (-not $BinPath) {
    $targetDir = if ($global:TargetDir) { $global:TargetDir } else { "C:\t" }
    $bins = Get-ChildItem -Path $targetDir -Filter "aegis-app*.bin" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if (-not $bins -or $bins.Count -eq 0) {
        $bins = Get-ChildItem -Path $targetDir -Filter "*.bin" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    }
    if (-not $bins -or $bins.Count -eq 0) {
        throw "Nenhum binário .bin encontrado em $targetDir. Execute um dos scripts de build primeiro."
    }

    Write-Host "Binários disponíveis em $($targetDir):" -ForegroundColor Gray
    $displayCount = [Math]::Min($bins.Count, 8)
    for ($i = 0; $i -lt $displayCount; $i++) {
        Write-Host "  [$($i+1)] $($bins[$i].Name) ($([math]::Round($bins[$i].Length / 1KB, 1)) KB) - $($bins[$i].LastWriteTime)" -ForegroundColor Yellow
    }

    $idx = Read-Host "Selecione o binário para gravar [1-$displayCount] (ou aperte Enter para o mais recente [1])"
    if (-not $idx) { $idx = 1 }
    $selectedBin = $bins[[int]$idx - 1]
    $BinPath = $selectedBin.FullName

    if ($selectedBin.Name -match "esp32s3|-s3-") {
        $Chip = "esp32s3"
    } else {
        $Chip = "esp32"
    }
}

$usedPort = Invoke-FirmwareFlash -Chip $Chip -BinPath $BinPath -Port $Port -Baud $Baud

if ($Monitor) {
    & (Join-Path $PSScriptRoot "monitor.ps1") -Port $usedPort -Reset
}
