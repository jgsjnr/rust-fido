# ==============================================================================
# AegisKey S3 - Monitor Serial Contínuo
# ==============================================================================
[CmdletBinding()]
param(
    [string]$Port,
    [int]$Baud = 115200,
    [switch]$Reset
)

. (Join-Path $PSScriptRoot "common.ps1")
Initialize-EspEnvironment

if (-not $Port) {
    $ports = Get-EspPorts
    if (-not $ports -or $ports.Count -eq 0) {
        throw "Nenhuma porta serial ESP32 conectada encontrada. Conecte o cabo USB na porta UART/COM."
    }
    $Port = $ports[0].Port
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " 📡 AegisKey: Monitor Serial Contínuo ($Port @ $Baud bps)" -ForegroundColor Cyan
Write-Host " Pressione Ctrl+C para encerrar o monitor." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

$resetCode = if ($Reset) {
    "ser.setDTR(False); ser.setRTS(True); time.sleep(0.1); ser.setRTS(False);"
} else {
    "# Sem toggle de reset (mantém dispositivo ligado)"
}

$pyScript = @"
import serial, sys, time

port = '$Port'
baud = $Baud

try:
    ser = serial.Serial(port, baud, timeout=0.1)
    $resetCode
    while True:
        data = ser.readline()
        if data:
            sys.stdout.write(data.decode('utf-8', errors='replace'))
            sys.stdout.flush()
except KeyboardInterrupt:
    pass
except Exception as e:
    sys.stderr.write(f"\n[ERRO SERIAL] {e}\n")
finally:
    try:
        ser.close()
    except:
        pass
"@

& python -c $pyScript
