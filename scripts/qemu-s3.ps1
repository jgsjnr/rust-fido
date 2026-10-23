# =============================================================================
# AegisKey - QEMU ESP32-S3 (bancada virtual; NUNCA toca nas COMs dos ESPs)
# Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/qemu-s3.ps1 [-BuildImage] [-TcpPort 5678] [-BootLog C:\t\qemu-s3-boot.log]
#   [-BuildImage] reconstrói a imagem flash 16MB dos artefatos do dia
#   (bootloader + PT do repo + app test-mode); sem a flag reusa a imagem.
# UART virtual: TCP 127.0.0.1:<TcpPort> (server, sem wait) p/ tools/ e testes.
# Log de boot espelhado em <BootLog> (tee via QEMU -serial TCP + leitor).
# Encerra: Ctrl+C (ou feche a janela do QEMU).
# =============================================================================
[CmdletBinding()]
param(
    [switch]$BuildImage,
    [int]$TcpPort = 5678,
    [string]$BootLog = "C:\t\qemu-s3-boot.log",
    [ValidateSet("Tcp", "File")] [string]$Mode = "Tcp"
)

$ErrorActionPreference = "Stop"
$QemuExe = "C:\qemu-esp\qemu\bin\qemu-system-xtensa.exe"
$FlashImg = "C:\t\qemu-flash-16m.bin"
$BlBin = "C:\t\xtensa-esp32s3-espidf\release\build\esp-idf-sys-4e2ab2ea0daead74\out\build\bootloader\bootloader.bin"

if (-not (Test-Path $QemuExe)) { throw "QEMU ausente em '$QemuExe'." }

function Find-Newest([string]$Pattern) {
    Get-ChildItem $Pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

if ($BuildImage) {
    $esptool = "C:/.embuild/espressif/python_env/idf5.3_py3.12_env/Scripts/esptool.exe"
    $ptCsv = Join-Path $PSScriptRoot "..\crates\aegis-fido-firmware\partitions.csv"
    $ptBin = "C:\t\partition-table-aegis-16m.bin"
    $appBin = "C:\t\aegis-app-freertos-s3-testmode.bin"
    foreach ($f in @($BlBin, $ptCsv, $appBin)) {
        if (-not (Test-Path $f)) { throw "Artefato ausente: $f (rode o build device primeiro)." }
    }
    # Gera a PT 16MB do repo e monta a imagem flash completa via merge_bin.
    & C:/.embuild/espressif/python_env/idf5.3_py3.12_env/Scripts/python `
        C:/.embuild/espressif/esp-idf/v5.3.1/components/partition_table/gen_esp32part.py `
        $ptCsv $ptBin | Out-Null
    & $esptool --chip esp32s3 merge_bin -o $FlashImg --flash_mode dio --flash_size 16MB `
        0x0 $BlBin 0x8000 $ptBin 0x10000 $appBin | Select-Object -Last 2
    # QEMU exige imagem exata (2/4/8/16MB): completa com 0xFF até 16MB.
    $need = 16777216 - (Get-Item $FlashImg).Length
    if ($need -gt 0) {
        $fs = [System.IO.File]::OpenWrite($FlashImg)
        $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        $pad = New-Object byte[] 65536
        for ($i = 0; $i -lt 65536; $i++) { $pad[$i] = 0xFF }
        while ($need -gt 0) {
            $n = [Math]::Min($need, 65536)
            $fs.Write($pad, 0, $n)
            $need -= $n
        }
        $fs.Close()
    }
    $len = (Get-Item $FlashImg).Length
    Write-Host ("[OK] imagem QEMU 16MB: {0} ({1} bytes)" -f $FlashImg, $len) -ForegroundColor Green
}

if (-not (Test-Path $FlashImg)) {
    throw "Imagem ausente: $FlashImg. Rode com -BuildImage uma vez."
}

Write-Host ("[QEMU] ESP32-S3 na imagem {0}" -f $FlashImg) -ForegroundColor Cyan
if ($Mode -eq "Tcp") {
    Write-Host ("[QEMU] UART TCP 127.0.0.1:{0} (server, sem wait)." -f $TcpPort) -ForegroundColor Cyan
    Write-Host "[QEMU] Boot log: rode tools/sim_ctap_init.py (handshake) ou um leitor TCP." -ForegroundColor Cyan
} else {
    Write-Host ("[QEMU] UART em arquivo {0} (sem interatividade)." -f $BootLog) -ForegroundColor Cyan
}
Write-Host "[QEMU] COMs dos ESPs intocadas. Ctrl+C para sair." -ForegroundColor Yellow
if ($Mode -eq "Tcp") {
    & $QemuExe -nographic -machine esp32s3 `
        -drive file=$FlashImg,if=mtd,format=raw `
        -serial tcp:127.0.0.1:$TcpPort,server=on,wait=off
} else {
    & $QemuExe -nographic -machine esp32s3 `
        -drive file=$FlashImg,if=mtd,format=raw `
        -serial file:$BootLog
}
