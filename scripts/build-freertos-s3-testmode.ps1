# ==============================================================================
# AegisKey - Build device ESP32-S3 da variante FreeRTOS + proximity + TEST-MODE
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3-testmode.ps1
# Imagem de BANCADA (gatilhos TEST_* ativos); NUNCA embarcar em release.
# Reusa common.ps1 (env ESP, sync de componentes C, elf->bin). Exit 0 = ELF ok.
# ==============================================================================
[CmdletBinding()]
param([switch]$Clean)

. (Join-Path $PSScriptRoot "common.ps1")

Invoke-FirmwareBuild -Target "xtensa-esp32s3-espidf" -Feature "board-devkitc,freertos,proximity,test-mode" -Clean:$Clean
$bin = Invoke-FirmwareElf2Image -Chip "esp32s3" -Target "xtensa-esp32s3-espidf" -OutBinName "aegis-app-freertos-s3-testmode.bin"
Write-Host ("[OK] bin test-mode em {0}" -f $bin) -ForegroundColor Green
# Proveniencia: arquiva copia `C:\t\aegis-app-<SHA8>.bin` a cada build
# bem-sucedido (o canonico acima segue intacto). Sem SHA local o binario da
# placa virava irreproduzivel; o SHA8 (git short ou prefixo do SHA256 do bin)
# amarra cada artefato ao commit/conteudo que o gerou.
try {
    $sha8 = $null
    try { $sha8 = (git rev-parse --short=8 HEAD 2>$null | Select-Object -First 1) } catch { $sha8 = $null }
    if ([string]::IsNullOrWhiteSpace($sha8)) {
        $sha8 = (Get-FileHash -LiteralPath $bin -Algorithm SHA256 -ErrorAction Stop).Hash.Substring(0, 8).ToLower()
    } else {
        $sha8 = $sha8.Trim()
    }
    $dest = Join-Path "C:\t" ("aegis-app-{0}.bin" -f $sha8)
    Copy-Item -LiteralPath $bin -Destination $dest -Force
    Write-Host ("[OK] copia de proveniencia em {0}" -f $dest) -ForegroundColor Green
} catch {
    Write-Warning ("Proveniencia nao arquivada: {0}" -f $_.Exception.Message)
}
