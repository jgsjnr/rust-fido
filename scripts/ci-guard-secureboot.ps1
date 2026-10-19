# CI guard: NUNCA ligar secure boot / flash encryption; NUNCA queimar eFuse de seguranca.
#
# Regra congelada: o AegisKey usa eFuse OTP SOMENTE para BLOCK7 (Master Key) e
# BLOCK8 (Device Salt) via `EfuseManager` (`crates/aegis-fido-firmware/src/efuse.rs`).
# Secure boot, flash encryption e key-purpose de seguranca sao PROIBIDOS:
# este script da FAIL se encontrar qualquer token ou chamada nessa direcao.
#
# 1. `sdkconfig*` contendo SECURE_BOOT / FLASH_CRYPT / KEY_PURPOSE / XTS_AES -> FAIL.
# 2. Fontes Rust chamando burn de eFuse de seguranca ou APIs de secure boot /
#    flash encryption (fora BLOCK7/8 de `efuse.rs`/`provision.rs`) -> FAIL.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot

$fail = $false
$scanned = 0

# 1. sdkconfig* : tokens proibidos.
$configTokens = "SECURE_BOOT|FLASH_CRYPT|FLASH_CRYPT_CNT|KEY_PURPOSE|XTS_AES|SECURE_FLASH_ENC|SECURE_BOOTLOADER|BOOTLOADER_ENCRYPT"
$configFiles = Get-ChildItem -Path "crates" -Recurse -Include "sdkconfig*" -File -ErrorAction SilentlyContinue
foreach ($f in $configFiles) {
    $scanned++
    $hits = Select-String -Pattern $configTokens -LiteralPath $f.FullName -AllMatches -ErrorAction SilentlyContinue
    if ($hits) {
        Write-Host ("FAIL: secure-boot/flash-crypt token em " + $f.FullName) -ForegroundColor Red
        $hits | ForEach-Object { Write-Host ("  line " + $_.LineNumber + ": " + $_.Line.Trim()) }
        $fail = $true
    }
}

# 2. Fontes Rust: burns/APIs de seguranca proibidos.
#    Permitido: `burn_block` SOMENTE com BLOCK7/8 em `efuse.rs`/`provision.rs`
#    (Master Key + Device Salt). Qualquer outro burn e suspeito e da FAIL.
$rsPattern = "SECURE_BOOT|FLASH_CRYPT|KEY_PURPOSE|XTS_AES|esp_secure_boot|esp_flash_encrypt|secure_bootloader|flash_encryption_enabled|efuse_write_field_cnt|esp_efuse_set_key_purpose|UART_BOOTLOADER_ALLOW_DEC|WR_DIS_FLASH_CRYPT|RD_DIS_EFUSE"
$rsHits = Select-String -Pattern $rsPattern -Path "crates\*\src\*.rs", "crates\*\src\*\*.rs" -AllMatches -ErrorAction SilentlyContinue
if ($rsHits) {
    Write-Host "FAIL: token de secure-boot/flash-crypt em fonte Rust" -ForegroundColor Red
    $rsHits | ForEach-Object { Write-Host ("  " + $_.Path + ":" + $_.LineNumber + ": " + $_.Line.Trim()) }
    $fail = $true
}

# 3. `burn_block` fora de efuse.rs/provision.rs/binding.rs(test wipe usa delete, nunca burn) -> FAIL.
$burnHits = Select-String -Pattern "burn_block" -Path "crates\*\src\*.rs", "crates\*\src\*\*.rs" -AllMatches -ErrorAction SilentlyContinue
foreach ($h in $burnHits) {
    $scanned++
    $fname = [System.IO.Path]::GetFileName($h.Path)
    if ($fname -ne "efuse.rs" -and $fname -ne "provision.rs") {
        Write-Host ("FAIL: burn_block fora de efuse.rs/provision.rs em " + $h.Path + ":" + $h.LineNumber) -ForegroundColor Red
        Write-Host ("  " + $h.Line.Trim())
        $fail = $true
    }
}

Pop-Location
if ($fail) { exit 1 }
Write-Host ("CI-GUARD-SECUREBOOT PASS: sem secure boot / flash encryption / eFuse de seguranca (" + $scanned + " arquivos varridos)") -ForegroundColor Green
exit 0
