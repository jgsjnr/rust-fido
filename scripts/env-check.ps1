# ==============================================================================
# AegisKey - Verificacao de ambiente ESP (fail-fast, sem efeitos colaterais)
# Uso: .\scripts\env-check.ps1 [-SaveJson <path>]
# Saida: PASS/FAIL por item; exit 0 se tudo pronto para build+flash.
# ==============================================================================

[CmdletBinding()]
param([string]$SaveJson = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$results = @()
function Add-Check([string]$name, [bool]$ok, [string]$detail) {
    $script:results += [PSCustomObject]@{ check = $name; ok = $ok; detail = $detail }
    $tag = if ($ok) { "PASS" } else { "FAIL" }
    $color = if ($ok) { "Green" } else { "Red" }
    Write-Host ("[{0}] {1}: {2}" -f $tag, $name, $detail) -ForegroundColor $color
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# 1. ESP-IDF fixado pelo projeto (.cargo/config.toml -> C:\.embuild v5.3.1)
$idf = "C:\.embuild\espressif\esp-idf\v5.3.1"
Add-Check "idf-dir" (Test-Path $idf) $idf
Add-Check "idf-py" (Test-Path (Join-Path $idf "tools\idf.py")) "tools\idf.py"

# 2. Toolchain C Xtensa + clang (linker do esp-idf-sys)
$clang = "C:\Users\junior\.rustup\toolchains\esp\xtensa-esp32-elf-clang\esp-clang\bin\libclang.dll"
Add-Check "esp-clang" (Test-Path $clang) $clang
$gcc = Get-ChildItem "C:\.embuild\espressif\tools\xtensa-esp-elf" -Directory -Name -ErrorAction SilentlyContinue | Select-Object -First 1
Add-Check "xtensa-gcc" ($null -ne $gcc) ("xtensa-esp-elf\" + $gcc)

# 3. Toolchain Rust Xtensa (fork ESP): std vem do fonte via -Zbuild-std, logo o
# que se verifica e rust-src presente + export-esp.ps1 (PATH do clang/gcc).
$espVer = & cargo +esp --version 2>&1
Add-Check "cargo-+esp" ($LASTEXITCODE -eq 0) ([string]$espVer)
$sysroot = (& rustc +esp --print sysroot 2>$null)
$rsrc = $false
if ($sysroot) { $rsrc = Test-Path (Join-Path $sysroot "lib\rustlib\src\rust\library\core\src\lib.rs") }
Add-Check "rust-src-esp" $rsrc "build-std a partir do fonte"
$expf = Join-Path ([Environment]::GetFolderPath("UserProfile")) "export-esp.ps1"
Add-Check "export-esp" (Test-Path $expf) $expf

# 4. Flash tooling
$ldp = Get-Command ldproxy -ErrorAction SilentlyContinue
Add-Check "ldproxy" ($null -ne $ldp) "linker do esp-idf-sys"
$ef = (& cargo-espflash --version 2>$null)
Add-Check "cargo-espflash" ($LASTEXITCODE -eq 0) ([string]$ef)
$esptool = Test-Path "C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts\esptool.exe"
Add-Check "esptool-idf53" $esptool "python_env idf5.3"

# 5. Portas seriais: exige ao menos 1 bridge ESP (CP210x/CH340/CH9102)
$ports = Get-CimInstance Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object DeviceID, Description
$esp = @($ports | Where-Object { $_.Description -match 'CP210|CH340|CH9102|USB.*Serial|Espressif' })
foreach ($p in $ports) { Write-Host ("  porta: {0} - {1}" -f $p.DeviceID, $p.Description) -ForegroundColor Gray }
Add-Check "porta-esp" ($esp.Count -ge 1) (($esp | ForEach-Object { $_.DeviceID }) -join ",")
$com7 = @($ports | Where-Object { $_.DeviceID -eq "COM7" }) | Select-Object -First 1
Add-Check "com7-cp210x" ($null -ne $com7 -and $com7.Description -match 'CP210') ([string]$com7.Description)

if ($SaveJson -ne "") {
    $results | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $SaveJson -Encoding UTF8
    Write-Host "Relatorio salvo em $SaveJson" -ForegroundColor Cyan
}
$fail = @($results | Where-Object { -not $_.ok }).Count
if ($fail -gt 0) {
    Write-Host ("FALTAM {0} item(ns). Rust Xtensa ausente => rode espup install e revalide." -f $fail) -ForegroundColor Red
    exit 1
}
Write-Host "Ambiente pronto para build+flash." -ForegroundColor Green
exit 0
