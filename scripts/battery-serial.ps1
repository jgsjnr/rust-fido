# =============================================================================
# AegisKey - Bateria serial padronizada (UART; sem COMs dos ESPs alem da alvo)
# Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/battery-serial.ps1 [-Port COM7] [-Phase all]
# Fases: offline -> base -> all-safe -> bench (seguras, sem escrita destrutiva).
# Destructive/wipe: SO com -Force (ordem explicita do usuario no turno).
# Cada etapa: 1 tentativa; resultado vai para o console + log em C:\t\.
# Pre-requisitos: placa com firmware test-mode ONLINE na porta indicada.
# =============================================================================
[CmdletBinding()]
param(
    [string]$Port = "COM7",
    [ValidateSet("all", "base", "all-safe", "bench", "offline", "destructive", "wipe")]
    [string]$Phase = "all",
    # Destrutivo SO com autorizacao explicita do usuario NESTE turno.
    # Agentes: NUNCA passe -Force sem ordem direta do usuario.
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = "C:\t\battery-serial-$Stamp.log"
$RepoRoot = Join-Path $PSScriptRoot ".."

function Invoke-Step {
    param([string]$Name, [string]$Exe, [string[]]$StepArgs)
    Write-Host ("`n===== {0} =====" -f $Name) -ForegroundColor Cyan
    "[STEP] $Name :: $Exe $($StepArgs -join ' ')" | Out-File -FilePath $LogFile -Append -Encoding utf8
    # Roda direto (sem powershell aninhado) e com Continue: texto em stderr
    # (ex. progresso `...` dos testes) nao pode abortar a bateria.
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        Push-Location $RepoRoot
        try {
            $out = & $Exe @StepArgs 2>&1 | Out-String
            $code = $LASTEXITCODE
        } finally {
            Pop-Location
        }
    } finally {
        $ErrorActionPreference = $prevPref
    }
    $out | Out-File -FilePath $LogFile -Append -Encoding utf8
    $tail = ($out -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 4) -join " | "
    $mark = if ($code -eq 0) { "EXIT=0" } else { "EXIT=$code" }
    Write-Host ("[{0}] {1} :: {2}" -f $Name, $mark, $tail)
    return @{ Code = $code; Out = $out }
}

Write-Host ("[BATERIA] porta={0} fases={1} log={2}" -f $Port, $Phase, $LogFile) -ForegroundColor Green
"BATTERY port=$Port phase=$Phase stamp=$Stamp" | Out-File -FilePath $LogFile -Encoding utf8

$summary = New-Object System.Collections.ArrayList

if ($Phase -in @("all", "offline")) {
    $r = Invoke-Step "self-test (offline)" "python" @("tools/app_simulator.py", "--self-test")
    [void]$summary.Add("self-test: $(if ($r.Out -match '17/17') { 'PASS 17/17' } else { 'VER LOG' })")
    $r = Invoke-Step "host-win (offline)" "python" @("tools/host/win/proximity_agent.py", "--self-test")
    [void]$summary.Add("host-win: $(if ($r.Code -eq 0) { 'PASS' } else { 'VER LOG' })")
    $r = Invoke-Step "host-win-tests (offline)" "python" @("tools/host/win/test_proximity_agent.py")
    [void]$summary.Add("host-win-tests: $(if ($r.Code -eq 0) { 'PASS' } else { 'VER LOG' })")
}
if ($Phase -in @("all", "base")) {
    $r = Invoke-Step "e2e-base ($Port)" "python" @("tools/e2e_user_test.py", "--port", $Port, "--phase", "base")
    $line = ($r.Out -split "`r?`n" | Select-String -Pattern '^RESUMO' | Select-Object -Last 1)
    [void]$summary.Add("base: $($line -replace 'RESUMO ', '')")
}
if ($Phase -in @("all", "all-safe")) {
    $r = Invoke-Step "e2e-all-safe ($Port)" "python" @("tools/e2e_user_test.py", "--port", $Port, "--phase", "all-safe")
    $line = ($r.Out -split "`r?`n" | Select-String -Pattern '^RESUMO' | Select-Object -Last 1)
    [void]$summary.Add("all-safe: $($line -replace 'RESUMO ', '')")
}
if ($Phase -in @("all", "bench")) {
    $r = Invoke-Step "e2e-bench ($Port)" "python" @("tools/e2e_user_test.py", "--port", $Port, "--phase", "bench")
    $line = ($r.Out -split "`r?`n" | Select-String -Pattern '^RESUMO' | Select-Object -Last 1)
    [void]$summary.Add("bench: $($line -replace 'RESUMO ', '')")
}
# Fases destrutivas: NUNCA automaticas. Exigem -Force (ordem explicita do
# usuario) + PIN 1234 provisionado no device (+ ota_test_key.bin p/ D08).
if ($Phase -in @("destructive", "wipe")) {
    if (-not $Force) {
        throw "Fase '$Phase' exige -Force (autorizacao explicita do usuario neste turno). Sem -Force, nada e executado."
    }
    Write-Host "!!! FASE DESTRUTIVA '$Phase' AUTORIZADA (-Force). PIN 1234 + backup NVS assumidos. !!!" -ForegroundColor Red
    if ($Phase -eq "destructive") {
        $r = Invoke-Step "e2e-destructive ($Port)" "python" @("tools/e2e_user_test.py", "--port", $Port, "--phase", "destructive", "--confirm")
        $line = ($r.Out -split "`r?`n" | Select-String -Pattern '^RESUMO' | Select-Object -Last 1)
        [void]$summary.Add("destructive: $($line -replace 'RESUMO ', '')")
    } else {
        $r = Invoke-Step "e2e-wipe ($Port)" "python" @("tools/e2e_user_test.py", "--port", $Port, "--phase", "wipe", "--confirm", "--confirm-release")
        $line = ($r.Out -split "`r?`n" | Select-String -Pattern '^RESUMO' | Select-Object -Last 1)
        [void]$summary.Add("wipe: $($line -replace 'RESUMO ', '')")
    }
}

Write-Host "`n===== RESUMO BATERIA =====" -ForegroundColor Green
$summary | ForEach-Object { Write-Output $_; $_ | Out-File -FilePath $LogFile -Append -Encoding utf8 }
Write-Host ("Log completo: {0}" -f $LogFile) -ForegroundColor Yellow
Write-Host "destructive/wipe: SO com -Force (ordem explicita do usuario no turno)." -ForegroundColor Yellow
