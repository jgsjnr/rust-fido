# ==============================================================================
# AegisKey - Sincronia de leitura com a master (avaliacao, sem merge)
# Uso: .\scripts\sync-master.ps1 [-SaveJson <path>] [-Gate]
# Faz fetch da origin, compara o branch atual com origin/main e main local,
# lista o que mudou na master e resume hotspots da lane (firmware/host/docs).
# Somente leitura: nunca faz merge, rebase, reset ou push.
# ==============================================================================
[CmdletBinding()]
param([string]$SaveJson = "", [switch]$Gate)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

function Write-Info([string]$m)    { Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)      { Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn([string]$m)    { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err([string]$m)     { Write-Host "[ERRO] $m" -ForegroundColor Red }

$report = [ordered]@{ branch = ""; ahead_origin_main = -1; behind_origin_main = -1; ahead_main = -1; behind_main = -1; new_commits = @(); hotspots = [ordered]@{}; gate = [ordered]@{} }

# 1. Fetch (somente leitura)
git fetch origin main fd/finalizacao-linux 2>&1 | ForEach-Object { Write-Info "fetch: $_" }

# 2. Posicao do branch atual
$report.branch = (git branch --show-current).Trim()
foreach ($pair in @(@("origin/main", "ahead_origin_main", "behind_origin_main"), @("main", "ahead_main", "behind_main"))) {
    $ref, $kAhead, $kBehind = $pair
    $a = git rev-list --count "$ref..HEAD" 2>$null
    $b = git rev-list --count "HEAD..$ref" 2>$null
    if ($a -ne $null -and $b -ne $null) { $report[$kAhead] = [int]$a; $report[$kBehind] = [int]$b }
    Write-Host ("[branch] HEAD vs {0}: ahead={1} behind={2}" -f $ref, $report[$kAhead], $report[$kBehind])
}

# 3. O que mudou na master (lado que falta na lane, se behind > 0)
if ($report.behind_origin_main -gt 0) {
    Write-Warn ("origin/main tem {0} commits fora da lane." -f $report.behind_origin_main)
    $report.new_commits = @(git log --oneline "HEAD..origin/main" | ForEach-Object { $_.Trim() })
    $report.new_commits | Select-Object -First 20 | ForEach-Object { Write-Host "  [novo] $_" }
    $files = @(git diff --name-only "HEAD" "origin/main" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    $cats = [ordered]@{ firmware = 0; host_agents = 0; docs = 0; plans = 0; tools_scripts = 0; app_android = 0; outros = 0 }
    foreach ($f in $files) {
        if ($f -like "crates/*") { $cats.firmware++ }
        elseif ($f -like "tools/host/*") { $cats.host_agents++ }
        elseif ($f -like "docs/*") { $cats.docs++ }
        elseif ($f -like "plans/*") { $cats.plans++ }
        elseif ($f -like "tools/*" -or $f -like "scripts/*") { $cats.tools_scripts++ }
        elseif ($f -like "app-android/*") { $cats.app_android++ }
        else { $cats.outros++ }
    }
    $report.hotspots = $cats
    Write-Info ("Arquivos novos na master: {0}" -f $files.Count)
    foreach ($k in $cats.Keys) { Write-Host ("  [hotspot] {0}: {1}" -f $k, $cats[$k]) }
    Write-Info "Diff stat (top 15):"
    git diff --stat "HEAD" "origin/main" | Select-Object -Last 15 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Ok "Lane contem 100% da origin/main (behind=0). Nada a puxar."
}

# 4. Gate opcional (testes da lane freertos+proximity)
if ($Gate) {
    Write-Info "Gate: cargo test + clippy (freertos,proximity)..."
    $t = (cargo test -p aegis-fido-firmware --features freertos,proximity 2>&1 | Select-String "test result") -join " | "
    $report.gate.tests = $t
    Write-Host "  [gate-test] $t"
    $c1 = cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity -- -D warnings 2>&1 | Select-String "error|Finished"
    $report.gate.clippy = ($c1 -join " | ")
    Write-Host ("  [gate-clippy] {0}" -f $report.gate.clippy)
}

if ($SaveJson -ne "") {
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $SaveJson -Encoding utf8
    Write-Ok "Relatorio salvo em $SaveJson"
}

if ($report.behind_origin_main -gt 0) { exit 2 } else { exit 0 }
