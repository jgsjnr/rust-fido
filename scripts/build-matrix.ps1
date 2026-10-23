# ==============================================================================
# AegisKey - Build paralela da matriz de variantes (target dirs isolados)
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-matrix.ps1
# Sobe 4 builds em paralelo via Start-Job, cada um com CARGO_TARGET_DIR proprio
# (cargo bloqueia o target dir; sem isolamento as builds serializariam no lock).
# Exit 0 se as 4 passarem; imprime resumo com duracao por variante.
# ==============================================================================
[CmdletBinding()]
param([string]$Package = "aegis-fido-firmware")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$matrix = @(
    @{ name = "default";            feats = @() },
    @{ name = "freertos";           feats = @("freertos") },
    @{ name = "proximity";          feats = @("proximity") },
    @{ name = "freertos-proximity"; feats = @("freertos", "proximity") }
)

$jobs = foreach ($v in $matrix) {
    $featArgs = if ($v.feats.Count -gt 0) { @("--features"; ($v.feats -join ",")) } else { @() }
    Start-Job -Name ("build-" + $v.name) -ScriptBlock {
        param([string]$root, [string]$pkg, [string]$tname, [string[]]$fargs)
        $env:CARGO_TARGET_DIR = "C:\t\par-$tname"
        Set-Location $root
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $out = & cargo build -p $pkg @fargs 2>&1 | Out-String
        $code = $LASTEXITCODE
        $sw.Stop()
        [PSCustomObject]@{ variant = $tname; exit = $code; secs = [math]::Round($sw.Elapsed.TotalSeconds, 1); tail = ($out -split "`r?`n" | Select-Object -Last 4) -join "`n" }
    } -ArgumentList $repoRoot, $Package, $v.name, $featArgs
    Write-Host ("[build] job {0} lancado (features: {1})" -f $v.name, ($v.feats -join ",")) -ForegroundColor Cyan
}

Write-Host "[build] aguardando 4 jobs..." -ForegroundColor Cyan
$jobs | Wait-Job | Out-Null
$results = $jobs | Receive-Job
$jobs | Remove-Job -Force | Out-Null

$fail = 0
foreach ($r in $results | Sort-Object variant) {
    $color = if ($r.exit -eq 0) { "Green" } else { "Red"; $fail++ }
    Write-Host ("[{0}] {1}: exit={2} {3}s" -f $(if ($r.exit -eq 0) { "PASS" } else { "FAIL" }), $r.variant, $r.exit, $r.secs) -ForegroundColor $color
    if ($r.exit -ne 0) { Write-Host $r.tail -ForegroundColor Red }
}
if ($fail -gt 0) { exit 1 } else { exit 0 }
