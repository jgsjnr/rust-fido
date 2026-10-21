# ==============================================================================
# AegisKey S3 - Executar Suíte Completa de Testes Unitários em Rust
# ==============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " 🛡️  AegisKey: Suíte Completa de Testes Unitários (Rust)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$crates = @("aegis-fido-core", "aegis-fido-usb", "aegis-fido-firmware")
$failed = @()

foreach ($c in $crates) {
    Write-Host "`n------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "🧪 Testando crate: $c..." -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------" -ForegroundColor Gray
    
    # stderr nativo nao pode derrubar o script (Stop): avalia-se pelo exit code.
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & cargo test -p $c --lib
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevPref
    if ($code -ne 0) {
        $failed += $c
        Write-Host "❌ Falha nos testes de $c!" -ForegroundColor Red
    } else {
        Write-Host "✅ Todos os testes de $c passaram!" -ForegroundColor Green
    }
}

Pop-Location

Write-Host "`n============================================================" -ForegroundColor Cyan
if ($failed.Count -eq 0) {
    Write-Host "🎉 SUCESSO: Todos os testes das crates passaram com louvor!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "❌ FALHA: As seguintes crates apresentaram erros: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
