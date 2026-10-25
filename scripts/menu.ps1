# ==============================================================================
# AegisKey S3 - Painel Interativo de Build, Testes & Flash (PowerShell)
# ==============================================================================

. (Join-Path $PSScriptRoot "common.ps1")

function Show-Header {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "     AEGISKEY S3 - GERENCIADOR DE BUILDS & FLASH (ESP)      " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   Repositorio: $global:RepoRoot" -ForegroundColor DarkGray
    Write-Host "   Target Dir:  $global:TargetDir" -ForegroundColor DarkGray
    Write-Host "============================================================`n" -ForegroundColor Cyan
}

function Show-Menu {
    Show-Header
    Write-Host "SELECIONE A OPERACAO DESEJADA (somente lane FreeRTOS; legado = NAO USAR, ver scripts/README.md):" -ForegroundColor Yellow
    Write-Host "  [1] ESP32-S3 FreeRTOS release (USB + BLE + WiFi)" -ForegroundColor White
    Write-Host "  [2] ESP32-S3 FreeRTOS test-mode (bancada, gatilhos TEST_*)" -ForegroundColor White
    Write-Host "  [3] Executar Suite de Testes Unitarios (cargo test)" -ForegroundColor Green
    Write-Host "  [4] Gravar Binario Existente (Flash Rapido)" -ForegroundColor Magenta
    Write-Host "  [5] Detectar Portas Seriais (COM) Conectadas" -ForegroundColor Cyan
    Write-Host "  [0] Sair" -ForegroundColor Gray
    Write-Host ""
}

function Invoke-FreeRTOSAction($label, $scriptFile, $binName) {
    Write-Host "`nOperacao para '$label':" -ForegroundColor Yellow
    Write-Host "  [1] Compilar Apenas (Build)" -ForegroundColor White
    Write-Host "  [2] Limpar Cache & Recompilar do Zero (Clean + Build)" -ForegroundColor Magenta
    Write-Host "  [3] Compilar & Gravar na Placa (Build + Flash via esptool)" -ForegroundColor Green
    Write-Host "  [0] Voltar ao Menu Principal" -ForegroundColor Gray

    $opt = Read-Host "`nEscolha a acao [0-3]"
    switch ($opt) {
        "1" { & (Join-Path $PSScriptRoot $scriptFile) }
        "2" { & (Join-Path $PSScriptRoot $scriptFile) -Clean }
        "3" {
            & (Join-Path $PSScriptRoot $scriptFile)
            if ($LASTEXITCODE -ne 0) { return }
            $bin = Join-Path $global:TargetDir $binName
            & (Join-Path $PSScriptRoot "flash.ps1") -Chip esp32s3 -BinPath $bin
        }
        default { return }
    }
}

do {
    Show-Menu
    $choice = Read-Host "Digite a opcao desejada [0-5]"

    switch ($choice) {
        "1" { Invoke-FreeRTOSAction "ESP32-S3 FreeRTOS release" "build-freertos-s3.ps1" "aegis-app-freertos-s3.bin" }
        "2" { Invoke-FreeRTOSAction "ESP32-S3 FreeRTOS test-mode (bancada)" "build-freertos-s3-testmode.ps1" "aegis-app-freertos-s3-testmode.bin" }
        "3" {
            & (Join-Path $PSScriptRoot "test-all.ps1")
        }
        "4" {
            & (Join-Path $PSScriptRoot "flash.ps1") -Monitor
        }
        "5" {
            Write-Host "`nBuscando portas seriais conectadas..." -ForegroundColor Yellow
            $ports = Get-EspPorts
            if ($ports.Count -eq 0) {
                Write-Warn "Nenhuma porta serial encontrada."
            } else {
                Write-Host "Portas detectadas:" -ForegroundColor Green
                foreach ($p in $ports) {
                    Write-Host "  - $($p.Port) : $($p.Name)" -ForegroundColor White
                }
            }
        }
        "0" {
            Write-Host "`nSaindo... Ate logo!" -ForegroundColor Gray
            break
        }
        default {
            Write-Warn "Opcao invalida."
        }
    }

    if ($choice -ne "0") {
        Write-Host "`nPressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
        $null = Read-Host
    }

} while ($choice -ne "0")
