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
    Write-Host "SELECIONE A PLACA OU OPERACAO DESEJADA:" -ForegroundColor Yellow
    Write-Host "  [1] LilyGO TTGO T-Display Classic (ESP32 - ST7789 135x240)" -ForegroundColor White
    Write-Host "  [2] ESP32-S3 DevKitC-1 (USB Nativo + LED RGB WS2812)" -ForegroundColor White
    Write-Host "  [3] LilyGO T-Display-S3 (ESP32-S3 + ST7789 170x320)" -ForegroundColor White
    Write-Host "  [4] Executar Suite de Testes Unitarios (cargo test)" -ForegroundColor Green
    Write-Host "  [5] Gravar Binario Existente (Flash Rapido)" -ForegroundColor Magenta
    Write-Host "  [6] Detectar Portas Seriais (COM) Conectadas" -ForegroundColor Cyan
    Write-Host "  [0] Sair" -ForegroundColor Gray
    Write-Host ""
}

function Ask-Action($boardName, $scriptFile) {
    Write-Host "`nOperacao para '$boardName':" -ForegroundColor Yellow
    Write-Host "  [1] Compilar Apenas (Build)" -ForegroundColor White
    Write-Host "  [2] Testar & Compilar (Test + Build)" -ForegroundColor White
    Write-Host "  [3] Compilar & Gravar na Placa (Build + Flash)" -ForegroundColor Green
    Write-Host "  [4] Compilar, Gravar & Abrir Monitor Serial (Build + Flash + Monitor)" -ForegroundColor Cyan
    Write-Host "  [5] Limpar Cache & Recompilar do Zero (Clean + Build)" -ForegroundColor Magenta
    Write-Host "  [0] Voltar ao Menu Principal" -ForegroundColor Gray

    $opt = Read-Host "`nEscolha a acao [1-5]"
    switch ($opt) {
        "1" { & (Join-Path $PSScriptRoot $scriptFile) }
        "2" { & (Join-Path $PSScriptRoot $scriptFile) -Test }
        "3" { & (Join-Path $PSScriptRoot $scriptFile) -Flash }
        "4" { & (Join-Path $PSScriptRoot $scriptFile) -Flash -Monitor }
        "5" { & (Join-Path $PSScriptRoot $scriptFile) -Clean -Flash }
        default { return }
    }
}

do {
    Show-Menu
    $choice = Read-Host "Digite a opcao desejada [0-6]"

    switch ($choice) {
        "1" { Ask-Action "LilyGO TTGO T-Display (ESP32)" "build-esp32-ttgo.ps1" }
        "2" { Ask-Action "ESP32-S3 DevKitC-1" "build-esp32s3-devkitc.ps1" }
        "3" { Ask-Action "LilyGO T-Display-S3" "build-esp32s3-tdisplay.ps1" }
        "4" {
            & (Join-Path $PSScriptRoot "test-all.ps1")
        }
        "5" {
            & (Join-Path $PSScriptRoot "flash.ps1") -Monitor
        }
        "6" {
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
