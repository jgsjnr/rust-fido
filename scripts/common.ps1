# ==============================================================================
# AegisKey S3 - Shared PowerShell Automation Engine for ESP32 Builds & Flashing
# ==============================================================================

$global:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$global:TargetDir = "C:\t"

# Logging Helpers
function Write-Info([string]$msg)    { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success([string]$msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg)    { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)     { Write-Host "[ERRO] $msg" -ForegroundColor Red }

# 1. Environment & Tools Validation
function Initialize-EspEnvironment {
    Write-Info "Configurando variaveis de ambiente do ESP-IDF e Rust..."

    if (-not (Test-Path $global:TargetDir)) {
        New-Item -ItemType Directory -Path $global:TargetDir -Force | Out-Null
    }

    $preferredIdf = "C:\.embuild\espressif\esp-idf\v5.3.1"
    if (Test-Path $preferredIdf) {
        $env:IDF_PATH = $preferredIdf
        $env:ESP_IDF_VERSION = "v5.3.1"
    } elseif ($env:IDF_PATH) {
        Write-Warn "Usando IDF_PATH existente: $env:IDF_PATH"
    } else {
        Write-Warn "IDF_PATH nao encontrado em $preferredIdf. O Cargo tentara autodetectar."
    }
    # Etapa B (BLE NimBLE): esp-idf-sys nao aplica sdkconfig.defaults.* sozinho
    # neste env; aponta os defaults BT/BLE-only do workspace root.
    $env:ESP_IDF_SDKCONFIG_DEFAULTS = Join-Path $global:RepoRoot "sdkconfig.defaults.esp32s3"

    $global:EsptoolExe = $null
    $candidates = @(
        "C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts\esptool.exe",
        "C:\.embuild\espressif\python_env\idf5.2_py3.12_env\Scripts\esptool.exe",
        (Get-Command esptool.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        (Get-Command esptool.py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
    )

    foreach ($cand in $candidates) {
        if ($cand -and (Test-Path $cand)) {
            $global:EsptoolExe = $cand
            break
        }
    }

    if (-not $global:EsptoolExe) {
        Write-Warn "esptool.exe nao encontrado. Tentando 'python -m esptool'..."
        $global:EsptoolExe = "python -m esptool"
    } else {
        Write-Success "Esptool localizado: $global:EsptoolExe"
    }
}

# 2. ESP Hardware Serial Port Discovery
function Get-EspPorts {
    $ports = @()
    try {
        $devices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -eq "Ports" }
        foreach ($dev in $devices) {
            if ($dev.Name -match '\((COM\d+)\)') {
                $portName = $matches[1]
                $desc = $dev.Name
                $ports += [PSCustomObject]@{
                    Port = $portName
                    Name = $desc
                    DeviceID = $dev.DeviceID
                }
            }
        }
    } catch {
        $netPorts = [System.IO.Ports.SerialPort]::GetPortNames()
        foreach ($p in $netPorts) {
            $ports += [PSCustomObject]@{
                Port = $p
                Name = "Serial Port $p"
                DeviceID = ""
            }
        }
    }
    return $ports
}

function Select-TargetPort($preferredPort = $null) {
    if ($preferredPort) {
        return $preferredPort
    }

    $available = Get-EspPorts
    if ($available.Count -eq 0) {
        throw "Nenhuma porta serial detectada no sistema. Conecte o dispositivo ESP32 via USB."
    }

    $espFiltered = @($available | Where-Object { 
        $_.Name -match 'CH340|CP210|CH9102|USB-Enhanced-SERIAL|JTAG|Espressif' 
    })

    if ($espFiltered.Count -eq 1) {
        $p = $espFiltered[0].Port
        Write-Success "Porta detectada automaticamente: $p ($($espFiltered[0].Name))"
        return $p
    } elseif ($espFiltered.Count -gt 1) {
        Write-Info "Multiplas portas ESP detectadas:"
        for ($i = 0; $i -lt $espFiltered.Count; $i++) {
            Write-Host "  [$($i+1)] $($espFiltered[$i].Port) - $($espFiltered[$i].Name)" -ForegroundColor Yellow
        }
        $idx = Read-Host "Selecione o numero da porta [1-$($espFiltered.Count)] (Padrao 1)"
        if (-not $idx) { $idx = 1 }
        return $espFiltered[[int]$idx - 1].Port
    } else {
        Write-Info "Portas seriais encontradas:"
        for ($i = 0; $i -lt $available.Count; $i++) {
            Write-Host "  [$($i+1)] $($available[$i].Port) - $($available[$i].Name)"
        }
        $idx = Read-Host "Selecione o numero da porta [1-$($available.Count)]"
        return $available[[int]$idx - 1].Port
    }
}

# 3. Cargo Test Runner
function Invoke-FirmwareTest {
    param([string]$crateName = "aegis-fido-firmware")
    Write-Info "Executando suite de testes unitarios para '$crateName'..."
    Push-Location $global:RepoRoot
    try {
        & cargo test -p $crateName --lib
        if ($LASTEXITCODE -ne 0) {
            throw "Os testes unitarios falharam com codigo $LASTEXITCODE."
        }
        Write-Success "Todos os testes unitarios passaram com sucesso!"
    } finally {
        Pop-Location
    }
}

# 4. Cargo ESP Build Runner
function Invoke-FirmwareBuild {
    param(
        [Parameter(Mandatory=$true)] [string]$Target,
        [Parameter(Mandatory=$true)] [string]$Feature,
        [switch]$Clean
    )

    Initialize-EspEnvironment

    Push-Location $global:RepoRoot
    try {
        if ($Clean) {
            Write-Info "Limpando diretorio de compilacao..."
            & cargo clean -p aegis-fido-firmware
        }

        Write-Info "Iniciando compilacao Cargo:"
        Write-Host "  Target:  $Target" -ForegroundColor Gray
        Write-Host "  Feature: $Feature" -ForegroundColor Gray
        Write-Host "  Profile: release" -ForegroundColor Gray

        $buildArgs = @(
            "+esp", "build",
            "-p", "aegis-fido-firmware",
            "--target", $Target,
            "--release",
            "--no-default-features",
            "--features", $Feature,
            "-Zbuild-std=std,panic_abort"
        )

        & cargo @buildArgs
        if ($LASTEXITCODE -ne 0) {
            throw "A compilacao do firmware falhou com codigo $LASTEXITCODE."
        }

        Write-Success "Firmware ELF compilado com sucesso!"
    } finally {
        Pop-Location
    }
}

# 5. ELF to Image Conversion
function Invoke-FirmwareElf2Image {
    param(
        [Parameter(Mandatory=$true)] [string]$Chip,
        [Parameter(Mandatory=$true)] [string]$Target,
        [Parameter(Mandatory=$true)] [string]$OutBinName
    )

    Initialize-EspEnvironment

    $elfPath = Join-Path $global:TargetDir "$Target\release\aegis-fido-firmware"
    $outBinPath = Join-Path $global:TargetDir $OutBinName

    if (-not (Test-Path $elfPath)) {
        throw "Arquivo ELF nao encontrado em '$elfPath'. Execute o build primeiro."
    }

    Write-Info "Convertendo ELF para binario executavel flashavel ($Chip)..."
    
    if ($global:EsptoolExe -match "python -m esptool") {
        & python -m esptool --chip $Chip elf2image --flash_size 4MB -o $outBinPath $elfPath
    } else {
        & $global:EsptoolExe --chip $Chip elf2image --flash_size 4MB -o $outBinPath $elfPath
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao converter ELF para binario com codigo $LASTEXITCODE."
    }

    Write-Success "Binario gerado: $outBinPath"
    return $outBinPath
}

# 6. Flash Firmware to Hardware
function Invoke-FirmwareFlash {
    param(
        [Parameter(Mandatory=$true)] [string]$Chip,
        [Parameter(Mandatory=$true)] [string]$BinPath,
        [string]$Port = $null,
        [int]$Baud = 921600,
        [string]$Offset = "0x10000"
    )

    Initialize-EspEnvironment

    if (-not (Test-Path $BinPath)) {
        throw "Arquivo binario nao encontrado em '$BinPath'."
    }

    $targetPort = Select-TargetPort $Port
    Write-Info "Gravando firmware na placa via $targetPort ($Chip a $Baud bps)..."

    $flashArgs = @(
        "--chip", $Chip,
        "--port", $targetPort,
        "--baud", "$Baud",
        "write_flash",
        $Offset,
        $BinPath
    )

    if ($global:EsptoolExe -match "python -m esptool") {
        & python -m esptool @flashArgs
    } else {
        & $global:EsptoolExe @flashArgs
    }

    if ($LASTEXITCODE -ne 0) {
        throw "A gravacao na porta $targetPort falhou com codigo $LASTEXITCODE."
    }

    Write-Success "Gravacao concluida com sucesso na $targetPort!"
    return $targetPort
}

# 7. Serial Boot Monitor
function Invoke-SerialMonitor {
    param(
        [Parameter(Mandatory=$true)] [string]$Port,
        [int]$Baud = 115200,
        [int]$DurationSecs = 8
    )

    Write-Info "Abrindo monitor serial em $Port a $Baud bps por $DurationSecs segundos..."
    $cmd = "import serial, time; ser = serial.Serial('$Port', $Baud, timeout=0.5); ser.setDTR(False); ser.setRTS(True); time.sleep(0.1); ser.setRTS(False); t0 = time.time(); [print(ser.readline().decode('utf-8', errors='replace'), end='') for _ in iter(lambda: time.time() - t0 < $DurationSecs, False) if ser.in_waiting > 0]; ser.close()"
    & python -c $cmd
}
