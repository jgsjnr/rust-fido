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

    # Toolchain ESP (espup): clang/gcc no PATH; sem isso o cmake do
    # esp-idf-sys cai no IDF errado ou nao acha o compilador (falha ABI).
    $exportEsp = Join-Path ([Environment]::GetFolderPath("UserProfile")) "export-esp.ps1"
    if (Test-Path $exportEsp) {
        . $exportEsp
        Write-Success "export-esp.ps1 aplicado."
    } else {
        Write-Warn "export-esp.ps1 ausente; rode 'espup install' e revalide com scripts/env-check.ps1."
    }

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

# 3b. Sincroniza componentes C locais (repo) para dentro do IDF.
# O build ESP compila $IDF_PATH/components/aegis_* (copias!), nao o repo.
# Sem isso, alteracao em components/*.c nunca embarca (ex.: fix GATT,
# reboot_to_download). Repo e fonte da verdade; copia e descartavel.
function Sync-IdfLocalComponents {
    $idfComps = Join-Path $env:IDF_PATH "components"
    if (-not (Test-Path $idfComps)) { return }
    $srcRoot = Join-Path $global:RepoRoot "crates\aegis-fido-firmware\components"
    foreach ($comp in @("aegis_usb", "aegis_ble", "aegis_wifi")) {
        $src = Join-Path $srcRoot $comp
        $dst = Join-Path $idfComps $comp
        if ((Test-Path $src) -and (Test-Path $dst)) {
            Copy-Item (Join-Path $src "*") $dst -Recurse -Force
            Write-Info "Componente C sincronizado: $comp"
        }
    }
    Clear-StaleIdfSysBuild -SrcRoot $srcRoot
}

# 3c. Invalida build C obsoleto (licao F5/D08 20/10).
# O cargo NAO re-executa o build-script do esp-idf-sys ao mudar .c: o ninja
# para no tempo e o link usa .a velho (`undefined reference` fantasma SÓ no
# símbolo novo). `cargo clean -p` não adianta (objetos C moram no pacote
# esp-idf-sys, separado). Se algum fonte C é mais novo que os outputs,
# apaga os build dirs do esp-idf-sys (fingerprint + out) p/ forçar
# reconfigure total no próximo build.
function Clear-StaleIdfSysBuild {
    param([string]$SrcRoot)
    $newestSrc = Get-ChildItem $SrcRoot -Recurse -File -Include @("*.c", "*.h", "*.txt") |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $newestSrc) { return }
    $roots = @($global:TargetDir, (Join-Path $global:RepoRoot "target")) | Where-Object { Test-Path $_ }
    foreach ($root in $roots) {
        foreach ($triple in Get-ChildItem $root -Directory -Filter "xtensa-*-espidf" -ErrorAction SilentlyContinue) {
            foreach ($sysdir in Get-ChildItem (Join-Path $triple.FullName "release\build") -Directory -Filter "esp-idf-sys-*" -ErrorAction SilentlyContinue) {
                $newestOut = Get-ChildItem $sysdir.FullName -Recurse -File -Include @("*.a", "*.obj") -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ((-not $newestOut) -or ($newestSrc.LastWriteTime -gt $newestOut.LastWriteTime)) {
                    Remove-Item -Recurse -Force $sysdir.FullName
                    Write-Warn ("Build C invalidado (fonte {0} mais novo que output): {1}" -f $newestSrc.Name, $sysdir.Name)
                }
            }
        }
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

        # O build ESP compila as COPIAS em $IDF_PATH/components (nao o repo!):
        # sincroniza repo -> IDF antes de compilar, senao C novo nunca embarca.
        Sync-IdfLocalComponents

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
        & python -m esptool --chip $Chip elf2image --flash_size 4MB -o $outBinPath $elfPath | Out-Null
    } else {
        & $global:EsptoolExe --chip $Chip elf2image --flash_size 4MB -o $outBinPath $elfPath | Out-Null
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao converter ELF para binario com codigo $LASTEXITCODE."
    }

    Write-Success "Binario gerado: $outBinPath"
    Test-FirmwareArtifact -BinPath $outBinPath | Out-Null
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

    Test-FirmwareArtifact -BinPath $BinPath | Out-Null
    $targetPort = Select-TargetPort $Port

    # Caminho sem botoes (padrao): TEST_DOWNLOAD via software (RTC_CNTL).
    # O firmware diag (test-mode) reboota direto p/ ROM download; o esptool
    # entra com --before no-reset. So cai no fallback manual se o app nao
    # responder (release sem test-mode, porta ocupada ou placa travada).
    $softOk = $false
    try {
        Write-Info "Tentando download-mode por software (TEST_DOWNLOAD, sem botoes)..."
        $softProbe = @"
import sys, time
sys.path.insert(0, 'tools')
from app_simulator import SerialLink
l = SerialLink('$targetPort', 115200)
l.open()
l.write(b'TEST_DOWNLOAD\n')
t0 = time.time(); ok = False
while time.time() - t0 < 8:
    try:
        raw = l.read_exact(64, deadline_s=1.0)
    except Exception:
        continue
    if 'download_mode' in bytes(raw).decode('ascii', 'replace'):
        ok = True
        break
l.close()
sys.exit(0 if ok else 2)
"@
        $probeFile = Join-Path ([IO.Path]::GetTempPath()) "aegis_softdl_probe.py"
        $softProbe | Set-Content -LiteralPath $probeFile -Encoding ASCII
        Push-Location $global:RepoRoot
        try { & python $probeFile 2>$null | Out-Null } catch {}
        $softOk = ($LASTEXITCODE -eq 0)
        Pop-Location
    } catch {}

    if ($softOk) {
        Write-Success "Placa em ROM download por software (sem botoes)."
    } else {
        Write-Warn "Sem resposta a TEST_DOWNLOAD (firmware sem test-mode, porta ocupada ou app travado)."
        Write-Host "Fallback manual: segure BOOT, aperte+solte EN, continue segurando BOOT e tecle ENTER." -ForegroundColor Yellow
        Read-Host "Pressione ENTER quando estiver segurando BOOT" | Out-Null
    }

    Write-Info "Gravando firmware na placa via $targetPort ($Chip, --before no-reset)..."
    $bauds = @($Baud)
    if ($Baud -ne 115200) { $bauds += 115200 }
    $flashed = $false
    foreach ($b in $bauds) {
        $flashArgs = @(
            "--chip", $Chip,
            "--port", $targetPort,
            "--baud", "$b",
            "--before", "no-reset",
            "--after", "hard-reset",
            "write_flash",
            $Offset,
            $BinPath
        )

        # Saida do esptool vai para o console via Write-Host para nao poluir o
        # valor de retorno da funcao (PowerShell retorna toda saida nao capturada).
        $flashOut = if ($global:EsptoolExe -match "python -m esptool") {
            & python -m esptool @flashArgs | Out-String
        } else {
            & $global:EsptoolExe @flashArgs | Out-String
        }
        Write-Host $flashOut

        if ($LASTEXITCODE -eq 0) { $flashed = $true; break }
        Write-Warn "Gravacao a $b bps falhou; tentando fallback..."
    }

    if (-not $flashed) {
        throw "A gravacao na porta $targetPort falhou."
    }

    Write-Success "Gravacao concluida com sucesso na $targetPort!"
    Write-Host "Se a placa nao bootar sozinha, aperte EN. (RTS faz o reset; BOOT+EN manual so e preciso se o TEST_DOWNLOAD falhar.)" -ForegroundColor Yellow
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

# 8. Tamanho maximo da particao factory (lido do partitions.csv, sem hardcode)
function Get-FactoryMaxSize {
    $csv = Join-Path $global:RepoRoot "crates/aegis-fido-firmware/partitions.csv"
    foreach ($line in (Get-Content -LiteralPath $csv)) {
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { continue }
        $cols = $t -split "\s*,\s*"
        if ($cols[0] -eq "factory") { return [Convert]::ToInt64($cols[4], 16) }
    }
    throw "Particao factory nao encontrada em partitions.csv."
}

# 9. Hash + tamanho + validacao do artefato (gera .sha256 sidecar)
function Test-FirmwareArtifact {
    param([Parameter(Mandatory=$true)] [string]$BinPath)
    if (-not (Test-Path -LiteralPath $BinPath)) { throw "Binario nao encontrado: $BinPath" }
    $f = Get-Item -LiteralPath $BinPath
    $sha = $null
    try { $sha = (Get-FileHash -LiteralPath $BinPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $sha = $null }
    if (-not $sha) {
        $sha = (& python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" $BinPath | Select-Object -First 1).Trim()
    }
    if (-not $sha) { throw "Nao foi possivel calcular o SHA256 de $BinPath." }
    $max = Get-FactoryMaxSize
    Write-Host ("  SHA256: {0}" -f $sha) -ForegroundColor Gray
    Write-Host ("  SIZE:   {0} bytes (max factory: {1})" -f $f.Length, $max) -ForegroundColor Gray
    "$sha  $($f.Name)" | Set-Content -LiteralPath ($BinPath + ".sha256") -Encoding ASCII
    if ($f.Length -gt $max) { throw ("Imagem ({0} B) nao cabe na factory ({1} B)." -f $f.Length, $max) }
    Write-Success "Artefato validado (hash + tamanho)."
    return $sha
}
