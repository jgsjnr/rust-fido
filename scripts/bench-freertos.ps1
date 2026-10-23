# ==============================================================================
# AegisKey - Bancada FreeRTOS lado-host (sem flash, sem monitor)
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bench-freertos.ps1 [-Skip @("usb")] [-LogDir <dir>]
# Etapas, em ordem: 1 env-check, 2 presenca USB, 3 suite python, 4 self-tests
# proximity, 5 bundle de logs. Saida: PASS/FAIL/SKIP por etapa; exit 0 = sem FAIL.
# ==============================================================================

[CmdletBinding()]
param(
    [string[]]$Skip = @(),
    [string]$LogDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Test-Skipped([string]$key) {
    foreach ($s in $Skip) {
        if ([string]$s -ieq $key) { return $true }
    }
    return $false
}

$script:results = @()
function Add-StepResult([string]$name, [string]$status, [string]$detail) {
    $script:results += [PSCustomObject]@{ step = $name; status = $status; detail = $detail }
    $color = "Gray"
    if ($status -eq "PASS") { $color = "Green" }
    elseif ($status -eq "FAIL") { $color = "Red" }
    elseif ($status -eq "SKIP") { $color = "Yellow" }
    Write-Host ("[{0}] {1}: {2}" -f $status, $name, $detail) -ForegroundColor $color
}

function Invoke-StepCommand([string]$filePath, [string[]]$arguments, [string]$outFile) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $filePath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $RepoRoot
    # `ArgumentList` (colecao) so existe no .NET Core/PS7; no Windows
    # PowerShell 5.1 use a string `Arguments` com aspas explicitas.
    $quoted = foreach ($a in $arguments) { '"' + ($a -replace '"', '""') + '"' }
    $psi.Arguments = ($quoted -join " ")
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $text = "CMD: $filePath $($arguments -join ' ')`r`nEXIT: $($p.ExitCode)`r`n--- stdout ---`r`n$stdout`r`n--- stderr ---`r`n$stderr"
    $text | Set-Content -LiteralPath $outFile -Encoding UTF8
    Write-Host $text
    return $p.ExitCode
}

function Get-PythonCommand {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $py) { return $py.Source }
    $py3 = Get-Command python3 -ErrorAction SilentlyContinue
    if ($null -ne $py3) { return $py3.Source }
    return ""
}

# --- LogDir padrao + transcript (etapa 5 consolida o bundle) ---
if ($LogDir -eq "") {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $base = Join-Path ([System.IO.Path]::GetTempPath()) ("bench-freertos-" + $stamp)
    if ($env:TEMP -ne $null -and $env:TEMP -ne "") { $base = Join-Path $env:TEMP ("bench-freertos-" + $stamp) }
    $LogDir = $base
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$transcript = Join-Path $LogDir "transcript.txt"
try { Start-Transcript -LiteralPath $transcript -Force | Out-Null } catch { Write-Host ("[WARN] transcript indisponivel: " + $_.Exception.Message) -ForegroundColor Yellow }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Bancada FreeRTOS lado-host (sem flash, sem monitor)" -ForegroundColor Cyan
Write-Host ("RepoRoot: {0}" -f $RepoRoot) -ForegroundColor Gray
Write-Host ("LogDir:   {0}" -f $LogDir) -ForegroundColor Gray
Write-Host ("Skip:     {0}" -f ($Skip -join ",")) -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# --- 1. env-check: IDF, esptool, export-esp (sem rede, so verificacao local) ---
if (Test-Skipped "env-check" -or (Test-Skipped "env")) {
    Add-StepResult "env-check" "SKIP" "solicitado via -Skip"
} else {
    $checks = @()
    $idfRoot = $env:IDF_PATH
    if ([string]::IsNullOrWhiteSpace($idfRoot)) {
        $sysDrive = $env:SystemDrive
        if ([string]::IsNullOrWhiteSpace($sysDrive)) { $sysDrive = "C:" }
        $idfRoot = Join-Path $sysDrive ".embuild\espressif\esp-idf\v5.3.1"
    }
    $idfOk = Test-Path (Join-Path $idfRoot "tools\idf.py")
    $checks += ("idf=" + $idfOk)
    $esptoolCmd = Get-Command esptool -ErrorAction SilentlyContinue
    if ($null -eq $esptoolCmd) { $esptoolCmd = Get-Command esptool.py -ErrorAction SilentlyContinue }
    $esptoolOk = ($null -ne $esptoolCmd)
    if (-not $esptoolOk) {
        $sysDrive = $env:SystemDrive
        if ([string]::IsNullOrWhiteSpace($sysDrive)) { $sysDrive = "C:" }
        $esptoolOk = (Get-ChildItem (Join-Path $sysDrive ".embuild\espressif\python_env") -Filter "esptool*" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) -ne $null
    }
    $checks += ("esptool=" + $esptoolOk)
    $exportEsp = Join-Path $env:USERPROFILE "export-esp.ps1"
    $exportOk = Test-Path $exportEsp
    $checks += ("export-esp=" + $exportOk)
    $detail = (($checks -join " ") + " idfRoot=" + $idfRoot)
    if ($idfOk -and $esptoolOk -and $exportOk) {
        Add-StepResult "env-check" "PASS" $detail
    } else {
        Add-StepResult "env-check" "FAIL" $detail
    }
}

# --- 2. presenca USB (VID 0x303A / PID 0xAE61) ---
if (Test-Skipped "usb") {
    Add-StepResult "usb" "SKIP" "solicitado via -Skip"
} else {
    $usbLog = Join-Path $LogDir "usb.log"
    $usbScript = Join-Path $RepoRoot "tools\usb_present.py"
    $usbOk = $false
    $usbDetail = ""
    if (Test-Path $usbScript) {
        $py = Get-PythonCommand
        if ($py -eq "") {
            Add-StepResult "usb" "FAIL" "tools/usb_present.py existe mas nenhum interpretador python no PATH"
        } else {
            $code = Invoke-StepCommand $py @("tools/usb_present.py") $usbLog
            $txt = Get-Content -LiteralPath $usbLog -Raw -ErrorAction SilentlyContinue
            $usbOk = ($code -eq 0) -and ($txt -match "303A" -or $txt -match "AE61" -or $txt -match "Present.*True")
            if ($txt -match "303A") { $usbOk = $true }
            $usbDetail = "via tools/usb_present.py exit=$code"
            Add-StepResult "usb" ($(if ($usbOk) { "PASS" } else { "FAIL" })) $usbDetail
        }
    } else {
        try {
            $devs = Get-PnpDevice -InstanceId "*VID_303A*" -ErrorAction Stop | Where-Object { $_.InstanceId -match "PID_AE61" -or $_.InstanceId -match "303A" }
            $found = @($devs).Count
            $usbDetail = ("Get-PnpDevice VID_303A encontrados=" + $found)
            "CMD: Get-PnpDevice -InstanceId *VID_303A*`r`nFOUND: $found`r`n$($devs | Out-String)" | Set-Content -LiteralPath $usbLog -Encoding UTF8
            Write-Host ("USB VID_303A dispositivos: " + $found)
            Add-StepResult "usb" ($(if ($found -ge 1) { "PASS" } else { "FAIL" })) $usbDetail
        } catch {
            ("Get-PnpDevice falhou: " + $_.Exception.Message) | Set-Content -LiteralPath $usbLog -Encoding UTF8
            Add-StepResult "usb" "FAIL" ("Get-PnpDevice indisponivel: " + $_.Exception.Message)
        }
    }
}

# --- 3. suite python tools/test_aegiskey_rust.py ---
if (Test-Skipped "suite") {
    Add-StepResult "suite" "SKIP" "solicitado via -Skip"
} else {
    $suiteLog = Join-Path $LogDir "suite.log"
    $suiteScript = Join-Path $RepoRoot "tools\test_aegiskey_rust.py"
    if (-not (Test-Path $suiteScript)) {
        Add-StepResult "suite" "FAIL" "tools/test_aegiskey_rust.py ausente"
    } else {
        $py = Get-PythonCommand
        if ($py -eq "") {
            Add-StepResult "suite" "FAIL" "nenhum interpretador python no PATH"
        } else {
            $code = Invoke-StepCommand $py @("tools/test_aegiskey_rust.py") $suiteLog
            Add-StepResult "suite" ($(if ($code -eq 0) { "PASS" } else { "FAIL" })) ("exit=" + $code)
        }
    }
}

# --- 4. self-tests proximity dos 3 hosts ---
if (Test-Skipped "proximity") {
    Add-StepResult "proximity" "SKIP" "solicitado via -Skip"
} else {
    $hosts = @("win", "linux", "macos")
    $py = Get-PythonCommand
    foreach ($h in $hosts) {
        $agent = Join-Path $RepoRoot ("tools\host\" + $h + "\proximity_agent.py")
        $key = "proximity-" + $h
        if (($h -ne "win") -and ($py -eq "")) {
            Add-StepResult $key "SKIP" "python ausente no PATH"
            continue
        }
        if (-not (Test-Path $agent)) {
            Add-StepResult $key "SKIP" ("agente ausente: tools/host/" + $h + "/proximity_agent.py")
            continue
        }
        if ($py -eq "") {
            Add-StepResult $key "FAIL" "nenhum interpretador python no PATH"
            continue
        }
        $agentLog = Join-Path $LogDir ($key + ".log")
        $rel = "tools/host/" + $h + "/proximity_agent.py"
        $code = Invoke-StepCommand $py @($rel, "--self-test") $agentLog
        Add-StepResult $key ($(if ($code -eq 0) { "PASS" } else { "FAIL" })) ("exit=" + $code)
    }
}

# --- 5. bundle de logs ---
if (Test-Skipped "logs" -or (Test-Skipped "log-bundle")) {
    Add-StepResult "logs" "SKIP" "solicitado via -Skip"
} else {
    try {
        $summary = Join-Path $LogDir "summary.txt"
        $lines = @()
        $lines += "bench-freertos lado-host (sem flash, sem monitor)"
        $lines += ("data=" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        foreach ($r in $script:results) { $lines += ("[" + $r.status + "] " + $r.step + ": " + $r.detail) }
        $lines | Set-Content -LiteralPath $summary -Encoding UTF8
        $script:results | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $LogDir "summary.json") -Encoding UTF8
        Add-StepResult "logs" "PASS" ("bundle em " + $LogDir)
    } catch {
        Add-StepResult "logs" "FAIL" ("falha ao consolidar bundle: " + $_.Exception.Message)
    }
}

try { Stop-Transcript | Out-Null } catch { }

Write-Host "------------------------------------------------------------" -ForegroundColor Gray
foreach ($r in $script:results) {
    $color = "Gray"
    if ($r.status -eq "PASS") { $color = "Green" }
    elseif ($r.status -eq "FAIL") { $color = "Red" }
    elseif ($r.status -eq "SKIP") { $color = "Yellow" }
    Write-Host (("[" + $r.status + "] " + $r.step)) -ForegroundColor $color
}
$fail = @($script:results | Where-Object { $_.status -eq "FAIL" }).Count
Write-Host ("LogDir: " + $LogDir) -ForegroundColor Cyan
if ($fail -gt 0) {
    Write-Host (("RESULTADO: FAIL (" + $fail + " etapa(s) com falha)")) -ForegroundColor Red
    exit 1
}
Write-Host "RESULTADO: PASS (nenhuma etapa com falha)" -ForegroundColor Green
exit 0
