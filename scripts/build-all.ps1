# ==============================================================================
# AegisKey - Build TOTAL paralelo (S3 + Classic + Host tests + APK)
# Uso: .\scripts\build-all.ps1 [-SkipApk] [-SkipTests]
# 4 pistas em paralelo via Jobs (12 threads). Retorna exit 0 só se tudo verde.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipApk,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sdk = "$env:LOCALAPPDATA/Android/Sdk"
$jdk17 = "C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot"

function New-Lane($name, [scriptblock]$code) {
    return @{ Name = $name; Job = Start-Job -Name "aegis-$name" -ScriptBlock $code }
}

$lanes = @()
if (-not $SkipTests) {
    $lanes += New-Lane "host-test" {
        Set-Location $using:repoRoot
        & cargo test --workspace 2>&1 | Select-Object -Last 5
        [pscustomobject]@{ lane = "host-test"; exit = $LASTEXITCODE }
    }
}
$lanes += New-Lane "s3" {
    Set-Location $using:repoRoot
    & "$using:repoRoot/scripts/build-esp32s3-devkitc.ps1" 2>&1 | Select-Object -Last 3
    $b = Get-Item "C:\t\aegis-app-esp32s3-devkitc.bin"
    [pscustomobject]@{ lane = "s3"; exit = $LASTEXITCODE; sha = (Get-FileHash $b.FullName -Algorithm SHA256).Hash.Substring(0, 12); size = $b.Length }
}
$lanes += New-Lane "classic" {
    Set-Location $using:repoRoot
    & "$using:repoRoot/scripts/build-esp32-ttgo.ps1" 2>&1 | Select-Object -Last 3
    $b = Get-Item "C:\t\aegis-app-esp32.bin"
    [pscustomobject]@{ lane = "classic"; exit = $LASTEXITCODE; sha = (Get-FileHash $b.FullName -Algorithm SHA256).Hash.Substring(0, 12); size = $b.Length }
}
if (-not $SkipApk) {
    $lanes += New-Lane "apk" {
        $env:JAVA_HOME = $using:jdk17
        $env:PATH = "$using:jdk17\bin;$env:PATH"
        $env:ANDROID_HOME = $using:sdk
        $env:ANDROID_SDK_ROOT = $using:sdk
        Set-Location "$using:repoRoot/app-android"
        $gb = @("C:/src/gradle-8.7/bin/gradle.bat",
            "$env:USERPROFILE/.gradle-portable/bin/gradle.bat",
            "$env:USERPROFILE/.gradle/wrapper/dists/gradle-8.7-bin/bhs2wmbdwecv87pi65oeuq5iu/gradle-8.7/bin/gradle.bat") | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $gb) { throw "Gradle 8.7 nao encontrado" }
        & $gb :app:assembleDebug --console=plain 2>&1 | Select-Object -Last 3
        $a = Get-Item "app/build/outputs/apk/debug/app-debug.apk"
        [pscustomobject]@{ lane = "apk"; exit = $LASTEXITCODE; size = $a.Length }
    }
}

Write-Host "Aguardando $($lanes.Count) pistas..." -ForegroundColor Cyan
$results = $lanes | ForEach-Object { Receive-Job -Job $_.Job -Wait -AutoRemoveJob } | Where-Object { $_ -is [pscustomobject] }
$fail = 0
foreach ($r in $results) {
    $c = if ($r.exit -eq 0) { "Green" } else { "Red"; $fail++ }
    Write-Host ("[{0}] exit={1} {2}" -f $r.lane, $r.exit, (($r | Select-Object sha, size | Out-String).Trim())) -ForegroundColor $c
}
if ($fail -eq 0) { Write-Host "BUILD-ALL OK" -ForegroundColor Green; exit 0 }
else { Write-Host ("BUILD-ALL FAIL: {0} pista(s)" -f $fail) -ForegroundColor Red; exit 1 }
