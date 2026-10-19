# ==============================================================================
# AegisKey - Build TOTAL paralelo (S3 + Classic + Host tests + APK)
# Uso: .\scripts\build-all.ps1 [-SkipApk] [-SkipTests]
# 4 pistas em paralelo via Jobs (12 threads fisicos: 3 jobs Rust/ninja + 3 workers Gradle por pista). Retorna exit 0 só se tudo verde.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipApk,
    [switch]$SkipTests,
    [switch]$Flash,
    [switch]$OnlyFlash,
    [string]$PortS3 = "COM7",
    [string]$PortClassic = "COM8"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sdk = "$env:LOCALAPPDATA/Android/Sdk"
$jdk17 = "C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot"

function New-Lane($name, [scriptblock]$code) {
    return @{ Name = $name; Job = Start-Job -Name "aegis-$name" -ScriptBlock $code }
}

$lanes = @()
if (-not $OnlyFlash) {
if (-not $SkipTests) {
    $lanes += New-Lane "host-test" {
        $env:CARGO_BUILD_JOBS = "3"
        $t0 = Get-Date
        Set-Location $using:repoRoot
        & cargo test --workspace 2>&1 | Select-Object -Last 5
        [pscustomobject]@{ lane = "host-test"; exit = $LASTEXITCODE; secs = [int]((Get-Date) - $t0).TotalSeconds }
    }
}
$lanes += New-Lane "s3" {
        $env:CARGO_BUILD_JOBS = "3"
        $env:CMAKE_BUILD_PARALLEL_LEVEL = "3"
        $t0 = Get-Date
    Set-Location $using:repoRoot
    & "$using:repoRoot/scripts/build-esp32s3-devkitc.ps1" 2>&1 | Select-Object -Last 3
    $b = Get-Item "C:\t\aegis-app-esp32s3-devkitc.bin"
    [pscustomobject]@{ lane = "s3"; exit = $LASTEXITCODE; secs = [int]((Get-Date) - $t0).TotalSeconds; sha = (Get-FileHash $b.FullName -Algorithm SHA256).Hash.Substring(0, 12); size = $b.Length }
}
$lanes += New-Lane "classic" {
        $env:CARGO_BUILD_JOBS = "3"
        $env:CMAKE_BUILD_PARALLEL_LEVEL = "3"
        $t0 = Get-Date
    Set-Location $using:repoRoot
    & "$using:repoRoot/scripts/build-esp32-ttgo.ps1" 2>&1 | Select-Object -Last 3
    $b = Get-Item "C:\t\aegis-app-esp32.bin"
    [pscustomobject]@{ lane = "classic"; exit = $LASTEXITCODE; secs = [int]((Get-Date) - $t0).TotalSeconds; sha = (Get-FileHash $b.FullName -Algorithm SHA256).Hash.Substring(0, 12); size = $b.Length }
}
if (-not $SkipApk) {
    $lanes += New-Lane "apk" {
        $env:JAVA_HOME = $using:jdk17
        $env:PATH = "$using:jdk17\bin;$env:PATH"
        $env:ANDROID_HOME = $using:sdk
        $env:ANDROID_SDK_ROOT = $using:sdk
        $env:GRADLE_OPTS = "-Dorg.gradle.workers.max=3"
        $t0 = Get-Date
        Set-Location "$using:repoRoot/app-android"
        $gb = @("C:/src/gradle-8.7/bin/gradle.bat",
            "$env:USERPROFILE/.gradle-portable/bin/gradle.bat",
            "$env:USERPROFILE/.gradle/wrapper/dists/gradle-8.7-bin/bhs2wmbdwecv87pi65oeuq5iu/gradle-8.7/bin/gradle.bat") | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $gb) { throw "Gradle 8.7 nao encontrado" }
        & $gb :app:assembleDebug --console=plain 2>&1 | Select-Object -Last 3
        $a = Get-Item "app/build/outputs/apk/debug/app-debug.apk"
        [pscustomobject]@{ lane = "apk"; exit = $LASTEXITCODE; secs = [int]((Get-Date) - $t0).TotalSeconds; size = $a.Length }
    }
}
} # fim if -not OnlyFlash

Write-Host "Aguardando $($lanes.Count) pistas..." -ForegroundColor Cyan
$results = $lanes | ForEach-Object { Receive-Job -Job $_.Job -Wait -AutoRemoveJob } | Where-Object { $null -ne $_.PSObject.Properties['lane'] -and $_.lane }
$fail = 0
foreach ($r in $results) {
    $c = if ($r.exit -eq 0) { "Green" } else { "Red"; $fail++ }
    Write-Host ("[{0}] exit={1} {2}" -f $r.lane, $r.exit, (($r | Select-Object sha, size, secs | Out-String).Trim())) -ForegroundColor $c
}
if ($fail -ne 0) { Write-Host ("BUILD-ALL FAIL: {0} pista(s)" -f $fail) -ForegroundColor Red; exit 1 }
if (-not $Flash -and -not $OnlyFlash) { Write-Host "BUILD-ALL OK (só build)." -ForegroundColor Green; exit 0 }
Write-Host "=== FLASH (S3 -> classic, sequencial por segurança) ===" -ForegroundColor Cyan
if (-not $OnlyFlash) {
    Write-Host "Bins já validados acima (hash + tamanho)." -ForegroundColor Gray
}
& "$repoRoot/scripts/build-esp32s3-devkitc.ps1" -OnlyFlash -Port $PortS3
if ($LASTEXITCODE -ne 0) { Write-Host "FLASH S3 FALHOU." -ForegroundColor Red; exit 1 }
& "$repoRoot/scripts/build-esp32-ttgo.ps1" -OnlyFlash -Port $PortClassic
if ($LASTEXITCODE -ne 0) { Write-Host "FLASH CLASSIC FALHOU." -ForegroundColor Red; exit 1 }
Write-Host "BUILD-ALL OK (build + flash)." -ForegroundColor Green
exit 0
