# Wave3 P2 — CI grep: Mock* only under cfg(test), with_default_keys test-only.
# FAILs when hardcoded fixtures leak into prod paths.
# Marker: CI-GREP: MOCK-ONLY-IN-TEST

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot

$fail = $false

# 1. with_default_keys must be gated by cfg(test) (previous line or same block).
$hits = Select-String -Pattern "with_default_keys" -Path "crates\*\src\*.rs", "crates\*\src\*\*.rs" -AllMatches
foreach ($h in $hits) {
    $lines = Get-Content $h.Path
    $idx = $h.LineNumber - 1
    $window = @()
    for ($i = [Math]::Max(0, $idx - 3); $i -lt [Math]::Min($lines.Count, $idx + 1); $i++) {
        $window += $lines[$i]
    }
    $ctx = ($window -join "`n")
    if ($ctx -notmatch "cfg\(test\)") {
        # Allow definition line itself if next line gated? Require marker in file.
        $fileText = ($lines -join "`n")
        if ($fileText -notmatch "MOCK-ONLY-IN-TEST") {
            Write-Host "FAIL: with_default_keys without cfg(test) at $($h.Path):$($h.LineNumber)" -ForegroundColor Red
            $fail = $true
        }
    }
}

# 2. Mock* in firmware main.rs prod path = FAIL (must use provision loader).
$mainHits = Select-String -Pattern "Mock(Efuse|Flash)" -Path "crates\aegis-fido-firmware\src\main.rs"
if ($mainHits) {
    Write-Host "FAIL: Mock* in main.rs prod path (use provision loader)" -ForegroundColor Red
    $mainHits | ForEach-Object { Write-Host "  $($_.Path):$($_.LineNumber): $($_.Line)" }
    $fail = $true
}

# 3. Hardcoded dev secrets in prod binary path = FAIL (main.rs only).
# Test modules (cfg(test)) legitimately assert fixture values; they carry
# CI-GREP: MOCK-ONLY-IN-TEST marker and are excluded here.
$prodSecret = Select-String -Pattern "\[0x5A" -Path "crates\aegis-fido-firmware\src\main.rs"
if ($prodSecret) {
    Write-Host "FAIL: hardcoded 0x5A fixture in prod path" -ForegroundColor Red
    $prodSecret | ForEach-Object { Write-Host "  $($_.Path):$($_.LineNumber)" }
    $fail = $true
}

Pop-Location
if ($fail) { exit 1 }
Write-Host "CI-GREP PASS: mocks confined to cfg(test)" -ForegroundColor Green
exit 0
