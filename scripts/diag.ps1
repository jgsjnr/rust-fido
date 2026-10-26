# scripts/diag.ps1 - consolidated from build-diag.ps1 + flash-diag.ps1 (no logic changed, origin headers only)
# --- BEGIN ORIGIN: scripts/build-diag.ps1 ---
. (Join-Path $PSScriptRoot "common.ps1")
$sw = [Diagnostics.Stopwatch]::StartNew()
Invoke-FirmwareBuild -Target 'xtensa-esp32s3-espidf' -Feature 'board-devkitc,test-mode,debug-terminal'
$sw.Stop()
Write-Host ("BUILD_SECS=" + $sw.Elapsed.TotalSeconds)
$elf = 'C:\t\xtensa-esp32s3-espidf\release\aegis-fido-firmware'
Get-Item $elf | Select-Object LastWriteTime, Length
# --- END ORIGIN: scripts/build-diag.ps1 ---

# --- BEGIN ORIGIN: scripts/flash-diag.ps1 ---
. (Join-Path $PSScriptRoot "common.ps1")
$binPath = Invoke-FirmwareElf2Image -Chip 'esp32s3' -Target 'xtensa-esp32s3-espidf' -OutBinName 'aegis-app-esp32s3-diag.bin'
Get-Item $binPath | Select-Object FullName, Length
$h = (Get-FileHash $binPath -Algorithm SHA256).Hash
Write-Host ("DIAG_SHA256=" + $h)
$usedPort = Invoke-FirmwareFlash -Chip 'esp32s3' -BinPath $binPath -Port 'COM7'
Write-Host ("FLASHED_PORT=" + $usedPort)
# --- END ORIGIN: scripts/flash-diag.ps1 ---
