. (Join-Path $PSScriptRoot "common.ps1")
$sw = [Diagnostics.Stopwatch]::StartNew()
Invoke-FirmwareBuild -Target 'xtensa-esp32s3-espidf' -Feature 'board-devkitc,test-mode,debug-terminal'
$sw.Stop()
Write-Host ("BUILD_SECS=" + $sw.Elapsed.TotalSeconds)
$elf = 'C:\t\xtensa-esp32s3-espidf\release\aegis-fido-firmware'
Get-Item $elf | Select-Object LastWriteTime, Length
