. (Join-Path $PSScriptRoot "common.ps1")
$binPath = Invoke-FirmwareElf2Image -Chip 'esp32s3' -Target 'xtensa-esp32s3-espidf' -OutBinName 'aegis-app-esp32s3-diag.bin'
Get-Item $binPath | Select-Object FullName, Length
$h = (Get-FileHash $binPath -Algorithm SHA256).Hash
Write-Host ("DIAG_SHA256=" + $h)
$usedPort = Invoke-FirmwareFlash -Chip 'esp32s3' -BinPath $binPath -Port 'COM7'
Write-Host ("FLASHED_PORT=" + $usedPort)
