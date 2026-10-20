# Build do cdylib aegis_bridge para Android (arm64 + x86_64) -> jniLibs.
param([switch]$Release = $true)
$ErrorActionPreference = "Stop"
$ndkBin = "C:\Users\junior\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$ndkBin\aarch64-linux-android31-clang.cmd"
$env:CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = "$ndkBin\x86_64-linux-android31-clang.cmd"
$env:CC_aarch64_linux_android = "$ndkBin\aarch64-linux-android31-clang.cmd"
$env:CC_x86_64_linux_android = "$ndkBin\x86_64-linux-android31-clang.cmd"
$profile = if ($Release) { "release" } else { "debug" }
$cargoProfile = if ($Release) { "--release" } else { "" }
Push-Location (Join-Path $PSScriptRoot "..")
try {
    foreach ($t in @("aarch64-linux-android", "x86_64-linux-android")) {
        Write-Host "=== cdylib $t ($profile) ==="
        if ($Release) {
            & cargo build -p uniffi-bridge --target $t --release
        } else {
            & cargo build -p uniffi-bridge --target $t
        }
        if ($LASTEXITCODE -ne 0) { throw "cargo build falhou para $t" }
    }
    $abiMap = @{
        "aarch64-linux-android" = "arm64-v8a"
        "x86_64-linux-android" = "x86_64"
    }
    foreach ($t in $abiMap.Keys) {
        $abi = $abiMap[$t]
        $dst = Join-Path "app-android/app/src/main/jniLibs" $abi
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        $dir = "C:/t/$t/release"
        if (-not $Release) { $dir = "C:/t/$t/debug" }
        $src = Join-Path $dir "libaegis_bridge.so"
        if (-not (Test-Path $src)) { $src = Join-Path $dir "aegis_bridge.so" }
        if (-not (Test-Path $src)) { $src = Join-Path $dir "aegis_bridge.dll" }
        if (-not (Test-Path $src)) { throw "cdylib nao encontrado em $dir" }
        Copy-Item $src (Join-Path $dst "libaegis_bridge.so") -Force
        $so = Join-Path $dst "libaegis_bridge.so"
        $h = (Get-FileHash $so -Algorithm SHA256).Hash
        $sz = (Get-Item $so).Length
        Write-Host ("OK {0}: {1} bytes SHA256={2}" -f $so, $sz, $h)
    }
} finally {
    Pop-Location
}
