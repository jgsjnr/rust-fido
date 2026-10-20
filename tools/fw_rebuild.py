import subprocess
r = subprocess.run(
    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
     ". ./scripts/common.ps1; Initialize-EspEnvironment; "
     "cargo clean -p aegis-fido-firmware; "
     ".\\scripts\\build-diag.ps1"],
    cwd=r"E:\projetos\fido")
print("RC=", r.returncode)
