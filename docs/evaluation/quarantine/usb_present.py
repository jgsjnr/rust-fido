import subprocess

PS = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

def ps(cmd):
    r = subprocess.run(PS + [cmd], capture_output=True, text=True, errors="replace")
    return r.stdout.strip() or ("(vazio) err=%s" % r.stderr.strip()[:200])

print("=== FIDO AE61: presente? problema? driver? ===")
print(ps("Get-PnpDevice -InstanceId 'HID\\VID_303A*' | Select-Object FriendlyName, Status, Class, DriverVersion | Format-List | Out-String -Width 160"))
print(ps("$d = Get-PnpDevice -InstanceId 'HID\\VID_303A*' | Select-Object -First 1; Get-PnpDeviceProperty -InstanceId $d.InstanceId | Where-Object { $_.KeyName -like '*IsPresent*' -or $_.KeyName -like '*Problem*' -or $_.KeyName -like '*Driver*' } | Select-Object KeyName, Data | Format-Table -AutoSize | Out-String -Width 200"))
print("=== Desconhecido com falha de descritor: detalhes ===")
print(ps("Get-PnpDevice -FriendlyName '*Desconhecido*' | Select-Object FriendlyName, InstanceId, Status, Class | Format-List | Out-String -Width 200"))
