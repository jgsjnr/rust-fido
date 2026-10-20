import subprocess

PS = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

def ps(cmd):
    r = subprocess.run(PS + [cmd], capture_output=True, text=True, errors="replace")
    return r.stdout.strip() or ("(vazio) err=%s" % r.stderr.strip()[:300])

print("=== AE61: problem code + filhos USB ===")
print(ps("$d = Get-PnpDevice -InstanceId 'HID\\VID_303A*' | Select-Object -First 1; Get-PnpDeviceProperty -InstanceId $d.InstanceId | Where-Object { $_.KeyName -like '*Problem*' -or $_.KeyName -like '*Present*' -or $_.KeyName -like '*DevNode*' } | Format-Table -AutoSize | Out-String -Width 200"))
print("=== Composite AE61 pai + interfaces filhas ===")
print(ps("Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_303A*PID_AE61*' } | Select-Object FriendlyName, Status, Class | Format-Table -AutoSize | Out-String -Width 160"))
print("=== HID classe: quantos com problem? ===")
print(ps("Get-PnpDevice -Class HIDClass | Where-Object { $_.Status -ne 'OK' } | Select-Object FriendlyName, Status | Format-Table -AutoSize | Out-String -Width 160"))
