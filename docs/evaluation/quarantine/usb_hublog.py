import subprocess

PS = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

def ps(cmd):
    r = subprocess.run(PS + [cmd], capture_output=True, text=True, errors="replace")
    return r.stdout.strip() or ("(vazio) err=%s" % r.stderr.strip()[:200])

print("=== USBHUB3 operacional: últimos 15 eventos ===")
print(ps("Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-USBHUB3/Operational' } -MaxEvents 15 -ErrorAction SilentlyContinue | ForEach-Object { '{0:HH:mm:ss} id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\\s+',' ').Substring(0, [Math]::Min(170, $_.Message.Length)) }"))
print("=== setupapi: últimas menções AE61/303A/VID_0000 ===")
print(ps("Get-Content C:\\Windows\\INF\\setupapi.dev.log -Tail 1500 | Select-String -Pattern 'AE61|303A|VID_0000' | Select-Object -Last 12"))
