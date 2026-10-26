#!/usr/bin/env python3
"""Diagnóstico USB via WMI/EventLog/setupapi (sem quebrar quoting do shell)."""
import subprocess
import sys

PS = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

def ps(cmd):
    r = subprocess.run(PS + [cmd], capture_output=True, text=True, errors="replace")
    return r.stdout.strip() or ("(vazio) rc=%d err=%s" % (r.returncode, r.stderr.strip()[:200]))

print("=== 1. Dispositivos USB com problema (PnP) ===")
print(ps("Get-PnpDevice | Where-Object { $_.InstanceId -like 'USB*' -and $_.Status -ne 'OK' } | Select-Object FriendlyName, Status | Format-Table -AutoSize | Out-String -Width 160"))
print("=== 2. Sons recentes Kernel-PnP (30 min, Id 400/410/411/412/430) ===")
print(ps("Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration' } -MaxEvents 12 -ErrorAction SilentlyContinue | ForEach-Object { '{0:HH:mm:ss} id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\\s+',' ').Substring(0, [Math]::Min(150, $_.Message.Length)) }"))
print("=== 3. setupapi.dev.log: falhas recentes (30 linhas finais com fail/error) ===")
print(ps("Get-Content C:\\Windows\\INF\\setupapi.dev.log -Tail 400 | Select-String -Pattern 'fail|error|303A|AE61|Device Descriptor' -CaseSensitive:$false | Select-Object -Last 15"))
print("=== 4. VID 303A em qualquer lugar do PnP ===")
print(ps("Get-PnpDevice | Where-Object { $_.InstanceId -like '*303A*' -or $_.InstanceId -like '*AE61*' } | Select-Object FriendlyName, InstanceId, Status | Format-Table -AutoSize | Out-String -Width 200"))
print("=== 5. Portas COM agora ===")
print(ps("[System.IO.Ports.SerialPort]::GetPortNames()"))
