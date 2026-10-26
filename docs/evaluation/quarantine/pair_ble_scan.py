#!/usr/bin/env python3
"""Reabre a janela via UART e escaneia BLE dentro dos 60s (prova over-the-air)."""
import asyncio, sys, time
sys.path.insert(0, "tools")
from app_simulator import Session
from bleak import BleakScanner

async def main():
    sess = Session("http://127.0.0.1:8888", test_mode=True)
    sess.connect("COM7", 115200)
    ack = sess.test_pairing_open(timeout_s=8.0)
    print("ACK:", ack.strip().splitlines()[-1][:80])
    sess.close()
    print("SCANNING 20s dentro da janela...")
    devs = await BleakScanner.discover(timeout=20.0)
    print("FOUND:", len(devs))
    hits = [d for d in devs if (d.name or "") and ("egis" in (d.name or "") or "ESP" in (d.name or "") or "NimBLE" in (d.name or ""))]
    for d in hits:
        print("MATCH:", d.address, repr(d.name))
    open(r"C:\t\ble_scan_pairing.txt", "w").write("\n".join(
        "%s | %s" % (d.address, d.name) for d in devs))
    print("HITS_AEGIS:", len(hits))

asyncio.run(main())
