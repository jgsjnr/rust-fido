#!/usr/bin/env python3
"""Caca ao wedge pos-BLE: UMA sessao serial capturando tudo + bond no meio."""
import asyncio
import sys
import threading
import time

sys.path.insert(0, "tools")
from app_simulator import SerialLink

PORT = "COM7"
MAC = "80:65:99:DF:4B:CE"

buf = bytearray()
lock = threading.Lock()
stop = False


def capture():
    l = SerialLink(PORT, 115200)
    l.open()
    time.sleep(0.3)
    with lock:
        buf.clear()
    # Sem reset aqui (SerialLink nao pulsa DTR); espera boot se veio de reset.
    t0 = time.time()
    while not stop and time.time() - t0 < 240:
        try:
            d = l.read_exact(512, deadline_s=1.0)
        except Exception:
            continue
        if d:
            with lock:
                buf.extend(d)
    l.close()


async def bond_cycle():
    from bleak import BleakClient

    await asyncio.sleep(25)  # device boota + abre janela sozinho? NAO: sem janela, bond radio ok
    try:
        async with BleakClient(MAC, timeout=25.0) as client:
            print("BLE-CONNECTED", flush=True)
            try:
                await client.pair()
                print("BOND-OK", flush=True)
            except Exception as exc:
                print("BOND-ERR %r" % (exc,), flush=True)
            await asyncio.sleep(5)
    except Exception as exc:
        print("CONNECT-ERR %r" % (exc,), flush=True)


def main():
    global stop
    th = threading.Thread(target=capture, daemon=True)
    th.start()
    time.sleep(20)  # boot + heartbeat visivel
    print("T+20 bond attempt (sem janela: radio-level apenas)...", flush=True)
    asyncio.run(bond_cycle())
    print("T+? captura +60s pos-bond...", flush=True)
    time.sleep(60)
    stop = True
    th.join(timeout=5)
    with lock:
        raw = bytes(buf)
    open(r"C:\t\wedge_hunt.txt", "wb").write(raw)
    text = raw.decode("utf-8", "replace")
    print("BYTES", len(raw), "BOOTS:", text.count("2nd stage"), flush=True)
    import re

    uts = [int(x) for x in re.findall(r"uptime: (\d+)s", text)]
    print("N_HB:", len(uts), "LAST:", uts[-5:] if uts else None, flush=True)
    tails = [l.strip()[:130] for l in text.splitlines() if l.strip()]
    print("---TAIL---", flush=True)
    for l in tails[-15:]:
        print(l, flush=True)


main()
