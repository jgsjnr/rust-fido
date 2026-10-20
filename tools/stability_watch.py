#!/usr/bin/env python3
"""Decide reboot-espontaneo vs DTR: UMA abertura serial, janela via ela,
connect BLE no meio, uptime monotono por 150s?

- Abre COM7 uma vez; envia TEST_PAIRING_OPEN_300 na mesma sessao;
  depois so LE (nenhum re-open = nenhum novo pulso DTR).
- Aos 40s faz connect BLE (sem pair/discover) e segura 10s.
- Veredito: BOOTS==0 e uptimes monotonicos => sem crash espontaneo.
"""
import asyncio
import re
import threading
import time

import serial

PORT = "COM7"
MAC = "80:65:99:DF:4B:CE"

buf = bytearray()
lock = threading.Lock()
stop = False


def session():
    s = serial.Serial(PORT, 115200, timeout=0.5, dsrdtr=False, rtscts=False)
    s.setDTR(True)
    time.sleep(0.3)
    s.reset_input_buffer()
    s.write(b"TEST_PAIRING_OPEN_300\n")
    t0 = time.time()
    while not stop and time.time() - t0 < 170:
        try:
            d = s.read(2048)
        except Exception:
            break
        if d:
            with lock:
                buf.extend(d)
    s.close()


async def connect_once():
    from bleak import BleakClient

    try:
        async with BleakClient(MAC, timeout=25.0):
            print("BLE-CONNECTED hold 10s", flush=True)
            await asyncio.sleep(10)
            print("BLE-DISCONNECT ok", flush=True)
    except Exception as exc:
        print("BLE-CONNECT-RESULT %r" % (exc,), flush=True)


def main():
    global stop
    th = threading.Thread(target=session, daemon=True)
    th.start()
    time.sleep(45)  # janela aberta + adv no ar
    print("T+45 connect attempt...", flush=True)
    asyncio.run(connect_once())
    time.sleep(90)
    stop = True
    th.join(timeout=5)
    with lock:
        raw = bytes(buf)
    open(r"C:\t\stability.txt", "wb").write(raw)
    text = raw.decode("utf-8", "replace")
    print("ACK300:", "window_s=300" in text, flush=True)
    print("BOOTS:", text.count("2nd stage bootloader"), flush=True)
    print("WDT:", text.count("reset by WDT"), flush=True)
    uts = [int(x) for x in re.findall(r"uptime: (\d+)s", text)]
    mono = all(b >= a for a, b in zip(uts, uts[1:]))
    print("N_HB:", len(uts), "MONOTONIC:", mono, flush=True)
    if uts:
        print("FIRST:", uts[0], "LAST:", uts[-1], flush=True)


main()
