#!/usr/bin/env python3
"""Bond + TEST_UP imprimindo TODAS as linhas do firmware no caminho."""
import asyncio
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import Session

MAC = "80:65:99:DF:4B:CE"
sess = Session("http://127.0.0.1:8888", test_mode=True)


def show(tag, text):
    print("===== %s =====" % tag, flush=True)
    for ln in text.splitlines():
        s = ln.strip()
        if s:
            print(s[:160], flush=True)


def main():
    sess.connect("COM7", 115200)
    try:
        time.sleep(12)
        t = sess.send_text_line("TEST_PAIRING_OPEN_300", timeout_s=8.0, until=b"pairing_open")
        show("WINDOW", t)
    except Exception as exc:
        sess.close()
        print("FAIL WINDOW %r" % (exc,))
        raise SystemExit(1)

    loop = asyncio.new_event_loop()

    async def bond_and_press():
        from bleak import BleakClient

        try:
            async with BleakClient(MAC, timeout=30.0) as client:
                print("BLE-CONNECTED", flush=True)
                try:
                    await client.pair()
                    print("BOND-OK", flush=True)
                except Exception as exc:
                    print("BOND-ERR %r" % (exc,), flush=True)
                await loop.run_in_executor(None, send_up)
                await asyncio.sleep(6)
        except Exception as exc:
            print("CONNECT-ERR %r" % (exc,), flush=True)

    def send_up():
        # 3 tentativas espacadas; imprime TUDO que o firmware disser.
        for i in range(3):
            text = sess.send_text_line("TEST_UP", timeout_s=6.0, until=b"up_latched")
            show("UP-TRY%d" % (i + 1), text)
            if "up_latched" in text and "source=software" in text:
                break
            time.sleep(2)

    try:
        loop.run_until_complete(bond_and_press())
    finally:
        try:
            d = sess.lifetime_dump(timeout_s=8.0)
            show("DUMP", d)
        finally:
            sess.close()
            loop.close()


main()
