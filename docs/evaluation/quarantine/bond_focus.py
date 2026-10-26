#!/usr/bin/env python3
"""Foco: o que o firmware imprime em SECURED/UP/pairing durante bond+TEST_UP."""
import asyncio
import sys
import threading
import time

sys.path.insert(0, "tools")
from app_simulator import Session

MAC = "80:65:99:DF:4B:CE"
sess = Session("http://127.0.0.1:8888", test_mode=True)


def main():
    sess.connect("COM7", 115200)
    try:
        time.sleep(12)
        print(sess.test_pairing_open(timeout_s=8.0).strip().splitlines()[-1][:60], flush=True)
    except Exception as exc:
        sess.close()
        print("FAIL WINDOW %r" % (exc,))
        raise SystemExit(1)

    loop = asyncio.new_event_loop()

    async def hold():
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
        try:
            sess.test_up(timeout_s=6.0, retries=4)
            print("UP-ACK ok", flush=True)
        except Exception as exc:
            print("UP-ERR %r" % (exc,), flush=True)

    try:
        loop.run_until_complete(hold())
    finally:
        # Janela de observacao: o firmware deve imprimir link seguro / bonding ok.
        time.sleep(2)
        sess.close()
        loop.close()


main()
