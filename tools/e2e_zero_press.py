#!/usr/bin/env python3
"""E2E sem tocar no BOOT: janela 300s + bond BLE + TEST_UP na MESMA sessao.

Uma unica abertura serial (sem re-opens = sem pulsos DTR). Prova:
lt.pairing.pairing >= 1 no dump final.
"""
import asyncio
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG  # noqa

MAC = "80:65:99:DF:4B:CE"


def main():
    sess = Session("http://127.0.0.1:8888", test_mode=True)
    sess.connect("COM7", 115200)
    try:
        print("BOOT-WAIT 12s...", flush=True)
        time.sleep(12)
        ack = sess.send_text_line("TEST_PAIRING_OPEN_300", timeout_s=8.0)
        assert "window_s=300" in ack, ack[-120:]
        print("WINDOW-300-OPEN", flush=True)
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
                    print("BOND-ERR %r (pode ja estar bonded)" % (exc,), flush=True)
                # UP por software COM a central ainda conectada (pending vivo).
                await loop.run_in_executor(None, send_up)
                await asyncio.sleep(4)
                print("BLE-DISCONNECT", flush=True)
        except Exception as exc:
            print("CONNECT-ERR %r" % (exc,), flush=True)

    def send_up():
        try:
            up = sess.test_up(timeout_s=8.0)
            print("UP-ACK:", up.strip().splitlines()[-1][:60], flush=True)
        except Exception as exc:
            print("UP-ERR %r" % (exc,), flush=True)

    try:
        loop.run_until_complete(bond_and_press())
    finally:
        try:
            dump = sess.lifetime_dump(timeout_s=8.0)
            pairs = [l.strip() for l in dump.splitlines() if "lt.pairing" in l]
            print("DUMP-PAIRING:", pairs, flush=True)
            ok = any("lt.pairing.pairing=" in l and not l.strip().endswith("=0") for l in pairs)
            print("E2E-ZERO-PRESS:", "PASS" if ok else "FAIL (sem pareamento)", flush=True)
        finally:
            sess.close()
            loop.close()


main()
