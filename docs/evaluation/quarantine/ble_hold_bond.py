#!/usr/bin/env python3
"""Segura conexao+bonde BLE aberta por N segundos (janela p/ UP fisico).

Uso: abrir janela no device, rodar este script (conecta+bond), e tocar
no BOOT durante a janela. Nao usa GATT (discover quebrado no bleak/Win).
"""
import asyncio
import sys

MAC = sys.argv[1] if len(sys.argv) > 1 else "80:65:99:DF:4B:CE"
HOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 90.0


async def main():
    from bleak import BleakClient

    print("CONNECT", MAC, flush=True)
    async with BleakClient(MAC, timeout=30.0) as client:
        print("CONNECTED pairedPending", flush=True)
        try:
            await client.pair()
            print("BOND-OK (link seguro; firmware aguarda UP)", flush=True)
        except Exception as exc:
            print("BOND-ERR %r (segue segurado: link pode ja estar bonded)" % (exc,), flush=True)
        print("HOLDING %.0fs - TOQUE NO BOOT AGORA (toque curto)" % HOLD, flush=True)
        await asyncio.sleep(HOLD)
        print("HOLD-DONE disconnect", flush=True)


asyncio.run(main())
