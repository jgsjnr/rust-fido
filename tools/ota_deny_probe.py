#!/usr/bin/env python3
"""Prova viva OTA negativa na SERIAL: 0x30 nao existe nesse transporte.

OTA (0x30-0x34) so e roteada no USB nativo (main.rs, secao C); na serial
o opcode cai em comando CTAP desconhecido -> 0x01 INVALID_COMMAND.
Fail-closed documentado: nenhum stage, nenhuma mudanca de fase.
O caminho USB positivo exige HID nativo (outro cabo/porta) — bloqueado
ate la. Nenhum burn de eFuse foi (nem sera) feito aqui.
"""
import hashlib
import struct
import sys

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

DIAG = r"C:\t\aegis-app-esp32s3-diag.bin"
img = open(DIAG, "rb").read()
manifest = (
    struct.pack(">I", 9999)
    + struct.pack(">I", len(img))
    + hashlib.sha256(img).digest()
    + bytes(64)
)
assert len(manifest) == 104, len(manifest)
print("DIAG_BYTES=%d SHA=%s" % (len(img), hashlib.sha256(img).hexdigest()[:16]))

sess = Session("http://127.0.0.1:8888")
sess.connect("COM7", 115200)
try:
    status, body = sess._exchange(
        CMD_MSG, bytes([0x30]) + manifest, timeout_s=15.0, op="ota-probe"
    )
finally:
    sess.close()
print("OTA_BEGIN_SERIAL_STATUS=0x%02x body_len=%d" % (status, len(body)))
assert status == 0x01, "serial deveria rejeitar 0x30 com INVALID_COMMAND, veio 0x%02x" % status
print("OTA_SERIAL_DENY_OK opcode inexistente rejeitado, zero estado tocado")
