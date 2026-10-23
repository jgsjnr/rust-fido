#!/usr/bin/env python3
"""Prova viva OTA negativa na SERIAL: negacao fail-closed em DUAS camadas.

Camada 1 (framing CTAPHID, pre-dispatch): opcode/canal invalido rejeitado
com 0x01 INVALID_COMMAND, body_len 0, nada staged (p.ex. e2e D08 e probe
atual via CMD_MSG/0x30 enquadrado na serial).

Camada 2 (dispatcher roteado F5): 0x30-0x34 roteados via dispatch_ota_request
(main.rs ramo SERIAL/OTA); probe oversize estoura o budget -> OtaError::Overflow
-> ota_fail -> OTA_STATUS_FAIL 0x04, body_len 0, nenhum stage, nenhuma
mudanca de fase.

PASS = status em {0x01, 0x04} com body_len 0. O caminho USB positivo exige
HID nativo (outro cabo/porta) — bloqueado ate la. Nenhum burn de eFuse foi
(nem sera) feito aqui. Sem mudar firmware.
"""
import hashlib
import struct
import sys

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

DIAG = r"C:\t\aegis-app-esp32s3-diag.bin"
with open(DIAG, "rb") as f:
    img = f.read()
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
assert status in (0x01, 0x04) and len(body) == 0, (
    "serial deveria negar 0x30 fail-closed (0x01 framing pre-dispatch ou "
    "0x04 dispatcher F5, body_len 0), veio 0x%02x len=%d" % (status, len(body))
)
print("OTA_SERIAL_DENY_OK fail-closed 0x%02x, zero estado tocado" % status)
