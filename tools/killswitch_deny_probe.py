#!/usr/bin/env python3
"""Prova viva do plumbing: killswitch remoto SEM UP/PIN deve negar (0x04).

Seguro: caminho de negacao apenas (confirm token certo, mas sem UP latch
e sem sessao PIN) — nenhum wipe.
"""
import struct
import sys

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

TOKEN = b"AEGISKEY_KILLSWITCH_CONFIRM"
frame = b"RESC" + bytes([0x01, 0x06]) + struct.pack(">H", len(TOKEN)) + TOKEN
payload = bytes([0x2E]) + frame

sess = Session("http://127.0.0.1:8888")
sess.connect("COM7", 115200)
try:
    status, body = sess._exchange(CMD_MSG, payload, timeout_s=15.0, op="rescue-probe")
finally:
    sess.close()
print("CTAP_STATUS=0x%02x body_len=%d body=%s" % (status, len(body), body[:8].hex()))
assert status == 0x04, "esperado CONFIRMATION_FAILED sem UP/PIN, veio 0x%02x" % status
print("DENY_OK sem UP/PIN (fail-closed vivo)")
