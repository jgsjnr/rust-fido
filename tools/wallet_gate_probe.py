#!/usr/bin/env python3
"""Prova viva das gates wallet: GEN sem pareamento nega NEED_BINDING (0x05)."""
import sys

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

s = Session("http://127.0.0.1:8888")
s.connect("COM7", 115200)
try:
    st, _ = s._exchange(CMD_MSG, bytes([0x35, 0x01, 0x00]), timeout_s=10.0, op="wallet-probe")
finally:
    s.close()
print("WALLET_GEN_NOPAIR_STATUS=0x%02x" % st)
assert st == 0x05, st
print("WALLET_GATE_OK sem pareamento nega NEED_BINDING vivo")
