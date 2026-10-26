#!/usr/bin/env python3
"""Prova viva do trigger produto 0x2F: abre janela 60s + adv, sem test-mode."""
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

sess = Session("http://127.0.0.1:8888")
sess.connect("COM7", 115200)
try:
    # O open pode resetar a placa (DTR); espera o boot (heartbeat).
    time.sleep(12)
    t0 = time.time()
    status, body = sess._exchange(CMD_MSG, bytes([0x2F]), timeout_s=15.0, op="pair-open")
    dt = time.time() - t0
finally:
    sess.close()
print("PAIR_OPEN_STATUS=0x%02x body_len=%d dt=%.1fs" % (status, len(body), dt))
assert status == 0x00, status
print("HOST_TRIGGER_OK janela aberta por software (produto, sem test-mode)")
