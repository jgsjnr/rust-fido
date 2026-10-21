#!/usr/bin/env python3
"""Prova viva do enrollment PIV 0x39 (F4) sobre serial.

Sequencia: abre janela de pareamento (software) -> TEST_UP (latch 1x) ->
CMD_MSG 0x39 [pin_len||pin||puk] -> espera 0x00; repete -> espera 0x04
(AlreadyProvisioned, fail-closed sem oraculo).
Uso: python tools/piv_enroll_live.py [port] [pin] [puk]
"""
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM7"
PIN = (sys.argv[2] if len(sys.argv) > 2 else "123456").encode()
PUK = (sys.argv[3] if len(sys.argv) > 3 else "12345678").encode()

s = Session("http://x", test_mode=True)
s.connect(PORT, 115200)
try:
    s.cmd_init()
except Exception as e:
    print("INIT falhou:", str(e)[:80])

# Janela de pareamento (test-mode; tolera a corrida do reader UART).
opened = False
for i in range(4):
    try:
        s.test_pairing_open()
        opened = True
        break
    except Exception as e:
        print("janela retry %d: %s" % (i + 1, str(e)[:60]))
        time.sleep(2)
if not opened:
    print("SEM JANELA; abortando.")
    sys.exit(2)

req = bytes([0x39, len(PIN)]) + PIN + PUK

def attempt(tag):
    try:
        s.test_up()
    except Exception as e:
        print(tag, "TEST_UP falhou:", str(e)[:60])
        return None
    st, body = s._exchange(CMD_MSG, req, timeout_s=10.0, op="piv-enroll")
    print("%s: wire=0x%02X body=%dB" % (tag, st, len(body)))
    return st

w1 = attempt("enroll#1")
w2 = attempt("enroll#2")
s.close()

ok = (w1 == 0x00 and w2 == 0x04) or (w1 == 0x04 and w2 == 0x04)
print("RESULTADO:", "OK (enroll + AlreadyProvisioned)" if ok else "DIVERGENTE (w1=%s w2=%s; pode ser placa ja enrolada ou gate)" % (w1, w2))
sys.exit(0 if ok else 1)
