#!/usr/bin/env python3
"""Dispara via UART a funcao de pareamento (diag test-mode) e valida janela 60s.

Funcao no firmware: dispatch_serial_pairing_line("TEST_PAIRING_OPEN")
  -> PairingManager::open_test_window() -> PairingBle{expires=now+60s}
  -> ack "pairing_open window_s=60 source=software".
Uso equivalente pelo simulador: tools/app_simulator.py --port COM7 --test-mode,
menu 11 (Session.test_pairing_open()).
"""
import sys, time
sys.path.insert(0, "tools")
from app_simulator import Session, PAIRING_WINDOW_SECS

PORT = "COM7"
LOG = open(r"C:\t\pair_diag_test.log", "w", encoding="utf-8")

def tee(s):
    print(s); LOG.write(s + "\n"); LOG.flush()

sess = Session("http://127.0.0.1:8888", test_mode=True)
sess.connect(PORT, 115200)
tee("CONNECTED port=%s test_mode=True" % PORT)

# 1. Abre a janela via UART (a funcao pedida).
ack = sess.test_pairing_open(timeout_s=8.0)
tee("ACK_RAW=" + ack.strip().replace("\r", ""))
assert "pairing_open" in ack and "window_s=60" in ack and "source=software" in ack, "ACK inesperado"
assert PAIRING_WINDOW_SECS == 60
tee("JANELA_ABERTA_OK window_s=60 source=software")

# 2. Dump imediato: estado deve mostrar pareamento/advertising.
dump1 = sess.lifetime_dump(timeout_s=8.0)
tee("DUMP_T0_BYTES=%d" % len(dump1))
for line in dump1.splitlines():
    if "pair" in line.lower() or "adv" in line.lower() or "state" in line.lower():
        tee("DUMP_T0: " + line.strip()[:160])

# 3. Re-sonda no meio da janela (prova que continua aberta).
time.sleep(10)
dump2 = sess.lifetime_dump(timeout_s=8.0)
tee("DUMP_T10_BYTES=%d" % len(dump2))
for line in dump2.splitlines():
    if "pair" in line.lower() or "adv" in line.lower() or "state" in line.lower():
        tee("DUMP_T10: " + line.strip()[:160])

sess.close()
tee("DONE sem wipe/reset; janela expira sozinha em 60s")
