"""Brute-force do strapping: acha combinacao DTR/RTS que entra em download."""
import ctypes
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import SerialLink

SETDTR, CLRDTR, SETRTS, CLRRTS = 5, 6, 3, 4
SYNC = bytes([0x07, 0x07, 0x12, 0x20] + [0x55] * 32)


def esc(link, func):
    return bool(link._k32.EscapeCommFunction(link.handle, func))


def trial(link, hold, pulse):
    # hold: ("DTR"|"RTS", True|False) mantido; pulse: outra linha, pulso.
    hset, hclr = (SETDTR, CLRDTR) if hold[0] == "DTR" else (SETRTS, CLRRTS)
    pset, pclr = (SETDTR, CLRDTR) if pulse[0] == "DTR" else (SETRTS, CLRRTS)
    esc(link, hset if hold[1] else hclr)
    time.sleep(0.05)
    esc(link, pset if pulse[1] else pclr)
    time.sleep(0.1)
    esc(link, pclr if pulse[1] else pset)
    time.sleep(0.3)
    # Limpa RX e tenta sync ROM.
    try:
        while True:
            link.read_exact(1, deadline_s=0.05)
    except Exception:
        pass
    link.write(SYNC)
    try:
        raw = link.read_exact(16, deadline_s=1.0)
        return "SYNC-ACK %s" % bytes(raw).hex()
    except Exception:
        pass
    try:
        raw = link.read_exact(64, deadline_s=1.0)
        t = bytes(raw)
        if b"HEARTBEAT" in t or b"INIT" in t or b"load:" in t:
            return "app viva"
        return "bytes? %s" % t[:16].hex()
    except Exception as e:
        return "silencio"


link = SerialLink("COM7", 115200)
link.open()
combos = []
for hline in ("DTR", "RTS"):
    for hval in (True, False):
        pline = "RTS" if hline == "DTR" else "DTR"
        for pval in (True, False):
            combos.append(((hline, hval), (pline, pval)))
for hold, pulse in combos:
    r = trial(link, hold, pulse)
    print("hold=%s%s pulse=%s%s -> %s" % (hold[0], hold[1], pulse[0], pulse[1], r))
    # Solta tudo e deixa bootar antes do proximo.
    esc(link, CLRDTR)
    esc(link, CLRRTS)
    time.sleep(1.5)
link.close()
