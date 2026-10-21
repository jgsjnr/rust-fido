"""Testa o circuito de auto-reset: sequência DTR/RTS do esptool + ouve boot."""
import ctypes
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import SerialLink

SETDTR, CLRDTR, SETRTS, CLRRTS = 5, 6, 3, 4

link = SerialLink("COM7", 115200)
link.open()
k32 = link._k32
h = link.handle


def esc(func):
    return bool(k32.EscapeCommFunction(h, func))


def listen(secs, tag):
    t0 = time.time()
    got = []
    while time.time() - t0 < secs:
        try:
            raw = link.read_exact(64, deadline_s=0.5)
        except Exception:
            continue
        t = bytes(raw).decode("ascii", "replace").strip("\x00").strip()
        if t:
            got.append(t[:80])
    print("%s: %d pacotes" % (tag, len(got)))
    for t in got[:4]:
        print("  RX:", t)
    return got


print("esptool?", end=" ")
import subprocess
r = subprocess.run([sys.executable, "-m", "esptool", "version"],
                   capture_output=True, text=True)
print((r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "?")

print("--- linha base 2s ---")
listen(2, "base")
print("--- sequencia default-reset do esptool ---")
esc(CLRDTR)
esc(SETRTS)
time.sleep(0.1)
esc(SETDTR)
esc(CLRRTS)
time.sleep(0.05)
esc(CLRDTR)
print("--- sequencia INVERTIDA (RTS=GPIO0, DTR=EN) ---")
esc(CLRRTS)
esc(SETDTR)
time.sleep(0.1)
esc(SETRTS)
esc(CLRDTR)
time.sleep(0.05)
esc(CLRRTS)
pkts = listen(4, "pos-reset-inv")
boot = [t for t in pkts if "waiting for download" in t or "Boot" in t or "entry " in t or "load:" in t]
print("BOOT/ROM!" if boot else "silencio (possivel download!)")
for t in boot[:4]:
    print("  RX:", t)
link.close()
