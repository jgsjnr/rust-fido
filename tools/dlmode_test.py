"""Sequencia do usuario (pyserial) via ctypes + teste de sync ROM."""
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import SerialLink

SETDTR, CLRDTR, SETRTS, CLRRTS = 5, 6, 3, 4
SYNC = bytes([0x07, 0x07, 0x12, 0x20] + [0x55] * 32)


def esc(link, func):
    return bool(link._k32.EscapeCommFunction(link.handle, func))


link = SerialLink("COM7", 115200)
link.open()
# 1. estavel
esc(link, CLRDTR)
esc(link, CLRRTS)
time.sleep(0.05)
# 2. IO0 + EN juntos
esc(link, SETDTR)
esc(link, SETRTS)
time.sleep(0.1)
# 3. solta EN, segura BOOT
esc(link, CLRRTS)
time.sleep(0.05)
# 4. solta BOOT
esc(link, CLRDTR)
time.sleep(0.3)
# 5. sync ROM?
try:
    while True:
        link.read_exact(1, deadline_s=0.05)
except Exception:
    pass
link.write(SYNC)
try:
    raw = link.read_exact(16, deadline_s=1.5)
    print("RESPOSTA ROM:", bytes(raw).hex())
except Exception as e:
    print("sem resposta ROM")
try:
    raw = link.read_exact(64, deadline_s=1.0)
    t = bytes(raw).decode("ascii", "replace").strip("\x00").strip()
    print("TEXTO:", t[:80])
except Exception:
    pass
link.close()
