#!/usr/bin/env python3
"""Captura diagnostico vivo: dump + log UART 25s (LED/pairing/BLE)."""
import sys, time
sys.path.insert(0, "tools")
from app_simulator import Session

sess = Session("http://127.0.0.1:8888", test_mode=True)
sess.connect("COM7", 115200)
try:
    dump = sess.lifetime_dump(timeout_s=8.0)
except Exception as e:
    dump = "DUMP_FAIL: %s" % e
print("===== DUMP =====")
print(dump)
open(r"C:\t\diag_dump_now.txt", "w", encoding="utf-8").write(dump)

print("===== LOG 25s (raw) =====")
link = sess.link
t0 = time.time()
raw = bytearray()
while time.time() - t0 < 25:
    try:
        chunk = link.read_exact(1, deadline_s=1.0)
    except Exception:
        continue
    raw.extend(chunk)
open(r"C:\t\diag_log25.txt", "wb").write(bytes(raw))
text = bytes(raw).decode("utf-8", "replace")
for line in text.splitlines():
    l = line.strip()
    if not l:
        continue
    kl = l.lower()
    if any(k in kl for k in ("pair", "ble", "led", "bond", "adv", "success", "error", "lock", "screen", "wink", "auth")):
        print("KEY:", l[:200])
print("TOTAL_BYTES=%d" % len(raw))
sess.close()
