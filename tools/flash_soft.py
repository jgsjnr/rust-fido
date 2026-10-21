#!/usr/bin/env python3
"""Flash via software: TEST_DOWNLOAD (RTC_CNTL) + esptool --before no-reset.

Dispensa BOOT/DTR/RTS. Uso:
  python tools/flash_soft.py [bin] [port]
"""
import subprocess
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import SerialLink

BIN = sys.argv[1] if len(sys.argv) > 1 else r"C:\t\aegis-app-esp32s3-diag.bin"
PORT = sys.argv[2] if len(sys.argv) > 2 else "COM7"

link = SerialLink(PORT, 115200)
link.open()
link.write(b"TEST_DOWNLOAD\n")
print("TEST_DOWNLOAD enviado; aguardando ack + silencio...")
t0 = time.time()
acked = False
while time.time() - t0 < 8:
    try:
        raw = link.read_exact(64, deadline_s=1.0)
    except Exception:
        continue
    t = bytes(raw).decode("ascii", "replace").strip("\x00").strip()
    if t:
        print("RX:", t[:80])
        if "download_mode" in t:
            acked = True
            break
link.close()
if not acked:
    print("SEM ACK (firmware sem test-mode?); abortando.")
    sys.exit(2)
time.sleep(1.5)  # reboot p/ ROM download
r = subprocess.run(
    [sys.executable, "-m", "esptool", "--chip", "esp32s3", "--port", PORT,
     "--baud", "921600", "--before", "no-reset", "--after", "hard-reset",
     "write_flash", "0x10000", BIN])
sys.exit(r.returncode)
