#!/usr/bin/env python3
"""Le ground-truth do LED e testa primarias (usuario confirma cores)."""
import sys, time
sys.path.insert(0, "tools")
from app_simulator import Session

sess = Session("http://127.0.0.1:8888", test_mode=True)
sess.connect("COM7", 115200)

def cmd(line, timeout_s=6.0):
    text = sess.send_text_line(line, timeout_s=timeout_s)
    print(">>> %s" % line)
    for ln in text.splitlines():
        s = ln.strip()
        if s and ("led_" in s or "pairing_open" in s or "lt_" in s):
            print("    " + s[:200])
    return text

time.sleep(3)  # boot
cmd("TEST_LED_STATE")
for c in ("TEST_LED_RED", "TEST_LED_GREEN", "TEST_LED_BLUE", "TEST_LED_OFF"):
    cmd(c)
    time.sleep(2)
cmd("TEST_LED_RELEASE")
cmd("TEST_LED_STATE")
sess.close()
print("Solicite ao usuario: o que apareceu em RED/GREEN/BLUE/OFF?")
