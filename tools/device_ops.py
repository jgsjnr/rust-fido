#!/usr/bin/env python3
"""Operacoes de placa ESP32-S3 via Python (sem BOOT fisico).

Uso:
  python tools/device_ops.py flash [--port COM7] [--app C:/t/app.bin]
  python tools/device_ops.py verify [--port COM7] [--app C:/t/app.bin]
  python tools/device_ops.py boot-check [--port COM7] [--secs 25]
  python tools/device_ops.py health [--port COM7]
  python tools/device_ops.py read-mac [--port COM7]
  python tools/device_ops.py flash-id [--port COM7]
  python tools/device_ops.py reset [--port COM7]
  python tools/device_ops.py backup --out C:/t/backup.bin [--port COM7]

Regras (docs/bateria-serial.md):
- --before default_reset funciona (DTR/RTS OK); NUNCA pedir BOOT fisico.
- Somente leitura/escrita de app/bootloader/PT/NVS via esptool.
  PROIBIDO: burn/write eFuse, secure boot, flash encryption.
- Identificar a placa pelo MAC (read-mac), nunca confiar so na COM.

Retorno: exit 0 = ok; exit 1 = falha operacional; exit 2 = placa em loop/panic.
"""

import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from app_simulator import SerialLink  # noqa: E402

EMBUILD_ESPTOOL = ("C:/.embuild/espressif/python_env/idf5.3_py3.12_env/"
                   "Scripts/esptool.exe")
DEFAULT_APP = "C:/t/aegis-app-freertos-s3-testmode.bin"
BAUD_FLASH = "460800"
BAUD_ID = "115200"


def find_esptool():
    """Localiza o esptool: .embuild primeiro, fallback python -m."""
    if os.path.exists(EMBUILD_ESPTOOL):
        return [EMBUILD_ESPTOOL]
    return [sys.executable, "-m", "esptool"]


def esptool(args, timeout=300):
    cmd = find_esptool() + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def cmd_flash(port, app):
    if not os.path.exists(app):
        print("ERRO: app nao encontrado: %s" % app)
        return 1
    print("FLASH %s -> %s (sem BOOT, via DTR/RTS)" % (app, port))
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       BAUD_FLASH, "--before", "default_reset", "--after",
                       "no_reset", "write_flash", "0x10000", app])
    print(out[-1500:])
    if rc != 0 or "Hash of data verified" not in out:
        print("FALHA no write_flash")
        return 1
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       BAUD_FLASH, "--before", "no_reset", "--after",
                       "hard_reset", "verify_flash", "0x10000", app])
    print(out[-500:])
    if rc != 0 or "verify OK" not in out:
        print("FALHA no verify")
        return 1
    print("FLASH OK + verificado (app resetado em seguida).")
    return 0


def cmd_verify(port, app):
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       BAUD_FLASH, "--before", "no_reset", "--after",
                       "no_reset", "verify_flash", "0x10000", app])
    print(out[-500:])
    if rc == 0 and "verify OK" in out:
        print("VERIFY OK")
        return 0
    print("VERIFY FALHOU (digest mismatch ou sem download mode)")
    return 1


def cmd_boot_check(port, secs=25):
    """Aguarda boot e classifica: ONLINE / loop / panic / mudo."""
    link = SerialLink(port, 115200, timeout_ms=200)
    try:
        link.open()
    except OSError as e:
        print("ERRO ao abrir %s: %s" % (port, e))
        return 1
    time.sleep(0.5)
    buf = bytearray()
    t0 = time.monotonic()
    while time.monotonic() - t0 < secs:
        try:
            b = link._read_some(1024)
        except Exception:
            b = b""
        if b:
            buf.extend(b)
    link.close()
    txt = bytes(buf)
    boots = txt.count(b"Calling app_main")
    online = b"ONLINE & ACTIVE" in txt
    panic = (b"Guru Meditation" in txt or b"stack overflow" in txt
             or b"panic'ed" in txt or b"Backtrace:" in txt)
    print("bytes=%d boots=%d online=%s panic=%s"
          % (len(txt), boots, online, panic))
    head = txt[:300].replace(b"\r", b"").decode("ascii", "replace")
    print("HEAD: %s" % head[:200])
    if panic:
        print("RESULTADO: PANIC/LOOP (ver log acima)")
        return 2
    if boots > 2:
        print("RESULTADO: REBOOT LOOP (%d boots em %ds)" % (boots, secs))
        return 2
    if online:
        print("RESULTADO: ONLINE e estavel")
        return 0
    if boots >= 1:
        print("RESULTADO: bootou mas sem ONLINE (verificar)")
        return 1
    print("RESULTADO: MUDA (0 bytes: placa em download ou sem firmware?)")
    return 1


def cmd_health(port):
    """Handshake TEST: UP + LED state + lifetime dump (resumo)."""
    link = SerialLink(port, 115200, timeout_ms=1000)
    try:
        link.open()
    except OSError as e:
        print("ERRO ao abrir %s: %s" % (port, e))
        return 1
    time.sleep(0.3)
    try:
        link.flush_input()
    except Exception:
        pass
    ok = True
    link.write(b"TEST_UP\n")
    time.sleep(0.8)
    try:
        up = link._read_some(64)
    except Exception:
        up = b""
    print("TEST_UP: %r" % bytes(up)[:60])
    ok = ok and b"up_latched" in bytes(up)
    link.write(b"TEST_LED_STATE\n")
    time.sleep(0.8)
    try:
        led = link._read_some(256)
    except Exception:
        led = b""
    print("TEST_LED_STATE: %r" % bytes(led)[:120])
    ok = ok and b"led_state" in bytes(led)
    link.write(b"TEST_LIFETIME_DUMP\n")
    t0 = time.monotonic()
    dump = bytearray()
    while time.monotonic() - t0 < 8.0:
        try:
            b = link._read_some(512)
        except Exception:
            b = b""
        if b:
            dump.extend(b)
        if b"lt_end" in bytes(dump):
            break
    print("LIFETIME_DUMP bytes=%d" % len(dump))
    ok = ok and b"lt_dump v=1" in bytes(dump)
    link.close()
    print("RESULTADO: %s" % ("SAUDAVEL" if ok else "FALHA (ver acima)"))
    return 0 if ok else 1


def cmd_read_mac(port):
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       BAUD_ID, "--before", "default_reset", "--after",
                       "hard_reset", "read_mac"])
    print(out[-600:])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("MAC:"):
            print("IDENTIDADE: %s" % line)
            return 0
    return 1


def cmd_flash_id(port):
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       BAUD_ID, "--before", "default_reset", "--after",
                       "hard_reset", "flash_id"])
    print(out[-800:])
    return 0 if rc == 0 else 1


def cmd_reset(port):
    """Sai do download e boota o app (hard reset via RTS; sem BOOT)."""
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       BAUD_ID, "--before", "no_reset", "--after",
                       "hard_reset", "chip_id"])
    print(out[-300:])
    return 0 if rc == 0 else 1


def cmd_backup(port, out_path):
    print("BACKUP 16MB %s -> %s (so leitura)" % (port, out_path))
    rc, out = esptool(["--chip", "esp32s3", "--port", port, "--baud",
                       "921600", "--before", "default_reset", "--after",
                       "no_reset", "read_flash", "0x0", "0x1000000",
                       out_path])
    print(out[-300:])
    if rc == 0 and os.path.exists(out_path):
        size = os.path.getsize(out_path)
        print("backup bytes=%d %s" % (size, "OK" if size == 16777216 else "INCOMPLETO"))
        return 0 if size == 16777216 else 1
    print("FALHA no backup")
    return 1


def usage():
    print(__doc__)
    return 2


def main(argv):
    if len(argv) < 2:
        return usage()
    cmd = argv[1]
    port = "COM7"
    app = DEFAULT_APP
    secs = 25
    out_path = None
    i = 2
    while i < len(argv):
        if argv[i] == "--port" and i + 1 < len(argv):
            port = argv[i + 1]
            i += 2
        elif argv[i] == "--app" and i + 1 < len(argv):
            app = argv[i + 1]
            i += 2
        elif argv[i] == "--secs" and i + 1 < len(argv):
            secs = int(argv[i + 1])
            i += 2
        elif argv[i] == "--out" and i + 1 < len(argv):
            out_path = argv[i + 1]
            i += 2
        else:
            i += 1
    if cmd == "flash":
        return cmd_flash(port, app)
    if cmd == "verify":
        return cmd_verify(port, app)
    if cmd == "boot-check":
        return cmd_boot_check(port, secs)
    if cmd == "health":
        return cmd_health(port)
    if cmd == "read-mac":
        return cmd_read_mac(port)
    if cmd == "reset":
        return cmd_reset(port)
    if cmd == "flash-id":
        return cmd_flash_id(port)
    if cmd == "backup":
        if not out_path:
            print("ERRO: informe --out <arquivo>")
            return 2
        return cmd_backup(port, out_path)
    return usage()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
