"""Leitor TCP do QEMU: despeja bytes crus por N segundos."""
import socket, sys, time
host, port, secs = "127.0.0.1", 5678, int(sys.argv[1]) if len(sys.argv) > 1 else 30
s = socket.create_connection((host, port), timeout=5)
s.settimeout(0.5)
t0 = time.monotonic()
buf = bytearray()
while time.monotonic() - t0 < secs:
    try:
        b = s.recv(4096)
        if b:
            buf.extend(b)
    except socket.timeout:
        pass
s.close()
print("TCP bytes:", len(buf))
txt = bytes(buf)
print("HEAD:", txt[:600])
for kw in [b"panic", b"Guru", b"abort", b"assert failed", b"FREERTOS", b"scheduler",
           b"test-mode", b"stack overflow", b"LoadProhibited", b"entry 0x",
           b"Flash Size", b"End of partition", b"segment", b"rst:"]:
    i = txt.find(kw)
    if i != -1:
        print("HIT", kw, ":", txt[max(0, i - 40):i + 120][:160])
open(r"C:\t\qemu-tcp-boot.log", "wb").write(txt)
print("saved C:/t/qemu-tcp-boot.log")
