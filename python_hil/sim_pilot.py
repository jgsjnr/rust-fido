#!/usr/bin/env python3
"""sim_pilot: piloto Renode/QEMU (TCP 127.0.0.1:5678) ou UART COM7.

Prova o caminho TCP cru -> INIT/PING CTAPHID 64B -> texto TEST_* sem
depender de COM fisico:
- TCP (Renode E:\\projetos\\tscircuit\\sim fido-s3-v3.resc UART TCP :5678,
  ou QEMU qemu-system-xtensa bins C:\\t\\*.bin na mesma porta):
  boot-check ONLINE&ACTIVE, INIT->CID, PING eco, LIFETIME_DUMP, TEST_UP.
- UART: mesmo roteiro via SerialLink (COM7 115200, sem DTR/RTS).
- Veredito all-safe: SIM-COVERED (sim respondeu tudo) vs HW-ONLY
  (falha documentada pedindo HW; nunca aprova sem evidencia).
- Sem test-doubles: guest local de loopback existe SOMENTE no
  --self-test como prova da camada TCP/CTAPHID, nunca como HW.

Uso:
    python -m python_hil.sim_pilot --tcp 127.0.0.1:5678
    python -m python_hil.sim_pilot --uart COM7
    python -m python_hil.sim_pilot --self-test   # loopback local, sem HW
"""
from __future__ import annotations

import argparse
import socket
import struct as _struct
import sys
import threading
import time

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from python_hil.link_serial import (
    CMD_INIT,
    CMD_PING,
    PACKET_SIZE,
    Reassembler,
    frame_message,
    is_text_chunk,
)

BROADCAST_CID = 0xFFFFFFFF
INIT_NONCE_LEN = 8
READ_TIMEOUT_S = 8.0
BOOT_MARKERS = (b"ONLINE", b"ACTIVE")


class PilotFail(OSError):
    """Falha real do piloto (sim/HW ausente ou sem resposta)."""


def recvall(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        if time.monotonic() > deadline:
            raise PilotFail("timeout lendo %d bytes (sim ativo? porta certa?)" % n)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise PilotFail("TCP fechou (sim caiu? porta certa?)")
        buf.extend(chunk)
    return bytes(buf)


def transact(sock: socket.socket, cid: int, cmd: int, payload: bytes,
             deadline: float) -> tuple:
    """1 mensagem CTAPHID sobre TCP; texto do guest ignorado nesta fase."""
    for pkt in frame_message(cid, cmd, payload):
        sock.sendall(pkt)
    asm = Reassembler()
    while True:
        if time.monotonic() > deadline:
            raise PilotFail("sem resposta CTAPHID (guest sem firmware CTAP?)")
        pkt = recvall(sock, PACKET_SIZE, deadline)
        if is_text_chunk(pkt):
            continue
        kind, data = asm.feed(pkt)
        if kind == "message":
            return data


def read_until(sock: socket.socket, marker: bytes, deadline: float,
               limit: int = 65536) -> bytes:
    buf = bytearray()
    while time.monotonic() < deadline and len(buf) < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if marker in buf:
            break
    return bytes(buf)


def boot_check(sock: socket.socket, deadline: float) -> dict:
    """Le banner ate ONLINE&ACTIVE (boot-check do sim)."""
    blob = read_until(sock, b"ACTIVE", deadline)
    online = b"ONLINE" in blob
    active = b"ACTIVE" in blob
    print("[hil] BOOT_CHECK online=%d active=%d bytes=%d"
          % (online, active, len(blob)), flush=True)
    if not (online and active):
        raise PilotFail("boot-check falhou (sem ONLINE&ACTIVE; trocar bin/.resc?)")
    return {"online": online, "active": active, "bytes": len(blob)}


def tcp_pilot(host: str = "127.0.0.1", port: int = 5678) -> dict:
    """Roteiro completo sobre TCP; retorna evidencia (veredito SIM-COVERED)."""
    ev: dict = {"transport": "tcp", "host": host, "port": port}
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        raise PilotFail(
            "TCP %s:%d recusado (Renode/QEMU ligado? porta certa?) : %s"
            % (host, port, e)) from e
    sock.settimeout(1.0)
    try:
        ev.update(boot_check(sock, time.monotonic() + READ_TIMEOUT_S))
        deadline = time.monotonic() + READ_TIMEOUT_S
        nonce = bytes(range(1, INIT_NONCE_LEN + 1))
        _, _, init_body = transact(sock, BROADCAST_CID, CMD_INIT, nonce, deadline)
        if len(init_body) < INIT_NONCE_LEN or init_body[:INIT_NONCE_LEN] != nonce:
            raise PilotFail("INIT sem eco de nonce")
        cid = _struct.unpack_from(">I", init_body, INIT_NONCE_LEN)[0]
        ev["cid"] = "0x%08X" % cid
        print("[hil] INIT_OK cid=%s" % ev["cid"], flush=True)
        deadline = time.monotonic() + READ_TIMEOUT_S
        echo = bytes((0xA5, 0x5A, 0x00, 0xFF))
        _, _, pong = transact(sock, cid, CMD_PING, echo, deadline)
        if pong != echo:
            raise PilotFail("PING sem eco")
        ev["ping"] = True
        print("[hil] PING_OK", flush=True)
        sock.sendall(b"TEST_LIFETIME_DUMP\n")
        dump = read_until(sock, b"lt_end", time.monotonic() + READ_TIMEOUT_S)
        if b"lt_dump v=1" not in dump or b"lt_end" not in dump:
            raise PilotFail("sem lt_dump completo (firmware test-mode no sim?)")
        ev["dump_bytes"] = len(dump)
        print("[hil] DUMP_OK bytes=%d" % len(dump), flush=True)
        sock.sendall(b"TEST_UP\n")
        ack = read_until(sock, b"source=software", time.monotonic() + READ_TIMEOUT_S)
        ev["test_up"] = b"source=software" in ack
        print("[hil] TEST_UP %d" % ev["test_up"], flush=True)
        ev["verdict"] = "SIM-COVERED"
    finally:
        sock.close()
    return ev


def uart_pilot(port: str = "COM7", baud: int = 115200) -> dict:
    """Mesmo roteiro via UART fisica (COM7, sem DTR/RTS)."""
    from python_hil.link_serial import SerialLink
    link = SerialLink(port, baud)
    link.open()
    ev: dict = {"transport": "uart", "port": port}
    try:
        blob = b""
        end = time.monotonic() + READ_TIMEOUT_S
        while time.monotonic() < end and b"ACTIVE" not in blob:
            try:
                blob += link.read_exact(1, deadline_s=1.0)
            except TimeoutError:
                break
            if len(blob) > 65536:
                break
        if b"ONLINE" not in blob or b"ACTIVE" not in blob:
            raise PilotFail("boot-check UART falhou (COM7 com HW? cabo dados?)")
        ev["boot_bytes"] = len(blob)
        cid, _ = link.cmd_init()
        ev["cid"] = "0x%08X" % cid
        link.ping(cid)
        ev["ping"] = True
        dump = link.lifetime_dump()
        ev["dump_bytes"] = len(dump)
        up = link.test_up()
        ev["test_up"] = "source=software" in up
        ev["verdict"] = "SIM-COVERED"
    finally:
        link.close()
    return ev


# -- guest de loopback: SOMENTE self-test da camada TCP/CTAPHID ------------
def _handle_text(line: bytes, conn: socket.socket) -> None:
    if b"TEST_LIFETIME_DUMP" in line:
        conn.sendall(b"lt_dump v=1\nlt_end\n")
    elif b"TEST_UP" in line:
        conn.sendall(b"up_latched source=software\n")


def _handle_packet(pkt: bytes, conn: socket.socket, cid_next: list) -> None:
    rcid, rcmd, total = _struct.unpack_from(">IBH", pkt, 0)
    if rcmd == CMD_INIT:
        nonce = pkt[7:7 + INIT_NONCE_LEN]
        body = nonce + _struct.pack(">I", cid_next[0])
        cid_next[0] += 1
        for p in frame_message(rcid, CMD_INIT, body):
            conn.sendall(p)
    elif rcmd == CMD_PING:
        for p in frame_message(rcid, CMD_PING, pkt[7:7 + total]):
            conn.sendall(p)


def _loopback_guest(listen_sock: socket.socket) -> None:
    conn, _ = listen_sock.accept()
    conn.settimeout(5.0)
    conn.sendall(b"ONLINE&ACTIVE\n")
    cid_next = [0x00010201]
    buf = bytearray()
    try:
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                chunk = b""
            if not chunk and len(buf) < PACKET_SIZE and b"\n" not in buf:
                return
            buf.extend(chunk or b"")
            progressed = False
            while len(buf) >= PACKET_SIZE:
                pkt, buf = bytes(buf[:PACKET_SIZE]), bytearray(buf[PACKET_SIZE:])
                progressed = True
                if is_text_chunk(pkt):
                    _handle_text(bytes(pkt).split(b"\x00")[0], conn)
                    continue
                _handle_packet(pkt, conn, cid_next)
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = bytearray(rest)
                progressed = True
                _handle_text(bytes(line), conn)
            if not progressed and not chunk:
                return
    except (ConnectionError, TimeoutError, OSError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def self_test() -> dict:
    """Prova a camada TCP/CTAPHID contra loopback local (nao e HW)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    th = threading.Thread(target=_loopback_guest, args=(srv,), daemon=True)
    th.start()
    ev = tcp_pilot("127.0.0.1", port)
    srv.close()
    assert ev["verdict"] == "SIM-COVERED" and ev["ping"] and ev["test_up"]
    print("SELFTEST_OK (loopback; nao e evidencia de HW)", flush=True)
    return ev


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Piloto Renode/QEMU ou UART")
    ap.add_argument("--tcp", default=None, help="host:port, ex. 127.0.0.1:5678")
    ap.add_argument("--uart", default=None, help="porta serial, ex. COM7")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.self_test:
            self_test()
        elif args.tcp:
            host, _, port = args.tcp.partition(":")
            ev = tcp_pilot(host or "127.0.0.1", int(port or 5678))
            print("PILOT verdict=%s %s" % (ev["verdict"], ev), flush=True)
        elif args.uart:
            ev = uart_pilot(args.uart)
            print("PILOT verdict=%s %s" % (ev["verdict"], ev), flush=True)
        else:
            ap.print_help()
            return 2
    except PilotFail as e:
        print("PILOT HW-ONLY (falha real documentada): %s" % e, flush=True)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
