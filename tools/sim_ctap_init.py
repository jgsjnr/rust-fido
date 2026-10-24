"""Sonda CTAPHID + TEST via UART virtual do QEMU (TCP; sem COM).

Uso: python tools/sim_ctap_init.py [host] [port]
     python tools/sim_ctap_init.py --self-test   (guest falso local; prova framing/parse TCP)

Prova o caminho: TCP cru -> INIT/PING CTAPHID 64B -> texto TEST_LIFETIME_DUMP/TEST_UP.
Nao usa Session (COM port); fala socket direto com a UART virtual do QEMU.
ASCII puro. Sem segredos. Guest real: validacao pendente (QEMU sem output
interativo nesta bancada); --self-test prova a camada TCP/CTAPHID.
"""
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, "tools")
from app_simulator import (  # noqa: E402
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


def recvall(sock, n, deadline):
    buf = bytearray()
    while len(buf) < n:
        if time.monotonic() > deadline:
            raise TimeoutError("timeout lendo %d bytes" % n)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("TCP fechou")
        buf.extend(chunk)
    return bytes(buf)


def transact(sock, cid, cmd, payload, deadline):
    """Envia 1 mensagem CTAPHID e retorna (resp_cid, resp_cmd, resp_payload)."""
    for pkt in frame_message(cid, cmd, payload):
        sock.sendall(pkt)
    reasm = Reassembler()
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("sem resposta CTAPHID")
        pkt = recvall(sock, PACKET_SIZE, deadline)
        if is_text_chunk(pkt):
            continue  # log do guest; ignora nesta fase
        kind, data = reasm.feed(pkt)
        if kind == "message":
            return data
        # keepalive/more: segue lendo


def read_until(sock, marker, deadline, limit=65536):
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


def tcp_probe(host="127.0.0.1", port=5678):
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(1.0)
    try:
        deadline = time.monotonic() + READ_TIMEOUT_S
        nonce = bytes(range(1, INIT_NONCE_LEN + 1))
        _, _, init_body = transact(sock, BROADCAST_CID, CMD_INIT, nonce, deadline)
        if len(init_body) < INIT_NONCE_LEN or init_body[:INIT_NONCE_LEN] != nonce:
            raise ValueError("INIT sem eco de nonce")
        cid = struct.unpack_from(">I", init_body, INIT_NONCE_LEN)[0]
        print("QEMU INIT_OK cid=0x%08X" % cid, flush=True)
        deadline = time.monotonic() + READ_TIMEOUT_S
        echo = bytes([0xA5, 0x5A, 0x00, 0xFF])
        _, _, pong = transact(sock, cid, CMD_PING, echo, deadline)
        if pong != echo:
            raise ValueError("PING sem eco")
        print("QEMU PING_OK", flush=True)
        sock.sendall(b"TEST_LIFETIME_DUMP\n")
        dump = read_until(sock, b"lt_end", time.monotonic() + READ_TIMEOUT_S)
        if b"lt_dump v=1" not in dump or b"lt_end" not in dump:
            raise ValueError("sem lt_dump completo")
        print("QEMU DUMP_OK bytes=%d" % len(dump), flush=True)
        sock.sendall(b"TEST_UP\n")
        ack = read_until(sock, b"source=software", time.monotonic() + READ_TIMEOUT_S)
        print("QEMU TEST_UP: %s" % ("1" if b"source=software" in ack else "0"), flush=True)
    finally:
        sock.close()
    print("SIM_CTAP_OK", flush=True)


def _handle_text(line, conn):
    if b"TEST_LIFETIME_DUMP" in line:
        conn.sendall(b"lt_dump v=1\nlt_end\n")
    elif b"TEST_UP" in line:
        conn.sendall(b"up_latched source=software\n")


def _handle_packet(pkt, conn, cid_next):
    rcid, rcmd, total = struct.unpack_from(">IBH", pkt, 0)
    if rcmd == CMD_INIT:
        nonce = pkt[7:7 + INIT_NONCE_LEN]
        body = nonce + struct.pack(">I", cid_next[0])
        cid_next[0] += 1
        for p in frame_message(rcid, CMD_INIT, body):
            conn.sendall(p)
    elif rcmd == CMD_PING:
        for p in frame_message(rcid, CMD_PING, pkt[7:7 + total]):
            conn.sendall(p)


def _fake_guest(listen_sock, ready):
    """Guest minimo: INIT->CID novo, PING->eco, texto TEST_*->acks."""
    conn, _ = listen_sock.accept()
    conn.settimeout(5.0)
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


def self_test():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    ready = threading.Event()
    th = threading.Thread(target=_fake_guest, args=(srv, ready), daemon=True)
    th.start()
    tcp_probe("127.0.0.1", port)
    srv.close()
    print("SELFTEST_OK", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
    else:
        host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 5678
        tcp_probe(host, port)
