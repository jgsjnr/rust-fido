"""Sonda CTAPHID + TEST via UART virtual do QEMU (TCP; sem COM).

Uso: python tools/sim_ctap_init.py [host] [port]
Prova o caminho: TCP -> SerialLink -> INIT/PING/TEST_LIFETIME_DUMP.
"""
import socket
import struct
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import Session, frame_message, CMD_CBOR  # noqa: E402


def tcp_probe(host="127.0.0.1", port=5678):
    s = Session("http://localhost", test_mode=True)
    s.connect("tcp://%s:%d" % (host, port), 115200)
    time.sleep(1.0)
    dump = s.lifetime_dump(timeout_s=8.0)
    print("QEMU DUMP_OK bytes=%d" % len(dump))
    up = s.test_up(timeout_s=8.0)
    print("QEMU TEST_UP:", up)
    s.close()
    print("SIM_CTAP_OK", flush=True)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5678
    tcp_probe(host, port)
