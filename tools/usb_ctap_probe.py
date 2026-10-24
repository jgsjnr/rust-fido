"""Sonda CTAPHID crua sobre USB com pyusb (U2; leitura/handshake apenas).

Uso: python tools/usb_ctap_probe.py --self-test   (fake local; nunca toca USB)
     python tools/usb_ctap_probe.py --live        (pyusb real: enumera, INIT, PING)

Sem --live, NUNCA toca em USB real (default = fake). --live faz somente
leitura/handshake: enumera (VID/PID/serial), INIT (broadcast CID + nonce),
PING (CID novo + eco), fecha. Nenhuma escrita NVS/claim persistente.
ASCII puro. Sem segredos.
"""
import queue
import struct
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import (
    CMD_INIT,
    CMD_PING,
    PACKET_SIZE,
    Reassembler,
    frame_message,
    is_text_chunk,
)

USB_VID = 0x303A
USB_PID = 0xAE61
BROADCAST_CID = 0xFFFFFFFF
INIT_NONCE_LEN = 8
READ_TIMEOUT_S = 5.0


class FakeUsb:
    """Backend falso: INIT -> CID novo + eco de nonce; PING -> eco."""

    def __init__(self):
        self.q = queue.Queue()
        self.reasm = Reassembler()
        self.cid_next = 0x00010201

    def write_64(self, pkt):
        assert len(pkt) == PACKET_SIZE, len(pkt)
        kind, data = self.reasm.feed(bytes(pkt))
        if kind != "message":
            return
        cid, cmd, payload = data
        if cmd == CMD_INIT:
            nonce = payload[:INIT_NONCE_LEN]
            body = nonce + struct.pack(">I", self.cid_next)
            self.cid_next += 1
            for p in frame_message(cid, CMD_INIT, body):
                self.q.put(p)
        elif cmd == CMD_PING:
            for p in frame_message(cid, CMD_PING, payload):
                self.q.put(p)

    def read_64(self, timeout=READ_TIMEOUT_S):
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("fake usb sem resposta")

    def close(self):
        pass


class PyUsbTransport:
    """Backend real pyusb: bulk/HID OUT+IN. Somente leitura/handshake."""

    def __init__(self, vid=USB_VID, pid=USB_PID):
        self.vid = vid
        self.pid = pid
        self.dev = None
        self.ep_out = None
        self.ep_in = None

    def describe(self):
        try:
            serial = self.dev.serial_number
        except Exception:
            serial = "?"
        return "VID=%04X PID=%04X serial=%s" % (self.vid, self.pid, serial)

    def open(self):
        import usb.core
        import usb.util

        self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.dev is None:
            raise OSError("USB %04X:%04X nao encontrado (cabo dados? driver?)" % (self.vid, self.pid))
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except Exception:
            pass
        try:
            self.dev.set_configuration()
        except Exception:
            pass
        cfg = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
        out = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        inp = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        if out is None or inp is None:
            raise OSError("endpoints bulk/HID OUT+IN nao encontrados")
        self.ep_out = out
        self.ep_in = inp

    def write_64(self, pkt):
        assert len(pkt) == PACKET_SIZE, len(pkt)
        self.ep_out.write(bytes(pkt), timeout=int(READ_TIMEOUT_S * 1000))

    def read_64(self, timeout=READ_TIMEOUT_S):
        data = bytes(self.ep_in.read(PACKET_SIZE, timeout=int(timeout * 1000)))
        if len(data) != PACKET_SIZE:
            raise OSError("leitura USB curta: %d bytes" % len(data))
        return data

    def close(self):
        try:
            if self.dev is not None:
                import usb.util

                usb.util.dispose_resources(self.dev)
        finally:
            self.dev = None


def transact(link, cid, cmd, payload, timeout=READ_TIMEOUT_S):
    for pkt in frame_message(cid, cmd, payload):
        link.write_64(pkt)
    reasm = Reassembler()
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("sem resposta CTAPHID")
        pkt = link.read_64(timeout=max(0.1, deadline - time.monotonic()))
        if is_text_chunk(pkt):
            continue
        kind, data = reasm.feed(pkt)
        if kind == "message":
            return data


def probe(link):
    nonce = bytes(range(1, INIT_NONCE_LEN + 1))
    _, _, init_body = transact(link, BROADCAST_CID, CMD_INIT, nonce)
    if len(init_body) < INIT_NONCE_LEN or init_body[:INIT_NONCE_LEN] != nonce:
        raise ValueError("INIT sem eco de nonce")
    cid = struct.unpack_from(">I", init_body, INIT_NONCE_LEN)[0]
    print("USB_INIT_OK cid=0x%08X" % cid, flush=True)
    echo = bytes([0xA5, 0x5A, 0x00, 0xFF])
    _, _, pong = transact(link, cid, CMD_PING, echo)
    if pong != echo:
        raise ValueError("PING sem eco")
    print("USB_PING_OK", flush=True)
    return cid


def self_test():
    link = FakeUsb()
    probe(link)
    print("USB_PROBE_OK", flush=True)


def live():
    try:
        import usb.core  # noqa: F401
    except ImportError:
        print("ERRO: pyusb ausente (pip install pyusb); sem fingir", flush=True)
        sys.exit(2)
    t = PyUsbTransport()
    try:
        t.open()
    except OSError as e:
        print("ERRO: %s" % str(e)[:120], flush=True)
        sys.exit(3)
    print("USB_ENUM %s" % t.describe(), flush=True)
    try:
        probe(t)
    finally:
        t.close()
    print("USB_PROBE_OK", flush=True)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    elif "--live" in sys.argv:
        live()
    else:
        self_test()