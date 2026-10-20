#!/usr/bin/env python3
"""Wave7 - AegisKey app simulator (terminal, stdlib only).

Simulates the Android app over two transports (same contract as the app):

- Serial UART: CTAPHID 64-byte packets (existing framing, reused byte-identical
  to USB: INIT/CONT, CID allocation, keepalive, CBOR status) for GetInfo (0x04),
  MakeCredential (0x01), GetAssertion (0x02), ClientPIN (0x06) and the Fase6
  vendor ops KEY (0x20-0x27) / OATH APDUs. Raw CBOR/TLV hex dev flow, exactly
  like Accounts/Auth screens (the transport frames; it never interprets secrets).
- HTTP (device AP, default http://192.168.4.1): POST /ctap (AEGN envelope),
  POST /config/wifi (UP+PIN), GET /oath/code?account= (code only, never secret)
  - the same routes WifiApi.kt uses.

Same rule as the app: privileged ops (MakeCredential, PIN set, KEY gen/delete,
OATH put/delete, WiFi config) require the device in pairing-mode. Pairing is a
physical hold-5s on BOOT opening a 60s window (PAIRING_WINDOW_SECS); the
simulator tracks the window locally after you confirm the hold in menu 9.

TEST MODE (--test-mode): only useful against firmware built with `test-mode`;
adds the TEST_LIFETIME_DUMP diagnostic (counters/states, no secrets) and, on
connect, verifies the device answers the dump command. Without the flag the
simulator behaves exactly like the app.

Privacy: logs carry event names, ids/labels and byte COUNTS only - payload hex
is never printed (mirrors SanitizedLog).

Device-side notes:
- TEST_LIFETIME_DUMP is answered by firmware with `test-mode` (text line over
  the same serial link; host bridge reads stdin, ESP-IDF polls UART RX lines).
- Serial CTAPHID bytes route into CtapHidManager / vendor dispatch on the
  device (firmware `serial_ctaphid`, same 64B framing, pairing-mode + UP
  gates); heartbeat text stays outside the framing and is ignored mid-exchange.

Usage:
  python tools/app_simulator.py [--port COM7] [--baud 115200]
      [--ap-base http://192.168.4.1] [--test-mode] [--demo]
  python tools/app_simulator.py --self-test   # offline checks, no hardware
"""
import argparse
import base64
import getpass
import glob
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

PACKET_SIZE = 64
INIT_PAYLOAD_MAX = 57
CONT_PAYLOAD_MAX = 59

CMD_INIT = 0x86
CMD_MSG = 0x83
CMD_CBOR = 0x90
CMD_PING = 0x81  # wire value already carries the INIT bit
CMD_KEEPALIVE = 0xBB
CMD_CANCEL = 0xBE | 0x80
CMD_WINK = 0x88

CTAP_CMD_MAKE_CREDENTIAL = 0x01
CTAP_CMD_GET_ASSERTION = 0x02
CTAP_CMD_GET_INFO = 0x04
CTAP_CMD_CLIENT_PIN = 0x06

STATUS_KEEPALIVE_PROCESSING = 0x01
STATUS_KEEPALIVE_UP_NEEDED = 0x02

PAIRING_WINDOW_SECS = 60
TEST_DUMP_CMD = "TEST_LIFETIME_DUMP"
TEST_PAIRING_OPEN_CMD = "TEST_PAIRING_OPEN"
TEST_UP_CMD = "TEST_UP"

# Fase6 vendor ops (BLE appendix 9, frozen range 0x20-0x27).
OP_KEY_GEN = 0x20
OP_KEY_IMPORT = 0x21
OP_KEY_LIST = 0x22
OP_KEY_DELETE = 0x23
OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27

VENDOR_OPS = {
    OP_KEY_GEN: "KEY_GEN", OP_KEY_IMPORT: "KEY_IMPORT", OP_KEY_LIST: "KEY_LIST",
    OP_KEY_DELETE: "KEY_DELETE", OP_OATH_PUT: "OATH_PUT", OP_OATH_LIST: "OATH_LIST",
    OP_OATH_CODE: "OATH_CODE", OP_OATH_DELETE: "OATH_DELETE",
}

PRIVILEGED = {
    "make_credential", "pin_set", "pin_change", "key_gen", "key_import",
    "key_delete", "oath_put", "oath_delete", "wifi_config",
}

LOG_EVENTS = []


def log_event(name, detail=""):
    """Sanitized log: fixed event names + counts/labels only, never payloads."""
    LOG_EVENTS.append((time.time(), name, detail))
    suffix = " " + detail if detail else ""
    print("[log] %s%s" % (name, suffix))


# ---------------------------------------------------------------------------
# CTAPHID 64B framing over a byte stream (same layout as USB, minus USB).
# ---------------------------------------------------------------------------

def frame_message(cid, cmd, payload):
    """Split payload into 64B INIT/CONT packets. Returns list of bytes."""
    total = len(payload)
    if total > 0xFFFF:
        raise ValueError("payload too large")
    first = payload[:INIT_PAYLOAD_MAX]
    pkt = bytearray(PACKET_SIZE)
    struct.pack_into(">IBH", pkt, 0, cid, cmd, total)
    pkt[7:7 + len(first)] = first
    out = [bytes(pkt)]
    seq = 0
    off = len(first)
    while off < total:
        chunk = payload[off:off + CONT_PAYLOAD_MAX]
        pkt = bytearray(PACKET_SIZE)
        struct.pack_into(">IB", pkt, 0, cid, seq)
        pkt[5:5 + len(chunk)] = chunk
        out.append(bytes(pkt))
        off += len(chunk)
        seq = (seq + 1) & 0xFF
    return out


def parse_init_header(pkt):
    """Parse a 64B INIT packet header -> (cid, cmd, total_len)."""
    if len(pkt) != PACKET_SIZE:
        raise ValueError("bad packet size")
    cid, cmd, total = struct.unpack_from(">IBH", pkt, 0)
    if not (cmd & 0x80):
        raise ValueError("not an INIT packet")
    if total > 0xFFFF:
        raise ValueError("bad length")
    return cid, cmd, total


def is_text_chunk(pkt):
    """Mirror of firmware `is_text_line` (serial_ctaphid.rs).

    True when a 64B chunk looks like log/heartbeat text: at least one
    non-NUL byte and every non-NUL byte printable ASCII or tab/CR/LF.
    Binary CTAPHID packets carry CIDs/lengths/CBOR outside that range,
    so real packets never match; a pathological all-printable packet
    would be skipped once (caller retries, same contract as firmware).
    """
    if len(pkt) != PACKET_SIZE:
        return False
    seen = False
    for b in pkt:
        if b == 0x00:
            continue
        seen = True
        if not (b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E):
            return False
    return seen


class Reassembler:
    """Reassemble INIT/CONT packets; surfaces keepalive status bytes."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.cid = None
        self.cmd = None
        self.total = 0
        self.buf = bytearray()
        self.seq = 0

    def feed(self, pkt):
        """Feed one 64B packet. Returns (kind, data):
        ('keepalive', status) | ('text', None) | ('message', (cid, cmd, payload)) | ('more', None)."""
        if len(pkt) != PACKET_SIZE:
            raise ValueError("bad packet size")
        if is_text_chunk(pkt):
            return ("text", None)
        cid, raw, total = struct.unpack_from(">IBH", pkt, 0)
        if raw == CMD_KEEPALIVE:
            return ("keepalive", pkt[7])
        if raw & 0x80:
            if total > 512:
                raise ValueError("overflow control-point")
            self.cid, self.cmd, self.total = cid, raw, total
            self.buf = bytearray(pkt[7:7 + min(total, INIT_PAYLOAD_MAX)])
            self.seq = 0
        else:
            if self.cid is None or cid != self.cid:
                raise ValueError("unexpected continuation")
            self.buf.extend(pkt[5:5 + CONT_PAYLOAD_MAX])
            self.seq = (self.seq + 1) & 0xFF
        if len(self.buf) >= self.total and self.cid is not None:
            msg = (self.cid, self.cmd, bytes(self.buf[:self.total]))
            self.reset()
            return ("message", msg)
        return ("more", None)


MIN_TEXT_LINE = 8  # text fast-path: shorter printable runs stay binary (0x0A in headers/CBOR)


class SerialStreamReader:
    """Byte-stream demux: text lines vs 64B CTAPHID frames on one wire.

    The device emits variable-length heartbeat/log lines (LF-terminated)
    on the same UART as fixed 64B binary packets, so fixed 64B reads
    misalign after every text line. This reader accumulates bytes,
    strips LF-terminated printable text lines, and yields the next 64B
    non-text frame. A frame that still fails to parse is returned to
    the caller, which drops one byte and retries (sliding resync).
    """
    def __init__(self, link):
        self.link = link
        self.buf = bytearray()

    def _is_text_line(self, raw):
        if not raw or b"\x00" in raw:
            return False
        return all(b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E for b in raw)

    def next_frame(self, deadline_s=2.0):
        """Return the next 64B frame, skipping interleaved text lines."""
        while True:
            nl = self.buf.find(b"\n")
            if nl + 1 >= MIN_TEXT_LINE and self._is_text_line(bytes(self.buf[:nl + 1])):
                log_event("SERIAL_TEXT_SKIPPED", "bytes=%d" % (nl + 1))
                del self.buf[:nl + 1]
                continue
            if len(self.buf) >= PACKET_SIZE:
                frame = bytes(self.buf[:PACKET_SIZE])
                if is_text_chunk(frame):
                    log_event("SERIAL_TEXT_SKIPPED", "bytes=%d" % PACKET_SIZE)
                    del self.buf[:PACKET_SIZE]
                    continue
                del self.buf[:PACKET_SIZE]
                return frame
            self.buf.extend(self.link.read_exact(1, deadline_s=deadline_s))
            if len(self.buf) > 4096:
                raise ValueError("serial stream desync (buffer overflow)")


def parse_ctap_response(payload):
    """Split CTAP response into (status, body)."""
    if not payload:
        raise ValueError("empty response")
    return payload[0], payload[1:]


def parse_dump(text):
    """Parse a TEST_LIFETIME_DUMP body into {name: count} + [state lines]."""
    counts = {}
    states = []
    lines = text.replace("\r", "").split("\n")
    if not lines or lines[0].strip() != "lt_dump v=1":
        raise ValueError("bad dump header")
    if lines[-1].strip() == "":
        lines = lines[:-1]
    if not lines or lines[-1].strip() != "lt_end":
        raise ValueError("bad dump footer")
    for line in lines[1:-1]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("lt.state "):
            states.append(line[len("lt.state "):])
        elif line.startswith("lt.") and "=" in line:
            name, val = line.split("=", 1)
            counts[name] = int(val)
        else:
            raise ValueError("bad dump line: %r" % line[:32])
    return counts, states


def validate_oath_json(body):
    """Validate a GET /oath/code JSON body (code only, never the secret)."""
    data = json.loads(body)
    account = data.get("account", "")
    code = data.get("code", "")
    remaining = data.get("remaining_seconds", -1)
    if not account or len(account) > 128:
        raise ValueError("bad account")
    if len(code) not in (6, 7, 8) or not code.isdigit():
        raise ValueError("bad code format")
    if not (0 <= remaining <= 30):
        raise ValueError("bad remaining_seconds")
    return account, code, remaining


def validate_aegn_envelope(raw):
    """Local AEGN envelope check (magic + version + min length)."""
    if len(raw) < 33 or raw[0:4] != b"AEGN" or raw[4] != 0x01:
        raise ValueError("invalid AEGN envelope")
    return len(raw) - 17


def wifi_password_valid(pw):
    return 8 <= len(pw) <= 63 and all(ord(c) < 128 for c in pw)


def parse_hex_even(text):
    clean = "".join(text.split())
    if len(clean) % 2 != 0 or not clean:
        raise ValueError("bad hex (need even length)")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        raise ValueError("bad hex digits")


# ---------------------------------------------------------------------------
# Serial link (stdlib only): Win32 COM via ctypes, POSIX via termios.
# ---------------------------------------------------------------------------

def list_serial_ports():
    ports = []
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM")
            i = 0
            while True:
                try:
                    _, data, _ = winreg.EnumValue(key, i)
                    ports.append(str(data))
                    i += 1
                except OSError:
                    break
        except Exception:
            pass
        if not ports:
            for n in range(1, 17):
                ports.append("COM%d" % n)
    else:
        for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*", "/dev/ttyS*"):
            ports.extend(sorted(glob.glob(pattern)))
    return ports


class SerialLink:
    """Blocking serial link with timeouts (115200 8N1 default)."""

    def __init__(self, port, baud=115200, timeout_ms=1000):
        self.port = port
        self.baud = baud
        self.timeout_ms = timeout_ms
        self.handle = None
        self.fd = None

    def open(self):
        if os.name == "nt":
            self._open_win()
        else:
            self._open_posix()

    def _open_win(self):
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        GENERIC_RW = 0x80000000 | 0x40000000
        OPEN_EXISTING = 3
        h = k32.CreateFileW("\\\\.\\" + self.port, GENERIC_RW, 0, None,
                            OPEN_EXISTING, 0, None)
        if h == wintypes.HANDLE(-1).value:
            raise OSError("cannot open %s" % self.port)

        class DCB(ctypes.Structure):
            _fields_ = [("DCBlength", wintypes.DWORD),
                        ("BaudRate", wintypes.DWORD),
                        ("Flags", wintypes.DWORD),
                        ("wReserved", wintypes.WORD),
                        ("XonLim", wintypes.WORD),
                        ("XoffLim", wintypes.WORD),
                        ("ByteSize", wintypes.BYTE),
                        ("Parity", wintypes.BYTE),
                        ("StopBits", wintypes.BYTE),
                        ("XonChar", ctypes.c_char),
                        ("XoffChar", ctypes.c_char),
                        ("ErrorChar", ctypes.c_char),
                        ("EofChar", ctypes.c_char),
                        ("EvtChar", ctypes.c_char),
                        ("wReserved1", wintypes.WORD)]

        class TIMEOUTS(ctypes.Structure):
            _fields_ = [("ReadIntervalTimeout", wintypes.DWORD),
                        ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
                        ("ReadTotalTimeoutConstant", wintypes.DWORD),
                        ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
                        ("WriteTotalTimeoutConstant", wintypes.DWORD)]

        dcb = DCB()
        dcb.DCBlength = ctypes.sizeof(DCB)
        if not k32.GetCommState(h, ctypes.byref(dcb)):
            k32.CloseHandle(h)
            raise OSError("GetCommState failed")
        dcb.BaudRate = self.baud
        dcb.ByteSize = 8
        dcb.Parity = 0
        dcb.StopBits = 0
        dcb.Flags = 0x00000001  # fBinary
        if not k32.SetCommState(h, ctypes.byref(dcb)):
            k32.CloseHandle(h)
            raise OSError("SetCommState failed")
        tmo = TIMEOUTS(50, 0, self.timeout_ms, 0, self.timeout_ms)
        k32.SetCommTimeouts(h, ctypes.byref(tmo))
        self.handle = h
        self._k32 = k32

    def _open_posix(self):
        import termios
        import fcntl
        fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY)
        attrs = termios.tcgetattr(fd)
        baud_const = {9600: termios.B9600, 57600: termios.B57600,
                      115200: termios.B115200}.get(self.baud, termios.B115200)
        attrs[4] = baud_const  # ispeed
        attrs[5] = baud_const  # ospeed
        attrs[2] &= ~(termios.PARENB | termios.CSTOPB | termios.CSIZE)
        attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = max(1, self.timeout_ms // 100)
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        self.fd = fd

    def write(self, data):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            written = wintypes.DWORD(0)
            ok = self._k32.WriteFile(self.handle, data, len(data),
                                     ctypes.byref(written), None)
            if not ok:
                raise OSError("serial write failed")
            return written.value
        total = 0
        view = memoryview(data)
        while total < len(data):
            n = os.write(self.fd, view[total:])
            total += n
        return total

    def read_exact(self, n, deadline_s=5.0):
        buf = bytearray()
        end = time.monotonic() + deadline_s
        while len(buf) < n and time.monotonic() < end:
            chunk = self._read_some(n - len(buf))
            if chunk:
                buf.extend(chunk)
            else:
                time.sleep(0.01)
        if len(buf) < n:
            raise TimeoutError("serial read timeout (%d/%d bytes)" % (len(buf), n))
        return bytes(buf)

    def _read_some(self, n):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            tmp = ctypes.create_string_buffer(min(n, PACKET_SIZE))
            got = wintypes.DWORD(0)
            ok = self._k32.ReadFile(self.handle, tmp, len(tmp),
                                    ctypes.byref(got), None)
            if not ok:
                return b""
            return tmp.raw[:got.value]
        try:
            return os.read(self.fd, min(n, PACKET_SIZE))
        except OSError:
            return b""

    def close(self):
        try:
            if os.name == "nt" and self.handle:
                self._k32.CloseHandle(self.handle)
            elif self.fd is not None:
                os.close(self.fd)
        finally:
            self.handle = None
            self.fd = None


# ---------------------------------------------------------------------------
# Device session: pairing gate + CTAP exchange + HTTP AP + dump.
# ---------------------------------------------------------------------------

class Session:
    def __init__(self, ap_base, test_mode=False, clock=time.monotonic):
        self.ap_base = ap_base.rstrip("/")
        self.test_mode = test_mode
        self.clock = clock
        self.link = None
        self.cid = 0x11223344
        self.pairing_until = 0.0

    def pairing_open(self):
        return self.clock() < self.pairing_until

    def confirm_pairing(self):
        self.pairing_until = self.clock() + PAIRING_WINDOW_SECS
        log_event("PAIRING_CONFIRMED", "window_s=%d" % PAIRING_WINDOW_SECS)

    def require_pairing(self, op):
        if op in PRIVILEGED and not self.pairing_open():
            raise PermissionError(
                "pairing-mode required: hold BOOT 5s on the device, then menu 9")

    def connect(self, port, baud):
        self.link = SerialLink(port, baud)
        self.link.open()
        log_event("DEVICE_CONNECTED", "port_bytes=%d" % len(port))
        if self.test_mode:
            dump = self.lifetime_dump(timeout_s=3.0)
            counts, _ = parse_dump(dump)
            log_event("TEST_MODE_OK", "counters=%d" % len(counts))

    def close(self):
        if self.link:
            self.link.close()
            self.link = None
            log_event("DEVICE_DISCONNECTED")

    def _exchange(self, cmd, payload, timeout_s=30.0, op="op"):
        if not self.link:
            raise OSError("not connected (menu 1)")
        self.require_pairing(op)
        packets = frame_message(self.cid, cmd, payload)
        log_event("CTAP_SENT", "cmd=%02x bytes=%d pkts=%d" % (cmd, len(payload), len(packets)))
        for pkt in packets:
            self.link.write(pkt)
        asm = Reassembler()
        stream = SerialStreamReader(self.link)
        end = time.monotonic() + timeout_s
        up_announced = False
        while time.monotonic() < end:
            raw = stream.next_frame(deadline_s=2.0)
            try:
                kind, data = asm.feed(raw)
            except ValueError:
                # Stray bytes (e.g. heartbeat tail + packet head):
                # drop one byte and resync, keep waiting for response.
                log_event("SERIAL_RESYNC", "dropped=1")
                stream.buf = bytearray(raw[1:]) + stream.buf
                continue
            if kind == "text":
                continue
            if kind == "keepalive":
                if data == STATUS_KEEPALIVE_UP_NEEDED and not up_announced:
                    up_announced = True
                    print("** UP necessario: pressione BOOT no device (ate 25s) **")
                    log_event("UP_NEEDED")
                continue
            if kind == "message":
                rcid, rcmd, body = data
                status, cbor = parse_ctap_response(body)
                log_event("CTAP_RESPONSE", "status=%02x bytes=%d" % (status, len(body)))
                return status, cbor
        raise TimeoutError("no CTAP response (UP? timeout?)")

    def cmd_init(self):
        import secrets
        nonce = secrets.token_bytes(8)
        status, body = self._exchange(CMD_INIT, nonce, timeout_s=5.0, op="init")
        _ = status
        if len(body) < 8 + 1 + 4:
            raise ValueError("bad INIT response")
        self.cid = struct.unpack_from(">I", body, 8 + 1)[0]
        log_event("CID_ALLOCATED")
        return self.cid

    def ctap(self, ctap_cmd, cbor_hex, op):
        cbor = parse_hex_even(cbor_hex) if cbor_hex.strip() else b""
        return self._exchange(CMD_CBOR, bytes([ctap_cmd]) + cbor, op=op)

    def send_text_line(self, line, timeout_s=5.0, until=None):
        if not self.link:
            raise OSError("not connected (menu 1)")
        self.link.write((line + "\n").encode("ascii"))
        log_event("DIAG_SENT", "cmd_bytes=%d" % len(line))
        buf = bytearray()
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            try:
                chunk = self.link.read_exact(1, deadline_s=1.0)
            except TimeoutError:
                break
            buf.extend(chunk)
            if until is not None and bytes(until) in buf:
                break
            if until is None and b"lt_end\n" in buf:
                break
            if len(buf) > 4096:
                break
        return buf.decode("ascii", "replace")

    def lifetime_dump(self, timeout_s=5.0):
        if not self.test_mode:
            raise PermissionError("dump needs --test-mode (firmware must have test-mode)")
        text = self.send_text_line(TEST_DUMP_CMD, timeout_s=timeout_s)
        if "lt_dump v=1" not in text:
            raise ValueError("device did not answer TEST_LIFETIME_DUMP (test-mode firmware?)")
        log_event("LIFETIME_DUMP", "bytes=%d" % len(text))
        return text

    def test_pairing_open(self, timeout_s=5.0, retries=3):
        """TEST_PAIRING_OPEN (test-mode fw only): device opens the same 60s
        pairing window as the 5s BOOT hold (source=software, no UP confirm).
        Mirrors menu 9: tracks the window locally so privileged ops pass the
        host-side gate while the window lasts. Retries: the UART text reader
        races CTAPHID framing, so a command lost among log lines is resent."""
        if not self.test_mode:
            raise PermissionError("pairing-open needs --test-mode (firmware must have test-mode)")
        text = ""
        for _ in range(max(1, retries)):
            text = self.send_text_line(TEST_PAIRING_OPEN_CMD, timeout_s=timeout_s, until=b"pairing_open")
            if "pairing_open" in text and "source=software" in text:
                break
        if "pairing_open" not in text or "source=software" not in text:
            raise ValueError("device did not open pairing (test-mode firmware?)")
        self.confirm_pairing()
        log_event("TEST_PAIRING_OPEN", "window_s=%d" % PAIRING_WINDOW_SECS)
        return text

    def test_up(self, timeout_s=5.0, retries=4):
        """TEST_UP (test-mode fw only): injects ONE BOOT tap in software
        (same 1.5s latch semantics as the physical tap; single-shot).
        Same resend policy as pairing-open (UART reader race)."""
        if not self.test_mode:
            raise PermissionError("test-up needs --test-mode (firmware must have test-mode)")
        text = ""
        for _ in range(max(1, retries)):
            text = self.send_text_line(TEST_UP_CMD, timeout_s=timeout_s, until=b"up_latched")
            if "up_latched" in text and "source=software" in text:
                break
        if "up_latched" not in text or "source=software" not in text:
            raise ValueError("device did not latch UP (test-mode firmware?)")
        log_event("TEST_UP", "latch=1x")
        return text

    # -- HTTP AP ----------------------------------------------------------
    def http_get(self, path):
        url = self.ap_base + path
        with urllib.request.urlopen(url, timeout=8) as resp:
            return resp.status, resp.read()

    def http_post(self, path, body, ctype):
        req = urllib.request.Request(self.ap_base + path, data=body,
                                     headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def oath_code(self, account):
        if not account or len(account) > 128:
            raise ValueError("bad account")
        code, body = self.http_get("/oath/code?account=" + urllib.parse.quote(account))
        if code == 401:
            raise PermissionError("presence required (press device button)")
        if code == 404:
            raise LookupError("unknown account")
        if code < 200 or code >= 300:
            raise OSError("oath fetch failed: HTTP %d" % code)
        acc, totp, remaining = validate_oath_json(body.decode("utf-8")[:512])
        log_event("OATH_FETCHED", "remaining_s=%d" % remaining)
        return acc, totp, remaining

    def wifi_config(self, password):
        self.require_pairing("wifi_config")
        if not wifi_password_valid(password):
            raise ValueError("password outside 8..63 ASCII")
        code, _ = self.http_post("/config/wifi", password.encode("ascii"), "text/plain")
        if code == 401:
            raise PermissionError("UP+PIN required (device button + PIN)")
        if code < 200 or code >= 300:
            raise OSError("wifi password change failed: HTTP %d" % code)
        log_event("WIFI_PASSWORD_CHANGED")

    def ctap_http(self, envelope_hex):
        raw = parse_hex_even(envelope_hex)
        validate_aegn_envelope(raw)
        code, body = self.http_post("/ctap", raw, "application/octet-stream")
        if code < 200 or code >= 300:
            raise OSError("ctap post failed: HTTP %d" % code)
        log_event("CTAP_HTTP_RESPONSE", "bytes=%d" % len(body))
        return body


# ---------------------------------------------------------------------------
# Interactive menu + self-test.
# ---------------------------------------------------------------------------

def ask(prompt, secret=False):
    if secret:
        return getpass.getpass(prompt)
    return input(prompt)


def run_menu(args):
    sess = Session(args.ap_base, test_mode=args.test_mode)
    port = args.port
    print("=" * 64)
    print("  AegisKey APP SIMULATOR (terminal)  test-mode=%s" % args.test_mode)
    print("  serial=CTAPHID-64B  http=%s" % sess.ap_base)
    print("=" * 64)
    while True:
        paired = "OPEN" if sess.pairing_open() else "closed"
        linked = sess.link.port if sess.link else "none"
        print("")
        print("[link=%s pairing=%s]" % (linked, paired))
        print(" 0 scan serial ports      1 connect")
        print(" 2 GetInfo (0x04)         3 MakeCredential (0x01, priv)")
        print(" 4 GetAssertion (0x02)    5 ClientPIN getRetries (0x06)")
        print(" 6 OATH code (HTTP)       7 vendor KEY/OATH raw (priv for writes)")
        print(" 8 WiFi config (HTTP, priv)  9 confirm pairing-mode (hold 5s BOOT)")
        if args.test_mode:
            print(" 10 TEST_LIFETIME_DUMP (test-mode fw)")
            print(" 11 TEST_PAIRING_OPEN 60s (test-mode fw, sem segurar BOOT)")
        print(" q quit")
        try:
            choice = ask("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "q"
        try:
            if choice == "q":
                break
            elif choice == "0":
                ports = list_serial_ports()
                print("ports: %s" % (", ".join(ports) if ports else "(none found)"))
                log_event("SCAN_STARTED", "ports=%d" % len(ports))
            elif choice == "1":
                port = ask("port [%s]: " % (port or "")) or port
                if not port:
                    print("no port (menu 0 to scan)")
                    continue
                sess.connect(port, args.baud)
            elif choice == "2":
                st, body = sess.ctap(CTAP_CMD_GET_INFO, "", op="get_info")
                print("GetInfo status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "3":
                cbor_hex = ask("MakeCredential CBOR hex: ")
                st, body = sess.ctap(CTAP_CMD_MAKE_CREDENTIAL, cbor_hex, op="make_credential")
                print("status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "4":
                cbor_hex = ask("GetAssertion CBOR hex: ")
                st, body = sess.ctap(CTAP_CMD_GET_ASSERTION, cbor_hex, op="get_assertion")
                print("status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "5":
                cbor_hex = ask("ClientPIN CBOR hex (empty = getRetries): ")
                if not cbor_hex.strip():
                    cbor_hex = "a2010102"  # {1:1, 2:1} getRetries dev hint
                op = "pin_set" if "03" in cbor_hex[:4] else "pin_verify"
                st, body = sess.ctap(CTAP_CMD_CLIENT_PIN, cbor_hex, op=op)
                print("status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "6":
                acc = ask("account (e.g. GitHub:alice): ")
                a, code, rem = sess.oath_code(acc)
                print("account=%s code=%s (%ds left)" % (a, code, rem))
            elif choice == "7":
                name = ask("vendor op (KEY_GEN/KEY_LIST/KEY_DELETE/OATH_PUT/OATH_LIST/OATH_CODE/OATH_DELETE): ").strip().upper()
                opcodes = {v: k for k, v in VENDOR_OPS.items()}
                if name not in opcodes:
                    print("unknown vendor op")
                    continue
                opcode = opcodes[name]
                tlv_hex = ask("TLV hex (empty ok): ")
                tlv = parse_hex_even(tlv_hex) if tlv_hex.strip() else b""
                writer = name in ("KEY_GEN", "KEY_IMPORT", "KEY_DELETE", "OATH_PUT", "OATH_DELETE")
                op = "key_gen" if writer else "vendor_read"
                st, body = sess._exchange(CMD_MSG, bytes([opcode]) + tlv, op=op)
                print("%s status=%02x body_bytes=%d" % (name, st, len(body)))
            elif choice == "8":
                pw = ask("new AP password: ", secret=True)
                sess.wifi_config(pw)
                print("wifi password changed (device enforces UP+PIN)")
            elif choice == "9":
                print("hold BOOT 5s on the device, then press ENTER here")
                ask("(ENTER after the hold) ")
                sess.confirm_pairing()
            elif choice == "10" and args.test_mode:
                print(sess.lifetime_dump())
            elif choice == "11" and args.test_mode:
                print(sess.test_pairing_open())
            else:
                print("unknown option")
        except PermissionError as e:
            print("DENIED: %s" % e)
        except (OSError, TimeoutError, ValueError, LookupError) as e:
            print("ERROR: %s" % str(e)[:96])
    sess.close()
    print("bye (%d sanitized events)" % len(LOG_EVENTS))


def run_self_test():
    passed = failed = 0

    def check(name, fn):
        nonlocal_pass = [0]
        try:
            fn()
            print("PASS %s" % name)
            return True
        except Exception as e:
            print("FAIL %s (%s)" % (name, e))
            return False

    def t_framing_single():
        pkts = frame_message(0x11223344, CMD_CBOR, b"A" * 10)
        assert len(pkts) == 1
        cid, cmd, total = parse_init_header(pkts[0])
        assert (cid, cmd, total) == (0x11223344, CMD_CBOR, 10)

    def t_framing_multi():
        payload = bytes(i % 256 for i in range(150))
        pkts = frame_message(0xAABBCCDD, CMD_MSG, payload)
        asm = Reassembler()
        got = None
        for p in pkts[:-1]:
            assert asm.feed(p) == ("more", None)
        kind, got = asm.feed(pkts[-1])
        assert kind == "message"
        assert got[2] == payload

    def t_keepalive():
        pkt = bytearray(64)
        struct.pack_into(">IBHB", pkt, 0, 0x55667788, CMD_KEEPALIVE, 1,
                         STATUS_KEEPALIVE_UP_NEEDED)
        asm = Reassembler()
        assert asm.feed(bytes(pkt)) == ("keepalive", STATUS_KEEPALIVE_UP_NEEDED)

    def t_ctap_status():
        st, body = parse_ctap_response(b"\x00\xa1\x01")
        assert (st, body) == (0x00, b"\xa1\x01")

    def t_pairing_gate():
        now = [1000.0]
        s = Session("http://127.0.0.1:9", clock=lambda: now[0])
        try:
            s.require_pairing("make_credential")
            raise AssertionError("should deny")
        except PermissionError:
            pass
        s.confirm_pairing()
        s.require_pairing("make_credential")
        now[0] += PAIRING_WINDOW_SECS + 1
        try:
            s.require_pairing("make_credential")
            raise AssertionError("should expire")
        except PermissionError:
            pass
        s.require_pairing("get_assertion")  # non-privileged always ok

    def t_dump_parse():
        sample = ("lt_dump v=1\nlt.key_slot.create=3\nlt.pin.retry=7\n"
                  "lt.state uptime_s=42\nlt_end\n")
        counts, states = parse_dump(sample)
        assert counts["lt.key_slot.create"] == 3
        assert states == ["uptime_s=42"]
        try:
            parse_dump("garbage\n")
            raise AssertionError("should reject")
        except ValueError:
            pass

    def t_oath_json():
        a, code, rem = validate_oath_json(
            '{"account":"GitHub:alice","code":"287082","remaining_seconds":28}')
        assert (a, code, rem) == ("GitHub:alice", "287082", 28)
        try:
            validate_oath_json('{"account":"x","code":"28a082","remaining_seconds":1}')
            raise AssertionError("should reject")
        except ValueError:
            pass

    def t_aegn():
        env = b"AEGN\x01" + b"\x00" * 12 + b"\x09" * 20 + b"\x00" * 16
        assert validate_aegn_envelope(env) == len(env) - 17
        try:
            validate_aegn_envelope(b"junk")
            raise AssertionError("should reject")
        except ValueError:
            pass

    def t_wifi_pw():
        assert wifi_password_valid("nova-senha-123")
        assert not wifi_password_valid("curta")
        assert not wifi_password_valid("x" * 64)

    def t_hex():
        assert parse_hex_even("a201 0102") == bytes.fromhex("a2010102")
        try:
            parse_hex_even("abc")
            raise AssertionError("should reject")
        except ValueError:
            pass

    def t_heartbeat_idle_ignored():
        hb = b"[HEARTBEAT] AegisKey S3 alive | uptime: 235s | USB Mounted: false"
        hb64 = hb[:PACKET_SIZE].ljust(PACKET_SIZE, b"\x00")
        assert is_text_chunk(hb64)
        asm = Reassembler()
        assert asm.feed(hb64) == ("text", None)
        assert asm.cid is None  # no state touched, no error raised

    def t_heartbeat_mid_reassembly():
        payload = bytes([0xAB] * 100)
        pkts = frame_message(0x0A0B0C0D, CMD_CBOR, payload)
        hb64 = b"[HEARTBEAT] AegisKey S3 alive | uptime: 235s".ljust(PACKET_SIZE, b"\x00")
        asm = Reassembler()
        assert asm.feed(pkts[0]) == ("more", None)
        assert asm.feed(hb64) == ("text", None)
        kind, got = asm.feed(pkts[1])
        assert kind == "message"
        assert got[2] == payload

    class _FakeLink:
        """Minimal SerialLink stub serving a fixed byte stream."""
        def __init__(self, stream):
            self.stream = bytearray(stream)
        def read_exact(self, n, deadline_s=5.0):
            if len(self.stream) < n:
                raise TimeoutError("short stream (%d/%d)" % (len(self.stream), n))
            out = bytes(self.stream[:n])
            del self.stream[:n]
            return out
        def write(self, data):
            return len(data)

    def t_pairing_open_cmd():
        assert TEST_PAIRING_OPEN_CMD == "TEST_PAIRING_OPEN"
        now = [2000.0]
        s = Session("http://127.0.0.1:9", test_mode=True, clock=lambda: now[0])
        try:
            s.require_pairing("make_credential")
            raise AssertionError("should deny before open")
        except PermissionError:
            pass
        # Device ack path is covered firmware-side; host tracks the window.
        s.confirm_pairing()
        s.require_pairing("make_credential")
        now[0] += PAIRING_WINDOW_SECS + 1
        try:
            s.require_pairing("make_credential")
            raise AssertionError("should expire")
        except PermissionError:
            pass
        s2 = Session("http://127.0.0.1:9", clock=lambda: now[0])
        try:
            s2.test_pairing_open()
            raise AssertionError("needs --test-mode flag")
        except PermissionError:
            pass

    def t_stream_skips_variable_heartbeat():
        # Stale idle heartbeat (variable length + CRLF, NOT 64B-aligned)
        # ahead of a 2-packet response must still reassemble.
        payload = bytes([0xAB] * 100)
        frames = frame_message(0x0A0B0C0D, CMD_CBOR, payload)
        hb_line = b"[HEARTBEAT] AegisKey S3 alive | uptime: 235s | USB Mounted: false\r\n"
        assert len(hb_line) % PACKET_SIZE != 0  # misaligned on purpose
        link = _FakeLink(hb_line + b"".join(frames))
        stream = SerialStreamReader(link)
        asm = Reassembler()
        got = None
        for _ in range(16):
            raw = stream.next_frame(deadline_s=1.0)
            try:
                kind, data = asm.feed(raw)
            except ValueError:
                # Short text tail + frame head: same drop-one-byte
                # resync the live exchange uses.
                stream.buf = bytearray(raw[1:]) + stream.buf
                continue
            if kind == "message":
                got = data
                break
            assert kind in ("more", "text", "keepalive")
        assert got is not None and got[2] == payload

    def t_stream_resync_after_corrupt_byte():
        # One garbage byte prepended (worst-case misalignment): the
        # drop-one-byte resync recovers the following message.
        payload = b"serial-ctaphid"
        frames = frame_message(0x11223344, CMD_CBOR, payload)
        link = _FakeLink(b"\xFF" + b"".join(frames))
        stream = SerialStreamReader(link)
        asm = Reassembler()
        got = None
        for _ in range(8):
            raw = stream.next_frame(deadline_s=1.0)
            try:
                kind, data = asm.feed(raw)
            except ValueError:
                stream.buf = bytearray(raw[1:]) + stream.buf
                continue
            if kind == "message":
                got = data
                break
        assert got is not None and got[2] == payload

    cases = [("framing single", t_framing_single), ("framing multi", t_framing_multi),
             ("keepalive", t_keepalive), ("ctap status", t_ctap_status),
             ("pairing gate", t_pairing_gate), ("dump parse", t_dump_parse),
             ("oath json", t_oath_json), ("aegn envelope", t_aegn),
             ("wifi password", t_wifi_pw), ("hex parse", t_hex),
             ("heartbeat idle ignored", t_heartbeat_idle_ignored),
             ("heartbeat mid reassembly", t_heartbeat_mid_reassembly),
             ("pairing open cmd", t_pairing_open_cmd),
             ("stream skips heartbeat", t_stream_skips_variable_heartbeat),
             ("stream resync corrupt", t_stream_resync_after_corrupt_byte)]
    for name, fn in cases:
        if check(name, fn):
            passed += 1
        else:
            failed += 1
    print("self-test: %d/%d passed" % (passed, passed + failed))
    return 0 if failed == 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="AegisKey app simulator (terminal, stdlib only)")
    ap.add_argument("--port", default=None, help="serial port (e.g. COM7)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--ap-base", default="http://192.168.4.1")
    ap.add_argument("--test-mode", action="store_true",
                    help="enable TEST_LIFETIME_DUMP (needs test-mode firmware)")
    ap.add_argument("--demo", action="store_true",
                    help="point HTTP at tools/server.py (http://127.0.0.1:8888)")
    ap.add_argument("--self-test", action="store_true", help="offline checks, no hardware")
    args = ap.parse_args(argv)
    if args.demo:
        args.ap_base = "http://127.0.0.1:8888"
    if args.self_test:
        return run_self_test()
    run_menu(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
