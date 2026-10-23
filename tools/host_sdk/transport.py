"""Transports: serial CTAPHID 64B framing + HTTP AP (stdlib-only).

Port: --port or AEGIS_PORT env, default COM7. MAC: resolved at runtime
via `esptool read_mac` (device_ops contract), never hardcoded.
"""
from __future__ import annotations

import os
import struct as _struct
import time as _time
import urllib.parse as _parse
import urllib.request as _request
import urllib.error as _urlerror

PACKET_SIZE = 64
INIT_PAYLOAD_MAX = 57
CONT_PAYLOAD_MAX = 59

CMD_INIT = 0x86
CMD_MSG = 0x83
CMD_CBOR = 0x90
CMD_PING = 0x81
CMD_KEEPALIVE = 0xBB
CMD_CANCEL = 0xBE | 0x80

DEFAULT_PORT = "COM7"
DEFAULT_AP_BASE = "http://192.168.4.1"


def default_port() -> str:
    return os.environ.get("AEGIS_PORT", DEFAULT_PORT)


def resolve_port(explicit: str | None) -> str:
    if explicit:
        return explicit
    return default_port()


def resolve_mac(port: str | None = None) -> str:
    """Read device MAC at runtime via esptool (never a fixed constant)."""
    import subprocess as _sp
    p = resolve_port(port)
    cmd = ["esptool", "--port", p, "read_mac"]
    out = _sp.run(cmd, capture_output=True, text=True, timeout=30)
    text = (out.stdout or "") + "\n" + (out.stderr or "")
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("MAC:"):
            return s.split("MAC:", 1)[1].strip()
    raise OSError("could not resolve device MAC via esptool read_mac")


def frame_message(cid: int, cmd: int, payload: bytes) -> list:
    total = len(payload)
    if total > 0xFFFF:
        raise ValueError("payload too large")
    first = payload[:INIT_PAYLOAD_MAX]
    pkt = bytearray(PACKET_SIZE)
    _struct.pack_into(">IBH", pkt, 0, cid, cmd, total)
    pkt[7:7 + len(first)] = first
    out = [bytes(pkt)]
    seq = 0
    off = len(first)
    while off < total:
        chunk = payload[off:off + CONT_PAYLOAD_MAX]
        pkt = bytearray(PACKET_SIZE)
        _struct.pack_into(">IB", pkt, 0, cid, seq)
        pkt[5:5 + len(chunk)] = chunk
        out.append(bytes(pkt))
        off += len(chunk)
        seq = (seq + 1) & 0xFF
    return out


def parse_init_header(pkt: bytes):
    if len(pkt) != PACKET_SIZE:
        raise ValueError("bad packet size")
    cid, cmd, total = _struct.unpack_from(">IBH", pkt, 0)
    if not (cmd & 0x80):
        raise ValueError("not an INIT packet")
    return cid, cmd, total


class Reassembler:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.cid = None
        self.cmd = None
        self.total = 0
        self.buf = bytearray()
        self.seq = 0

    def feed(self, pkt: bytes):
        if len(pkt) != PACKET_SIZE:
            raise ValueError("bad packet size")
        cid, raw, total = _struct.unpack_from(">IBH", pkt, 0)
        if raw == CMD_KEEPALIVE:
            return ("keepalive", pkt[7])
        if raw & 0x80:
            if total > 7609:
                raise ValueError("overflow ctaphid")
            self.cid, self.cmd, self.total = cid, raw, total
            self.buf = bytearray(pkt[7:7 + min(total, INIT_PAYLOAD_MAX)])
            self.seq = 0
        else:
            if self.cid is None or cid != self.cid:
                raise ValueError("unexpected continuation")
            self.buf.extend(pkt[5:5 + CONT_PAYLOAD_MAX])
            self.seq = (self.seq + 1) & 0xFF
        if self.cid is not None and len(self.buf) >= self.total:
            msg = (self.cid, self.cmd, bytes(self.buf[:self.total]))
            self.reset()
            return ("message", msg)
        return ("more", None)


def exchange_ctaphid(link, cid: int, cmd: int, payload: bytes,
                     timeout_s: float = 30.0, op: str = "op"):
    """Write framed packets, read until one CTAP message. Returns (status, body)."""
    packets = frame_message(cid, cmd, payload)
    for pkt in packets:
        link.write(pkt)
    asm = Reassembler()
    end = _time.monotonic() + timeout_s
    while _time.monotonic() < end:
        raw = link.read_exact(PACKET_SIZE, deadline_s=2.0)
        kind, data = asm.feed(raw)
        if kind in ("more", "keepalive"):
            continue
        if kind == "message":
            _, _, body = data
            if not body:
                raise ValueError("empty response")
            return body[0], body[1:]
    raise TimeoutError("no CTAP response op=%s" % op)


def http_get(ap_base: str, path: str, timeout: float = 8.0):
    url = ap_base.rstrip("/") + path
    with _request.urlopen(url, timeout=timeout) as resp:
        return resp.status, resp.read()


def http_post(ap_base: str, path: str, body: bytes, ctype: str, timeout: float = 8.0):
    req = _request.Request(ap_base.rstrip("/") + path, data=bytes(body),
                           headers={"Content-Type": ctype})
    try:
        with _request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except _urlerror.HTTPError as e:
        return e.code, e.read()


def oath_code(ap_base: str, account: str):
    if not account or len(account) > 128:
        raise ValueError("bad account")
    import json as _json
    code, body = http_get(ap_base, "/oath/code?account=" + _parse.quote(account))
    if code == 401:
        raise PermissionError("presence required")
    if code == 404:
        raise LookupError("unknown account")
    if not 200 <= code < 300:
        raise OSError("oath fetch failed: HTTP %d" % code)
    data = _json.loads(body.decode("utf-8")[:512])
    totp = data.get("code", "")
    if len(totp) not in (6, 7, 8) or not totp.isdigit():
        raise ValueError("bad code format")
    return data.get("account", ""), totp, data.get("remaining_seconds", -1)
