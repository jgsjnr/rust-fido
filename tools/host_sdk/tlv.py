"""Canonical TLV (BER short/long form), byte-identical to tlv.rs (stdlib-only).

Wire frozen: data tags 0x01 slot, 0x02 label, 0x07 address (response),
0x08 network (GEN request); vendor op range 0x20-0x27; rescue 0x2E;
fw-log 0x38.
"""
from __future__ import annotations

TAG_WALLET_SLOT = 0x01
TAG_WALLET_LABEL = 0x02
TAG_WALLET_ADDRESS = 0x07
TAG_WALLET_NETWORK = 0x08

TAG_SLOT = 0x01
TAG_LABEL = 0x02
TAG_ALG_HINT = 0x05
TAG_USAGE_HINT = 0x06
TAG_OATH_NAME = 0x71
TAG_OATH_RESPONSE = 0x75

VENDOR_OP_MIN = 0x20
VENDOR_OP_MAX = 0x27
RESCUE_TRANSPORT_OP = 0x2E
FW_LOG_OP = 0x38

MAX_LABEL_BYTES = 32

_WALLET_TAGS = frozenset((TAG_WALLET_SLOT, TAG_WALLET_LABEL, TAG_WALLET_ADDRESS, TAG_WALLET_NETWORK))


class TlvError(ValueError):
    pass


def parse_tlv(data: bytes | bytearray):
    """Parse all TLV records -> list of (tag, value). Fail-closed on malformed."""
    raw = bytes(data)
    out = []
    idx = 0
    n = len(raw)
    while idx < n:
        tag = raw[idx]
        idx += 1
        if idx >= n:
            raise TlvError("truncated length")
        lb = raw[idx]
        idx += 1
        if lb < 0x80:
            ln = lb
        elif lb == 0x81:
            if idx >= n:
                raise TlvError("truncated 0x81 length")
            ln = raw[idx]
            idx += 1
        elif lb == 0x82:
            if idx + 1 >= n:
                raise TlvError("truncated 0x82 length")
            ln = (raw[idx] << 8) | raw[idx + 1]
            idx += 2
        else:
            raise TlvError("indefinite/reserved length form")
        if idx + ln > n:
            raise TlvError("length overrun")
        out.append((tag, raw[idx:idx + ln]))
        idx += ln
    return out


def find_tlv(records, tag: int):
    """First value for tag, or None."""
    for t, v in records:
        if t == tag:
            return v
    return None


def write_tlv(tag: int, value: bytes | bytearray) -> bytes:
    """Serialize one TLV record, byte-identical to tlv.rs write_tlv."""
    v = bytes(value)
    ln = len(v)
    if not 0 <= tag <= 0xFF:
        raise TlvError("tag must fit in one byte")
    if ln < 0x80:
        return bytes((tag, ln)) + v
    if ln <= 0xFF:
        return bytes((tag, 0x81, ln)) + v
    if ln <= 0xFFFF:
        return bytes((tag, 0x82, (ln >> 8) & 0xFF, ln & 0xFF)) + v
    raise TlvError("value too large")


def is_wallet_tag(tag: int) -> bool:
    return tag in _WALLET_TAGS


def is_vendor_op(op: int) -> bool:
    return VENDOR_OP_MIN <= op <= VENDOR_OP_MAX


def single_byte(records, tag: int):
    v = find_tlv(records, tag)
    if v is not None and len(v) == 1:
        return v[0]
    return None


def slot_id(records):
    return single_byte(records, TAG_SLOT)


def label_bytes(records):
    v = find_tlv(records, TAG_LABEL)
    if v is not None and 1 <= len(v) <= MAX_LABEL_BYTES:
        return v
    return None


def append_slot_label(slot: int, label: bytes | bytearray) -> bytes:
    return write_tlv(TAG_SLOT, bytes((slot,))) + write_tlv(TAG_LABEL, bytes(label))
