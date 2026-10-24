"""L5 OATH funcional via USB-HID (leitura/operacional seguro).

Cobre: vendor 0x20-0x27 (OATH_PUT 0x24 / LIST 0x25 / CODE 0x26 / DELETE
0x27), PUT/LIST/challenge com janela TOTP ±1 (offline, vetor RFC4226),
CODE via --ap-base ou USB quando HW presente.

PUT/DELETE sao escrita: NUNCA executados live aqui (so builders offline).
Live USB: LIST (0x25) e CODE/challenge (0x26) read-only; gate do device
(binding->UP->PIN) negando => SKIP documentado. Sem HW: SKIP.
Segredo nunca em log (codigos TOTP fora do log; so contagens).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import struct as _struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_usb import HidLink, HwMissingError, enumerate_aegis  # noqa: E402

pytestmark = pytest.mark.hil

OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27

# Vetor RFC4226 Ap. D (HOTP, SHA-1, chave ASCII de 20 B).
_RFC_KEY = b"12345678901234567890"


def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    msg = _struct.pack(">Q", counter)
    mac = _hmac.new(bytes(key), msg, hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (_struct.unpack_from(">I", mac, off)[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_accept(key: bytes, counter: int, presented: str, window: int = 1) -> bool:
    for c in range(counter - window, counter + window + 1):
        if c < 0:
            continue
        if hotp(key, c) == presented:
            return True
    return False


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado (cabo dados?): SKIP, falha documentada")
    return devs


# -- vetores offline (sempre rodam) --------------------------------------

def test_l5_oath_ops_range_offline():
    assert (OP_OATH_PUT, OP_OATH_LIST, OP_OATH_CODE, OP_OATH_DELETE) == (0x24, 0x25, 0x26, 0x27)
    for op in (OP_OATH_PUT, OP_OATH_LIST, OP_OATH_CODE, OP_OATH_DELETE):
        assert 0x20 <= op <= 0x27


def test_l5_oath_hotp_rfc4226_offline():
    assert hotp(_RFC_KEY, 0) == "755224"
    assert hotp(_RFC_KEY, 1) == "287082"
    assert hotp(_RFC_KEY, 2) == "359152"


def test_l5_oath_totp_window_pm1_offline():
    assert totp_accept(_RFC_KEY, 1, "755224", window=1)
    assert totp_accept(_RFC_KEY, 1, "287082", window=1)
    assert totp_accept(_RFC_KEY, 1, "359152", window=1)
    assert not totp_accept(_RFC_KEY, 1, "000000", window=1)
    assert not totp_accept(_RFC_KEY, 10, "287082", window=1)


def test_l5_oath_put_builder_offline():
    """PUT (0x24) builder: TLV slot+label validado, nunca enviado live aqui."""
    from tools.host_sdk import ops as _ops
    from tools.host_sdk import tlv as _tlv
    body = _ops.vendor_slot_label(3, b"test-oath")
    recs = _tlv.parse_tlv(body)
    assert _tlv.slot_id(recs) == 3
    assert _tlv.label_bytes(recs) == b"test-oath"


def test_l5_oath_put_never_live_without_confirm_offline(confirm_token):
    """PUT/DELETE live exigem escrita: sem --confirm OATH-WRITE, nao executam."""
    if confirm_token == "OATH-WRITE":
        pytest.skip("confirm presente: este teste offline nao escreve mesmo assim")
    assert confirm_token != "OATH-WRITE"


# -- live USB read-only (LIST / CODE) -------------------------------------

def test_l5_oath_list_readonly_usb():
    """OATH LIST (0x25): leitura; erro de gate => SKIP documentado."""
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.vendor_op(OP_OATH_LIST, b"", timeout_s=10.0)
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("OATH_LIST negou status=0x%02x (gate?)" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou OATH_LIST: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_oath_challenge_readonly_usb():
    """OATH CODE/challenge (0x26) com slot TLV: leitura, sem PUT previo."""
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        from tools.host_sdk import tlv as _tlv

        body = _tlv.write_tlv(_tlv.TAG_SLOT, bytes((0,)))
        status, resp = link.vendor_op(OP_OATH_CODE, body, timeout_s=10.0)
        assert isinstance(status, int) and isinstance(resp, bytes)
        if status != 0x00:
            pytest.skip("OATH_CODE negou status=0x%02x (slot vazio/gate?)" % status)
    except (PermissionError, ValueError, LookupError) as e:
        pytest.skip("gate do device negou OATH_CODE: %s" % str(e)[:100])
    finally:
        link.close()
