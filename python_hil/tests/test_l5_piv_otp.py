"""L5 PIV + OTP funcional (somente leitura/presenca, sem enroll).

Cobre: PIV SELECT (AID), VERIFY (PIN 6-8 digitos), GEN AUTH envelope +
strip-FF (normalizacao F4), OTP typer 6-8 digitos ASCII com presenca
(binding->UP). CCID nunca claimed/written aqui: live e enumerate
read-only + builders; escrita PIV (enroll 0x39) proibida.

Sem HW: SKIP. Gate negando => SKIP documentado. Segredo (PIN/OTP)
nunca em log: getpass fora dos testes; aqui so vetores de formato.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_usb import HwMissingError, enumerate_aegis, probe_interfaces  # noqa: E402

pytestmark = pytest.mark.hil

PIV_AID = bytes((0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00))


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado (cabo dados?): SKIP, falha documentada")
    return devs


# -- vetores offline (sempre rodam) --------------------------------------

def test_l5_piv_select_builder_offline():
    from tools.host_sdk import ops as _ops

    apdu = _ops.piv_select_aid()
    assert apdu[:4] == bytes((0x00, 0xA4, 0x04, 0x00))
    assert _ops.PIV_AID in apdu


def test_l5_piv_verify_pin_format_offline():
    from tools.host_sdk import ops as _ops

    apdu = _ops.piv_verify_pin(b"123456")
    assert apdu[:4] == bytes((0x00, 0x20, 0x00, 0x80))
    for bad in (b"12345", b"123456789", b"abcdef", b"", b"12 456"):
        with pytest.raises(ValueError):
            _ops.piv_verify_pin(bad)


def test_l5_piv_gen_auth_strip_ff_offline():
    from tools.host_sdk import ops as _ops

    env = _ops.piv_gen_auth(b"\x11" * 32)
    assert env[0] == 32 and len(env) == 33
    with pytest.raises(ValueError):
        _ops.piv_gen_auth(b"\x11" * 31)
    assert _ops.piv_strip_ff(b"AB\xff\xff") == b"AB"
    with pytest.raises(ValueError):
        _ops.piv_strip_ff(b"")


def test_l5_otp_typer_digits_presence_offline():
    from tools.host_sdk import gates as _gates
    from tools.host_sdk import ops as _ops

    assert _ops.otp_typer_input("123456") == b"123456"
    assert _ops.otp_typer_input("12345678") == b"12345678"
    for bad in ("12345", "123456789", "abcdef", "12 456", ""):
        with pytest.raises(ValueError):
            _ops.otp_typer_input(bad)
    # Presenca exigida p/ uso: sem UP => GateDenied NEED_UP 0x01.
    with pytest.raises(_gates.GateDenied):
        _gates.authorize_usage_op(False, op="otp_type")
    _gates.authorize_usage_op(True, op="otp_type")


def test_l5_piv_apdu_ins_scope_offline():
    from tools.host_sdk import ops as _ops

    for ins in (0x01, 0x02, 0x03, 0x04, 0xA1, 0xA2, 0xA3, 0xA4, 0x20):
        _ops.piv_apdu(0x00, ins, 0x00, 0x00)
    with pytest.raises(ValueError):
        _ops.piv_apdu(0x00, 0xFF, 0x00, 0x00)
    assert _ops.ext_route_status("ykman") == bytes((0x6D, 0x00))


# -- live USB read-only (enumerate, sem claim CCID) ------------------------

def test_l5_piv_iface_readonly_usb():
    """CCID/KBD/WinUSB: so enumerate (nunca claim/write fora CTAPHID)."""
    devs = _require_usb()
    ev = probe_interfaces()
    assert ev["total"] == len(devs) and ev["fido_ctaphid"] >= 1


def test_l5_piv_select_builder_matches_aid_usb():
    """Com HW: so valida builder SELECT (nenhum APDU enviado ao CCID)."""
    _require_usb()
    from tools.host_sdk import ops as _ops

    apdu = _ops.piv_select_aid()
    assert apdu[4] == len(_ops.PIV_AID)
    assert apdu[5:5 + len(_ops.PIV_AID)] == _ops.PIV_AID
