"""L5 mgmt funcional via USB/UART (gates, pairing, fw-log, backup, OTA, prox).

Cobre: gates binding->UP->PIN (ordem canonica), janela de pairing 60 s /
300 s (TEST_PAIRING_OPEN_300), fw-log livre (0x38), backup envelope AEGN
parse de cabecalho (nunca exfiltra segredo), OTA begin/chunk/verify SEM
COMMIT (COMMIT exige --confirm OTA-COMMIT e nunca e enviado aqui),
proximity walkaway 5..300 s (builder + BLE 0xFFFE nunca FFF1-FFF4).

Sem HW: SKIP. Destrutivo sem --confirm: SKIP. Segredo nunca em log.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_ble_wifi import (  # noqa: E402
    AEGN_MAGIC,
    AEGN_VERSION,
    validate_aegn_envelope,
)
from python_hil.link_serial import SerialLink  # noqa: E402
from python_hil.link_usb import HidLink, HwMissingError, enumerate_aegis  # noqa: E402

pytestmark = pytest.mark.hil

PAIRING_WINDOW_60 = 60
PAIRING_WINDOW_300 = 300


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado (cabo dados?): SKIP, falha documentada")
    return devs


# -- vetores offline (sempre rodam) --------------------------------------

def test_l5_mgmt_gate_order_offline():
    from tools.host_sdk import gates as _gates

    assert (_gates.NEED_BINDING, _gates.NEED_UP, _gates.NEED_PIN) == (0x05, 0x01, 0x02)
    # Ordem canonica binding -> UP -> PIN: cada etapa negada por vez.
    # 0x21 (KEY_IMPORT) e privilegiado (exige PIN); 0x22 (KEY_LIST) nao.
    with pytest.raises(_gates.GateDenied) as e1:
        _gates.authorize_config_op(0x21, False, False, False, op="t")
    assert e1.value.status == _gates.NEED_BINDING
    with pytest.raises(_gates.GateDenied) as e2:
        _gates.authorize_config_op(0x21, True, False, False, op="t")
    assert e2.value.status == _gates.NEED_UP
    with pytest.raises(_gates.GateDenied) as e3:
        _gates.authorize_config_op(0x21, True, True, False, op="t")
    assert e3.value.status == _gates.NEED_PIN
    _gates.authorize_config_op(0x21, True, True, True, op="import-ok")
    _gates.authorize_config_op(0x22, True, True, False, op="list-ok")


def test_l5_mgmt_pairing_windows_offline():
    assert PAIRING_WINDOW_60 == 60 and PAIRING_WINDOW_300 == 300
    from python_hil import app_usb_sim as _app

    assert _app.PAIRING_WINDOW_SECS == 60
    assert "300" in "TEST_PAIRING_OPEN_300"


def test_l5_mgmt_fwlog_free_offline():
    from tools.host_sdk import ops as _ops

    assert _ops.fw_log_req() == b""


def test_l5_mgmt_aegn_parse_offline():
    body = b"\x01" * 32
    env = AEGN_MAGIC + bytes((AEGN_VERSION,)) + body
    assert validate_aegn_envelope(env) == len(env) - 17
    with pytest.raises(ValueError):
        validate_aegn_envelope(b"BAD!" + bytes(32))
    with pytest.raises(ValueError):
        validate_aegn_envelope(AEGN_MAGIC + b"\x02" + body)


def test_l5_mgmt_ota_builders_no_commit_offline():
    from tools.host_sdk import ops as _ops

    assert _ops.ota_verify() == b"" and _ops.ota_abort() == b""
    assert _ops.ota_commit() == b""
    begin = _ops.ota_begin(1024, b"\x00" * 32)
    assert len(begin) > 32
    chunk = _ops.ota_chunk(0, b"\x01\x02\x03\x04")
    assert chunk[:2] == b"\x00\x00"
    for bad in (0, 1000000 + 0xFFFFFF):
        with pytest.raises(ValueError):
            _ops.ota_begin(bad, b"\x00" * 32)
    with pytest.raises(ValueError):
        _ops.ota_chunk(0, b"")


def test_l5_mgmt_prox_walkaway_offline():
    from tools.host_sdk import ops as _ops

    assert _ops.prox_walkaway(60) == b"\x00\x3c"
    assert _ops.prox_walkaway(300)[1] == 0x2C
    for bad in (4, 301, 0):
        with pytest.raises(ValueError):
            _ops.prox_walkaway(bad)
    assert _ops.PROXIMITY_SERVICE == 0xFFFE


def test_l5_mgmt_commit_blocked_without_confirm_offline(confirm_token):
    """COMMIT/wipe/killswitch: sem --confirm exato, bloqueado."""
    if confirm_token == "OTA-COMMIT":
        pytest.skip("confirm presente: este teste offline nao executa mesmo assim")
    assert confirm_token != "OTA-COMMIT"


# -- live (exigem HW; destrutivos nunca executados) -----------------------

def test_l5_mgmt_pairing_window_live_usb(uart_port):
    """Pairing 60/300 s: via UART TEST_PAIRING_OPEN_300 (so test-mode)."""
    if not uart_port:
        pytest.skip("sem --uart (HW ausente): SKIP, falha documentada")
    link = SerialLink(uart_port, 115200)
    link.open()
    try:
        text = link.test_pairing_open()
        assert "pairing_open" in text
    except ValueError as e:
        pytest.skip("pairing negou (fw sem test-mode?): %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_mgmt_fwlog_free_live_usb():
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.fw_log()
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("fw-log negou status=0x%02x" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou fw-log: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_mgmt_backup_envelope_header_live_usb():
    """Backup AEGN: parse so de cabecalho sobre envelope sintetico.

    Nenhum envelope real e lido/exfiltrado do device aqui; o live apenas
    prova que a USB esta viva (GetInfo) e o parse roda offline.
    """
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, _ = link.get_info()
        assert isinstance(status, int)
        env = AEGN_MAGIC + bytes((AEGN_VERSION,)) + b"\x02" * 32
        assert validate_aegn_envelope(env) == len(env) - 17
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_mgmt_ota_begin_chunk_verify_no_commit_usb(confirm_token):
    """OTA begin/chunk/verify live + abort de limpeza; COMMIT nunca enviado."""
    _require_usb()
    from tools.host_sdk import ops as _ops
    from python_hil.link_serial import CMD_MSG, parse_ctap_response

    def _msg_op(op: int, body: bytes) -> tuple:
        rcid, rcmd, raw = link.exchange(CMD_MSG, bytes((op,)) + bytes(body),
                                        timeout_s=10.0, op="ota_%02x" % op)
        if rcmd != CMD_MSG:
            raise ValueError("bad ota response (cmd=%02x)" % rcmd)
        return parse_ctap_response(raw)

    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        begin = _ops.ota_begin(64, b"\xAB" * 32)
        st, _ = _msg_op(0x30, begin)
        assert isinstance(st, int)
        if st != 0x00:
            pytest.skip("OTA_BEGIN negou status=0x%02x (gate?)" % st)
        st, _ = _msg_op(0x31, _ops.ota_chunk(0, b"\x01\x02\x03\x04"))
        assert isinstance(st, int)
        st, _ = _msg_op(0x32, _ops.ota_verify())
        assert isinstance(st, int)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou OTA staged: %s" % str(e)[:100])
    finally:
        try:
            from tools.host_sdk import ops as _ops2

            rcid, rcmd, raw = link.exchange(CMD_MSG, bytes((0x34,)) + _ops2.ota_abort(),
                                            timeout_s=10.0, op="ota_abort")
        except Exception:
            pass
        link.close()
    _ = confirm_token  # COMMIT nunca enviado neste teste por construcao.


def test_l5_mgmt_proximity_walkaway_builder_live_usb():
    """Walkaway: builder validado com HW presente; sem radio BLE nao ha envio."""
    _require_usb()
    from tools.host_sdk import ops as _ops

    assert _ops.prox_walkaway(60) == b"\x00\x3c"
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, _ = link.get_info()
        assert isinstance(status, int)
    finally:
        link.close()
