"""L4 app: AppUsbSim sobre USB (connect_usb->INIT->exchange_ctaphid).

Offline (sempre roda): builders TLV/wallet/vendor + framings + gate
local "sem connect_usb nao ha claim" (HwMissingError, nao aprova sem HW).
Com HW USB: GetInfo (0x04) / fw-log livre (0x38) / probes vendor-wallet
read-only; MC/GA so com CBOR valido e gates do device (UP fisico).
Com --tcp: veredito SIM-COVERED do piloto. Sem HW/sim: SKIP elegante.
Segredo nunca em log (so contagens).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.app_usb_sim import AppUsbSim, run_self_test  # noqa: E402
from python_hil.link_usb import HwMissingError, enumerate_aegis  # noqa: E402

pytestmark = pytest.mark.hil


def test_l4_app_selftest_offline():
    assert run_self_test() == 0


def test_l4_app_no_claim_without_usb():
    app = AppUsbSim()
    with pytest.raises(HwMissingError):
        app.get_info()


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado: SKIP, falha documentada")


def test_l4_app_get_info_usb():
    _require_usb()
    app = AppUsbSim()
    app.connect_usb()
    try:
        app.cmd_init()
        status, body = app.get_info()
        assert isinstance(status, int) and isinstance(body, bytes)
    finally:
        app.close()


def test_l4_app_fwlog_usb_free():
    """fw-log (0x38) livre: sem UP claim neste path."""
    _require_usb()
    app = AppUsbSim()
    app.connect_usb()
    try:
        app.cmd_init()
        status, body = app.fw_log()
        assert isinstance(status, int) and isinstance(body, bytes)
    finally:
        app.close()


def test_l4_app_wallet_list_readonly_usb():
    """Wallet LIST (0x36) vazio: leitura; erro de gate documentado se negado."""
    _require_usb()
    app = AppUsbSim()
    app.connect_usb()
    try:
        app.cmd_init()
        status, body = app.wallet(0x36, "")
        assert isinstance(status, int) and isinstance(body, bytes)
    except (PermissionError, ValueError, OSError) as e:
        pytest.skip("gate do device negou (binding->UP->PIN): %s" % str(e)[:100])
    finally:
        app.close()
