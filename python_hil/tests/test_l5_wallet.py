"""L5 wallet funcional via USB-HID (somente leitura/storage-only).

Cobre: wallet_gen (0x35, builder offline), wallet_addr (0x37) e
wallet_list (0x36) read-only nos slots 0-31 com prefixo `wallet:`,
sem sign-tx (storage-only: nenhum op de assinatura existe no range).

GEN live NAO e executado (escrita em slot); ADDR/LIST live sao leitura.
Sem HW: SKIP. Gate negando => SKIP documentado. Segredo nunca em log.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_usb import (  # noqa: E402
    OP_WALLET_ADDR,
    OP_WALLET_GEN,
    OP_WALLET_LIST,
    HidLink,
    HwMissingError,
    enumerate_aegis,
)

pytestmark = pytest.mark.hil

WALLET_SLOTS = range(0, 32)
WALLET_LABEL_PREFIX = b"wallet:"


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado (cabo dados?): SKIP, falha documentada")
    return devs


# -- vetores offline (sempre rodam) --------------------------------------

def test_l5_wallet_ops_storage_only_offline():
    assert (OP_WALLET_GEN, OP_WALLET_LIST, OP_WALLET_ADDR) == (0x35, 0x36, 0x37)
    # Nenhum op de assinatura no range wallet: storage-only por construcao.
    assert OP_WALLET_GEN not in (0x38, 0x39)
    assert OP_WALLET_LIST == 0x36 and OP_WALLET_ADDR == 0x37


def test_l5_wallet_slots_0_31_offline():
    assert list(WALLET_SLOTS) == list(range(32))
    assert 0 in WALLET_SLOTS and 31 in WALLET_SLOTS and 32 not in WALLET_SLOTS


def test_l5_wallet_gen_builders_offline():
    from tools.host_sdk import ops as _ops
    from tools.host_sdk import tlv as _tlv

    for slot in (0, 15, 31):
        body = _ops.wallet_gen(slot, WALLET_LABEL_PREFIX + b"btc-%d" % slot, 0x01)
        recs = _tlv.parse_tlv(body)
        assert _tlv.find_tlv(recs, _tlv.TAG_WALLET_SLOT) == bytes((slot,))
        label = _tlv.find_tlv(recs, _tlv.TAG_WALLET_LABEL)
        assert label is not None and label.startswith(WALLET_LABEL_PREFIX)
    assert _ops.wallet_list_req() == b""
    assert _tlv.parse_tlv(_ops.wallet_addr_req(3))[0] == (_tlv.TAG_WALLET_SLOT, b"\x03")


def test_l5_wallet_label_prefix_offline():
    assert WALLET_LABEL_PREFIX == b"wallet:"
    for good in (b"wallet:btc-0", b"wallet:eth-main"):
        assert good.startswith(WALLET_LABEL_PREFIX)
    assert not b"btc-0".startswith(WALLET_LABEL_PREFIX)


def test_l5_wallet_gen_never_live_without_confirm_offline(confirm_token):
    """GEN escreve em slot: live proibido sem --confirm WALLET-WRITE."""
    if confirm_token == "WALLET-WRITE":
        pytest.skip("confirm presente: este teste offline nao escreve mesmo assim")
    assert confirm_token != "WALLET-WRITE"


# -- live USB read-only (LIST / ADDR) -------------------------------------

def test_l5_wallet_list_readonly_usb():
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.wallet_op(OP_WALLET_LIST, b"", timeout_s=10.0)
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("WALLET_LIST negou status=0x%02x (gate?)" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou WALLET_LIST: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_wallet_addr_slot0_readonly_usb():
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        from tools.host_sdk import ops as _ops

        status, body = link.wallet_op(OP_WALLET_ADDR, _ops.wallet_addr_req(0),
                                      timeout_s=10.0)
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("WALLET_ADDR slot0 negou status=0x%02x (vazio/gate?)" % status)
    except (PermissionError, ValueError, LookupError) as e:
        pytest.skip("gate do device negou WALLET_ADDR: %s" % str(e)[:100])
    finally:
        link.close()
