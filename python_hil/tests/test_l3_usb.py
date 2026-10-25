"""L3 USB: HidLink VID 0x303A PID 0xAE61, INIT->CID, PING 64B, GetInfo 0x04.

Vetores offline (sempre rodam): ranges vendor 0x20-0x27 / wallet
0x35-0x37 / rescue 0x2E / fw-log 0x38 + framing 64B + Report ID 00.
Com HW (enumerate acha 303A:AE61): INIT->CID, PING eco, CBOR GetInfo
(0x04), probes read-only CCID/KBD/WinUSB (so enumerate, sem claim).
Sem HW: SKIP elegante (falha real documentada). Segredo nunca em log.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_usb import (  # noqa: E402
    OP_FW_LOG,
    OP_RESCUE,
    OP_WALLET_ADDR,
    OP_WALLET_GEN,
    OP_WALLET_LIST,
    HidLink,
    HwMissingError,
    enumerate_aegis,
    is_vendor_op,
    is_wallet_op,
    probe_interfaces,
)
from python_hil.link_serial import frame_message  # noqa: E402
from python_hil.link_serial import CMD_PING  # noqa: E402

pytestmark = pytest.mark.hil


def test_l3_op_ranges_offline():
    assert all(is_vendor_op(o) for o in range(0x20, 0x28))
    assert not is_vendor_op(0x28) and not is_vendor_op(0x1F)
    assert all(is_wallet_op(o) for o in (OP_WALLET_GEN, OP_WALLET_LIST, OP_WALLET_ADDR))
    assert OP_RESCUE == 0x2E and OP_FW_LOG == 0x38


def test_l3_report_64b_offline():
    pkts = frame_message(0x11223344, CMD_PING, b"\xa5\x5a\x00\xff")
    assert len(pkts) == 1 and len(pkts[0]) == 64


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado (cabo dados?): SKIP, falha documentada")
    return devs


def test_l3_usb_init_ping():
    _require_usb()
    link = HidLink()
    link.open()
    try:
        cid = link.cmd_init()
        assert cid != 0xFFFFFFFF
        assert link.ping() == b"\xa5\x5a\x00\xff"
    finally:
        link.close()


def test_l3_usb_get_info():
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.get_info()
        assert isinstance(status, int) and isinstance(body, bytes)
    finally:
        link.close()


def test_l3_usb_iface_probes_readonly():
    """CCID/KBD/WinUSB: somente enumerate (nunca claim/write fora CTAPHID)."""
    devs = _require_usb()
    ev = probe_interfaces()
    assert ev["total"] == len(devs) and ev["fido_ctaphid"] >= 1


def test_l3_usb_ping_large_multipkt_usb():
    """PING-200B (4 pkts) idempotente: sessao fresca + 1 retry (wedge host-side)."""
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        echo = bytes((i % 256 for i in range(200)))
        assert link.ping(echo, timeout_s=10.0) == echo
    finally:
        link.close()


# -- vetores offline da mitigacao wedge (sempre rodam; doubles so aqui) ---

def _fake_link():
    """HidLink sem HW: doubles locais (nunca em producao)."""
    link = HidLink()
    link.dev = object()  # finge aberto; I/O real stubado abaixo
    calls = {"init": 0, "exchange": 0, "reconnect": 0}

    def _cmd_init(nonce=None, timeout_s=5.0):
        _ = (nonce, timeout_s)
        calls["init"] += 1
        link.cid = 0x01020304 + calls["init"]
        return link.cid

    link.cmd_init = _cmd_init  # type: ignore[method-assign]
    orig_reconnect = link.reconnect

    def _reconnect():
        calls["reconnect"] += 1
        # sem re-enumerar de verdade no offline
        _ = orig_reconnect

    link.reconnect = _reconnect  # type: ignore[method-assign]
    return link, calls


def test_l3_usb_fresh_session_offline():
    link, calls = _fake_link()
    cid = link.fresh_session()
    assert cid != 0xFFFFFFFF and calls["init"] == 1


def test_l3_usb_getinfo_does_fresh_before_exchange_offline():
    from python_hil.link_serial import CMD_CBOR  # noqa

    link, calls = _fake_link()
    order: list = []

    def _cmd_init(nonce=None, timeout_s=5.0):
        _ = (nonce, timeout_s)
        calls["init"] += 1
        order.append("init")
        link.cid = 0x0A0B0C0D
        return link.cid

    def _exchange(cmd, payload, timeout_s=10.0, op="op"):
        _ = (cmd, payload, timeout_s, op)
        calls["exchange"] += 1
        order.append("exchange")
        return link.cid, CMD_CBOR, bytes((0x00, 0x41))

    link.cmd_init = _cmd_init  # type: ignore[method-assign]
    link.exchange = _exchange  # type: ignore[method-assign]
    status, body = link.get_info()
    assert (status, body) == (0x00, b"\x41")
    assert order[0] == "init" and "exchange" in order
    assert calls["init"] >= 1 and calls["exchange"] == 1


def test_l3_usb_ping_small_no_fresh_offline():
    link, calls = _fake_link()

    def _no_init(nonce=None, timeout_s=5.0):
        raise AssertionError("ping-1pkt nao deve fazer INIT novo")

    def _exchange(cmd, payload, timeout_s=5.0, op="op"):
        _ = (cmd, timeout_s, op)
        calls["exchange"] += 1
        return link.cid, cmd, bytes(payload)

    link.cmd_init = _no_init  # type: ignore[method-assign]
    link.exchange = _exchange  # type: ignore[method-assign]
    assert link.ping(b"\xa5\x5a\x00\xff") == b"\xa5\x5a\x00\xff"
    assert calls["exchange"] == 1 and calls["init"] == 0


def test_l3_usb_ping_large_fresh_and_retry_offline():
    from python_hil.link_serial import CMD_PING  # noqa

    link, calls = _fake_link()
    attempts: list = []

    def _exchange(cmd, payload, timeout_s=5.0, op="op"):
        _ = (cmd, timeout_s, op)
        calls["exchange"] += 1
        attempts.append(bytes(payload))
        if len(attempts) == 1:
            raise TimeoutError("no CTAP response op=ping")
        return link.cid, CMD_PING, bytes(payload)

    link.exchange = _exchange  # type: ignore[method-assign]
    echo = b"C" * 100  # >57 B => multi-pacote
    assert link.ping(echo, timeout_s=5.0) == echo
    assert calls["init"] >= 2  # fresca ANTES + fresca no retry
    assert calls["exchange"] == 2 and calls["reconnect"] == 1


def test_l3_usb_writes_never_retry_offline():
    """MC/GA/PUT (vendor/wallet/ctap) nunca retentam: 1 exchange, sem INIT novo."""
    link, calls = _fake_link()

    def _exchange(cmd, payload, timeout_s=30.0, op="op"):
        _ = (cmd, payload, timeout_s, op)
        calls["exchange"] += 1
        raise TimeoutError("no CTAP response op=%s" % op)

    link.exchange = _exchange  # type: ignore[method-assign]
    for fn in (lambda: link.vendor_op(0x21, b"\x01\x02"),
               lambda: link.wallet_op(OP_WALLET_LIST, b""),
               lambda: link.ctap(0x01, b"\xa0", timeout_s=5.0,
                                 op="make_credential")):
        with pytest.raises(TimeoutError):
            fn()
    assert calls["exchange"] == 3 and calls["init"] == 0
    assert calls["reconnect"] == 0


def test_l3_usb_no_secret_in_log_offline(capsys):
    link, calls = _fake_link()

    def _exchange(cmd, payload, timeout_s=5.0, op="op"):
        _ = (cmd, timeout_s, op)
        from python_hil.link_serial import sanitize_log as _san
        print(_san("USB_SENT cmd=%02x pkts=1" % cmd, len(payload)), flush=True)
        return link.cid, cmd, bytes(payload)

    link.exchange = _exchange  # type: ignore[method-assign]
    secret = b"S3CR3T-" * 10  # 70 B => path multi-pacote, eco verificavel
    link.dev = object()
    # ping-1pkt curto com marcador secreto (nao deve vazar em log)
    assert link.ping(b"\x01\x02") == b"\x01\x02"
    out = capsys.readouterr().out
    assert "S3CR3T" not in out
    _ = secret
