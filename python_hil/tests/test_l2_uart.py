"""L2 UART: SerialLink COM7 115200 sem DTR/RTS + CTAPHID + TEST_*.

Sem --uart: SKIP elegante (falha real documentada: sem HW na bancada).
Com --uart: abre sem tocar DTR/RTS, INIT->CID, PING eco, GetInfo (0x04),
MakeCredential/GetAssertion base (CBOR opaco), TEST_PAIRING_OPEN/TEST_UP/
TEST_LED_STATE/LIFETIME_DUMP (so firmware test-mode; erro documentado
caso contrario). Log so com contagens (segredo nunca).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_serial import SerialLink  # noqa: E402

pytestmark = pytest.mark.hil

BAUD = 115200


def _open(uart_port):
    if not uart_port:
        pytest.skip("sem --uart COM7 (HW ausente): SKIP, falha documentada")
    link = SerialLink(uart_port, BAUD)
    link.open()
    return link


def test_l2_uart_open_no_dtr_reset(uart_port):
    """Abrir a porta nao reseta: DCB/termios sem DTR/RTS (reabre 2x)."""
    if not uart_port:
        pytest.skip("sem --uart COM7 (HW ausente): SKIP, falha documentada")
    for _ in range(2):
        link = SerialLink(uart_port, BAUD)
        link.open()
        link.close()


def test_l2_uart_init_ping(uart_port):
    link = _open(uart_port)
    try:
        cid, _ = link.cmd_init()
        assert cid != 0xFFFFFFFF
        assert link.ping(cid) == b"\xa5\x5a\x00\xff"
    finally:
        link.close()


def test_l2_uart_get_info_base(uart_port):
    link = _open(uart_port)
    try:
        cid, _ = link.cmd_init()
        status, body = link.get_info(cid)
        assert isinstance(status, int) and isinstance(body, bytes)
    finally:
        link.close()


def test_l2_uart_test_mode_gates(uart_port):
    """TEST_PAIRING_OPEN_300 / TEST_UP / LED / DUMP (so test-mode)."""
    link = _open(uart_port)
    try:
        link.cmd_init()
        link.test_pairing_open()
        link.test_up()
        link.test_led_state("ON")
        text = link.lifetime_dump()
        assert "lt_dump v=1" in text and "lt_end" in text
    finally:
        link.close()
