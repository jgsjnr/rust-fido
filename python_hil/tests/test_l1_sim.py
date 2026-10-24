"""L1 sim: piloto TCP/CTAPHID sem HW fisico (loopback local e vetores offline).

Sem HW fisico: o guest de loopback prova a camada TCP/CTAPHID (framing,
INIT->CID, PING, dump, TEST_UP). Nenhum teste finge HW: sem --tcp o
caso live faz skip; o self-test declara LOOPBACK na evidencia.
Teto CTAPHID 7609 B; BLE frag 244/512 B offline.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_ble_wifi import ble_defrag, ble_frag  # noqa: E402
from python_hil.link_serial import (  # noqa: E402
    CMD_CBOR,
    CMD_PING,
    Reassembler,
    frame_message,
    is_text_chunk,
    parse_dump,
)
from python_hil.sim_pilot import self_test as pilot_self_test  # noqa: E402
from python_hil.sim_pilot import tcp_pilot  # noqa: E402

pytestmark = pytest.mark.hil


def test_l1_framing_roundtrip_offline():
    payload = bytes(i % 256 for i in range(150))
    pkts = frame_message(0xAABBCCDD, CMD_CBOR, payload)
    assert all(len(p) == 64 for p in pkts)
    asm = Reassembler()
    for p in pkts[:-1]:
        assert asm.feed(p) == ("more", None)
    kind, msg = asm.feed(pkts[-1])
    assert kind == "message" and msg[2] == payload


def test_l1_text_chunk_never_masks_ctap():
    pkt = frame_message(0x11223344, CMD_PING, b"\xa5" * 4)[0]
    assert not is_text_chunk(pkt)
    assert is_text_chunk(b"lt_dump v=1\n" + b"\x00" * (64 - 12))


def test_l1_dump_parser_offline():
    counts, states = parse_dump("lt_dump v=1\nlt.boot=3\nlt.state ACTIVE\nlt_end\n")
    assert counts == {"lt.boot": 3} and states == ["ACTIVE"]


def test_l1_ble_frag_offline():
    frags = ble_frag(0x90, bytes(range(200)))
    assert all(len(f) <= 244 for f in frags)
    op, body = ble_defrag(frags)
    assert op == 0x90 and body == bytes(range(200))
    with pytest.raises(ValueError):
        ble_frag(0x90, bytes(513))


def test_l1_pilot_selftest_loopback():
    """Loopback local: prova TCP/CTAPHID, rotulado LOOPBACK (nao e HW)."""
    ev = pilot_self_test()
    assert ev["verdict"] == "SIM-COVERED" and ev["ping"] and ev["test_up"]


def test_l1_tcp_live_needs_sim(tcp_target):
    """Com --tcp host:port: roteiro total no Renode/QEMU. Sem flag: skip."""
    if not tcp_target:
        pytest.skip("sem --tcp (Renode/QEMU em 127.0.0.1:5678?): SKIP, falha documentada")
    from python_hil.sim_pilot import PilotFail as _PilotFail
    host, _, port = tcp_target.partition(":")
    try:
        ev = tcp_pilot(host or "127.0.0.1", int(port or 5678))
    except _PilotFail as e:
        pytest.skip("sim inativo em %s (HW-ONLY): %s" % (tcp_target, e))
    assert ev["verdict"] == "SIM-COVERED"
