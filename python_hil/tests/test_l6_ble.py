"""L6 BLE funcional via GATT 0xFFFD (read-only + PING eco, sem bonding).

Cobre: mapa FFF1 control/write + FFF2 status/notify + FFF3 len/read +
FFF4 revision (firmware `ble/gatt_core.rs`), frag [op|len_BE]+[seq]
244/512 B, notify FFF2 [opcode, status, payload] (0x00 OK, 0x01 UP,
0x05 binding), scan 0xFFFD/AegisKey*, probe somente-leitura,
PING 0x81 via frag com eco.

Pre-condicao live: janela de pairing aberta
(TEST_PAIRING_OPEN_300 via UART COM7; anuncio 0xFFFD so existe na
janela). Sem --ble-addr faz scan 10 s. Sem HW/radio/janela: SKIP
elegante. Gate de firmware (0x01 UP fisico por operacao no BLE --
latch UART nao vale; 0x05 sem claim): SKIP documentado, nunca FAIL.
Resposta ausente com radio+link OK: FAIL real (report via resumo).
Bonding/pareamento Windows (hold+UP+Bonded): NUNCA executado aqui
(estado persistente + gesto fisico); so leitura do PnP.
Nenhum segredo em log (payloads fora do log; so contagens).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_ble_wifi import (  # noqa: E402
    AEGIS_NAME_PREFIX,
    BLE_CH_CONTROL,
    BLE_CH_LEN,
    BLE_CH_REVISION,
    BLE_CH_STATUS,
    BLE_FRAG_MAX,
    BLE_MSG_MAX,
    GATT_REVISION,
    GATT_STATUS_NEED_BINDING,
    GATT_STATUS_OK,
    GATT_STATUS_PRESENCE_REQUIRED,
    HwMissingError,
    OP_CANCEL,
    OP_MSG,
    OP_PING,
    ble_defrag,
    ble_frag,
    ble_ping,
    ble_probe_fff1_fff4,
    ble_scan,
    ble_subscribe_fff2,
    windows_ble_paired,
)

pytestmark = pytest.mark.hil

PING_ECHO = b"\xa5\x5a\x00\xff"


def _resolve_addr(ble_addr):
    """--ble-addr direto ou primeiro hit do scan 10 s. Sem HW: SKIP."""
    if ble_addr:
        return str(ble_addr)
    try:
        hits = ble_scan(timeout_s=10.0)
    except HwMissingError as e:
        pytest.skip("BLE HW ausente (%s): SKIP, falha documentada" % e)
    if not hits:
        pytest.skip("scan 10 s sem 0xFFFD/AegisKey* (fora de janela ou sem "
                     "radio: abrir TEST_PAIRING_OPEN_300 via COM7): SKIP")
    return hits[0]["address"]


# -- vetores offline (sempre rodam) --------------------------------------

def test_l6_ble_consts_offline():
    """Mapa FFF1-FFF4 + opcodes + revisao congelados com o firmware."""
    assert (BLE_CH_CONTROL, BLE_CH_STATUS, BLE_CH_LEN, BLE_CH_REVISION) == (
        "FFF1", "FFF2", "FFF3", "FFF4")
    assert (OP_PING, OP_MSG, OP_CANCEL) == (0x81, 0x83, 0xBE)
    assert GATT_REVISION == 0x01
    assert (GATT_STATUS_OK, GATT_STATUS_PRESENCE_REQUIRED,
            GATT_STATUS_NEED_BINDING) == (0x00, 0x01, 0x05)
    assert (BLE_FRAG_MAX, BLE_MSG_MAX) == (244, 512)
    assert AEGIS_NAME_PREFIX == "AegisKey"


def test_l6_ble_ping_single_frag_offline():
    """Vetor congelado do ar: PING eco vira 1 frag 81 00 04 a5 5a 00 ff."""
    frags = ble_frag(OP_PING, PING_ECHO)
    assert len(frags) == 1
    assert frags[0] == bytes.fromhex("810004a55a00ff")
    op, body = ble_defrag(frags)
    assert (op, body) == (OP_PING, PING_ECHO)


def test_l6_ble_frag_roundtrip_offline():
    """Ida-volta em tamanhos de borda (0/241/242/244/512) e mtu 1."""
    for size in (0, 1, 241, 242, 244, 245, 511, 512):
        for mtu in (244, 20, 2):
            body = bytes((i & 0xFF for i in range(size)))
            op, back = ble_defrag(ble_frag(OP_MSG, body, mtu=mtu))
            assert (op, back) == (OP_MSG, body)


def test_l6_ble_frag_seq_wrap_offline():
    """Multi-frag longo: seq de continuacao e 1 byte que envolve em 0xFF."""
    body = bytes(512)
    frags = ble_frag(OP_MSG, body, mtu=2)
    assert len(frags) > 0xFF + 1  # forca wrap do seq
    seqs = [f[0] for f in frags[1:]]
    assert seqs[0] == 0 and seqs[0xFF] == 0xFF and seqs[0x100] == 0x00
    op, back = ble_defrag(frags)
    assert (op, back) == (OP_MSG, body)


def test_l6_ble_frag_limits_offline():
    """Fail-closed: 513 B, op fora de 1 byte, mtu fora de 1..244."""
    with pytest.raises(ValueError):
        ble_frag(OP_PING, bytes(513))
    with pytest.raises(ValueError):
        ble_frag(0x1FF, b"x")
    for bad_mtu in (0, 245, 1000):
        with pytest.raises(ValueError):
            ble_frag(OP_PING, b"x", mtu=bad_mtu)
    with pytest.raises(ValueError):
        ble_frag(OP_MSG, b"nao-cabe-em-mtu-1", mtu=1)  # sem progresso
    assert ble_frag(OP_MSG, b"", mtu=1) == [b"\x83\x00\x00"]  # vazio ok
    with pytest.raises(ValueError):
        ble_defrag([])
    with pytest.raises(ValueError):
        ble_defrag([b"\x81\x00"])  # cabeca curta
    with pytest.raises(ValueError):
        ble_defrag([bytes.fromhex("810005414243")])  # declara 5, entrega 3
    with pytest.raises(ValueError):
        ble_defrag([bytes.fromhex("81ffff")])  # teto 512 B estourado


def test_l6_ble_notify_frame_offline():
    """Quadro FFF2 [opcode, status, payload]: 8101 = UP (visto no ar)."""
    gate = bytes((OP_PING, GATT_STATUS_PRESENCE_REQUIRED))
    assert gate == bytes.fromhex("8101")
    assert gate[1] == GATT_STATUS_PRESENCE_REQUIRED
    ok_frame = bytes((OP_PING, GATT_STATUS_OK)) + PING_ECHO
    assert ok_frame[1] == GATT_STATUS_OK
    assert bytes(ok_frame[2:]) == PING_ECHO
    assert bytes.fromhex("0000") == b"\x00\x00"  # FFF3 idle: len 0
    assert bytes((GATT_REVISION,)) == b"\x01"  # FFF4 revision


# -- live: scan / GATT (SKIP sem HW) -------------------------------------

def test_l6_ble_scan_live():
    """Scan 10 s: exige anuncio 0xFFFD ou nome AegisKey* (janela aberta)."""
    try:
        hits = ble_scan(timeout_s=10.0)
    except HwMissingError as e:
        pytest.skip("BLE HW ausente (%s): SKIP, falha documentada" % e)
    if not hits:
        pytest.skip("scan 10 s sem 0xFFFD/AegisKey* (fora de janela ou sem "
                     "radio): SKIP, falha documentada")
    assert any(any("fffd" in u for u in h["uuids"])
               or h["name"].startswith(AEGIS_NAME_PREFIX) for h in hits)


def test_l6_ble_gatt_probe_live(ble_addr):
    """GATT 0xFFFD: FFF1 write + FFF2 notify + FFF3 read + FFF4 rev 0x01."""
    addr = _resolve_addr(ble_addr)
    try:
        ev = ble_probe_fff1_fff4(addr)
    except HwMissingError as e:
        pytest.skip("BLE %s inacessivel (%s): SKIP" % (addr, e))
    assert ev["fff1_write"], "FFF1 sem write (mapa quebrou?)"
    assert ev["fff2_notify"], "FFF2 sem notify (mapa quebrou?)"
    assert ev["fff3_read"], "FFF3 sem read (mapa quebrou?)"
    assert ev["fff4_read"], "FFF4 sem read (mapa quebrou?)"
    assert ev["fff3_len"] == 0, "FFF3 != idle (len=%r)" % ev["fff3_len"]
    assert ev["fff4_revision"] == GATT_REVISION


def test_l6_ble_fff2_subscribe_live(ble_addr):
    """FFF2 subscribe read-only: inscreve, coleta idle, desinscreve."""
    addr = _resolve_addr(ble_addr)
    try:
        ev = ble_subscribe_fff2(addr)
    except HwMissingError as e:
        pytest.skip("BLE %s inacessivel (%s): SKIP" % (addr, e))
    assert ev["subscribed"]


def test_l6_ble_ping_live(ble_addr):
    """PING 0x81 via frag: eco OK = PASS; gate 0x01/0x05 = SKIP; mudo = FAIL."""
    addr = _resolve_addr(ble_addr)
    try:
        res = ble_ping(addr, PING_ECHO)
    except HwMissingError as e:
        pytest.skip("BLE %s inacessivel (%s): SKIP" % (addr, e))
    if res["echo"]:
        assert res["status"] == GATT_STATUS_OK
        return
    if res["status"] == GATT_STATUS_PRESENCE_REQUIRED:
        pytest.skip("PING negou 0x01 presence-required (UP fisico por operacao "
                     "no BLE; latch UART nao vale): SKIP, gate documentado")
    if res["status"] == GATT_STATUS_NEED_BINDING:
        pytest.skip("PING negou 0x05 need-binding (claim 0x28 antes): SKIP, "
                     "gate documentado")
    pytest.fail("PING sem eco e sem gate (notifs=%d): FAIL real, ver resumo"
                % len(res["notifs"]))


def test_l6_ble_windows_enum_live():
    """Windows enumera como BLE pareado? Leitura PnP; bonding nunca executado."""
    paired = windows_ble_paired()
    if paired is None:
        pytest.skip("PnP indeterminado (sem powershell/Get-PnpDevice): SKIP")
    if not paired:
        pytest.skip("Windows nao enumera AegisKey como BLE (sem bonding; "
                     "hold+UP+Bonded fisico fora do escopo read-only): SKIP, "
                     "estado documentado")
