#!/usr/bin/env python3
"""AegisKey BLE connect test (harness IRL + self-test offline).

Roteiro IRL (8 etapas, cada uma com assert+log; falha = exit!=0 + etapa nomeada):
    SCAN -> CONNECT -> PAIR -> DISCOVER -> READ -> SUBSCRIBE -> WRITE_NOTIFY -> UNPAIR

Contrato: docs/ble-protocol.md + firmware/src/ble_gatt.rs
    servico 0xFFFD; FFF1 write (control-point fragmentado); FFF2 notify
    (status 0=idle,1=processing,2=up-needed); FFF3 read (u16 LE pendente);
    FFF4 read/write (revisao 0x01). Framing FFF1: primeiro
    [op:1, len_hi:1, len_lo:1, data..], continuacao [seq:1, data..],
    fragmento max 244B, total max 512B, CANCEL (0xBE) single-byte.

Regras duras (licoes anteriores):
- MTU race: poll de max_write_without_response_size ate >20, timeout 10s.
- NOTIFY sem CCCD nao chega: usa start_notify (programa CCCD), nunca read polling.
- UP fisico exigido pelo firmware: script pede/instrui, nunca fakea UP.
- Test-mode abre janela via TEST_PAIRING_OPEN no serial (fora deste script).
- Sem segredo em log: logs carregam opcode/tamanhos/status, nunca payload bytes.
- Limpeza: stop_notify + unpair + disconnect sempre (finally).

Usage:
    python tools/ble_connect_test.py --self-test   # offline, sem hardware
    python tools/ble_connect_test.py               # scan 0xFFFD + roteiro
    python tools/ble_connect_test.py --mac AA:BB:CC:DD:EE:FF
    python tools/ble_connect_test.py --mac AA:BB:CC:DD:EE:FF --no-pair
"""

import argparse
import asyncio
import sys
import time

SERVICE_UUID16 = 0xFFFD
CHAR_CONTROL16 = 0xFFF1
CHAR_STATUS16 = 0xFFF2
CHAR_LEN16 = 0xFFF3
CHAR_REVISION16 = 0xFFF4

GATT_REVISION = 0x01

OP_PING = 0x81
OP_MSG = 0x83
OP_CANCEL = 0xBE

STATUS_IDLE = 0
STATUS_PROCESSING = 1
STATUS_UP_NEEDED = 2

MAX_FRAGMENT_BYTES = 244
CONTROL_POINT_LENGTH = 512

DEFAULT_MTU_PAYLOAD = 20
MTU_POLL_TIMEOUT_S = 10.0
MTU_POLL_INTERVAL_S = 0.25

DEFAULT_SCAN_SECONDS = 8.0
DEFAULT_STEP_TIMEOUT_S = 15.0
PING_PAYLOAD = b"aegis-ping"

STAGES = ("SCAN", "CONNECT", "PAIR", "DISCOVER",
          "READ", "SUBSCRIBE", "WRITE_NOTIFY", "UNPAIR")


class StageError(Exception):
    """Falha nomeada de uma etapa do roteiro IRL."""

    def __init__(self, stage, reason):
        super().__init__("[%s] %s" % (stage, reason))
        self.stage = stage
        self.reason = reason


def uuid16(short):
    """Expande handle 16-bit para UUID 128-bit (igual BleContract.uuid16)."""
    return "0000%04X-0000-1000-8000-00805F9B34FB" % (short & 0xFFFF)


SERVICE_UUID = uuid16(SERVICE_UUID16)
CHAR_CONTROL_UUID = uuid16(CHAR_CONTROL16)
CHAR_STATUS_UUID = uuid16(CHAR_STATUS16)
CHAR_LEN_UUID = uuid16(CHAR_LEN16)
CHAR_REVISION_UUID = uuid16(CHAR_REVISION16)


def status_label(status):
    """Rotulo humano do byte FFF2 (sem expor nada alem do status)."""
    if status == STATUS_IDLE:
        return "idle"
    if status == STATUS_PROCESSING:
        return "processing"
    if status == STATUS_UP_NEEDED:
        return "up-needed (press device button)"
    return "unknown"


def parse_fff2(data):
    """Parser FFF2: exige >=1B, retorna status (primeiro byte)."""
    if not data:
        raise ValueError("FFF2 vazio")
    return data[0]


def parse_fff3(data):
    """Parser FFF3: u16 LE do tamanho pendente (exige >=2B)."""
    if len(data) < 2:
        raise ValueError("FFF3 curto: %dB" % len(data))
    return data[0] | (data[1] << 8)


def parse_fff4(data):
    """Parser FFF4: primeiro byte = revisao."""
    if not data:
        raise ValueError("FFF4 vazio")
    return data[0]


def check_fff4_revision(data):
    """Assert FFF4 == 0x01 (rejeita resto, igual firmware write_revision)."""
    rev = parse_fff4(bytes(data))
    if rev != GATT_REVISION:
        raise ValueError("FFF4 revision 0x%02X != 0x%02X" % (rev, GATT_REVISION))
    return rev


def clamp_mtu_payload(value):
    """Normaliza MTU payload: None/invalido -> default 20."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DEFAULT_MTU_PAYLOAD
    if n <= 0 or n > MAX_FRAGMENT_BYTES:
        return DEFAULT_MTU_PAYLOAD
    return n


def fmt_tx(opcode, idx, total, frag_len, payload_len):
    """Linha de log TX sem segredo: so opcode/contadores/tamanhos."""
    return ("TX FFF1 OP=0x%02X frag %d/%d frag_len=%d payload_len=%d"
            % (opcode, idx, total, frag_len, payload_len))


def fmt_rx_fff2(status, nbytes):
    """Linha de log RX FFF2 sem segredo: so status/tamanho."""
    return "RX FFF2 status=%s (0x%02X) nbytes=%d" % (
        status_label(status), status, nbytes)


def split_fragments(opcode, payload, max_fragment=MAX_FRAGMENT_BYTES):
    """Fragmenta payload para FFF1 (espelha ble_split_fragments do bridge).

    Primeiro: [op, len_hi, len_lo, data..] (ate max_fragment-3 de dados).
    Continuacao: [seq, data..] (ate max_fragment-1 cada, seq=0,1,...).
    CANCEL (0xBE) e single-byte. Total limitado a 512B.
    """
    payload = bytes(payload)
    if max_fragment < 4:
        raise ValueError("max_fragment muito pequeno: %d" % max_fragment)
    if opcode == OP_CANCEL:
        if payload:
            raise ValueError("CANCEL nao carrega payload")
        return [bytes([OP_CANCEL])]
    if len(payload) > CONTROL_POINT_LENGTH:
        raise ValueError("payload %dB > %dB" % (len(payload), CONTROL_POINT_LENGTH))
    total = len(payload)
    first_cap = min(max_fragment - 3, total)
    out = [bytes([opcode, (total >> 8) & 0xFF, total & 0xFF])
           + payload[:first_cap]]
    offset = first_cap
    seq = 0
    while offset < total:
        chunk = min(max_fragment - 1, total - offset)
        out.append(bytes([(seq & 0xFF)]) + payload[offset:offset + chunk])
        offset += chunk
        seq = (seq + 1) & 0xFF
    return out


def reassemble(fragments):
    """Inverso de split_fragments (espelha BleReassembler::feed).

    Retorna (opcode, payload). Levanta ValueError em truncado/colisao/limite.
    """
    frags = [bytes(f) for f in fragments]
    if not frags:
        raise ValueError("sem fragmentos")
    first = frags[0]
    if first == bytes([OP_CANCEL]):
        if len(frags) > 1:
            raise ValueError("colisao: CANCEL com transacao ativa")
        return (OP_CANCEL, b"")
    if len(first) < 3:
        raise ValueError("primeiro fragmento curto: %dB" % len(first))
    opcode = first[0]
    total = (first[1] << 8) | first[2]
    if total > CONTROL_POINT_LENGTH:
        raise ValueError("total %dB > %dB" % (total, CONTROL_POINT_LENGTH))
    buf = first[3:]
    for frag in frags[1:]:
        if not frag:
            raise ValueError("continuacao vazia")
        buf += frag[1:]
    if len(buf) != total:
        raise ValueError("truncado: %dB != declarado %dB" % (len(buf), total))
    return (opcode, bytes(buf))


def parse_notify_frame(data):
    """Parser generico do frame de resposta: [op, status, payload...]."""
    data = bytes(data)
    if len(data) < 2:
        raise ValueError("notify frame curto: %dB" % len(data))
    return (data[0], data[1], data[2:])


def log(stage, msg):
    """Log padrao [BLE][<stage>] (nunca recebe payload bytes)."""
    print("[BLE][%s] %s" % (stage, msg), flush=True)


def _match_device(device, mac):
    addr = (getattr(device, "address", "") or "").lower()
    if mac and addr != mac.lower():
        return False
    if mac:
        return True
    uuids = [str(u).lower() for u in (getattr(device, "metadata", {}) or {}).get("uuids", [])]
    if SERVICE_UUID.lower() in uuids:
        return True
    name = (getattr(device, "name", "") or "")
    return name.startswith("AegisKey")


async def _poll_mtu_payload(client, timeout=MTU_POLL_TIMEOUT_S):
    """Poll anti-race: espera max_write_without_response_size > 20."""
    deadline = time.monotonic() + timeout
    last = DEFAULT_MTU_PAYLOAD
    while time.monotonic() < deadline:
        for attr in ("max_write_without_response_size", "mtu_size"):
            try:
                raw = getattr(client, attr, None)
                val = raw() if callable(raw) else raw
                if isinstance(val, int) and val > DEFAULT_MTU_PAYLOAD:
                    if attr == "mtu_size":
                        val = max(DEFAULT_MTU_PAYLOAD + 1, val - 3)
                    return min(int(val), MAX_FRAGMENT_BYTES)
                if isinstance(val, int) and val > 0:
                    last = int(val)
            except Exception:
                pass
        await asyncio.sleep(MTU_POLL_INTERVAL_S)
    return clamp_mtu_payload(last)


async def run_live(args):
    """Roteiro IRL completo. Retorna 0; levanta StageError na etapa que falhar."""
    try:
        from bleak import BleakClient, BleakScanner
    except ImportError as exc:
        raise StageError("SCAN", "bleak ausente: pip install bleak (%s)" % exc)

    mac = (args.mac or "").strip() or None
    scan_seconds = float(args.scan_seconds or DEFAULT_SCAN_SECONDS)
    step_timeout = float(args.step_timeout or DEFAULT_STEP_TIMEOUT_S)

    # -- SCAN -------------------------------------------------------------
    log("SCAN", "procurando 0xFFFD por %.0fs%s" % (
        scan_seconds, (" mac=%s" % mac) if mac else " (filtro 0xFFFD/AegisKey-*)"))
    try:
        devices = await BleakScanner.discover(timeout=scan_seconds)
    except Exception as exc:
        raise StageError("SCAN", "discover falhou: %r" % exc)
    target = next((d for d in devices if _match_device(d, mac)), None)
    if target is None:
        seen = len(devices)
        raise StageError(
            "SCAN", "device nao encontrado (vistos=%d). "
            "Abra a janela: hold 5s GPIO0 (adv pareamento 60s) ou "
            "TEST_PAIRING_OPEN no serial em test-mode." % seen)
    log("SCAN", "encontrado addr=%s name=%s" % (
        getattr(target, "address", "?"), getattr(target, "name", "?") or "?"))

    address = target.address
    notifies = []
    notify_event = asyncio.Event()
    paired_here = False
    client = BleakClient(address)

    def _on_fff2(_handle, data):
        notifies.append(bytes(data))
        notify_event.set()

    try:
        # -- CONNECT ------------------------------------------------------
        log("CONNECT", "conectando %s ..." % address)
        try:
            await asyncio.wait_for(client.connect(), timeout=step_timeout)
        except Exception as exc:
            raise StageError("CONNECT", "connect falhou: %r" % exc)
        if not getattr(client, "is_connected", False):
            raise StageError("CONNECT", "is_connected=False apos connect")
        log("CONNECT", "conectado")

        # -- PAIR ---------------------------------------------------------
        if args.no_pair:
            log("PAIR", "pulando bond (--no-pair); FFF1 pode exigir bonding")
        else:
            log("PAIR", "bonding JustWorks (requer janela 60s aberta no device) ...")
            try:
                pair = getattr(client, "pair", None)
                if pair is None:
                    raise StageError(
                        "PAIR", "backend sem pair(); use BlueZ/Windows e abra "
                        "a janela (hold 5s / TEST_PAIRING_OPEN)")
                await asyncio.wait_for(pair(), timeout=step_timeout)
                paired_here = True
                log("PAIR", "bond ok")
            except StageError:
                raise
            except Exception as exc:
                raise StageError(
                    "PAIR", "pair falhou: %r. Abra a janela de pareamento "
                    "(hold 5s GPIO0 / TEST_PAIRING_OPEN) e tente de novo." % (exc,))

        # -- DISCOVER -----------------------------------------------------
        log("DISCOVER", "checando GATT 0xFFFD/FFF1-FFF4 ...")
        try:
            svcs = getattr(client, "services", None)
            if svcs is None or len(list(svcs)) == 0:
                # bleak >=0.20: sem get_services(); servicos vêm do connect.
                # Aguarda breve (descoberta assíncrona no backend) e relê.
                for _ in range(20):
                    await asyncio.sleep(0.5)
                    svcs = getattr(client, "services", None)
                    if svcs is not None and len(list(svcs)) > 0:
                        break
            if svcs is None or len(list(svcs)) == 0:
                raise StageError("DISCOVER", "servicos vazios apos connect (bleak sem get_services)")
            found = set()
            for svc in svcs:
                for ch in getattr(svc, "characteristics", []):
                    found.add(str(getattr(ch, "uuid", "")).lower())
            missing = [u for u in (CHAR_CONTROL_UUID, CHAR_STATUS_UUID,
                                   CHAR_LEN_UUID, CHAR_REVISION_UUID)
                       if u.lower() not in found]
        except Exception as exc:
            raise StageError("DISCOVER", "get_services falhou: %r" % exc)
        if missing:
            raise StageError("DISCOVER", "chars ausentes: %s" % ",".join(missing))
        log("DISCOVER", "FFF1-FFF4 presentes")

        # -- READ ---------------------------------------------------------
        log("READ", "lendo FFF4 (revisao) + FFF3 (pendente) ...")
        try:
            raw_rev = await asyncio.wait_for(
                client.read_gatt_char(CHAR_REVISION_UUID), timeout=step_timeout)
            check_fff4_revision(bytes(raw_rev))
            raw_len = await asyncio.wait_for(
                client.read_gatt_char(CHAR_LEN_UUID), timeout=step_timeout)
            pending = parse_fff3(bytes(raw_len))
        except StageError:
            raise
        except ValueError as exc:
            raise StageError("READ", "%s" % exc)
        except Exception as exc:
            raise StageError("READ", "read falhou: %r" % exc)
        log("READ", "FFF4=0x%02X ok FFF3=%d" % (GATT_REVISION, pending))

        # -- SUBSCRIBE ----------------------------------------------------
        log("SUBSCRIBE", "start_notify FFF2 (programa CCCD) ...")
        try:
            await asyncio.wait_for(
                client.start_notify(CHAR_STATUS_UUID, _on_fff2), timeout=step_timeout)
        except Exception as exc:
            raise StageError(
                "SUBSCRIBE", "start_notify falhou: %r (sem CCCD nao ha notify)" % (exc,))
        log("SUBSCRIBE", "SUB FFF2 ok")

        # -- WRITE_NOTIFY -------------------------------------------------
        mtu = await _poll_mtu_payload(client)
        log("WRITE_NOTIFY", "MTU payload efetivo=%d; PING 0x81 payload_len=%d"
            % (mtu, len(PING_PAYLOAD)))
        frags = split_fragments(OP_PING, PING_PAYLOAD, max_fragment=mtu)
        notify_event.clear()
        try:
            for i, frag in enumerate(frags, 1):
                log("WRITE_NOTIFY", fmt_tx(OP_PING, i, len(frags), len(frag),
                                           len(PING_PAYLOAD)))
                await asyncio.wait_for(
                    client.write_gatt_char(CHAR_CONTROL_UUID, frag, response=False),
                    timeout=step_timeout)
            try:
                await asyncio.wait_for(notify_event.wait(), timeout=step_timeout)
            except asyncio.TimeoutError:
                raise StageError(
                    "WRITE_NOTIFY", "sem notify FFF2 em %.0fs. "
                    "Causas: UP fisico pendente no device (toque no botao), "
                    "CCCD nao programado, ou MTU race." % step_timeout)
            raw = notifies[-1]
            status = parse_fff2(bytes(raw))
            log("WRITE_NOTIFY", fmt_rx_fff2(status, len(raw)))
            if status == STATUS_UP_NEEDED:
                raise StageError(
                    "WRITE_NOTIFY", "device pediu UP fisico (FFF2=0x02). "
                    "Toque no botao do device e repita. UP nunca e fakeado.")
            if status not in (STATUS_IDLE, STATUS_PROCESSING):
                raise StageError(
                    "WRITE_NOTIFY", "status inesperado 0x%02X" % status)
        except StageError:
            raise
        except Exception as exc:
            raise StageError("WRITE_NOTIFY", "write/notify falhou: %r" % exc)
        log("WRITE_NOTIFY", "PING ok notifies=%d" % len(notifies))

        # -- UNPAIR -------------------------------------------------------
        log("UNPAIR", "limpando (stop_notify%s) ..." % (
            "+unpair" if paired_here and not args.no_pair else ""))
        try:
            try:
                await client.stop_notify(CHAR_STATUS_UUID)
            except Exception:
                pass
            if paired_here and not args.no_pair:
                unpair = getattr(client, "unpair", None)
                if unpair is not None:
                    await asyncio.wait_for(unpair(), timeout=step_timeout)
                    log("UNPAIR", "unpair ok")
                else:
                    log("UNPAIR", "backend sem unpair(); mantendo bond")
            else:
                log("UNPAIR", "bond mantido (nada a desfazer)")
        except Exception as exc:
            raise StageError("UNPAIR", "limpeza falhou: %r" % exc)
        return 0
    finally:
        try:
            if getattr(client, "is_connected", False):
                try:
                    await client.stop_notify(CHAR_STATUS_UUID)
                except Exception:
                    pass
                await client.disconnect()
        except Exception:
            pass


def run_self_test():
    """Checks offline: fragments, framing, parsers (sem hardware, sem bleak)."""
    passed = failed = 0

    def check(name, fn):
        try:
            fn()
            print("PASS %s" % name)
            return True
        except Exception as e:
            print("FAIL %s (%s)" % (name, e))
            return False

    def t_uuid16():
        assert uuid16(0xFFFD) == "0000FFFD-0000-1000-8000-00805F9B34FB"
        assert uuid16(0xFFF1) == "0000FFF1-0000-1000-8000-00805F9B34FB"
        assert SERVICE_UUID == uuid16(SERVICE_UUID16)
        assert CHAR_CONTROL_UUID == uuid16(CHAR_CONTROL16)

    def t_status_label():
        assert status_label(0) == "idle"
        assert status_label(1) == "processing"
        assert "press" in status_label(2)
        assert status_label(9) == "unknown"

    def t_parse_fff2():
        assert parse_fff2(b"\x00") == 0
        assert parse_fff2(b"\x02") == 2
        try:
            parse_fff2(b"")
            raise AssertionError("vazio devia falhar")
        except ValueError:
            pass

    def t_parse_fff3():
        assert parse_fff3(b"\x0a\x00") == 10
        assert parse_fff3(b"\x00\x02") == 512
        try:
            parse_fff3(b"\x01")
            raise AssertionError("curto devia falhar")
        except ValueError:
            pass

    def t_parse_fff4():
        assert check_fff4_revision(b"\x01") == 0x01
        try:
            check_fff4_revision(b"\x02")
            raise AssertionError("rev errada devia falhar")
        except ValueError:
            pass
        try:
            check_fff4_revision(b"")
            raise AssertionError("vazio devia falhar")
        except ValueError:
            pass

    def t_single_fragment_shape():
        frags = split_fragments(OP_PING, b"\x01\x02\x03\x04")
        assert len(frags) == 1
        assert frags[0] == b"\x81\x00\x04\x01\x02\x03\x04"
        op, payload = reassemble(frags)
        assert op == OP_PING and payload == b"\x01\x02\x03\x04"

    def t_multi_fragment_default_mtu():
        payload = bytes(range(256)) + b"\xaa" * 44  # 300B
        frags = split_fragments(OP_PING, payload)
        assert len(frags) == 2
        assert len(frags[0]) == MAX_FRAGMENT_BYTES  # 3 + 241
        assert frags[0][:3] == b"\x81\x01\x2c"
        assert frags[1][0] == 0  # seq
        assert len(frags[1]) == 1 + 59
        op, back = reassemble(frags)
        assert op == OP_PING and back == payload

    def t_small_mtu_respected():
        payload = bytes(50)
        frags = split_fragments(OP_PING, payload, max_fragment=20)
        assert all(len(f) <= 20 for f in frags)
        assert frags[0][:3] == b"\x81\x00\x32"
        assert len(frags[0]) == 20  # 3 + 17
        assert all(len(f) == 20 for f in frags[1:-1])
        op, back = reassemble(frags)
        assert op == OP_PING and back == payload

    def t_rejects_oversize_and_cancel_shape():
        try:
            split_fragments(OP_PING, bytes(CONTROL_POINT_LENGTH + 1))
            raise AssertionError("oversize devia falhar")
        except ValueError:
            pass
        assert split_fragments(OP_CANCEL, b"") == [b"\xbe"]
        op, payload = reassemble([b"\xbe"])
        assert op == OP_CANCEL and payload == b""
        try:
            split_fragments(OP_CANCEL, b"\x01")
            raise AssertionError("cancel com payload devia falhar")
        except ValueError:
            pass

    def t_reassemble_rejects_truncated():
        frags = split_fragments(OP_PING, b"hello world")
        cut = [frags[0][:-2]]  # declara 11B, entrega 9B
        try:
            reassemble(cut)
            raise AssertionError("truncado devia falhar")
        except ValueError:
            pass
        try:
            reassemble([])
            raise AssertionError("vazio devia falhar")
        except ValueError:
            pass

    def t_notify_frame():
        op, status, rest = parse_notify_frame(b"\x83\x00\x01\x02")
        assert (op, status, rest) == (0x83, 0x00, b"\x01\x02")
        try:
            parse_notify_frame(b"\x00")
            raise AssertionError("curto devia falhar")
        except ValueError:
            pass

    def t_mtu_clamp():
        assert clamp_mtu_payload(None) == 20
        assert clamp_mtu_payload(0) == 20
        assert clamp_mtu_payload(244) == 244
        assert clamp_mtu_payload(999) == 20

    def t_log_sem_segredo():
        line = fmt_tx(OP_PING, 1, 2, 20, 50)
        assert "0x81" in line and "50" in line
        assert "aegis" not in line.lower()
        rx = fmt_rx_fff2(2, 1)
        assert "up-needed" in rx

    def t_stage_matrix():
        assert STAGES == ("SCAN", "CONNECT", "PAIR", "DISCOVER",
                          "READ", "SUBSCRIBE", "WRITE_NOTIFY", "UNPAIR")
        assert len(STAGES) == 8

    cases = [("uuid16 expansao", t_uuid16),
             ("status label", t_status_label),
             ("parse FFF2", t_parse_fff2),
             ("parse FFF3 LE", t_parse_fff3),
             ("parse FFF4 revisao", t_parse_fff4),
             ("single fragment shape", t_single_fragment_shape),
             ("multi fragment 244B", t_multi_fragment_default_mtu),
             ("small MTU=20 respeitado", t_small_mtu_respected),
             ("oversize+CANCEL", t_rejects_oversize_and_cancel_shape),
             ("reassemble rejeita truncado", t_reassemble_rejects_truncated),
             ("notify frame", t_notify_frame),
             ("mtu clamp", t_mtu_clamp),
             ("log sem segredo", t_log_sem_segredo),
             ("stage matrix IRL", t_stage_matrix)]
    for name, fn in cases:
        if check(name, fn):
            passed += 1
        else:
            failed += 1
    print("self-test: %d/%d passed" % (passed, passed + failed))
    return 0 if failed == 0 else 1


def main(argv=None):
    """CLI entry point."""
    ap = argparse.ArgumentParser(
        description="AegisKey BLE connect test (scan->connect->bond->discover"
                    "->read->subscribe->write->notify->unpair)")
    ap.add_argument("--mac", default=None, help="endereco BLE alvo (ex. AA:BB:CC:DD:EE:FF)")
    ap.add_argument("--no-pair", action="store_true", help="pula bonding/pairing")
    ap.add_argument("--scan-seconds", type=float, default=DEFAULT_SCAN_SECONDS)
    ap.add_argument("--step-timeout", type=float, default=DEFAULT_STEP_TIMEOUT_S)
    ap.add_argument("--self-test", action="store_true",
                    help="checks offline, sem hardware")
    args = ap.parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        return asyncio.run(run_live(args))
    except StageError as exc:
        print("FAIL %s (%s)" % (exc.stage, exc.reason))
        return 1
    except KeyboardInterrupt:
        print("FAIL INTERRUPTED (operador cancelou)")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
