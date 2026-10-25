"""BLE GATT 0xFFFD (FFF1-FFF4, frag [op|len]+[seq]) + WiFi AP 192.168.4.1.

Contrato (firmware `ble/gatt_core.rs`, APP-INTEGRACAO §1.1):
- BLE servico 0xFFFD, caracteristicas FFF1 control/write, FFF2 status/notify,
  FFF3 len/read (u16 BE, 0 = idle), FFF4 revision/read-write (so aceita 0x01).
  Opcodes FFF1: PING 0x81, MSG 0x83, CANCEL 0xBE ([BE 00 00]).
  Resposta FFF2 notify: [opcode, status, payload...]; status 0x00 OK,
  0x01 presence-required (UP fisico), 0x05 need-binding.
  Proximidade usa servico separado 0xFFFE (nunca FFF1-FFF4).
  Frag max 244 B, teto 512 B por mensagem (CONTROL_POINT_LENGTH);
- WiFi AP AegisKey-XXXX em 192.168.4.1: POST /ctap (envelope AEGN) e
  GET /oath/code?account= com timeout curto.
- Sem HW: HwMissingError / TimeoutError reais com mensagem documentada;
  o teste faz skip elegante (nunca aprova sem evidencia). Nenhum segredo em log.
- `bleak` e `requests` importados sob demanda (coleta offline intacta);
  o path padrao usa urllib stdlib para nao exigir requests.

Evidencia sem HW: este modulo nao gera evidencia; apenas levanta a
falta com instrucao de bancada (SSID AP / adaptador BLE / janela pairing
TEST_PAIRING_OPEN_300 via UART COM7 antes do scan live).
"""
from __future__ import annotations

import time as _time
import urllib.parse as _parse
import urllib.request as _request
import urllib.error as _urlerror

BLE_SERVICE = 0xFFFD
BLE_CH_CONTROL = "FFF1"  # control/write (host -> device, frags [op|len]+[seq])
BLE_CH_STATUS = "FFF2"  # status/notify (device -> host, [opcode, status, ...])
BLE_CH_LEN = "FFF3"  # len/read (u16 BE pendente, 0 = idle)
BLE_CH_REVISION = "FFF4"  # revision/read-write (so aceita GATT_REVISION)

OP_PING = 0x81
OP_MSG = 0x83
OP_CANCEL = 0xBE
GATT_REVISION = 0x01
GATT_STATUS_OK = 0x00
GATT_STATUS_PRESENCE_REQUIRED = 0x01  # UP fisico (latch por operacao no BLE)
GATT_STATUS_NEED_BINDING = 0x05  # vinculo claim (so BLE, nunca USB)

AEGIS_NAME_PREFIX = "AegisKey"

BLE_FRAG_MAX = 244
BLE_MSG_MAX = 512
CTAPHID_CEILING = 7609

WIFI_AP_BASE = "http://192.168.4.1"
AEGN_MAGIC = b"AEGN"
AEGN_VERSION = 0x01

SHORT_TIMEOUT_S = 5.0


class HwMissingError(OSError):
    """Radio/AP ausente: falha real documentada, nunca mascarada."""


# -- fragmentacao BLE [op|len]+[seq] --------------------------------------
def ble_frag(op: int, payload: bytes, mtu: int = BLE_FRAG_MAX) -> list:
    """Fragmenta em [op|len_BE16|chunk]+[seq|chunk...]; len total em cabeca."""
    if not 0 <= op <= 0xFF:
        raise ValueError("op must fit in one byte")
    body = bytes(payload)
    if len(body) > BLE_MSG_MAX:
        raise ValueError("ble message over 512 B")
    if not 1 <= mtu <= BLE_FRAG_MAX:
        raise ValueError("mtu fora de 1..244")
    import struct as _s
    frags = []
    head = bytes((op,)) + _s.pack(">H", len(body)) + body[:max(0, mtu - 3)]
    frags.append(head)
    off = len(head) - 3
    if off < len(body) and mtu < 2:
        raise ValueError("mtu sem progresso p/ continuacao (min 2)")
    seq = 0
    while off < len(body):
        chunk = body[off:off + mtu - 1]
        frags.append(bytes((seq,)) + chunk)
        off += len(chunk)
        seq = (seq + 1) & 0xFF
    return frags


def ble_defrag(frags: list) -> tuple:
    """Remonta frags -> (op, payload). Fail-closed em cabeca/tamanho."""
    import struct as _s
    if not frags:
        raise ValueError("no frags")
    first = bytes(frags[0])
    if len(first) < 3:
        raise ValueError("bad frag header")
    op = first[0]
    total = _s.unpack_from(">H", first, 1)[0]
    if total > BLE_MSG_MAX:
        raise ValueError("ble message over 512 B")
    buf = bytearray(first[3:])
    for f in frags[1:]:
        raw = bytes(f)
        if len(raw) < 1:
            raise ValueError("bad cont frag")
        buf.extend(raw[1:])
    if len(buf) < total:
        raise ValueError("truncated ble message")
    return op, bytes(buf[:total])


def sanitize_log(name: str, byte_count: int = 0) -> str:
    if byte_count:
        return "[hil] %s bytes=%d" % (name, byte_count)
    return "[hil] %s" % name


# -- BLE scan/conexao (bleak sob demanda) ----------------------------------
def _ble_errors():
    """Tupla de erros de transporte BLE (falta/transiente => HwMissingError)."""
    try:
        from bleak.exc import BleakError as _BleakError
        return (OSError, _BleakError)
    except ImportError:
        return (OSError,)


def _ble_uuids_of(device, adv) -> list:
    """UUIDs do anuncio (bleak 3.x: via AdvertisementData; fallback metadata)."""
    try:
        if adv is not None:
            uuids = list(getattr(adv, "service_uuids", None) or [])
            if uuids:
                return [str(u).lower() for u in uuids]
    except Exception:
        pass
    try:
        return [str(u).lower() for u in ((device.metadata or {}).get("uuids") or [])]
    except Exception:
        return []


def _ble_name_of(device, adv) -> str:
    """Nome local do anuncio (fallback nome do device)."""
    try:
        if adv is not None and getattr(adv, "local_name", None):
            return str(adv.local_name)
    except Exception:
        pass
    return str(getattr(device, "name", None) or getattr(device, "address", "?"))


def ble_scan(timeout_s: float = SHORT_TIMEOUT_S) -> list:
    """Escaneia BLE filtrando servico 0xFFFD ou nome AegisKey*.

    Retorna [{address, name, rssi, uuids}]; [] sem radio/HW/janela
    (skip no teste). O anuncio 0xFFFD so aparece com a janela de
    pairing aberta (TEST_PAIRING_OPEN_300 via UART COM7). Log so
    com contagens (sem MAC/nome em log).
    """
    try:
        from bleak import BleakScanner as _Scanner
    except ImportError as e:
        raise HwMissingError("bleak ausente (pip install bleak): %s" % e) from e
    import asyncio as _asyncio

    async def _run():
        found = await _Scanner.discover(timeout=timeout_s, return_adv=True)
        items = list(found.values()) if isinstance(found, dict) else list(found or [])
        out = []
        for item in items:
            if isinstance(item, tuple) and len(item) == 2:
                dev, adv = item
            else:
                dev, adv = item, None
            uuids = _ble_uuids_of(dev, adv)
            name = _ble_name_of(dev, adv)
            if any("fffd" in u for u in uuids) or name.startswith(AEGIS_NAME_PREFIX):
                try:
                    rssi = getattr(adv, "rssi", getattr(dev, "rssi", None))
                except Exception:
                    rssi = None
                out.append({"address": str(dev.address), "name": name,
                            "rssi": rssi, "uuids": uuids})
        return out

    try:
        hits = _asyncio.run(_run())
    except _ble_errors() as e:
        raise HwMissingError("BLE radio indisponivel: %s" % e) from e
    print(sanitize_log("BLE_SCAN", len(hits)), flush=True)
    return hits


def ble_probe_fff1_fff4(address: str, timeout_s: float = SHORT_TIMEOUT_S) -> dict:
    """Sonda GATT 0xFFFD (FFF1 control/write, FFF2 notify, FFF3 len,
    FFF4 revision) somente leitura + leituras FFF3/FFF4.

    Retorna evidencia {fff1_write, fff2_notify, fff3_read, fff4_read,
    fff4_writable, fff3_len, fff4_revision}; sem HW levanta HwMissingError.
    Nunca escreve caracteristicas aqui (probe read-only: FFF4 write
    e FFF1 write ficam para os testes live explicitos).
    """
    try:
        from bleak import BleakClient as _Client
    except ImportError as e:
        raise HwMissingError("bleak ausente (pip install bleak): %s" % e) from e
    import asyncio as _asyncio

    async def _run():
        evidence = {"fff1_write": False, "fff2_notify": False,
                    "fff3_read": False, "fff4_read": False,
                    "fff4_writable": False, "fff3_len": None,
                    "fff4_revision": None}
        async with _Client(address, timeout=timeout_s) as cli:
            for svc in cli.services:
                if "fffd" not in str(svc.uuid).lower():
                    continue
                for ch in svc.characteristics:
                    u = str(ch.uuid).lower()
                    props = set(ch.properties or [])
                    if "fff1" in u and "write" in props:
                        evidence["fff1_write"] = True
                    if "fff2" in u and "notify" in props:
                        evidence["fff2_notify"] = True
                    if "fff3" in u and "read" in props:
                        evidence["fff3_read"] = True
                        try:
                            raw = bytes(await cli.read_gatt_char(ch.uuid))
                            if len(raw) == 2:
                                import struct as _s
                                evidence["fff3_len"] = _s.unpack(">H", raw)[0]
                        except Exception:
                            evidence["fff3_len"] = None
                    if "fff4" in u and "read" in props:
                        evidence["fff4_read"] = True
                        try:
                            raw = bytes(await cli.read_gatt_char(ch.uuid))
                            if len(raw) == 1:
                                evidence["fff4_revision"] = raw[0]
                        except Exception:
                            evidence["fff4_revision"] = None
                        if "write" in props:
                            evidence["fff4_writable"] = True
        return evidence

    try:
        ev = _asyncio.run(_run())
    except _ble_errors() as e:
        raise HwMissingError("BLE %s inacessivel: %s" % (address, e)) from e
    print("[hil] BLE_PROBE %s" % {k: v for k, v in ev.items()}, flush=True)
    return ev


def ble_subscribe_fff2(address: str, timeout_s: float = SHORT_TIMEOUT_S,
                       idle_s: float = 1.0) -> dict:
    """Assina FFF2 notify e coleta quadros idle (read-only, sem escrita).

    Retorna {subscribed: bool, notif_count: int}; sem HW levanta
    HwMissingError. Log so com contagens (payload nunca em log).
    """
    try:
        from bleak import BleakClient as _Client
    except ImportError as e:
        raise HwMissingError("bleak ausente (pip install bleak): %s" % e) from e
    import asyncio as _asyncio

    fff2 = "0000fff2-0000-1000-8000-00805f9b34fb"

    async def _run():
        got = []

        def _cb(_sender, data):
            got.append(bytes(data))

        async with _Client(address, timeout=timeout_s) as cli:
            await cli.start_notify(fff2, _cb)
            await _asyncio.sleep(min(idle_s, timeout_s))
            try:
                await cli.stop_notify(fff2)
            except Exception:
                pass
        return {"subscribed": True, "notif_count": len(got)}

    try:
        ev = _asyncio.run(_run())
    except _ble_errors() as e:
        raise HwMissingError("BLE %s inacessivel: %s" % (address, e)) from e
    print(sanitize_log("FFF2_SUBSCRIBED", ev["notif_count"]), flush=True)
    return ev


def ble_ping(address: str, payload: bytes = b"\xa5\x5a\x00\xff",
             timeout_s: float = SHORT_TIMEOUT_S,
             notify_wait_s: float = 3.0) -> dict:
    """PING 0x81 via frag FFF1 + eco em notify FFF2.

    Retorna {written_frags, notifs: [bytes], echo: bool, status: int|None}.
    Gate do firmware vira evidencia, nao excecao: status 0x01 =
    presence-required (UP fisico por operacao, latch UART nao vale no
    BLE), 0x05 = need-binding (claim 0x28 antes). Payload padrao e
    eco fixo nao-segredo; log so com contagens.
    """
    try:
        from bleak import BleakClient as _Client
    except ImportError as e:
        raise HwMissingError("bleak ausente (pip install bleak): %s" % e) from e
    import asyncio as _asyncio

    fff1 = "0000fff1-0000-1000-8000-00805f9b34fb"
    fff2 = "0000fff2-0000-1000-8000-00805f9b34fb"
    frags = ble_frag(OP_PING, bytes(payload))

    async def _run():
        got = []

        def _cb(_sender, data):
            got.append(bytes(data))

        async with _Client(address, timeout=timeout_s) as cli:
            await cli.start_notify(fff2, _cb)
            for f in frags:
                await cli.write_gatt_char(fff1, f, response=True)
            await _asyncio.sleep(min(notify_wait_s, timeout_s))
            try:
                await cli.stop_notify(fff2)
            except Exception:
                pass
        return got

    try:
        notifs = _asyncio.run(_run())
    except _ble_errors() as e:
        raise HwMissingError("BLE %s inacessivel: %s" % (address, e)) from e
    echo = any(len(n) >= 2 + len(payload) and n[0] == OP_PING
               and n[1] == GATT_STATUS_OK
               and bytes(n[2:2 + len(payload)]) == bytes(payload)
               for n in notifs)
    status = notifs[-1][1] if notifs and len(notifs[-1]) >= 2 \
        and notifs[-1][0] == OP_PING else None
    print(sanitize_log("BLE_PING_NOTIFS", len(notifs)), flush=True)
    return {"written_frags": len(frags), "notifs": notifs,
            "echo": echo, "status": status}


def windows_ble_paired(name_substr: str = AEGIS_NAME_PREFIX,
                       timeout_s: float = 8.0) -> bool | None:
    """Checa se o Windows enumera o device como BLE pareado (somente leitura).

    Retorna True (pareado/visivel no PnP Bluetooth), False (nao pareado)
    ou None (indeterminado: sem powershell/Get-PnpDevice). Bonding real
    (hold+UP fisico + pareamento) nunca e executado aqui.
    """
    import shutil as _sh
    import subprocess as _sp
    ps = _sh.which("powershell")
    if not ps:
        return None
    try:
        out = _sp.run(
            [ps, "-NoProfile", "-Command",
             "Get-PnpDevice -Class Bluetooth | "
             "Select-Object -ExpandProperty FriendlyName"],
            capture_output=True, text=True, timeout=timeout_s)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    names = (out.stdout or "").splitlines()
    return any(name_substr.lower() in (n or "").lower() for n in names)


# -- WiFi AP (urllib stdlib, timeout curto) ----------------------------------
def validate_aegn_envelope(raw: bytes) -> int:
    if len(raw) < 33 or raw[0:4] != AEGN_MAGIC or raw[4] != AEGN_VERSION:
        raise ValueError("invalid AEGN envelope")
    return len(raw) - 17


def wifi_post_ctap(ap_base: str, envelope: bytes,
                   timeout_s: float = SHORT_TIMEOUT_S) -> bytes:
    """POST /ctap com envelope AEGN; HTTPError vira OSError documentado."""
    raw = bytes(envelope)
    validate_aegn_envelope(raw)
    url = ap_base.rstrip("/") + "/ctap"
    req = _request.Request(url, data=raw,
                           headers={"Content-Type": "application/octet-stream"})
    try:
        with _request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
    except _urlerror.HTTPError as e:
        raise OSError("ctap post falhou: HTTP %d" % e.code) from e
    except OSError as e:
        raise HwMissingError(
            "AP %s inacessivel (conectar no SSID AegisKey-XXXX): %s" % (ap_base, e)) from e
    print(sanitize_log("WIFI_CTAP_RESPONSE", len(body)), flush=True)
    return body


def wifi_get_oath_code(ap_base: str, account: str,
                       timeout_s: float = SHORT_TIMEOUT_S) -> tuple:
    """GET /oath/code?account=: retorna (account, code, remaining_s).

    Timeout curto; sem AP levanta HwMissingError (skip elegante no teste).
    """
    if not account or len(account) > 128:
        raise ValueError("bad account")
    url = ap_base.rstrip("/") + "/oath/code?account=" + _parse.quote(account)
    try:
        with _request.urlopen(url, timeout=timeout_s) as resp:
            status, body = resp.status, resp.read()
    except _urlerror.HTTPError as e:
        if e.code == 401:
            raise PermissionError("presence required") from e
        if e.code == 404:
            raise LookupError("unknown account") from e
        raise OSError("oath fetch failed: HTTP %d" % e.code) from e
    except OSError as e:
        raise HwMissingError(
            "AP %s inacessivel (conectar no SSID AegisKey-XXXX): %s" % (ap_base, e)) from e
    import json as _json
    data = _json.loads(body.decode("utf-8")[:512])
    code = data.get("code", "")
    if len(code) not in (6, 7, 8) or not code.isdigit():
        raise ValueError("bad code format")
    print(sanitize_log("OATH_FETCHED"), flush=True)
    return data.get("account", ""), code, data.get("remaining_seconds", -1)


def wifi_ap_probe(ap_base: str = WIFI_AP_BASE,
                  timeout_s: float = SHORT_TIMEOUT_S) -> dict:
    """Probe read-only do AP: GET /oath/code com conta invalida esperada.

    Evidencia {reachable, http_status}; sem rede vira HwMissingError.
    """
    url = ap_base.rstrip("/") + "/oath/code?account=__hil_probe__"
    try:
        with _request.urlopen(url, timeout=timeout_s) as resp:
            return {"reachable": True, "http_status": resp.status}
    except _urlerror.HTTPError as e:
        return {"reachable": True, "http_status": e.code}
    except OSError as e:
        raise HwMissingError(
            "AP %s inacessivel (conectar no SSID AegisKey-XXXX): %s" % (ap_base, e)) from e


def bench_stamp() -> str:
    """Carimbo de bancada para falha documentada (sem HW)."""
    return "bancada: AP SSID AegisKey-XXXX @192.168.4.1, BLE 0xFFFD; ts=%.0f" % _time.time()
