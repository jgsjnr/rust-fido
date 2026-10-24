"""BLE GATT 0xFFFD (FFF1-FFF4, frag [op|len]+[seq]) + WiFi AP 192.168.4.1.

Contrato (recon):
- BLE servico 0xFFFD, caracteristicas FFF1 (notify) FFF2 (indicate)
  FFF3 (write) FFF4 (read); frag max 244 B, teto 512 B por mensagem,
  teto CTAPHID 7609 B no reassemble (mesmo teto do USB/serial).
- WiFi AP AegisKey-XXXX em 192.168.4.1: POST /ctap (envelope AEGN) e
  GET /oath/code?account= com timeout curto.
- Sem HW: HwMissingError / TimeoutError reais com mensagem documentada;
  o teste faz skip elegante (nunca aprova sem evidencia). Nenhum segredo em log.
- `bleak` e `requests` importados sob demanda (coleta offline intacta);
  o path padrao usa urllib stdlib para nao exigir requests.

Evidencia sem HW: este modulo nao gera evidencia; apenas levanta a
falta com instrucao de bancada (SSID AP / adaptador BLE).
"""
from __future__ import annotations

import time as _time
import urllib.parse as _parse
import urllib.request as _request
import urllib.error as _urlerror

BLE_SERVICE = 0xFFFD
BLE_CH_NOTIFY = "FFF1"
BLE_CH_INDICATE = "FFF2"
BLE_CH_WRITE = "FFF3"
BLE_CH_READ = "FFF4"

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
def ble_scan(timeout_s: float = SHORT_TIMEOUT_S) -> list:
    """Escaneia BLE filtrando servico 0xFFFD. [] sem radio/HW (skip no teste)."""
    try:
        from bleak import BleakScanner as _Scanner
    except ImportError as e:
        raise HwMissingError("bleak ausente (pip install bleak): %s" % e) from e
    import asyncio as _asyncio

    async def _run():
        devs = await _Scanner.discover(timeout=timeout_s)
        out = []
        for d in devs or []:
            uuids = []
            try:
                uuids = [u.lower() for u in (d.metadata.get("uuids") or [])]
            except Exception:
                uuids = []
            if any("fffd" in u for u in uuids):
                out.append({"address": d.address, "name": d.name or ""})
        return out

    try:
        found = _asyncio.run(_run())
    except OSError as e:
        raise HwMissingError("BLE radio indisponivel: %s" % e) from e
    print(sanitize_log("BLE_SCAN", len(found)), flush=True)
    return found


def ble_probe_fff1_fff4(address: str, timeout_s: float = SHORT_TIMEOUT_S) -> dict:
    """Le descritores FFF1-FFF4 (notify/indicate/write/read) somente leitura.

    Retorna evidencia {fff1..fff4: bool}; sem HW levanta HwMissingError.
    Nunca escreve caracteristicas aqui (probe read-only).
    """
    try:
        from bleak import BleakClient as _Client
    except ImportError as e:
        raise HwMissingError("bleak ausente (pip install bleak): %s" % e) from e
    import asyncio as _asyncio

    async def _run():
        evidence = {"fff1_notify": False, "fff2_indicate": False,
                    "fff3_write": False, "fff4_read": False}
        async with _Client(address, timeout=timeout_s) as cli:
            for svc in cli.services:
                if "fffd" not in str(svc.uuid).lower():
                    continue
                for ch in svc.characteristics:
                    u = str(ch.uuid).lower()
                    props = set(ch.properties or [])
                    if "fff1" in u and ("notify" in props or "indicate" in props):
                        evidence["fff1_notify"] = True
                    if "fff2" in u and "indicate" in props:
                        evidence["fff2_indicate"] = True
                    if "fff3" in u and "write" in props:
                        evidence["fff3_write"] = True
                    if "fff4" in u and "read" in props:
                        evidence["fff4_read"] = True
        return evidence

    try:
        ev = _asyncio.run(_run())
    except OSError as e:
        raise HwMissingError("BLE %s inacessivel: %s" % (address, e)) from e
    print("[hil] BLE_PROBE %s" % ev, flush=True)
    return ev


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
