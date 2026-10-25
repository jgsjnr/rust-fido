"""HidLink USB-HID CTAPHID puro (report 64B + Report ID 00).

Contrato (recon):
- USB VID 0x303A PID 0xAE61, 4 IFs (CTAPHID 0x81/0x01, CCID, kbd, WinUSB).
- Report 64B com Report ID 00 prefixado no write (hidapi).
- INIT (0x86) -> CID alocado; PING (0x81) 64B com eco; CBOR (0x90)
  GetInfo (0x04) como base; MSG (0x83) carrega ops:
  vendor 0x20-0x27, wallet 0x35-0x37, rescue 0x2E, fw-log 0x38.
- CCID/KBD/WinUSB: probes SOMENTE leitura (enumerate, nunca claim/write
  fora do CTAPHID; nenhum segredo em log).
- Sem dependencias no import: `hid` (hidapi) importado sob demanda em
  open(); sem HW vira HwMissingError real (skip elegante no teste).

Uso rapido:
    from python_hil.link_usb import HidLink, enumerate_aegis
"""
from __future__ import annotations

import struct as _struct
import time as _time

from python_hil.link_serial import (
    CMD_CBOR,
    CMD_INIT,
    CMD_MSG,
    CMD_PING,
    CTAPHID_CEILING,
    INIT_PAYLOAD_MAX,
    PACKET_SIZE,
    Reassembler,
    frame_message,
    parse_ctap_response,
    sanitize_log,
)

USB_VID = 0x303A
USB_PID = 0xAE61
HID_USAGE_PAGE_FIDO = 0xF1D0

CTAP_GET_INFO = 0x04

OP_VENDOR_MIN = 0x20
OP_VENDOR_MAX = 0x27
OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37
OP_OTA_BEGIN = 0x30
OP_RESCUE = 0x2E
OP_FW_LOG = 0x38

INIT_NONCE_LEN = 8
BROADCAST_CID = 0xFFFFFFFF


class HwMissingError(OSError):
    """USB HID ausente: falha real documentada, nunca mascarada."""


def is_vendor_op(op: int) -> bool:
    return OP_VENDOR_MIN <= op <= OP_VENDOR_MAX


def is_wallet_op(op: int) -> bool:
    return op in (OP_WALLET_GEN, OP_WALLET_LIST, OP_WALLET_ADDR)


def enumerate_aegis(vid: int = USB_VID, pid: int = USB_PID) -> list:
    """Enumera dispositivos HID do par VID/PID (leitura; [] sem HW)."""
    try:
        import hid as _hid
    except ImportError as e:
        raise HwMissingError("hidapi ausente (pip install hidapi): %s" % e) from e
    try:
        found = _hid.enumerate(vid, pid)
    except Exception as e:  # backend hidapi indisponivel na bancada
        raise HwMissingError("hid enumerate falhou: %s" % e) from e
    return list(found or [])


def probe_interfaces(vid: int = USB_VID, pid: int = USB_PID) -> dict:
    """Probes read-only das IFs (CTAPHID/CCID/KBD/WinUSB): so enumerate.

    Nunca abre handle nem escreve; retorna evidencia estruturada
    (contagens + usage pages), sem segredo.
    """
    devs = enumerate_aegis(vid, pid)
    evidence = {"total": len(devs), "fido_ctaphid": 0,
                "ccid_like": 0, "other": 0, "paths": len(devs)}
    for d in devs:
        up = d.get("usage_page")
        if up == HID_USAGE_PAGE_FIDO:
            evidence["fido_ctaphid"] += 1
        elif up in (0xFF00, 0x0001, 0xFF31):
            evidence["ccid_like"] += 1
        else:
            evidence["other"] += 1
    print("[hil] IFACE_PROBE total=%d ctaphid=%d ccid_like=%d other=%d"
          % (evidence["total"], evidence["fido_ctaphid"],
             evidence["ccid_like"], evidence["other"]), flush=True)
    return evidence


class HidLink:
    """Transporte USB-HID nativo CTAPHID (sem texto entrelacado)."""

    def __init__(self, vid: int = USB_VID, pid: int = USB_PID) -> None:
        self.vid = vid
        self.pid = pid
        self.dev = None
        self.cid = BROADCAST_CID

    def open(self) -> None:
        try:
            import hid as _hid
        except ImportError as e:
            raise HwMissingError("hidapi ausente (pip install hidapi): %s" % e) from e
        try:
            found = _hid.enumerate(self.vid, self.pid)
        except Exception as e:
            raise HwMissingError("hid enumerate falhou: %s" % e) from e
        if not found:
            raise HwMissingError(
                "USB HID %04X:%04X nao enumerado (cabo dados? driver?)" % (self.vid, self.pid))
        self.dev = _hid.device()
        try:
            self.dev.open_path(found[0]["path"])
            self.dev.set_nonblocking(0)
        except Exception as e:
            self.dev = None
            raise HwMissingError("USB HID open falhou: %s" % e) from e
        print(sanitize_log("USB_CONNECTED"), flush=True)

    def write(self, data: bytes) -> int:
        if self.dev is None:
            raise HwMissingError("usb nao aberto (open primeiro)")
        if len(data) != PACKET_SIZE:
            raise ValueError("usb report deve ter 64 B")
        n = self.dev.write(b"\x00" + bytes(data))  # Report ID 00
        if n < 0:
            raise OSError("usb hid write failed")
        return n

    def read_exact(self, n: int, deadline_s: float = 5.0) -> bytes:
        if self.dev is None:
            raise HwMissingError("usb nao aberto (open primeiro)")
        buf = bytearray()
        end = _time.monotonic() + deadline_s
        while len(buf) < n and _time.monotonic() < end:
            chunk = bytes(self.dev.read(64, timeout_ms=100) or b"")
            if chunk:
                if len(chunk) == PACKET_SIZE + 1:
                    chunk = chunk[1:]  # tolera com/sem prefixo de report
                buf.extend(chunk[:n - len(buf)])
        if len(buf) < n:
            raise TimeoutError("usb hid read timeout (%d/%d bytes)" % (len(buf), n))
        return bytes(buf)

    def close(self) -> None:
        try:
            if self.dev is not None:
                self.dev.close()
        finally:
            self.dev = None
            self.cid = BROADCAST_CID

    def reconnect(self) -> None:
        """Re-enumera + reabre o HID (1x; sem reset/wipe no device).

        Cobre o transiente HIL (INIT+PING ok, 2o comando mudo): a sessao
        anterior pode ter deixado assembly orfa no firmware; re-enumerar
        + novo INIT recupera sem tocar no device. Falha persistente apos
        o reconnect pede re-plug fisico (hint no erro final).
        """
        try:
            self.close()
        finally:
            pass
        _time.sleep(0.5)
        self.open()

    def _timeout_hint(self, op: str, got: int, want: int) -> str:
        return ("usb hid read timeout op=%s (%d/%d bytes): "
                "transiente conhecido (INIT ok + 2o comando mudo); "
                "retry com re-enumerar 1x; se persistir, re-plugar o "
                "AEGIS-S3-0002 e repetir o teste isolado" % (op, got, want))

    def fresh_session(self, timeout_s: float = 5.0,
                      op: str = "fresh") -> int:
        """Sessao fresca host-side (INIT novo / CID novo; re-enumera se preciso).

        Mitigacao do wedge USB sob trafego acumulado (INIT/PING-1pkt ok,
        multi-pacote GetInfo/fw-log/PING>57B emudece 0/64 apos N sessoes;
        TX do firmware descartava pacotes): antes de cada comando
        multi-pacote idempotente, um INIT novo descarta assembly orfa no
        host e no device. Se o INIT precisar, `cmd_init` ja re-enumera 1x
        (via `reconnect`). Idempotente (so nonce; sem efeito colateral alem
        de alocar CID). Nunca loga segredo (so contagens + `op`).
        """
        _ = op
        cid = self.cmd_init(timeout_s=timeout_s)
        print(sanitize_log("FRESH_SESSION"), flush=True)
        return cid

    # -- CTAPHID ------------------------------------------------------
    def exchange(self, cmd: int, payload: bytes,
                 timeout_s: float = 30.0, op: str = "op") -> tuple:
        """Troca CTAPHID cru: retorna (cid, cmd_resp, raw_body) sem parse.

        O parse CTAP (status+CBOR) acontece so nos paths CBOR/MSG
        (ctap/get_info/vendor/wallet/rescue/fw_log). INIT/PING usam o
        corpo cru (nonce+cid / eco), sem strip de status.
        """
        if self.dev is None:
            raise HwMissingError("usb nao aberto (open primeiro)")
        packets = frame_message(self.cid, cmd, payload)
        print(sanitize_log("USB_SENT cmd=%02x pkts=%d" % (cmd, len(packets)),
                           len(payload)), flush=True)
        for pkt in packets:
            self.write(pkt)
        asm = Reassembler()
        end = _time.monotonic() + timeout_s
        while _time.monotonic() < end:
            raw = self.read_exact(PACKET_SIZE, deadline_s=2.0)
            kind, data = asm.feed(raw)
            if kind in ("more", "text", "keepalive"):
                continue
            if kind == "message":
                rcid, rcmd, body = data
                print(sanitize_log("USB_RESPONSE", len(body)), flush=True)
                return rcid, rcmd, bytes(body)
        raise TimeoutError("no CTAP response op=%s" % op)

    def exchange_read_retry(self, cmd: int, payload: bytes,
                              timeout_s: float = 10.0, op: str = "op") -> tuple:
        """Troca read-only com 1 retry (re-enumerar + INIT novo + timeout maior).

        So para leituras idempotentes (GetInfo/fw-log/rescue/PING>57B): o 2o
        comando apos INIT+PING e o ponto do transiente HIL (mudo 0/64 bytes).
        Chamadores multi-pacote fazem `fresh_session()` ANTES (INIT novo/CID
        novo); aqui o retry reativo cobre o TimeoutError com sessao fresca de
        novo. MC/GA e escritas NUNCA usam este retry (nao-idempotentes).
        """
        try:
            return self.exchange(cmd, payload, timeout_s=timeout_s, op=op)
        except TimeoutError as first:
            print("[hil] RETRY_REENUMERATE op=%s (%s)" % (op, first), flush=True)
            self.reconnect()
            self.cmd_init()
            try:
                return self.exchange(cmd, payload,
                                     timeout_s=max(timeout_s, 20.0),
                                     op="%s-retry" % op)
            except TimeoutError as second:
                raise TimeoutError(
                    self._timeout_hint(op, 0, PACKET_SIZE)) from second

    def cmd_init(self, nonce: bytes | None = None,
                 timeout_s: float = 5.0) -> int:
        """INIT->CID alocado; atualiza self.cid.

        Idempotente (só nonce; sem efeito colateral no device além de
        alocar CID): 1 retry com re-enumerar em Timeout/OSError (flake
        USB 5-10 s no INIT). Falha persistente pede re-plug físico
        (hint AEGIS-S3-0002). Nonce nunca vai para log (só contagens).
        """
        import secrets as _secrets
        nc = bytes(nonce) if nonce is not None else _secrets.token_bytes(INIT_NONCE_LEN)
        if len(nc) != INIT_NONCE_LEN:
            raise ValueError("nonce must be %d bytes" % INIT_NONCE_LEN)
        try:
            return self._cmd_init_once(nc, timeout_s=timeout_s)
        except (TimeoutError, OSError) as first:
            print("[hil] RETRY_REENUMERATE op=init (%s)" % first, flush=True)
            self.reconnect()
            try:
                return self._cmd_init_once(
                    nc, timeout_s=max(timeout_s, 10.0), op="init-retry")
            except (TimeoutError, OSError, ValueError) as second:
                raise TimeoutError(
                    self._timeout_hint("init", 0, PACKET_SIZE)
                    + (" (retry: %s)" % second)) from second

    def _cmd_init_once(self, nc: bytes, timeout_s: float = 5.0,
                       op: str = "init") -> int:
        rcid, rcmd, raw = self.exchange(CMD_INIT, nc, timeout_s=timeout_s, op=op)
        _ = rcid
        if rcmd != CMD_INIT:
            raise ValueError("bad INIT response (cmd=%02x)" % rcmd)
        if len(raw) < INIT_NONCE_LEN + 4 + 3 + 1:  # nonce8+cid4+ver3+caps1=17
            raise ValueError("bad INIT response (curta)")
        if raw[:INIT_NONCE_LEN] != nc:
            raise ValueError("bad INIT response (sem eco de nonce)")
        self.cid = _struct.unpack_from(">I", raw, INIT_NONCE_LEN)[0]
        if self.cid == BROADCAST_CID:
            raise ValueError("bad INIT response (CID broadcast)")
        print(sanitize_log("CID_ALLOCATED"), flush=True)
        return self.cid

    def ping(self, echo: bytes = b"\xa5\x5a\x00\xff",
             timeout_s: float = 5.0) -> bytes:
        """PING com eco; PING>57B (multi-pacote) usa sessao fresca + 1 retry.

        Single-packet (<=57 B) mantem path cru sem retry (sempre ok mesmo
        wedged). Multi-pacote (>57 B, ex. PING-100B/200B) faz `fresh_session`
        ANTES e, em TimeoutError, 1 retry com sessao fresca (idempotente:
        so eco). Eco nunca vai para log (so contagens).
        """
        if len(bytes(echo)) > INIT_PAYLOAD_MAX:
            self.fresh_session(timeout_s=5.0, op="ping%d" % len(bytes(echo)))
            _, _, pong = self.exchange_read_retry(
                CMD_PING, bytes(echo), timeout_s=timeout_s, op="ping")
            if pong != bytes(echo):
                raise ValueError("PING sem eco")
            print(sanitize_log("PING_OK", len(pong)), flush=True)
            return pong
        _, _, pong = self.exchange(CMD_PING, bytes(echo),
                                   timeout_s=timeout_s, op="ping")
        if pong != bytes(echo):
            raise ValueError("PING sem eco")
        print(sanitize_log("PING_OK", len(pong)), flush=True)
        return pong

    def _parse_cbor_msg(self, rcid: int, rcmd: int, raw: bytes,
                        expect_cmd: int, op: str) -> tuple:
        _ = rcid
        if rcmd != expect_cmd:
            raise ValueError("bad %s response (cmd=%02x)" % (op, rcmd))
        return parse_ctap_response(raw)

    def ctap(self, ctap_cmd: int, cbor: bytes = b"",
             timeout_s: float = 30.0, op: str = "op") -> tuple:
        rcid, rcmd, raw = self.exchange(
            CMD_CBOR, bytes((ctap_cmd,)) + bytes(cbor),
            timeout_s=timeout_s, op=op)
        return self._parse_cbor_msg(rcid, rcmd, raw, CMD_CBOR, op)

    def get_info(self, timeout_s: float = 10.0) -> tuple:
        """GetInfo (0x04) via CBOR: retorna (status, corpo opaco).

        Multi-pacote na resposta: sessao fresca (INIT novo/CID novo, e se
        preciso re-enumerar via `cmd_init`) ANTES; em TimeoutError, 1 retry
        com sessao fresca (via `exchange_read_retry`) antes de falhar.
        Idempotente (so leitura). Nenhum segredo em log.
        """
        self.fresh_session(timeout_s=5.0, op="get_info")
        rcid, rcmd, raw = self.exchange_read_retry(
            CMD_CBOR, bytes((CTAP_GET_INFO,)),
            timeout_s=timeout_s, op="get_info")
        return self._parse_cbor_msg(rcid, rcmd, raw, CMD_CBOR, "get_info")

    def vendor_op(self, op: int, body: bytes = b"",
                  timeout_s: float = 30.0) -> tuple:
        """Vendor 0x20-0x27 via MSG (gates binding->UP->PIN no device)."""
        if not is_vendor_op(op):
            raise ValueError("op fora de 0x20-0x27")
        rcid, rcmd, raw = self.exchange(CMD_MSG, bytes((op,)) + bytes(body),
                                        timeout_s=timeout_s,
                                        op="vendor_%02x" % op)
        return self._parse_cbor_msg(rcid, rcmd, raw, CMD_MSG,
                                    "vendor_%02x" % op)

    def wallet_op(self, op: int, body: bytes = b"",
                  timeout_s: float = 30.0) -> tuple:
        """Wallet 0x35-0x37 via MSG (gates no device)."""
        if not is_wallet_op(op):
            raise ValueError("op fora de 0x35-0x37")
        rcid, rcmd, raw = self.exchange(CMD_MSG, bytes((op,)) + bytes(body),
                                        timeout_s=timeout_s,
                                        op="wallet_%02x" % op)
        return self._parse_cbor_msg(rcid, rcmd, raw, CMD_MSG,
                                    "wallet_%02x" % op)

    def rescue(self, body: bytes = b"", timeout_s: float = 10.0) -> tuple:
        """Rescue 0x2E via MSG (somente leitura/diagnostico aqui).

        Sessao fresca ANTES + 1 retry com sessao fresca em TimeoutError
        (idempotente). Nenhum segredo em log.
        """
        self.fresh_session(timeout_s=5.0, op="rescue")
        rcid, rcmd, raw = self.exchange_read_retry(
            CMD_MSG, bytes((OP_RESCUE,)) + bytes(body),
            timeout_s=timeout_s, op="rescue")
        return self._parse_cbor_msg(rcid, rcmd, raw, CMD_MSG, "rescue")

    def fw_log(self, timeout_s: float = 10.0) -> tuple:
        """fw-log 0x38 via MSG, livre (sem UP claim neste path).

        Multi-pacote na resposta: sessao fresca ANTES + 1 retry com sessao
        fresca em TimeoutError (idempotente). Nenhum segredo em log.
        """
        self.fresh_session(timeout_s=5.0, op="fw_log")
        rcid, rcmd, raw = self.exchange_read_retry(
            CMD_MSG, bytes((OP_FW_LOG,)),
            timeout_s=timeout_s, op="fw_log")
        return self._parse_cbor_msg(rcid, rcmd, raw, CMD_MSG, "fw_log")
