"""SerialLink UART 115200 8N1 sem DTR/RTS + framing CTAPHID 64B.

Contrato (recon):
- UART 115200 COM7, sem DTR/RTS: DTR reseta o dispositivo (BOOT/KEY
  strapping); este modulo NUNCA toca em DTR/RTS.
- Report 64B + ID00; CTAPHID INIT 0x86 / PING 0x81 / CBOR 0x90.
- Texto TEST_* (TEST_UP, PAIRING_OPEN_300/CLOSE, LED_*, DOWNLOAD,
  USB_RECONNECT, LIFETIME_DUMP) so em firmware test-mode; drenado fora
  do framing binario (linhas LF, nunca segredo em log).
- Teto CTAPHID 7609 B (o 512 B e so do control-point BLE).
- Sem dependencias: stdlib-only (ctypes no Windows, termios no POSIX).
- Sem test-doubles aqui: qualquer ausencia de HW vira OSError/TimeoutError
  real, documentado pela camada de teste (skip elegante, nunca aprova sem evidencia).

Uso rapido:
    from python_hil.link_serial import SerialLink, frame_message, Reassembler
"""
from __future__ import annotations

import os
import struct as _struct
import time as _time

PACKET_SIZE = 64
INIT_PAYLOAD_MAX = 57
CONT_PAYLOAD_MAX = 59
CTAPHID_CEILING = 7609

CMD_PING = 0x81
CMD_MSG = 0x83
CMD_INIT = 0x86
CMD_WINK = 0x88
CMD_CBOR = 0x90
CMD_KEEPALIVE = 0xBB

CTAP_MAKE_CREDENTIAL = 0x01
CTAP_GET_ASSERTION = 0x02
CTAP_GET_INFO = 0x04
CTAP_CLIENT_PIN = 0x06

STATUS_OK = 0x00

BROADCAST_CID = 0xFFFFFFFF
DEFAULT_UART = "COM7"
DEFAULT_BAUD = 115200

INIT_NONCE_LEN = 8
TEXT_LINE_MAX = 4096

TEST_UP = "TEST_UP"
TEST_PAIRING_OPEN = "TEST_PAIRING_OPEN_300"
TEST_PAIRING_CLOSE = "TEST_PAIRING_CLOSE"
TEST_LED_PREFIX = "TEST_LED_"
TEST_DOWNLOAD = "TEST_DOWNLOAD"
TEST_USB_RECONNECT = "TEST_USB_RECONNECT"
TEST_LIFETIME_DUMP = "TEST_LIFETIME_DUMP"
DUMP_HEADER = "lt_dump v=1"
DUMP_FOOTER = "lt_end"


class HwMissingError(OSError):
    """HW ausente/inacessivel: falha real documentada, nunca mascarada."""


def frame_message(cid: int, cmd: int, payload: bytes) -> list:
    """Fatia payload em pacotes INIT/CONT de 64 B (byte-identico ao USB)."""
    total = len(payload)
    if total > 0xFFFF:
        raise ValueError("payload too large")
    first = payload[:INIT_PAYLOAD_MAX]
    pkt = bytearray(PACKET_SIZE)
    _struct.pack_into(">IBH", pkt, 0, cid, cmd, total)
    pkt[7:7 + len(first)] = first
    out = [bytes(pkt)]
    seq = 0
    off = len(first)
    while off < total:
        chunk = payload[off:off + CONT_PAYLOAD_MAX]
        pkt = bytearray(PACKET_SIZE)
        _struct.pack_into(">IB", pkt, 0, cid, seq)
        pkt[5:5 + len(chunk)] = chunk
        out.append(bytes(pkt))
        off += len(chunk)
        seq = (seq + 1) & 0xFF
    return out


def is_text_chunk(pkt: bytes) -> bool:
    """True quando o bloco de 64 B parece texto/log (fora do framing)."""
    if len(pkt) != PACKET_SIZE:
        return False
    seen = False
    for b in pkt:
        if b == 0x00:
            continue
        seen = True
        if not (b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E):
            return False
    return seen


TEXT_MARKERS = (b"[FREERTOS]", b"TEST_", b"tick ", b"lt_", b"pairing",
                b"up_latched", b"led", b"ctaphid")


def is_text_line(line: bytes) -> bool:
    """True quando uma linha ate \\n parece log texto (multiplex serial)."""
    if not line:
        return False
    body = line.strip(b"\x00 \t\r\n")
    if not body:
        return False
    for m in TEXT_MARKERS:
        if m in body:
            return True
    for b in body:
        if b == 0x00:
            continue
        if not (b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E):
            return False
    return True


def _pkt_cid(pkt: bytes) -> int | None:
    """CID dos 4 primeiros bytes (None se janela curta)."""
    if len(pkt) < 4:
        return None
    try:
        return _struct.unpack_from(">I", pkt, 0)[0]
    except Exception:
        return None


def _looks_like_init(pkt: bytes) -> bool:
    """True quando a janela de 64 B tem cabeca INIT plausivel (>IBH)."""
    if len(pkt) != PACKET_SIZE:
        return False
    try:
        _, raw, total = _struct.unpack_from(">IBH", pkt, 0)
    except Exception:
        return False
    return bool(raw & 0x80) and 0 < total <= CTAPHID_CEILING


def _looks_like_cont(pkt: bytes, cid: int | None) -> bool:
    """True quando a janela parece CONT (seq + CID esperado)."""
    if len(pkt) != PACKET_SIZE:
        return False
    try:
        pcid, seq = _struct.unpack_from(">IB", pkt, 0)
    except Exception:
        return False
    if seq & 0x80:
        return False
    if cid is not None and pcid != cid:
        return False
    return not is_text_chunk(pkt)


class Reassembler:
    """Remonta INIT/CONT; texto e keepalive sao sinalizados, nao erro."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.cid = None
        self.cmd = None
        self.total = 0
        self.buf = bytearray()
        self.seq = 0

    def feed(self, pkt: bytes):
        if len(pkt) != PACKET_SIZE:
            raise ValueError("bad packet size")
        if is_text_chunk(pkt):
            return ("text", None)
        cid, raw, total = _struct.unpack_from(">IBH", pkt, 0)
        if raw == CMD_KEEPALIVE:
            return ("keepalive", pkt[7])
        if raw & 0x80:
            if total > CTAPHID_CEILING:
                raise ValueError("overflow ctaphid")
            self.cid, self.cmd, self.total = cid, raw, total
            self.buf = bytearray(pkt[7:7 + min(total, INIT_PAYLOAD_MAX)])
            self.seq = 0
        else:
            if self.cid is None or cid != self.cid:
                raise ValueError("unexpected continuation")
            self.buf.extend(pkt[5:5 + CONT_PAYLOAD_MAX])
            self.seq = (self.seq + 1) & 0xFF
        if self.cid is not None and len(self.buf) >= self.total:
            msg = (self.cid, self.cmd, bytes(self.buf[:self.total]))
            self.reset()
            return ("message", msg)
        return ("more", None)


def parse_ctap_response(payload: bytes):
    if not payload:
        raise ValueError("empty response")
    return payload[0], payload[1:]


def parse_dump(text: str):
    """Parseia TEST_LIFETIME_DUMP em ({contadores}, [estados])."""
    lines = text.replace("\r", "").split("\n")
    if not lines or lines[0].strip() != DUMP_HEADER:
        raise ValueError("bad dump header")
    while lines and lines[-1].strip() == "":
        lines = lines[:-1]
    if not lines or lines[-1].strip() != DUMP_FOOTER:
        raise ValueError("bad dump footer")
    counts: dict = {}
    states: list = []
    for line in lines[1:-1]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("lt.state "):
            states.append(line[len("lt.state "):])
        elif line.startswith("lt.") and "=" in line:
            name, val = line.split("=", 1)
            counts[name] = int(val)
        else:
            continue  # tick/lixo intercalado: ignora a linha, nao quebra
    return counts, states


def sanitize_log(name: str, byte_count: int = 0) -> str:
    """Log sanitizado: nomes de evento + contagens, nunca payload."""
    if byte_count:
        return "[hil] %s bytes=%d" % (name, byte_count)
    return "[hil] %s" % name


class SerialLink:
    """UART 115200 8N1 sem DTR/RTS.

    NUNCA configura DTR/RTS: no Windows o DCB e programado com Flags=0x1
    (fBinary) sem DTR_CONTROL/RTS_CONTROL; no POSIX usa CLOCAL|CREAD sem
    HUPCL. Abrir a porta nao reseta o dispositivo.
    """

    def __init__(self, port: str = DEFAULT_UART, baud: int = DEFAULT_BAUD,
                 timeout_ms: int = 1000) -> None:
        self.port = port
        self.baud = baud
        self.timeout_ms = timeout_ms
        self.handle = None
        self.fd = None
        self._k32 = None

    # -- abertura ------------------------------------------------------
    def open(self) -> None:
        try:
            if os.name == "nt":
                self._open_win()
            else:
                self._open_posix()
        except OSError as e:
            raise HwMissingError("uart %s inacessivel: %s (holder? fechar monitor/Renode; re-plugar cabo dados; retry 1x)" % (self.port, e)) from e

    def _open_win(self) -> None:  # sem DTR/RTS por construcao
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        GENERIC_RW = 0x80000000 | 0x40000000
        OPEN_EXISTING = 3
        h = k32.CreateFileW("\\\\.\\" + self.port, GENERIC_RW, 0, None,
                            OPEN_EXISTING, 0, None)
        if h == wintypes.HANDLE(-1).value:
            raise OSError("cannot open %s" % self.port)

        class DCB(ctypes.Structure):
            _fields_ = [("DCBlength", wintypes.DWORD),
                        ("BaudRate", wintypes.DWORD),
                        ("Flags", wintypes.DWORD),
                        ("wReserved", wintypes.WORD),
                        ("XonLim", wintypes.WORD),
                        ("XoffLim", wintypes.WORD),
                        ("ByteSize", wintypes.BYTE),
                        ("Parity", wintypes.BYTE),
                        ("StopBits", wintypes.BYTE),
                        ("XonChar", ctypes.c_char),
                        ("XoffChar", ctypes.c_char),
                        ("ErrorChar", ctypes.c_char),
                        ("EofChar", ctypes.c_char),
                        ("EvtChar", ctypes.c_char),
                        ("wReserved1", wintypes.WORD)]

        class TIMEOUTS(ctypes.Structure):
            _fields_ = [("ReadIntervalTimeout", wintypes.DWORD),
                        ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
                        ("ReadTotalTimeoutConstant", wintypes.DWORD),
                        ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
                        ("WriteTotalTimeoutConstant", wintypes.DWORD)]

        dcb = DCB()
        dcb.DCBlength = ctypes.sizeof(DCB)
        if not k32.GetCommState(h, ctypes.byref(dcb)):
            k32.CloseHandle(h)
            raise OSError("GetCommState failed")
        dcb.BaudRate = self.baud
        dcb.ByteSize = 8
        dcb.Parity = 0
        dcb.StopBits = 0
        dcb.Flags = 0x00000001  # fBinary apenas: sem DTR/RTS
        if not k32.SetCommState(h, ctypes.byref(dcb)):
            k32.CloseHandle(h)
            raise OSError("SetCommState failed")
        tmo = TIMEOUTS(50, 0, self.timeout_ms, 0, self.timeout_ms)
        k32.SetCommTimeouts(h, ctypes.byref(tmo))
        self.handle = h
        self._k32 = k32

    def _open_posix(self) -> None:  # CLOCAL|CREAD, sem HUPCL => sem reset
        import termios
        import fcntl
        fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY)
        try:
            attrs = termios.tcgetattr(fd)
            baud_const = {9600: termios.B9600, 57600: termios.B57600,
                          115200: termios.B115200}.get(self.baud, termios.B115200)
            attrs[4] = baud_const
            attrs[5] = baud_const
            attrs[2] &= ~(termios.PARENB | termios.CSTOPB | termios.CSIZE
                          | termios.HUPCL)
            attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
            attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = max(1, self.timeout_ms // 100)
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        except Exception:
            os.close(fd)
            raise
        self.fd = fd

    # -- I/O cru --------------------------------------------------------
    def write(self, data: bytes) -> int:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            written = wintypes.DWORD(0)
            ok = self._k32.WriteFile(self.handle, data, len(data),
                                     ctypes.byref(written), None)
            if not ok:
                raise OSError("serial write failed")
            return written.value
        total = 0
        view = memoryview(bytes(data))
        while total < len(data):
            n = os.write(self.fd, view[total:])
            total += n
        return total

    def _read_some(self, n: int) -> bytes:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            tmp = ctypes.create_string_buffer(min(n, PACKET_SIZE))
            got = wintypes.DWORD(0)
            ok = self._k32.ReadFile(self.handle, tmp, len(tmp),
                                    ctypes.byref(got), None)
            if not ok:
                return b""
            return tmp.raw[:got.value]
        try:
            return os.read(self.fd, min(n, PACKET_SIZE))
        except OSError:
            return b""

    def read_exact(self, n: int, deadline_s: float = 5.0) -> bytes:
        buf = bytearray()
        end = _time.monotonic() + deadline_s
        while len(buf) < n and _time.monotonic() < end:
            chunk = self._read_some(n - len(buf))
            if chunk:
                buf.extend(chunk)
            else:
                _time.sleep(0.01)
        if len(buf) < n:
            raise TimeoutError("serial read timeout (%d/%d bytes)" % (len(buf), n))
        return bytes(buf)

    def flush_input(self) -> None:
        try:
            if os.name == "nt":
                if self.handle:
                    self._k32.PurgeComm(self.handle, 0x0004 | 0x0008)
            elif self.fd is not None:
                import termios
                termios.tcflush(self.fd, termios.TCIFLUSH)
        except Exception:
            pass

    def close(self) -> None:
        try:
            if os.name == "nt" and self.handle:
                self._k32.CloseHandle(self.handle)
            elif self.fd is not None:
                os.close(self.fd)
        finally:
            self.handle = None
            self.fd = None

    # -- texto TEST_* drenado -------------------------------------------
    def send_text_line(self, line: str, timeout_s: float = 5.0,
                       until: bytes | None = None) -> str:
        """Envia linha TEST_* e drena a resposta textual (fora do framing)."""
        if self.handle is None and self.fd is None:
            raise HwMissingError("uart %s nao aberto" % self.port)
        self.flush_input()
        self.write((line + "\n").encode("ascii"))
        buf = bytearray()
        end = _time.monotonic() + timeout_s
        while _time.monotonic() < end:
            try:
                chunk = self.read_exact(1, deadline_s=1.0)
            except TimeoutError:
                break
            buf.extend(chunk)
            if until is not None and bytes(until) in buf:
                break
            if until is None and b"lt_end\n" in buf:
                break
            if len(buf) > TEXT_LINE_MAX:
                break
        return buf.decode("ascii", "replace")

    def test_pairing_open(self, timeout_s: float = 5.0) -> str:
        text = self.send_text_line(TEST_PAIRING_OPEN, timeout_s, until=b"pairing_open")
        if "pairing_open" not in text:
            raise ValueError("device nao abriu pairing (firmware test-mode?)")
        print(sanitize_log("TEST_PAIRING_OPEN", len(text)), flush=True)
        return text

    def test_up(self, timeout_s: float = 5.0) -> str:
        text = self.send_text_line(TEST_UP, timeout_s, until=b"up_latched")
        if "up_latched" not in text:
            raise ValueError("device nao lanchou UP (firmware test-mode?)")
        print(sanitize_log("TEST_UP", len(text)), flush=True)
        return text

    def test_led_state(self, state: str, timeout_s: float = 5.0) -> str:
        """TEST_LED_<state>: eco textual do estado do LED (test-mode)."""
        cmd = TEST_LED_PREFIX + str(state).upper()
        text = self.send_text_line(cmd, timeout_s, until=b"led")
        if "led" not in text.lower():
            raise ValueError("device nao confirmou LED (firmware test-mode?)")
        print(sanitize_log("TEST_LED_STATE", len(text)), flush=True)
        return text

    def lifetime_dump(self, timeout_s: float = 5.0) -> str:
        text = self.send_text_line(TEST_LIFETIME_DUMP, timeout_s)
        if DUMP_HEADER not in text:
            raise ValueError("device nao respondeu LIFETIME_DUMP (test-mode?)")
        print(sanitize_log("LIFETIME_DUMP", len(text)), flush=True)
        return text

    # -- CTAPHID ----------------------------------------------------------
    def _read_framed_packet(self, asm: "Reassembler",
                            deadline: float) -> tuple[bytes, int]:
        """Le uma janela 64 B CTAPHID drenando logs texto multiplexados.

        - Drena linhas texto \\r\\n ([FREERTOS]/TEST_*/tick) antes de cada
          janela 64 B, byte a byte (log e binario dividem o mesmo UART).
          So drena quando a linha termina em \\r\\n E e texto (marcador ou
          100% imprimivel): 0x0A/0x0D solto dentro do payload binario nao
          quebra o pacote (nao divide janela no meio).
        - Resync: em janela mista descarta o prefixo texto ate um cabecalho
          plausivel INIT (>IBH, total>0, CID broadcast FFFFFFFF p/ INIT) ou
          CONT (seq sem 0x80 + CID da sessao); janela so-texto e drenada.
        - Retorna (pacote_64B, linhas_drenadas). TimeoutError se estourar.
        """
        pending = bytearray()
        drained = 0
        while _time.monotonic() < deadline:
            # 1) drena linhas texto genuinas (\\r\\n + texto) antes da janela
            while True:
                nl = pending.find(b"\n")
                if nl == -1:
                    break
                line = bytes(pending[:nl + 1])
                if line.endswith(b"\r\n") and is_text_line(line):
                    del pending[:nl + 1]
                    drained += 1
                    continue
                break  # \\n solto (byte 0x0A do payload) ou nao-texto: binario
            # 2) janela 64 B disponivel? valida framing (binario pode ter \\n)
            if len(pending) >= PACKET_SIZE:
                cand = bytes(pending[:PACKET_SIZE])
                if is_text_chunk(cand):
                    del pending[:PACKET_SIZE]
                    drained += 1
                    continue
                if asm.cid is None:
                    if _looks_like_init(cand):
                        del pending[:PACKET_SIZE]
                        return cand, drained
                    # resync: descarta prefixo (1 B) ate marcador INIT/CONT
                    del pending[:1]
                    continue
                if _looks_like_cont(cand, asm.cid):
                    del pending[:PACKET_SIZE]
                    return cand, drained
                if _looks_like_init(cand) and _pkt_cid(cand) != asm.cid:
                    # resync em INIT de outra sessao (ex. broadcast): nova
                    # mensagem reinicia o reassembler; INIT com mesmo CID
                    # no meio da montagem e falso-positivo de payload => 1 B
                    del pending[:PACKET_SIZE]
                    return cand, drained
                del pending[:1]  # resync CONT: avanca 1 B
                continue
            # 3) precisa de mais bytes do fio
            try:
                chunk = self.read_exact(1, deadline_s=min(2.0, max(0.1, deadline - _time.monotonic())))
            except TimeoutError:
                raise TimeoutError("framed packet timeout")
            if chunk:
                pending.extend(chunk)
            else:
                _time.sleep(0.01)
        raise TimeoutError("framed packet timeout")

    def exchange(self, cid: int, cmd: int, payload: bytes,
                 timeout_s: float = 30.0, op: str = "op") -> tuple:
        """Troca CTAPHID cru: retorna (cid, cmd_resp, raw_body) sem parse.

        O parse CTAP (status+CBOR) acontece so no path CBOR (ctap/get_info/
        make_credential/get_assertion). INIT/PING usam o corpo cru.
        """
        if self.handle is None and self.fd is None:
            raise HwMissingError("uart %s nao aberto" % self.port)
        packets = frame_message(cid, cmd, payload)
        print(sanitize_log("CTAP_SENT cmd=%02x pkts=%d" % (cmd, len(packets)),
                           len(payload)), flush=True)
        for pkt in packets:
            self.write(pkt)
        asm = Reassembler()
        end = _time.monotonic() + timeout_s
        drained = 0
        while _time.monotonic() < end:
            try:
                raw, nd = self._read_framed_packet(asm, end)
            except TimeoutError:
                break
            drained += nd
            try:
                kind, data = asm.feed(raw)
            except ValueError:
                # resync em INIT: nova mensagem reinicia o reassembler;
                # CONT espurio e descartado (prefixo texto ja drenado acima)
                if _looks_like_init(raw):
                    asm.reset()
                    kind, data = asm.feed(raw)
                else:
                    continue
            if kind in ("more", "text"):
                if kind == "text":
                    drained += 1
                continue
            if kind == "keepalive":
                continue
            if kind == "message":
                rcid, rcmd, body = data
                print(sanitize_log("CTAP_RESPONSE", len(body)), flush=True)
                if drained:
                    print(sanitize_log("TEXT_DRAINED_LINES", drained), flush=True)
                return rcid, rcmd, bytes(body)
        raise TimeoutError("no CTAP response op=%s" % op)

    def cmd_init(self, cid: int = BROADCAST_CID,
                 nonce: bytes | None = None) -> tuple:
        """INIT->CID: retorna (cid_alocado, corpo_resposta cru)."""
        import secrets as _secrets
        nc = bytes(nonce) if nonce is not None else _secrets.token_bytes(INIT_NONCE_LEN)
        if len(nc) != INIT_NONCE_LEN:
            raise ValueError("nonce must be %d bytes" % INIT_NONCE_LEN)
        _, rcmd, raw = self.exchange(cid, CMD_INIT, nc, timeout_s=5.0, op="init")
        if rcmd != CMD_INIT:
            raise ValueError("bad INIT response (cmd=%02x)" % rcmd)
        if len(raw) < INIT_NONCE_LEN + 4 + 3 + 1 or raw[:INIT_NONCE_LEN] != nc:
            raise ValueError("bad INIT response (sem eco de nonce)")
        new_cid = _struct.unpack_from(">I", raw, INIT_NONCE_LEN)[0]
        if new_cid == BROADCAST_CID:
            raise ValueError("bad INIT response (CID broadcast)")
        print(sanitize_log("CID_ALLOCATED"), flush=True)
        return new_cid, raw

    def ping(self, cid: int, echo: bytes = b"\xa5\x5a\x00\xff",
             timeout_s: float = 5.0) -> bytes:
        _, _, pong = self.exchange(cid, CMD_PING, bytes(echo),
                                   timeout_s=timeout_s, op="ping")
        if pong != bytes(echo):
            raise ValueError("PING sem eco")
        print(sanitize_log("PING_OK", len(pong)), flush=True)
        return pong

    # -- CTAP base (CBOR cru; sem interpretacao de segredo) ----------------
    def ctap(self, cid: int, ctap_cmd: int, cbor: bytes = b"",
             timeout_s: float = 30.0, op: str = "op") -> tuple:
        rcid, rcmd, raw = self.exchange(cid, CMD_CBOR,
                                        bytes((ctap_cmd,)) + bytes(cbor),
                                        timeout_s=timeout_s, op=op)
        _ = rcid
        if rcmd != CMD_CBOR:
            raise ValueError("bad %s response (cmd=%02x)" % (op, rcmd))
        return parse_ctap_response(raw)

    def get_info(self, cid: int, timeout_s: float = 10.0) -> tuple:
        """GetInfo (0x04): corpo CBOR retornado opaco (contagem em log)."""
        return self.ctap(cid, CTAP_GET_INFO, b"", timeout_s=timeout_s, op="get_info")

    def make_credential(self, cid: int, cbor: bytes, timeout_s: float = 30.0) -> tuple:
        return self.ctap(cid, CTAP_MAKE_CREDENTIAL, cbor,
                         timeout_s=timeout_s, op="make_credential")

    def get_assertion(self, cid: int, cbor: bytes, timeout_s: float = 30.0) -> tuple:
        return self.ctap(cid, CTAP_GET_ASSERTION, cbor,
                         timeout_s=timeout_s, op="get_assertion")
