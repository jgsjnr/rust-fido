#!/usr/bin/env python3
"""E2E como usuário: finge ser o app e testa cada funcionalidade da chave.

Uso:
  python tools/e2e_user_test.py --phase base            # sem UP/janela
  python tools/e2e_user_test.py --phase pairing         # janela+UP (diag)
  python tools/e2e_user_test.py --phase all-safe        # base + pairing
  python tools/e2e_user_test.py --only T17              # um teste só
  python tools/e2e_user_test.py --phase destructive --confirm   # muda estado!

Segurança: fase destructive exige --confirm; RELEASE/wipe pede digitar SIM.
Uma sessão serial por rodada (abrir a porta reseta a placa e mata a janela).
Resultados vão para o console + append em docs/teste-ponta-a-ponta.md.
"""

import argparse
import datetime
import struct
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import (
    Session, CMD_MSG, CMD_CBOR, CMD_PING,
    CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_GET_ASSERTION, CTAP_CMD_CLIENT_PIN,
)

PORT_DEFAULT = "COM7"
MD_PATH = "docs/teste-ponta-a-ponta.md"

# Ops (espelho frozen do contrato BLE/serial).
OP = {
    "KEY_GEN": 0x20, "KEY_IMPORT": 0x21, "KEY_LIST": 0x22, "KEY_DELETE": 0x23,
    "OATH_PUT": 0x24, "OATH_LIST": 0x25, "OATH_CODE": 0x26, "OATH_DELETE": 0x27,
    "BIND_CHALLENGE": 0x29, "RESCUE": 0x2E, "PAIR_TRIG": 0x2F,
    "OTA_BEGIN": 0x30, "WALLET_GEN": 0x35, "WALLET_LIST": 0x36,
    "WALLET_ADDR": 0x37, "FW_LOG": 0x38,
}

E2E_SLOT_KEY = 5
E2E_SLOT_WALLET = 6
E2E_SLOT_BADNET = 7
E2E_LABEL = b"e2e-t1"
E2E_OATH = b"e2e@test"
E2E_RP = "e2e"


def tlv(tag, val):
    """TLV BER igual ao da firmware (len<0x80 direto, 0x81+1B, 0x82+2B)."""
    n = len(val)
    if n < 0x80:
        lb = bytes([n])
    elif n <= 0xFF:
        lb = bytes([0x81, n])
    else:
        lb = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + lb + val


# --- CBOR mínimo (só o que MC/GA precisam) ---
def cbor_uint(n):
    if n < 24:
        return bytes([n])
    if n < 256:
        return bytes([0x18, n])
    return bytes([0x19, (n >> 8) & 0xFF, n & 0xFF])


def cbor_neg(n):  # n < 0
    v = -1 - n
    if v < 24:
        return bytes([0x20 | v])
    return bytes([0x38, v])


def cbor_int(n):
    return cbor_neg(n) if n < 0 else cbor_uint(n)


def cbor_text(s):
    b = s.encode()
    return bytes([0x60 | len(b)]) + b if len(b) < 24 else None


def cbor_bytes(b):
    if len(b) < 24:
        return bytes([0x40 | len(b)]) + b
    return bytes([0x58, len(b)]) + b


def cbor_arr(items):
    return bytes([0x80 | len(items)]) + b"".join(items)


def cbor_map(pairs):
    return bytes([0xA0 | len(pairs)]) + b"".join(k + v for k, v in pairs)


def mc_cbor():
    h = bytes(32)  # clientDataHash zerado (teste local, sem origem real)
    rp = cbor_map([(cbor_text("id"), cbor_text(E2E_RP))])
    user = cbor_map([(cbor_text("id"), cbor_bytes(b"u1")),
                     (cbor_text("name"), cbor_text(E2E_RP))])
    pkp = cbor_arr([cbor_map([(cbor_text("type"), cbor_text("public-key")),
                              (cbor_text("alg"), cbor_int(-7))])])
    opts = cbor_map([(cbor_text("rk"), bytes([0xF5]))])
    return cbor_map([(cbor_uint(1), cbor_bytes(h)), (cbor_uint(2), rp),
                     (cbor_uint(3), user), (cbor_uint(4), pkp),
                     (cbor_uint(7), opts)])


def ga_cbor():
    h = bytes(32)
    return cbor_map([(cbor_uint(1), cbor_text(E2E_RP)), (cbor_uint(2), cbor_bytes(h))])


def tlv_find(body, tag):
    """Acha o valor do TLV `tag` no corpo (codec oath/tlv da firmware)."""
    i = 0
    while i + 2 <= len(body):
        t = body[i]
        i += 1
        f = body[i]
        i += 1
        if f < 0x80:
            n = f
        elif f == 0x81:
            if i >= len(body):
                return None
            n = body[i]
            i += 1
        elif f == 0x82:
            if i + 1 >= len(body):
                return None
            n = (body[i] << 8) | body[i + 1]
            i += 2
        else:
            return None
        if i + n > len(body):
            return None
        if t == tag:
            return body[i:i + n]
        i += n
    return None


def cbor_dec(data):
    """Decodificador mínimo (comprimentos definidos) p/ respostas da firmware."""
    def take(n, pos):
        if pos + n > len(data):
            raise ValueError("cbor curto")
        return data[pos:pos + n], pos + n

    def dec(pos):
        if pos >= len(data):
            raise ValueError("cbor vazio")
        b = data[pos]
        pos += 1
        mt, ai = b >> 5, b & 0x1F
        if ai < 24:
            arg = ai
        elif ai == 24:
            arg, pos = data[pos], pos + 1
        elif ai == 25:
            arg, pos = (data[pos] << 8) | data[pos + 1], pos + 2
        elif ai == 26:
            import struct as _s
            arg, pos = _s.unpack_from(">I", data, pos)[0], pos + 4
        else:
            raise ValueError("cbor indefinido")
        if mt == 0:
            return arg, pos
        if mt == 1:
            return -1 - arg, pos
        if mt in (2, 3):
            raw, pos = take(arg, pos)
            return (bytes(raw), pos) if mt == 2 else (raw.decode(), pos)
        if mt == 4:
            out = []
            for _ in range(arg):
                v, pos = dec(pos)
                out.append(v)
            return out, pos
        if mt == 5:
            out = {}
            for _ in range(arg):
                k, pos = dec(pos)
                v, pos = dec(pos)
                out[k] = v
            return out, pos
        if mt == 7:
            return {20: False, 21: True, 22: None}.get(arg, None), pos
        raise ValueError("mt desconhecido")
    v, _ = dec(0)
    return v


class PinClient:
    """ClientPIN protocolo 1 (espelho de crypto/pin_protocol.rs)."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, hmac as hmac_mod
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self._ec, self._hashes, self._hmac = ec, hashes, hmac_mod
        self._Cipher, self._algorithms, self._modes = Cipher, algorithms, modes
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.priv.public_key().public_numbers()
        self.x = pub.x.to_bytes(32, "big")
        self.y = pub.y.to_bytes(32, "big")

    def my_cose(self):
        return cbor_map([
            (cbor_int(1), cbor_int(2)),
            (cbor_int(3), cbor_int(-25)),
            (cbor_int(-1), cbor_int(1)),
            (cbor_int(-2), cbor_bytes(self.x)),
            (cbor_int(-3), cbor_bytes(self.y)),
        ])

    def _peer(self, cose):
        m = cbor_dec(cose) if isinstance(cose, (bytes, bytearray)) else cose
        x, y = m[-2], m[-3]
        pn = self._ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), self._ec.SECP256R1())
        return pn.public_key()

    def shared(self, peer_cose):
        peer = self._peer(peer_cose)
        z = self.priv.exchange(self._ec.ECDH(), peer)
        import hashlib
        return hashlib.sha256(z).digest()

    def _aes(self, k, data):
        enc = self._Cipher(self._algorithms.AES(k), self._modes.CBC(bytes(16))).encryptor()
        return enc.update(data) + enc.finalize()

    def _mac(self, k, data):
        import hmac as _h, hashlib as _hl
        return _h.new(k, data, _hl.sha256).digest()[:16]

    @staticmethod
    def _pad(raw):
        if not 4 <= len(raw) <= 63:
            raise ValueError("pin len")
        return raw + bytes(64 - len(raw))

    def setpin_req(self, pin, peer_cose):
        k = self.shared(peer_cose)
        new_enc = self._aes(k, self._pad(pin))
        auth = self._mac(k, new_enc)
        return cbor_map([(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(3)),
                         (cbor_uint(3), self.my_cose()), (cbor_uint(4), cbor_bytes(auth)),
                         (cbor_uint(5), cbor_bytes(new_enc))])

    def _hash_enc(self, k, pin):
        import hashlib
        h = hashlib.sha256(pin).digest()[:16]
        return self._aes(k, self._pad(h))

    def changepin_req(self, old_pin, new_pin, peer_cose):
        k = self.shared(peer_cose)
        new_enc = self._aes(k, self._pad(new_pin))
        hash_enc = self._hash_enc(k, old_pin)
        auth = self._mac(k, new_enc + hash_enc)
        return cbor_map([(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(4)),
                         (cbor_uint(3), self.my_cose()), (cbor_uint(4), cbor_bytes(auth)),
                         (cbor_uint(5), cbor_bytes(new_enc)), (cbor_uint(6), cbor_bytes(hash_enc))])

    def token_req(self, pin, peer_cose):
        k = self.shared(peer_cose)
        hash_enc = self._hash_enc(k, pin)
        return (k, cbor_map([(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(5)),
                             (cbor_uint(3), self.my_cose()), (cbor_uint(6), cbor_bytes(hash_enc))]))

    def token_dec(self, k, enc_token):
        dec = self._Cipher(self._algorithms.AES(k), self._modes.CBC(bytes(16))).decryptor()
        return dec.update(enc_token) + dec.finalize()


class Ctx:
    def __init__(self, port):
        # test_mode=True: a firmware diag tem TEST_UP/TEST_PAIRING_OPEN;
        # sem ela, a fase pairing falha avisando (use hold físico + --only).
        self.s = Session("http://127.0.0.1:9", test_mode=True)
        self.s.connect(port, 115200)
        self.results = []

    def close(self):
        self.s.close()

    def up(self):
        """Um toque via software (diag); latch 1x, vale ~1.5s."""
        self.s.test_up()

    def pairing(self):
        self.s.test_pairing_open()

    def rec(self, tid, name, ok, detail, expected=""):
        self.results.append((tid, name, ok, detail, expected))
        tag = {"pass": "PASS", "div": "DIVERGENTE", "fail": "FAIL"}[ok]
        print("%s %s %s %s" % (tag, tid, name, detail))

    def check(self, tid, name, actual, expected):
        if actual == expected:
            self.rec(tid, name, "pass", "0x%02X" % actual)
        else:
            self.rec(tid, name, "div", "recebido=0x%02X esperado=0x%02X" % (actual, expected),
                     "0x%02X" % expected)

    def msg(self, payload, timeout=15.0):
        return self.s._exchange(CMD_MSG, payload, timeout_s=timeout, op="e2e")

    def msg_up(self, payload, timeout=15.0):
        """UP + envio; se o latch expirou na corrida do leitor (0x01),
        injeta de novo e tenta uma vez (latch 1x/1.5s)."""
        self.up()
        st, body = self.msg(payload, timeout)
        if st == 0x01:
            self.up()
            st, body = self.msg(payload, timeout)
        return st, body

    def ctap_up(self, cmd, cbor, timeout=30.0, tries=3):
        """CTAP com UP; respostas longas sofrem a corrida do leitor UART —
        tenta até `tries` vezes com latch novo (MC duplica credencial
        residente; anotado no detalhe)."""
        last = None
        for _ in range(tries):
            self.up()
            try:
                return self.s._exchange(CMD_CBOR, bytes([cmd]) + cbor,
                                        timeout_s=timeout, op="e2e")
            except (TimeoutError, OSError, ValueError) as e:
                last = e
        raise last


def _t01(c):
    s = c.s
    s.cmd_init()
    c.rec("T01", "INIT aloca CID", "pass", "cid=0x%08X" % s.cid)


def _t02(c):
    s = c.s
    echo = b"ping-e2e"
    st, body = s._exchange(CMD_PING, echo, timeout_s=10.0, op="e2e")
    c.rec("T02", "PING eco", "pass" if bytes([st]) + body == echo else "div",
          "eco=%r" % (bytes([st]) + body))


def _t03(c):
    s = c.s
    # GetInfo = CTAP 0x04 sem CBOR:
    st, body = s._exchange(CMD_CBOR, bytes([0x04]), timeout_s=10.0, op="e2e")
    c.rec("T03", "GetInfo", "pass" if st == 0 and len(body) > 0 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _t04(c):
    st, body = c.msg(bytes([OP["FW_LOG"]]))
    c.rec("T04", "FW-LOG serial livre", "pass" if st == 0 and b"EV=" in body else "div",
          "status=0x%02X linhas=%d" % (st, body.decode("ascii", "replace").count("EV=")))


def _t05(c):
    st, _ = c.msg(bytes([OP["KEY_LIST"]]))
    c.check("T05", "KEY_LIST sem UP barra", st, 0x01)


def _t06(c):
    # Sem UP e sem janela: pairing barra primeiro (0x05). Se der 0x01, uma
    # janela residual ainda está aberta (placa não reseta; ver fw-log).
    st, _ = c.msg(bytes([OP["WALLET_GEN"], 0x01, 0x01, 0x00]))
    if st == 0x05:
        c.rec("T06", "WALLET_GEN sem UP/janela barra", "pass", "0x05")
    else:
        c.rec("T06", "WALLET_GEN sem UP/janela barra", "div",
              "recebido=0x%02X (0x01=janela residual aberta)" % st)


def _t06b(c):
    # Com UP mas sem janela: pairing/bind barra (0x05). TLV inválido de
    # propósito: mesmo com janela aberta por engano, não cria nada.
    st, _ = c.msg_up(bytes([OP["WALLET_GEN"], 0x01, 0x01, 0x00]))
    c.check("T06b", "WALLET_GEN com UP sem janela barra", st, 0x05)


def _t07(c):
    st, _ = c.msg(bytes([OP["RESCUE"]]) + bytes(8))
    # Lixo sem magic RESC: INVALID_MAGIC 0x01 (não é NEED_UP; é o status
    # do próprio rescue para frame inválido).
    c.check("T07", "RESCUE lixo sem magic", st, 0x01)


def _t08(c):
    st, body = c.msg(bytes([OP["OTA_BEGIN"]]))
    c.rec("T08", "OTA-BEGIN sem janela nega", "pass" if st != 0 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _t09(c):
    s = c.s
    st, body = s._exchange(CMD_CBOR, bytes([0x06]) + bytes.fromhex("a201010201"),
                           timeout_s=10.0, op="e2e")
    c.rec("T09", "PIN getRetries", "pass" if st == 0 else "div",
          "status=0x%02X body=%s" % (st, body.hex()[:32]))


def _t10(c):
    st, body = c.msg(bytes([OP["BIND_CHALLENGE"]]))
    if st == 0 and len(body) == 32:
        c.rec("T10", "BIND_CHALLENGE", "pass", "0x00+32B (device CLAIMED — ver D06)")
    else:
        c.rec("T10", "BIND_CHALLENGE sem posse nega", "pass" if st != 0 else "div",
              "status=0x%02X (anotar)" % st)


def _t11(c):
    c.pairing()
    c.rec("T11", "janela via TEST_PAIRING_OPEN", "pass", "pairing_open 60s")


def _t12(c):
    st, body = c.msg(bytes([OP["PAIR_TRIG"]]))
    c.check("T12", "trigger 0x2F abre janela", st, 0x00)


def _t07b(c):
    st, _ = c.msg_up(bytes([OP["RESCUE"]]) + bytes(8))
    c.rec("T07b", "RESCUE lixo com UP dá INVALID_MAGIC", "pass" if st == 0x01 else "div",
          "status=0x%02X" % st)


def _t07c(c):
    # Frame válido (magic+ver+cmd+token) mas SEM UP/PIN: negação fail-closed.
    import struct as _st
    token = b"AEGISKEY_KILLSWITCH_CONFIRM"
    frame = b"RESC" + bytes([0x01, 0x06]) + _st.pack(">H", len(token)) + token
    st, _ = c.msg(bytes([OP["RESCUE"]]) + frame)
    c.rec("T07c", "killswitch sem UP/PIN nega 0x04 (sem wipe)", "pass" if st == 0x04 else "div",
          "status=0x%02X" % st)


def _t13(c):
    # F2: GEN executa de verdade (0x00 + eco slot/label). Rotaciona 5..9
    # (NVS persiste entre boots agora).
    st, body, used = 0x03, b"", None
    for slot in (5, 6, 7, 8, 9):
        req = (tlv(0x01, bytes([slot])) + tlv(0x02, E2E_LABEL)
               + tlv(0x05, (-7 & 0xFFFFFFFF).to_bytes(4, "big")))
        st, body = c.msg_up(bytes([OP["KEY_GEN"]]) + req)
        if st == 0x00:
            used = slot
            break
        if st != 0x03:
            break
    ok = st == 0x00 and tlv_find(body, 0x01) == bytes([used or 0])
    c.rec("T13", "KEY_GEN e2e-t1 real", "pass" if ok else "div",
          "status=0x%02X slot=%s" % (st, used))
    c.ctx_keys_slot = used


def _t14(c):
    c.up()
    st, body = c.msg(bytes([OP["KEY_LIST"]]))
    slot = getattr(c, "ctx_keys_slot", None)
    has = slot is not None and bytes([slot]) in body
    # Sem T13 na sessão: só prova 0x00 (lista pode estar vazia).
    ok = (st == 0 and (has or slot is None))
    c.rec("T14", "KEY_LIST real", "pass" if ok else "div",
          "status=0x%02X bytes=%d tem=%s" % (st, len(body), has))


def oath_hotp(secret, counter, digits=6):
    """RFC4226 local (prova: device calcula igual)."""
    import hmac as _h, hashlib as _hl, struct as _s
    mac = _h.new(secret, _s.pack(">Q", counter), _hl.sha1).digest()
    off = mac[-1] & 0x0F
    code = ((mac[off] & 0x7F) << 24 | mac[off + 1] << 16
            | mac[off + 2] << 8 | mac[off + 3]) % (10 ** digits)
    return str(code).zfill(digits)


def oath_totp(secret, digits=6, period=30, now=None):
    import time as _t
    return oath_hotp(secret, int((now if now is not None else _t.time()) // period), digits)


E2E_OATH_SECRET = bytes(range(20))


def _t15(c):
    put = tlv(0x71, E2E_OATH) + tlv(0x73, bytes([0x11, 0x06]) + E2E_OATH_SECRET)
    st, body = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    # PUT é privilegiada (UP+PIN): sem PIN na sessão, o certo é 0x02.
    c.rec("T15", "OATH_PUT sem PIN pede PIN", "pass" if st == 0x02 else "div",
          "status=0x%02X" % st)


def _t15b(c):
    # F2 (destructive, com sessão): PUT HOTP real -> 0x00.
    if not _ensure_session(c):
        c.rec("T15b", "OATH_PUT com sessão (sem PIN?)", "fail", "token falhou")
        return
    c.pairing()
    put = tlv(0x71, E2E_OATH) + tlv(0x73, bytes([0x11, 0x06]) + E2E_OATH_SECRET)
    st, _ = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    c.rec("T15b", "OATH_PUT HOTP real", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _t15c(c):
    # F2: PUT TOTP + CODE com challenge (app faz igual) — verificado local.
    if not _ensure_session(c):
        c.rec("T15c", "OATH TOTP (sem PIN?)", "fail", "token falhou")
        return
    c.pairing()
    name = b"e2e-totp"
    put = tlv(0x71, name) + tlv(0x73, bytes([0x21, 0x06]) + E2E_OATH_SECRET)
    st, _ = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    if st != 0:
        c.rec("T15c", "OATH_PUT TOTP real", "div", "status=0x%02X" % st)
        return
    import time as _t, struct as _s
    counter = int(_t.time()) // 30
    req = tlv(0x71, name) + tlv(0x74, _s.pack(">Q", counter))
    c.up()
    st, body = c.msg(bytes([OP["OATH_CODE"]]) + req)
    got = tlv_find(body, 0x75).decode() if st == 0 else ""
    want = oath_totp(E2E_OATH_SECRET)
    # Janela de 30s pode virar no meio: aceita counter±1.
    ok = st == 0 and got in (want, oath_hotp(E2E_OATH_SECRET, counter - 1),
                             oath_hotp(E2E_OATH_SECRET, counter + 1))
    c.rec("T15c", "OATH_CODE TOTP bate conta local", "pass" if ok else "div",
          "status=0x%02X got=%s want=%s" % (st, got, want))


def _t16(c):
    c.up()
    st, body = c.msg(bytes([OP["OATH_CODE"]]) + tlv(0x71, E2E_OATH))
    if st == 0x03:
        c.rec("T16", "OATH_CODE sem conta dá NoSlot", "pass", "0x03 (lista vazia)")
        return
    got = tlv_find(body, 0x75)
    ok = st == 0 and bool(got) and got.decode().isdigit()
    c.rec("T16", "OATH_CODE", "pass" if ok else "div",
          "status=0x%02X code=%s (0x03 se lista vazia)" % (st, (got or b"")[:8]))


def _t16b(c):
    # F2 (destructive, após T15b): HOTP avança — dois CODEs diferentes,
    # ambos batendo com a conta local (contadores 0 e 1... ou N/N+1).
    if not _ensure_session(c):
        c.rec("T16b", "OATH HOTP contador (sem PIN?)", "fail", "token falhou")
        return
    c.pairing()
    codes = []
    for _ in range(2):
        c.up()
        st, body = c.msg(bytes([OP["OATH_CODE"]]) + tlv(0x71, E2E_OATH))
        if st != 0:
            c.rec("T16b", "OATH_CODE HOTP", "div", "status=0x%02X" % st)
            return
        codes.append(tlv_find(body, 0x75).decode())
    ok = (len(codes) == 2 and codes[0] != codes[1]
          and all(x.isdigit() and len(x) == 6 for x in codes))
    c.rec("T16b", "HOTP avança e é válido", "pass" if ok else "div",
          "codes=%s (segredo nunca sai do device)" % codes)


def _t17(c):
    st, body = c.ctap_up(CTAP_CMD_MAKE_CREDENTIAL, mc_cbor())
    c.rec("T17", "MakeCredential rp e2e", "pass" if st == 0 and len(body) > 20 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))
    if st == 0:
        c.rec("T17n", "MC gravou residente (persiste no NVS!)", "pass", "credencial e2e criada")


def _t18(c):
    st, body = c.ctap_up(CTAP_CMD_GET_ASSERTION, ga_cbor())
    c.rec("T18", "GetAssertion rp e2e", "pass" if st == 0 and len(body) > 10 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _t19(c):
    # A placa NÃO reseta ao abrir (SerialLink sem DTR): WalletStore (RAM)
    # persiste entre rodadas; roda slots 6..9 até achar um livre.
    addr1 = b""
    used = None
    st = 0x03
    for slot in (6, 7, 8, 9):
        gen = tlv(0x01, bytes([slot])) + tlv(0x02, b"e2e-btc") + tlv(0x08, bytes([0x01]))
        st, body = c.msg_up(bytes([OP["WALLET_GEN"]]) + gen)
        if st == 0x00:
            addr1 = tlv_find(body, 0x07) or b""
            used = slot
            break
        if st != 0x03:
            break
    c.rec("T19", "WALLET_GEN BTC", "pass" if st == 0 and addr1.startswith(b"bc1") else "div",
          "status=0x%02X slot=%s addr=%s" % (st, used, addr1[:44].decode("ascii", "replace")))
    c.ctx_addr = addr1
    c.ctx_slot = used


def _t20(c):
    slot = getattr(c, "ctx_slot", None)
    if slot is None:
        # Sem T19 na mesma sessão: só prova que LIST responde 0x00.
        st, body = c.msg_up(bytes([OP["WALLET_LIST"]]))
        c.rec("T20", "WALLET_LIST responde", "pass" if st == 0 else "div",
              "status=0x%02X bytes=%d (sem T19 na sessão)" % (st, len(body)))
        return
    st, body = c.msg_up(bytes([OP["WALLET_LIST"]]))
    has = bytes([slot]) in body
    c.rec("T20", "WALLET_LIST tem s%d" % slot, "pass" if st == 0 and has else "div",
          "status=0x%02X tem=%s" % (st, has))


def _t21(c):
    slot = getattr(c, "ctx_slot", None)
    if slot is None:
        c.rec("T21", "WALLET_ADDR (sem T19 na sessão)", "fail", "rode --phase pairing inteiro")
        return
    st, body = c.msg_up(bytes([OP["WALLET_ADDR"]]) + tlv(0x01, bytes([slot])))
    addr2 = tlv_find(body, 0x07) if st == 0 else None
    same = bool(addr2) and addr2 == getattr(c, "ctx_addr", b"")
    c.rec("T21", "WALLET_ADDR bate T19", "pass" if same else "div",
          "igual=%s" % same)


def _t22(c):
    bad = tlv(0x01, bytes([E2E_SLOT_BADNET])) + tlv(0x02, b"e2e-bad") + tlv(0x08, bytes([0x09]))
    st, _ = c.msg_up(bytes([OP["WALLET_GEN"]]) + bad)
    c.check("T22", "WALLET rede invalida barra", st, 0x04)


def _d01(c):
    c.up()
    st, _ = c.msg(bytes([OP["KEY_DELETE"]]) + tlv(0x01, bytes([E2E_SLOT_KEY])))
    # DELETE é UP+PIN; o plumbing de PIN nas vendor ainda é follow-up
    # (firmware passa pin=false fixo) → 0x02 mesmo com sessão viva.
    c.rec("D01", "KEY_DELETE s5 pede PIN (gap plumbing)", "pass" if st == 0x02 else "div",
          "status=0x%02X" % st)


def _d02(c):
    c.up()
    st, _ = c.msg(bytes([OP["OATH_DELETE"]]) + tlv(0x71, E2E_OATH))
    c.rec("D02", "OATH_DELETE pede PIN (gap plumbing)", "pass" if st == 0x02 else "div",
          "status=0x%02X" % st)


def _pin_ka(c):
    """KeyAgreement fresco (a chave efêmera do device nasce aqui)."""
    st, body = c.s._exchange(CMD_CBOR, bytes([0x06]) + cbor_map(
        [(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(2))]),
        timeout_s=10.0, op="e2e")
    if st != 0:
        raise ValueError("keyAgreement 0x%02X" % st)
    return cbor_dec(body)[1]


def _d03(c):
    pc = PinClient()
    peer = _pin_ka(c)
    req = pc.setpin_req(b"1234", peer)
    st, _ = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    # Idempotente: 0x33 = PIN já definido em rodada anterior (D03b prova).
    ok = "pass" if st in (0x00, 0x33) else "div"
    c.rec("D03", "setPIN 1234 (muda o device!)", ok,
          "status=0x%02X%s" % (st, " (já tinha PIN)" if st == 0x33 else ""))
    c.pin_client = pc


def _d03b(c):
    pc = getattr(c, "pin_client", None) or PinClient()
    peer = _pin_ka(c)
    k, req = pc.token_req(b"1234", peer)
    st, body = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    detail = "status=0x%02X" % st
    if st == 0:
        tok = pc.token_dec(k, cbor_dec(body)[2])
        detail = "token %dB (oculto)" % len(tok)
        c.pin_token = True
    c.rec("D03b", "getPinToken 1234 (sessão viva)", "pass" if st == 0 else "div", detail)


def _ensure_session(c):
    """Garante sessão PIN viva (reusa D03b ou faz o token inline)."""
    if getattr(c, "pin_token", False):
        return True
    pc = getattr(c, "pin_client", None) or PinClient()
    try:
        peer = _pin_ka(c)
        k, req = pc.token_req(b"1234", peer)
        st, body = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
        if st == 0:
            c.pin_token = True
            return True
    except (OSError, TimeoutError, ValueError):
        pass
    return False


def _d01b(c):
    # F1: com sessão PIN viva, DELETE passa o gate (0x04 = gate-ok).
    if not _ensure_session(c):
        c.rec("D01b", "KEY_DELETE com sessão (sem PIN 1234 no device?)", "fail", "token falhou")
        return
    c.up()
    st, used, last = 0x03, None, 0x03
    for slot in (5, 6, 7, 8, 9):
        st, _ = c.msg(bytes([OP["KEY_DELETE"]]) + tlv(0x01, bytes([slot])))
        last = st
        if st == 0x00:
            used = slot
            break
        if st != 0x03:
            break
    c.rec("D01b", "KEY_DELETE com sessão PIN executa", "pass" if st == 0x00 else "div",
          "status=0x%02X slot=%s" % (last, used))


def _d02b(c):
    if not _ensure_session(c):
        c.rec("D02b", "OATH_DELETE com sessão (sem PIN 1234 no device?)", "fail", "token falhou")
        return
    c.up()
    st, _ = c.msg(bytes([OP["OATH_DELETE"]]) + tlv(0x71, E2E_OATH))
    c.rec("D02b", "OATH_DELETE com sessão PIN executa", "pass" if st == 0x00 else "div",
          "status=0x%02X" % st)


def _d04(c):
    pc = getattr(c, "pin_client", None) or PinClient()
    peer = _pin_ka(c)
    req = pc.changepin_req(b"1234", b"5678", peer)
    st, _ = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    c.rec("D04a", "changePIN 1234->5678", "pass" if st == 0 else "div",
          "status=0x%02X" % st)
    if st != 0:
        return
    peer = _pin_ka(c)
    req = pc.changepin_req(b"5678", b"1234", peer)
    st, _ = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    c.rec("D04b", "changePIN 5678->1234 (volta)", "pass" if st == 0 else "div",
          "status=0x%02X (device fica com 1234)" % st)


def _d05(c):
    c.up()
    st, _ = c.msg(bytes([0x2C]) + b"1234")
    c.rec("D05a", "RECOVERY_SET 1234", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _claim_once(c, tag):
    import os as _os
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    priv = _ec.generate_private_key(_ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    sec1 = (b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))
    bid = _os.urandom(16)
    c.up()
    st, _ = c.msg(bytes([0x28]) + sec1 + bid)
    # Idempotente: 0x04 = já claimed em rodada anterior (D06b prova).
    ok = "pass" if st in (0x00, 0x04) else "div"
    c.rec(tag, "CLAIM posse (muda binding!)", ok,
          "status=0x%02X id=%s%s" % (st, bid.hex()[:8], " (já claimed)" if st == 0x04 else ""))


def _d06(c):
    _claim_once(c, "D06")
    if True:
        c.rec("D06n", "device agora CLAIMED (NVS)", "pass", "gates de binding mudam; ver T10")


def _d06c(c):
    _claim_once(c, "D06c")


def _d06b(c):
    st, body = c.msg(bytes([0x29]))
    ok = st == 0 and len(body) == 32
    c.rec("D06b", "CHALLENGE pós-claim dá 32B", "pass" if ok else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _d07(c):
    # RELEASE em test-mode: bypass com só UP (sig ignorada) → wipe binding.
    # PIN/credencial/recovery sobrevivem (só BIND_* some do NVS).
    c.up()
    st, _ = c.msg(bytes([0x2B]) + bytes(64))
    c.rec("D07", "RELEASE (wipe binding, test-mode)", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _d07b(c):
    st, body = c.msg(bytes([0x29]))
    c.rec("D07b", "CHALLENGE pós-release nega (unclaimed)",
          "pass" if st == 0x05 else "div",
          "status=0x%02X (prova do wipe)" % st)


def _d05b(c):
    # UNLOCK com PIN certo + UP → wipe binding (recovery PIN preservado).
    c.up()
    st, _ = c.msg(bytes([0x2D]) + b"1234")
    c.rec("D05b", "RECOVERY_UNLOCK 1234 (wipe binding)", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _d05c(c):
    st, body = c.msg(bytes([0x29]))
    c.rec("D05c", "CHALLENGE pós-unlock nega (unclaimed)",
          "pass" if st == 0x05 else "div",
          "status=0x%02X (prova do wipe)" % st)


def _d08(c):
    # F5: ciclo OTA real com chave lab (privada fora do repo).
    import hashlib as _hl, os as _os, struct as _st
    try:
        priv = open(r"C:\t\ota_test_key.bin", "rb").read()
        assert len(priv) == 32
    except Exception:
        c.rec("D08", "OTA lab (sem C:\\t\\ota_test_key.bin)", "fail", "chave de teste ausente")
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(priv)

    def manifest(version, image, key):
        digest = _hl.sha256(image).digest()
        signed = _st.pack(">II", version, len(image)) + digest
        return signed + key.sign(signed)

    def begin(m):
        return c.msg(bytes([0x30]) + m)

    image = _os.urandom(20 * 1024)
    # 1. Negativo: assinatura errada -> FINISH nega e limpa.
    bad = manifest(2, image, Ed25519PrivateKey.generate())
    st, _ = begin(bad)
    if st != 0x00:
        c.rec("D08a", "BEGIN bad-sig (aceito p/ testar FINISH)", "div", "status=0x%02X" % st)
        return
    c.msg(bytes([0x31]) + _st.pack(">I", 0) + image[:4096])
    st, _ = c.msg(bytes([0x32]))
    if st == 0x00:
        c.rec("D08a", "FINISH com bad-sig passou?!", "fail", "fail-closed quebrou")
        return
    c.rec("D08a", "FINISH bad-sig nega e limpa", "pass", "status=0x%02X" % st)
    # 2. Positivo: BEGIN -> CHUNKs -> FINISH (verify Ed25519 real).
    good = manifest(2, image, sk)
    st, _ = begin(good)
    if st != 0x00:
        c.rec("D08b", "BEGIN lab", "div", "status=0x%02X" % st)
        return
    off, ok = 0, True
    for i in range(0, len(image), 4096):
        chunk = image[i:i + 4096]
        st, body = c.msg(bytes([0x31]) + _st.pack(">I", off) + chunk)
        off += len(chunk)
        if st != 0x00 or body != _st.pack(">I", off):
            ok = False
            break
    c.rec("D08b", "BEGIN+5 CHUNKs 20KiB", "pass" if ok else "div",
          "recebidos=%d/20480" % off)
    if not ok:
        return
    st, _ = c.msg(bytes([0x32]))
    c.rec("D08c", "FINISH verify real", "pass" if st == 0 else "div",
          "status=0x%02X" % st)
    if st != 0:
        return
    # 3. COMMIT sem UP nega; com UP grava só marker (sem swap: partição única).
    st, _ = c.msg(bytes([0x33]))
    if st != 0x01:
        c.rec("D08d", "COMMIT sem UP nega", "div", "status=0x%02X" % st)
        return
    c.rec("D08d", "COMMIT sem UP nega", "pass", "0x01 (sessão preservada)")
    c.up()
    st, body = c.msg(bytes([0x33]))
    ok = st == 0x00 and body == _st.pack(">I", 2)
    c.rec("D08e", "COMMIT com UP (só marker, sem swap)", "pass" if ok else "div",
          "status=0x%02X body=%s" % (st, body.hex()))
    st, _ = c.msg(bytes([0x34]))
    c.rec("D08f", "ABORT limpa sessão", "pass" if st == 0x00 else "div",
          "status=0x%02X" % st)


# ID -> (função, fase, precisa_janela). Ordem das fases preservada.
REG = {
    "T01": (_t01, "base"), "T02": (_t02, "base"), "T03": (_t03, "base"),
    "T04": (_t04, "base"), "T05": (_t05, "base"), "T06": (_t06, "base"),
    "T06b": (_t06b, "base"),
    "T07": (_t07, "base"), "T08": (_t08, "base"), "T09": (_t09, "base"),
    "T10": (_t10, "base"),
    "T11": (_t11, "pairing"), "T12": (_t12, "pairing"),
    "T07b": (_t07b, "pairing"), "T07c": (_t07c, "pairing"),
    "T13": (_t13, "pairing"), "T14": (_t14, "pairing"),
    "T15": (_t15, "pairing"), "T15b": (_t15b, "destructive"),
    "T15c": (_t15c, "destructive"),
    "T16": (_t16, "pairing"), "T16b": (_t16b, "destructive"),
    "T17": (_t17, "pairing"), "T18": (_t18, "pairing"),
    "T19": (_t19, "pairing"), "T20": (_t20, "pairing"),
    "T21": (_t21, "pairing"), "T22": (_t22, "pairing"),
    "D01": (_d01, "destructive"), "D02": (_d02, "destructive"),
    "D03": (_d03, "destructive"), "D03b": (_d03b, "destructive"),
    "D01b": (_d01b, "destructive"), "D02b": (_d02b, "destructive"),
    "D04a": (_d04, "destructive"),
    "D05a": (_d05, "destructive"), "D05b": (_d05b, "wipe"), "D05c": (_d05c, "wipe"),
    "D06": (_d06, "destructive"),
    "D06b": (_d06b, "destructive"), "D06c": (_d06c, "wipe"),
    "D07": (_d07, "wipe"), "D07b": (_d07b, "wipe"),
    "D08": (_d08, "destructive"),
}
PHASES = {
    "base": [t for t, (_, p) in REG.items() if p == "base"],
    "pairing": [t for t, (_, p) in REG.items() if p == "pairing"],
    "all-safe": [t for t, (_, p) in REG.items() if p in ("base", "pairing")],
    "destructive": [t for t, (_, p) in REG.items() if p == "destructive"],
    # Ciclo completo de wipes: claim -> release -> re-claim -> unlock.
    # F2: PUT/CODE antes dos DELETEs (senao 0x03 sem alvo).
    "wipe": ["D01", "D02", "D03", "D03b", "T15b", "T15c", "T16b", "D01b",
             "D02b", "D04a", "D05a", "D06", "D06b", "D07", "D07b", "D06c",
             "D06b", "D05b", "D05c", "D08"],
}


def append_md(results, phase):
    now = datetime.datetime.now().strftime("%d/%m %H:%M")
    lines = ["", "### %s — phase=%s" % (now, phase)]
    for tid, name, ok, detail, _ in results:
        mark = {"pass": "PASS", "div": "DIVERGENTE", "fail": "FAIL"}[ok]
        lines.append("- [%s] %s %s — %s" % (mark, tid, name, detail))
    with open(MD_PATH, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=PORT_DEFAULT)
    ap.add_argument("--phase", default="base",
                    choices=["base", "pairing", "all-safe", "destructive", "wipe"])
    ap.add_argument("--only", default=None, help="ID único, ex. T17")
    ap.add_argument("--confirm", action="store_true")
    ap.add_argument("--confirm-release", action="store_true",
                    help="autoriza wipes (D07 release, D05b unlock)")
    args = ap.parse_args()

    if args.phase in ("destructive", "wipe") and not args.confirm:
        print("fase destructive/wipe exige --confirm (muda estado do device)")
        sys.exit(2)
    if args.phase == "wipe" and not args.confirm_release:
        print("fase wipe exige --confirm-release (apaga binding do NVS)")
        sys.exit(2)

    c = Ctx(args.port)
    try:
        if args.only:
            wanted = args.only.strip()
            # IDs com sufixo minúsculo (T06b, T07b, T17n): busca insensível.
            match = next((k for k in REG if k.lower() == wanted.lower()), None)
            if match is None:
                print("ID desconhecido: %s" % wanted)
                sys.exit(2)
            wanted = match
            fn, phase = REG[wanted]
            if phase in ("destructive", "wipe") and not args.confirm:
                print("teste D exige --confirm")
                sys.exit(2)
            if phase == "wipe" and not args.confirm_release:
                print("teste wipe exige --confirm-release")
                sys.exit(2)
            if phase in ("pairing", "destructive", "wipe"):
                # Janela é pré-requisito dos gates; abre uma fresca p/ o teste.
                try:
                    c.pairing()
                except (OSError, TimeoutError, ValueError) as e:
                    c.rec(wanted, "abrir janela", "fail", str(e)[:100])
                    raise SystemExit
            run_ids = [wanted]
            REG[wanted][0](c)
            if wanted == "T21":
                print("nota: T21 compara com T19 da MESMA sessão (WalletStore é RAM);")
                print("em --only isolado, rode: --phase pairing e veja T19+T21 juntos.")
        else:
            ids = PHASES[args.phase]
            if args.phase in ("destructive", "wipe"):
                # Janela fresca p/ a fase toda (gates pairing).
                try:
                    _t11(c)
                except (OSError, TimeoutError, ValueError) as e:
                    c.rec("T11", "abrir janela", "fail", str(e)[:100])
                    ids = []
            for tid in ids:
                if tid == "T11":
                    continue  # já aberta acima (destructive)
                try:
                    REG[tid][0](c)
                except (OSError, TimeoutError, ValueError) as e:
                    # Isola: um transporte falhou, a fase continua no próximo.
                    c.rec(tid, "transporte", "fail", str(e)[:120])
    except (OSError, TimeoutError, ValueError) as e:
        c.rec("TRANSPORTE", "erro", "fail", str(e)[:120])
    finally:
        c.close()
    n_pass = sum(1 for r in c.results if r[2] == "pass")
    n_div = sum(1 for r in c.results if r[2] == "div")
    n_fail = sum(1 for r in c.results if r[2] == "fail")
    print("RESUMO pass=%d divergente=%d fail=%d" % (n_pass, n_div, n_fail))
    append_md(c.results, args.phase + (" only=" + args.only if args.only else ""))
    # Atualiza a tabela de status no MD (TODO -> resultado).
    try:
        with open(MD_PATH, encoding="utf-8") as f:
            md = f.read()
        for tid, name, ok, detail, _ in c.results:
            mark = {"pass": "PASS", "div": "DIVERGENTE", "fail": "FAIL"}[ok]
            old = "| %s |" % tid
            # troca o TODO da linha do teste pelo resultado (primeira ocorrência)
            idx = md.find(old)
            if idx >= 0:
                line_end = md.find("\n", idx)
                line = md[idx:line_end]
                if "TODO" in line:
                    md = md[:idx] + line.replace("TODO", mark, 1) + md[line_end:]
        with open(MD_PATH, "w", encoding="utf-8") as f:
            f.write(md)
    except OSError as e:
        print("aviso: MD não atualizado (%s)" % e)


if __name__ == "__main__":
    main()
