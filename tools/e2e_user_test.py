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
    req = tlv(0x01, bytes([E2E_SLOT_KEY])) + tlv(0x02, E2E_LABEL)
    st, body = c.msg_up(bytes([OP["KEY_GEN"]]) + req)
    c.rec("T13", "KEY_GEN e2e-t1", "pass" if st == 0x04 else "div",
          "status=0x%02X (0x04=gate-ok sem executor)" % st)


def _t14(c):
    c.up()
    st, body = c.msg(bytes([OP["KEY_LIST"]]))
    c.rec("T14", "KEY_LIST", "pass" if st in (0x00, 0x04) else "div",
          "status=0x%02X bytes=%d (anotar)" % (st, len(body)))


def _t15(c):
    put = tlv(0x71, E2E_OATH) + tlv(0x73, bytes([0x21, 0x06]) + bytes(range(20)))
    st, body = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    # PUT é privilegiada (UP+PIN): sem PIN na sessão, o certo é 0x02.
    c.rec("T15", "OATH_PUT sem PIN pede PIN", "pass" if st == 0x02 else "div",
          "status=0x%02X (PUT cheio fica p/ após D03)" % st)


def _t16(c):
    c.up()
    st, body = c.msg(bytes([OP["OATH_CODE"]]) + tlv(0x71, E2E_OATH))
    ok = "pass" if st in (0x00, 0x04) else "div"
    extra = ""
    if st == 0 and len(body) >= 6:
        extra = " code_len=%d" % len(body)
    c.rec("T16", "OATH_CODE", ok, "status=0x%02X%s (anotar)" % (st, extra))


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
    c.rec("D01", "KEY_DELETE s5", "pass" if st in (0x00, 0x04) else "div",
          "status=0x%02X" % st)


def _d02(c):
    c.up()
    st, _ = c.msg(bytes([OP["OATH_DELETE"]]) + tlv(0x71, E2E_OATH))
    c.rec("D02", "OATH_DELETE e2e@test", "pass" if st in (0x00, 0x04) else "div",
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
    "T15": (_t15, "pairing"), "T16": (_t16, "pairing"),
    "T17": (_t17, "pairing"), "T18": (_t18, "pairing"),
    "T19": (_t19, "pairing"), "T20": (_t20, "pairing"),
    "T21": (_t21, "pairing"), "T22": (_t22, "pairing"),
    "D01": (_d01, "destructive"), "D02": (_d02, "destructive"),
}
PHASES = {
    "base": [t for t, (_, p) in REG.items() if p == "base"],
    "pairing": [t for t, (_, p) in REG.items() if p == "pairing"],
    "all-safe": [t for t, (_, p) in REG.items() if p in ("base", "pairing")],
    "destructive": [t for t, (_, p) in REG.items() if p == "destructive"],
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
                    choices=["base", "pairing", "all-safe", "destructive"])
    ap.add_argument("--only", default=None, help="ID único, ex. T17")
    ap.add_argument("--confirm", action="store_true")
    args = ap.parse_args()

    if args.phase == "destructive" and not args.confirm:
        print("fase destructive exige --confirm (muda estado do device)")
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
            if phase == "destructive" and not args.confirm:
                print("teste D exige --confirm")
                sys.exit(2)
            if phase == "pairing":
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
            for tid in PHASES[args.phase]:
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
