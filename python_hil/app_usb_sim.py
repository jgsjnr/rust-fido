#!/usr/bin/env python3
"""app_usb_sim: simula o app sobre USB-HID CTAPHID puro (menus 0-18).

Espelho USB de tools/app_simulator.py (que e serial+HTTP):
- connect_usb -> cmd_init (INIT->CID) -> exchange_ctaphid.
- GetInfo (0x04) / MakeCredential (0x01) / GetAssertion (0x02) sem claim
  (o transporte enquadra; nunca interpreta nem loga segredo).
- fw-log (0x38) livre; OATH/Wallet/PIV/OTA-gated sao USB-only e passam
  pelos gates do device (binding -> UP -> PIN); este simulador nao
  finge gates locais.
- Menus 0-18 no mesmo estilo do app_simulator; TLV/op builders
  reutilizados de tools.host_sdk.ops (stdlib, sem I/O).
- Sem test-doubles: sem HW todos os comandos levantam HwMissingError
  real (o teste L4 faz skip elegante, nunca aprova sem evidencia).

Uso:
    python -m python_hil.app_usb_sim [--vid 0x303A] [--pid 0xAE61]
    python -m python_hil.app_usb_sim --self-test   # offline, sem HW
"""
from __future__ import annotations

import argparse
import struct as _struct
import sys
import time

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from python_hil.link_serial import (
    CMD_CBOR,
    CMD_MSG,
    CTAP_CLIENT_PIN,
    CTAP_GET_ASSERTION,
    CTAP_GET_INFO,
    CTAP_MAKE_CREDENTIAL,
    frame_message,
    parse_ctap_response,
    sanitize_log,
)
from python_hil.link_usb import (
    OP_FW_LOG,
    OP_RESCUE,
    OP_WALLET_ADDR,
    OP_WALLET_GEN,
    OP_WALLET_LIST,
    HwMissingError,
    HidLink,
    is_vendor_op,
    is_wallet_op,
    probe_interfaces,
)

try:
    from tools.host_sdk import ops as _ops
except ImportError:  # rodando de dentro de python_hil/
    import pathlib as _pl
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
    from tools.host_sdk import ops as _ops

VENDOR_OPS = {
    0x20: "KEY_GEN", 0x21: "KEY_IMPORT", 0x22: "KEY_LIST",
    0x23: "KEY_DELETE", 0x24: "OATH_PUT", 0x25: "OATH_LIST",
    0x26: "OATH_CODE", 0x27: "OATH_DELETE",
}
WALLET_OPS = {OP_WALLET_GEN: "WALLET_GEN", OP_WALLET_LIST: "WALLET_LIST",
              OP_WALLET_ADDR: "WALLET_ADDR"}

PAIRING_WINDOW_SECS = 60

LOG_EVENTS: list = []


def log_event(name: str, detail: str = "") -> None:
    LOG_EVENTS.append((time.monotonic(), name, detail))
    suffix = " " + detail if detail else ""
    print("[log] %s%s" % (name, suffix), flush=True)


class AppUsbSim:
    """Sessao app sobre USB: connect_usb -> cmd_init -> exchange_ctaphid."""

    def __init__(self) -> None:
        self.link: HidLink | None = None
        self.pairing_until = 0.0

    # -- ciclo de vida -------------------------------------------------
    def connect_usb(self, vid: int = 0x303A, pid: int = 0xAE61) -> None:
        self.link = HidLink(vid, pid)
        self.link.open()
        log_event("USB_CONNECTED", "vid=%04X pid=%04X" % (vid, pid))

    def close(self) -> None:
        if self.link is not None:
            self.link.close()
            self.link = None
            log_event("USB_DISCONNECTED")

    def cmd_init(self) -> int:
        if self.link is None:
            raise HwMissingError("connect_usb primeiro (menu 1)")
        cid = self.link.cmd_init()
        log_event("CID_ALLOCATED")
        return cid

    def exchange_ctaphid(self, cmd: int, payload: bytes,
                         timeout_s: float = 30.0, op: str = "op") -> tuple:
        if self.link is None:
            raise HwMissingError("connect_usb primeiro (menu 1)")
        rcid, rcmd, raw = self.link.exchange(cmd, payload, timeout_s=timeout_s, op=op)
        _ = rcid
        if cmd in (CMD_CBOR, CMD_MSG):
            if rcmd != cmd:
                raise ValueError("bad %s response (cmd=%02x)" % (op, rcmd))
            return parse_ctap_response(bytes(raw))
        return rcmd, bytes(raw)

    # -- CTAP base (sem claim: enquadra, nao interpreta segredo) --------
    def get_info(self) -> tuple:
        st, body = self.exchange_ctaphid(
            CMD_CBOR, bytes((CTAP_GET_INFO,)), op="get_info")
        print("GetInfo status=%02x body_bytes=%d" % (st, len(body)))
        return st, body

    def make_credential(self, cbor_hex: str) -> tuple:
        cbor = bytes.fromhex("".join(cbor_hex.split()))
        return self.exchange_ctaphid(
            CMD_CBOR, bytes((CTAP_MAKE_CREDENTIAL,)) + cbor,
            op="make_credential")

    def get_assertion(self, cbor_hex: str) -> tuple:
        cbor = bytes.fromhex("".join(cbor_hex.split()))
        return self.exchange_ctaphid(
            CMD_CBOR, bytes((CTAP_GET_ASSERTION,)) + cbor,
            op="get_assertion")

    def client_pin(self, cbor_hex: str) -> tuple:
        cbor = bytes.fromhex("".join(cbor_hex.split())) if cbor_hex.strip() else b""
        return self.exchange_ctaphid(
            CMD_CBOR, bytes((CTAP_CLIENT_PIN,)) + cbor, op="client_pin")

    # -- vendor/wallet/rescue/fw-log (USB-only, gates no device) --------
    def vendor(self, op: int, tlv_hex: str = "") -> tuple:
        if not is_vendor_op(op):
            raise ValueError("vendor op fora de 0x20-0x27")
        body = bytes.fromhex("".join(tlv_hex.split())) if tlv_hex.strip() else b""
        st, resp = self.exchange_ctaphid(CMD_MSG, bytes((op,)) + body,
                                         op="vendor_%02x" % op)
        print("%s status=%02x body_bytes=%d" % (VENDOR_OPS[op], st, len(resp)))
        return st, resp

    def wallet(self, op: int, tlv_hex: str = "") -> tuple:
        if not is_wallet_op(op):
            raise ValueError("wallet op fora de 0x35-0x37")
        body = bytes.fromhex("".join(tlv_hex.split())) if tlv_hex.strip() else b""
        st, resp = self.exchange_ctaphid(CMD_MSG, bytes((op,)) + body,
                                         op="wallet_%02x" % op)
        print("%s status=%02x body_bytes=%d" % (WALLET_OPS[op], st, len(resp)))
        return st, resp

    def rescue_probe(self) -> tuple:
        frame = _ops.rescue_frame(0x06, b"")
        log_event("RESCUE_BUILDER", "bytes=%d" % len(frame))
        return self.exchange_ctaphid(CMD_MSG, bytes((OP_RESCUE,)),
                                     timeout_s=10.0, op="rescue")

    def fw_log(self) -> tuple:
        st, body = self.exchange_ctaphid(CMD_MSG, bytes((OP_FW_LOG,)),
                                         timeout_s=10.0, op="fw_log")
        log_event("FW_LOG", "bytes=%d" % len(body))
        return st, body

    # -- builders offline (F3: OTA/CCID/PIV/OTP/ext/prox/F4/killswitch) --
    def ota_builder(self, sub: str) -> None:
        if sub == "begin":
            vec = _ops.ota_begin(1024, b"\x00" * 32)
            print("OTA BEGIN bytes=%d (COMMIT USB-only, nunca aqui)" % len(vec))
        elif sub == "chunk":
            print("OTA CHUNK hex=%s" % _ops.ota_chunk(0, b"\x01\x02\x03\x04").hex())
        elif sub == "verify":
            print("OTA VERIFY bytes=%d" % len(_ops.ota_verify()))
        elif sub == "commit":
            print("OTA COMMIT USB-only no device; vetor vazio bytes=%d"
                  % len(_ops.ota_commit()))
        elif sub == "abort":
            print("OTA ABORT bytes=%d" % len(_ops.ota_abort()))
        else:
            print("unknown ota sub")
        log_event("OTA_BUILDER", "sub=%s" % sub)


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return "q"


def run_menu(vid: int, pid: int) -> None:
    app = AppUsbSim()
    print("=" * 64)
    print("  AegisKey APP USB SIM (CTAPHID puro, sem claim de segredo)")
    print("  vid=%04X pid=%04X" % (vid, pid))
    print("=" * 64)
    while True:
        linked = "usb" if app.link is not None else "none"
        print("")
        print("[link=%s]" % linked)
        print(" 0 probe IFs (read-only)   1 connect_usb + INIT->CID")
        print(" 2 GetInfo (0x04)           3 MakeCredential (0x01)")
        print(" 4 GetAssertion (0x02)      5 ClientPIN (0x06)")
        print(" 6 fw-log livre (0x38)      7 vendor 0x20-27 (gated device)")
        print(" 8 wallet 0x35-37 (gated)  9 rescue 0x2E probe")
        print(" 12 OTA builders           13 PIV-APDU builders (no enroll)")
        print(" 14 OTP typer check         15 ext routes 6D00")
        print(" 16 proximity FFFE          17 PIV-OpenSC/F4 helpers")
        print(" 18 killswitch builder (nunca executa)   q quit")
        choice = ask("> ").strip().lower()
        try:
            if choice == "q":
                break
            elif choice == "0":
                ev = probe_interfaces(vid, pid)
                print("ifaces: %s" % ev)
            elif choice == "1":
                app.connect_usb(vid, pid)
                app.cmd_init()
            elif choice == "2":
                app.get_info()
            elif choice == "3":
                hx = ask("MC CBOR hex: ")
                st, body = app.make_credential(hx)
                print("status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "4":
                hx = ask("GA CBOR hex: ")
                st, body = app.get_assertion(hx)
                print("status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "5":
                hx = ask("ClientPIN CBOR hex (vazio=getRetries): ") or "a2010102"
                st, body = app.client_pin(hx)
                print("status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "6":
                st, body = app.fw_log()
                print("fw-log status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "7":
                name = ask("vendor op (KEY_GEN/KEY_LIST/KEY_DELETE/OATH_*): ").strip().upper()
                rev = {v: k for k, v in VENDOR_OPS.items()}
                if name not in rev:
                    print("unknown vendor op")
                    continue
                tlv_hex = ask("TLV hex (vazio ok): ")
                app.vendor(rev[name], tlv_hex)
            elif choice == "8":
                name = ask("wallet op (WALLET_GEN/WALLET_LIST/WALLET_ADDR): ").strip().upper()
                rev = {v: k for k, v in WALLET_OPS.items()}
                if name not in rev:
                    print("unknown wallet op")
                    continue
                tlv_hex = ask("TLV hex (vazio ok): ")
                app.wallet(rev[name], tlv_hex)
            elif choice == "9":
                st, body = app.rescue_probe()
                print("rescue status=%02x body_bytes=%d" % (st, len(body)))
            elif choice == "12":
                app.ota_builder(ask("ota sub (begin/chunk/verify/commit/abort): ").strip())
            elif choice == "13":
                print("SELECT -> %s" % _ops.piv_select_aid().hex())
                log_event("PIV_APDU", "select_only")
            elif choice == "14":
                import getpass as _gp
                code = _gp.getpass("otp (6-8 digitos, nao logado): ").strip()
                ok = _ops.otp_typer_input(code)
                print("ok digits=%d (segredo nunca logado)" % len(ok))
            elif choice == "15":
                r = ask("route (ykman/nitrokey/yubiotp): ").strip().lower()
                print("route=%s answers %s" % (r, _ops.ext_route_status(r).hex()))
            elif choice == "16":
                t = ask("walkaway 5..300 s: ").strip()
                print("walkaway hex=%s" % _ops.prox_walkaway(int(t)).hex())
            elif choice == "17":
                print("GEN AUTH envelope bytes=%d" % len(_ops.piv_gen_auth(b"\x11" * 32)))
            elif choice == "18":
                c = ask("digite --confirm WIPE-ACK: ").strip()
                if c != "--confirm WIPE-ACK":
                    print("DENIED: precisa --confirm WIPE-ACK")
                    continue
                f = _ops.rescue_killswitch_frame("WIPE-ACK")
                print("killswitch frame bytes=%d (builder; jig+HSM p/ real)" % len(f))
            else:
                print("unknown option")
        except (OSError, TimeoutError, ValueError, LookupError,
                PermissionError) as e:
            print("ERROR: %s" % str(e)[:120])
    app.close()
    print("bye (%d eventos sanitizados)" % len(LOG_EVENTS))


def run_self_test() -> int:
    """Cheques offline (sem HW): framing, ops, TLV, envelope, gates locais."""
    fails = []

    def check(name, fn):
        try:
            fn()
            print("PASS %s" % name)
        except Exception as e:
            print("FAIL %s (%s)" % (name, e))
            fails.append(name)

    def t_framing():
        payload = bytes(i % 256 for i in range(150))
        pkts = frame_message(0xAABBCCDD, CMD_CBOR, payload)
        assert all(len(p) == 64 for p in pkts)
        from python_hil.link_usb import Reassembler as _R
        asm = _R()
        for p in pkts[:-1]:
            assert asm.feed(p)[0] == "more"
        kind, msg = asm.feed(pkts[-1])
        assert kind == "message" and msg[2] == payload

    def t_wallet_vectors():
        g = _ops.wrap_op(_ops.OP_WALLET_GEN, _ops.wallet_gen(3, b"btc", 0x01))
        assert g[0] == OP_WALLET_GEN
        assert _ops.wallet_addr_req(3) and _ops.wallet_list_req() == b""

    def t_vendor_range():
        assert all(is_vendor_op(o) for o in range(0x20, 0x28))
        assert not is_vendor_op(0x28) and not is_wallet_op(0x2E)
        assert _ops.fw_log_req() == b""

    def t_rescue_fwlog_ops():
        assert OP_RESCUE == 0x2E and OP_FW_LOG == 0x38
        assert _ops.rescue_frame(0x06, b"\x01").startswith(b"RESC\x01")

    def t_no_hw_claim():
        app = AppUsbSim()
        assert app.link is None
        try:
            app.get_info()
            raise AssertionError("deveria exigir connect_usb")
        except HwMissingError:
            pass

    for name, fn in [("framing_usb", t_framing),
                     ("wallet_vectors", t_wallet_vectors),
                     ("vendor_range", t_vendor_range),
                     ("rescue_fwlog_ops", t_rescue_fwlog_ops),
                     ("no_hw_claim", t_no_hw_claim)]:
        check(name, fn)
    print("self-test: %d failed" % len(fails))
    return 1 if fails else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="App USB sim (CTAPHID puro)")
    ap.add_argument("--vid", default="0x303A")
    ap.add_argument("--pid", default="0xAE61")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return run_self_test()
    vid = int(str(args.vid), 0)
    pid = int(str(args.pid), 0)
    run_menu(vid, pid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
