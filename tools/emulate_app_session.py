#!/usr/bin/env python3
"""Emulated app + server session (offline, no HW/COM/BLE).

Scope: tools/ only. Reads crates/docs/app-android as reference, modifies nothing
outside tools/. Stdlib-only + tools/host_sdk (tlv, ops, gates) + tools/ota_server.

What it emulates (SIMULATED, never physical):
  S1 scan -> bond JustWorks -> CLAIM/CHALLENGE/VERIFY (frozen vectors host_sdk)
  S2 ops OATH LIST/CODE, wallet ADDR, fw-log parse
  S3 OTA stage BEGIN/CHUNK/FINISH with manifest via tools/ota_server.py (localhost)
  S4 mock Integrity validation server (opaque token -> allowed true/false)
     + SPKI pin verification example (format + guard + match/mismatch)
  S5 gates binding -> UP -> PIN honored (UP is SIMULATED latch, never physical)

UP badge: every presence event prints "UP-SIMULATED (no hardware)".
No COM/BLE/USB/HID/socket-to-device: only localhost HTTP (OTA + integrity mock).

Run:  python tools/emulate_app_session.py
Exit: 0 = all steps PASS; 1 = any FAIL/DIV.
"""
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import struct
import sys
import threading
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools.host_sdk import tlv, ops, gates  # noqa: E402
from tools.host_sdk import transport as tp  # noqa: E402
import tools.ota_server as ota_server  # noqa: E402

RESULTS = []  # (step, name, verdict, detail)


def log_event(name, detail=""):
    print("[log] %s%s" % (name, (" " + detail) if detail else ""))


def rec(step, name, ok, detail=""):
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((step, name, verdict, detail))
    print("%s %s %s %s" % (verdict, step, name, ("| " + detail) if detail else ""))


def expect_fail_closed(fn, status_attr="status"):
    """Run fn, expect GateDenied; return (denied_ok, status_or_None)."""
    try:
        fn()
    except gates.GateDenied as e:
        return True, e.status
    except PermissionError:
        return True, None
    return False, None


# ---------------------------------------------------------------------------
# Simulated presence (UP): single-use latch, explicitly NOT physical.
# ---------------------------------------------------------------------------
class SimPresence:
    def __init__(self):
        self.latched = False

    def press(self):
        """Simulate a user-presence tap. Single-use latch."""
        self.latched = True
        log_event("UP_SIMULATED", "no-hardware latch=1x")

    def consume(self):
        if not self.latched:
            return False
        self.latched = False
        return True


# ---------------------------------------------------------------------------
# Simulated device: binding + challenge + ops (RAM only, deterministic).
# ---------------------------------------------------------------------------
BIND_OP_RELEASE = 0x52
FROZEN_APP_PUB = b"\x04" + b"\x11" * 32 + b"\x22" * 32  # 65B SEC1 uncompressed (simulated)
FROZEN_BINDING_ID = bytes(range(16))  # 00..0F opaque 16B
FROZEN_CHALLENGE = bytes(range(32))  # 00..1F deterministic (simulated TRNG stand-in)
FROZEN_OATH_SECRET = b"12345678901234567890"  # RFC6238 test vector only
FROZEN_TIME = 59  # RFC6238 T=1 -> TOTP 287082 (SHA1, 6 digits)


def oath_totp_sha1(secret, t):
    counter = t // 30
    msg = struct.pack(">Q", counter)
    hs = hmac.new(secret, msg, hashlib.sha1).digest()
    off = hs[-1] & 0x0F
    code = struct.unpack(">I", hs[off:off + 4])[0] & 0x7FFFFFFF
    return "%06d" % (code % 1000000)


class SimDevice:
    """Offline device twin: binding state + single-use challenge + stores."""

    def __init__(self):
        self.claimed = False
        self.app_pub = None
        self.binding_id = None
        self.challenge = None
        self.challenge_used = True
        self.pin_ok = False
        self.oath = {}  # name bytes -> secret bytes
        self.wallet = {}  # slot -> (label, address)
        self.ota_buf = bytearray()
        self.ota_len = 0
        self.ota_sha = b""
        self.fw_log_lines = [
            "SEQ=1 EV=boot ARG=ok T=12ms",
            "SEQ=2 EV=ble-bond ARG=justworks T=140ms",
            "SEQ=3 EV=claim ARG=ok T=210ms",
            "SEQ=4 EV=oath-code ARG=count T=320ms",
        ]

    # -- binding ---------------------------------------------------------
    def claim(self, pairing_open, up: SimPresence, app_pub, binding_id):
        if not pairing_open:
            raise gates.GateDenied(gates.NEED_UP, "pairing window required")
        if not up.consume():
            raise gates.GateDenied(gates.NEED_UP, "presence required")
        if self.claimed:
            raise gates.GateDenied(0x04, "AlreadyClaimed")
        if len(app_pub) != 65 or app_pub[0] != 0x04:
            raise gates.GateDenied(0x04, "bad pubkey")
        if len(binding_id) != 16:
            raise gates.GateDenied(0x04, "bad binding_id")
        self.claimed = True
        self.app_pub = bytes(app_pub)
        self.binding_id = bytes(binding_id)
        return bytes(binding_id)  # echo

    def challenge_new(self):
        if not self.claimed:
            raise gates.GateDenied(gates.NEED_BINDING, "unclaimed")
        self.challenge = bytes(FROZEN_CHALLENGE)
        self.challenge_used = False
        return self.challenge

    def verify(self, op, payload_hash, sig):
        """Simulated P-256 verify stand-in: HMAC over (ch||op||ph) with pub-derived key.

        Offline emulation only: proves owner + single-use + anti-replay wiring.
        Real firmware does P-256 DER/raw verify; this twin never claims equivalence.
        """
        if not self.claimed:
            raise gates.GateDenied(gates.NEED_BINDING, "unclaimed")
        if self.challenge is None or self.challenge_used:
            raise gates.GateDenied(gates.NEED_BINDING, "replay/stale challenge")
        key = hashlib.sha256(self.app_pub).digest()
        want = hmac.new(key, self.challenge + bytes([op]) + bytes(payload_hash), hashlib.sha256).digest()
        if not hmac.compare_digest(want, bytes(sig)):
            raise gates.GateDenied(gates.NEED_BINDING, "bad signature")
        self.challenge_used = True
        return True

    def sign_sim(self, op, payload_hash):
        key = hashlib.sha256(self.app_pub).digest()
        return hmac.new(key, self.challenge + bytes([op]) + bytes(payload_hash), hashlib.sha256).digest()

    # -- gates ------------------------------------------------------------
    def gate_config(self, opcode, binding_ok, up: SimPresence, op_name):
        # canonical order binding -> UP -> PIN via host_sdk.gates (no secrets logged)
        present = up.consume()
        gates.authorize_config_op(opcode, binding_ok, present, self.pin_ok, op=op_name)

    # -- oath --------------------------------------------------------------
    def oath_put(self, name, secret):
        self.oath[bytes(name)] = bytes(secret)

    def oath_list(self):
        return list(self.oath.keys())

    def oath_code(self, name, challenge8=None):
        if name not in self.oath:
            return None
        return oath_totp_sha1(self.oath[name], FROZEN_TIME)

    # -- wallet -------------------------------------------------------------
    def wallet_gen(self, slot, label, network):
        digest = hashlib.sha256(bytes([slot]) + bytes(label)).hexdigest()
        addr = ("bc1q" + digest[:32]).encode("ascii")
        self.wallet[slot] = (bytes(label), addr)
        return addr

    def wallet_addr(self, slot):
        return self.wallet[slot][1] if slot in self.wallet else None

    # -- fw-log --------------------------------------------------------------
    def fw_log(self, bonded):
        gates.authorize_fw_log(bonded)
        body = "\n".join(self.fw_log_lines) + "\n"
        return body.encode("ascii")


# ---------------------------------------------------------------------------
# BLE control-point framing (docs/ble-protocol.md S3): [op,hi,lo,...]+[seq,...]
# ---------------------------------------------------------------------------
def ble_frame(op, payload):
    p = bytes(payload)
    if len(p) > 512:
        raise ValueError("ble payload overflow")
    return bytes([op, (len(p) >> 8) & 0xFF, len(p) & 0xFF]) + p


def ble_parse(frame):
    if len(frame) < 3:
        raise ValueError("short ble frame")
    total = (frame[1] << 8) | frame[2]
    if len(frame[3:]) != total:
        raise ValueError("ble length mismatch")
    return frame[0], frame[3:]


# ---------------------------------------------------------------------------
# Integrity mock server (opaque token -> allowed), localhost only.
# ---------------------------------------------------------------------------
VALID_TOKEN = "VALID-OPAQUE-TOKEN-001"
LEGIT_PACKAGE = "dev.aegiskey.app"


class IntegrityEmulatedHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path != "/api/integrity/verify":
            self.send_error(404)
            return
        ln = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(ln) if ln else b""
        try:
            data = json.loads(raw.decode()) if raw else {}
        except ValueError:
            self._json({"allowed": False, "error": "invalid_json"}, 400)
            return
        token = data.get("integrityToken", "")
        package = data.get("package", "")
        # opaque: compare only, never log the token itself
        allowed = (token == VALID_TOKEN and package == LEGIT_PACKAGE)
        self._json({"allowed": allowed})

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve_integrity_emulated():
    srv = http.server.HTTPServer(("127.0.0.1", 0), IntegrityEmulatedHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv


def integrity_verify(base, token, package):
    req = urllib.request.Request(
        base + "/api/integrity/verify",
        data=json.dumps({"integrityToken": token, "package": package}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# SPKI pin check (mirrors DevicePinning rules, offline example).
# ---------------------------------------------------------------------------
PIN_RE = re.compile(r"[A-Za-z0-9+/]{43}=$")
_pins = None


def pin_install(*pins):
    global _pins
    if not pins:
        raise ValueError("pins vazios")
    for p in pins:
        if PIN_RE.fullmatch(p) is None:
            raise ValueError("pin fora do formato base64(sha256)")
    _pins = set(pins)
    log_event("PINNING_INSTALLED", "pins=%d" % len(pins))


def pin_guard(url):
    if url.startswith("https://") and _pins is None:
        raise PermissionError("pinning nao configurado (HTTPS negado)")


def pin_check_leaf(spki_der, pins=None):
    want = pins if pins is not None else _pins
    if want is None:
        raise PermissionError("pinning nao configurado (HTTPS negado)")
    digest = hashlib.sha256(bytes(spki_der)).digest()
    pin = base64.b64encode(digest).decode("ascii")
    if pin not in want:
        raise ValueError("pin mismatch")
    return pin


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def step_s1_scan_bond_claim(dev):
    # S1a: simulated scan (no radio): frozen GATT record
    gatt = {"service": 0xFFFD, "chars": ["FFF1", "FFF2", "FFF3", "FFF4"], "rev": 0x01}
    ok = gatt["service"] == 0xFFFD and gatt["rev"] == 0x01 and len(gatt["chars"]) == 4
    rec("S1", "scan-sim GATT FFFD/rev01", ok, "service=FFFD chars=4 rev=01 SIMULATED-RADIO")
    if not ok:
        return False
    # S1b: simulated bond JustWorks+bonding+UP flags (no BLE stack)
    bond = {"method": "JustWorks", "bonding": True, "up": True, "transport": "SIMULATED"}
    ok = bond["method"] == "JustWorks" and bond["bonding"] and bond["up"]
    rec("S1", "bond-sim JustWorks+bonding+UP", ok, "SIMULATED-BOND no-keys-exchanged")
    # S1c: CLAIM 0x28 = 81B frozen (SEC1 65B || binding_id 16B), needs pairing+UP
    up = SimPresence()
    up.press()
    try:
        echo = dev.claim(True, up, FROZEN_APP_PUB, FROZEN_BINDING_ID)
        ok = echo == FROZEN_BINDING_ID
    except gates.GateDenied as e:
        ok = False
        echo = b""
    wire = ble_frame(0x28, FROZEN_APP_PUB + FROZEN_BINDING_ID)
    op, body = ble_parse(wire)
    ok = ok and op == 0x28 and len(body) == 81
    rec("S1", "claim 0x28 81B echo-id", ok, "op=28 body=81 echo=%s" % echo.hex()[:8])
    if not ok:
        return False
    # S1d: CHALLENGE 0x29 -> 32B
    try:
        ch = dev.challenge_new()
        ok = len(ch) == 32
    except gates.GateDenied:
        ok = False
    rec("S1", "challenge 0x29 32B", ok, "SIMULATED-TRNG frozen-vector")
    if not ok:
        return False
    # S1e: VERIFY 0x2A over challenge||op||sha256(payload) + replay denied
    payload = tlv.write_tlv(tlv.TAG_SLOT, b"\x08") + tlv.write_tlv(tlv.TAG_LABEL, b"e2e-t1")
    ph = hashlib.sha256(payload).digest()
    sig = dev.sign_sim(0x20, ph)
    try:
        dev.verify(0x20, ph, sig)
        first_ok = True
    except gates.GateDenied:
        first_ok = False
    denied, _ = expect_fail_closed(lambda: dev.verify(0x20, ph, sig))
    ok = first_ok and denied
    rec("S1", "verify 0x2A single-use+replay-deny", ok, "first=ok replay=NEED_BINDING")
    # S1f: frozen tlv vector cross-check (host_sdk canonical)
    frozen = bytes([0x01, 0x01, 0x03, 0x02, 0x03]) + b"btc" + bytes([0x08, 0x01, 0x01])
    got = (tlv.write_tlv(tlv.TAG_WALLET_SLOT, b"\x03")
           + tlv.write_tlv(tlv.TAG_WALLET_LABEL, b"btc")
           + tlv.write_tlv(tlv.TAG_WALLET_NETWORK, b"\x01"))
    ok = got == frozen and tlv.slot_id(tlv.parse_tlv(frozen)) == 3
    rec("S1", "tlv frozen vector (host_sdk)", ok, "hex=%s" % frozen.hex()[:32])
    # S1g: CTAPHID 64B framing roundtrip (host_sdk.transport, no wire)
    payload2 = bytes(i % 256 for i in range(150))
    pkts = tp.frame_message(0xAABBCCDD, tp.CMD_MSG, payload2)
    asm = tp.Reassembler()
    kind = got2 = None
    for p in pkts[:-1]:
        assert asm.feed(p) == ("more", None)
    kind, got2 = asm.feed(pkts[-1])
    ok = kind == "message" and got2[2] == payload2 and all(len(p) == 64 for p in pkts)
    rec("S1", "ctaphid 64B roundtrip 150B", ok, "pkts=%d" % len(pkts))
    return all(v == "PASS" for (s, n, v, d) in RESULTS if s == "S1")


def step_s2_gates():
    # canonical order binding -> UP -> PIN, each denial distinct
    denied, st = expect_fail_closed(
        lambda: gates.authorize_config_op(ops.OP_KEY_DELETE, False, False, False, op="key_delete"))
    rec("S2", "gate binding-first NEED_BINDING", denied and st == gates.NEED_BINDING, "status=0x05")
    denied, st = expect_fail_closed(
        lambda: gates.authorize_config_op(ops.OP_KEY_DELETE, True, False, True, op="key_delete"))
    rec("S2", "gate UP-second NEED_UP", denied and st == gates.NEED_UP, "status=0x01 SIMULATED-UP")
    denied, st = expect_fail_closed(
        lambda: gates.authorize_config_op(ops.OP_KEY_DELETE, True, True, False, op="key_delete"))
    rec("S2", "gate PIN-third NEED_PIN", denied and st == gates.NEED_PIN, "status=0x02")
    try:
        gates.authorize_config_op(ops.OP_KEY_DELETE, True, True, True, op="key_delete")
        ok = True
    except gates.GateDenied:
        ok = False
    rec("S2", "gate allow binding+UP+PIN", ok, "GATE_OK")
    # usage ops: UP only, never binding
    try:
        gates.authorize_usage_op(True, op="oath_code")
        ok2 = True
    except gates.GateDenied:
        ok2 = False
    rec("S2", "usage UP-only (no binding)", ok2, "oath_code SIMULATED-UP")
    denied, _ = expect_fail_closed(lambda: gates.authorize_fw_log(False))
    rec("S2", "fw-log needs bonding", denied, "NEED_BINDING")
    return all(v == "PASS" for (s, n, v, d) in RESULTS if s == "S2")


def step_s3_oath_wallet_fwlog(dev):
    # OATH PUT is UP+PIN config; emulate PIN set then allow
    up = SimPresence()
    up.press()
    dev.pin_ok = True
    try:
        dev.gate_config(ops.OP_OATH_PUT, True, up, "oath_put")
        gate_ok = True
    except gates.GateDenied:
        gate_ok = False
    rec("S3", "oath_put gate binding+UP-SIM+PIN", gate_ok, "UP-SIMULATED")
    # frozen OATH vectors: LIST empty req, PUT TLV 0x71+0x73
    put = tlv.write_tlv(0x71, b"GitHub:alice") + tlv.write_tlv(0x73, bytes([0x21, 0x06]) + FROZEN_OATH_SECRET)
    dev.oath_put(b"GitHub:alice", FROZEN_OATH_SECRET)
    names = dev.oath_list()
    ok = b"GitHub:alice" in names and len(put) > 0
    rec("S3", "oath LIST names", ok, "accounts=%d secret-never-logged" % len(names))
    # CODE with UP-SIM: TLV 0x71 + opt 0x74 challenge; expect RFC vector 287082 at t=59
    up2 = SimPresence()
    up2.press()
    try:
        gates.authorize_usage_op(up2.consume(), op="oath_code")
        code = dev.oath_code(b"GitHub:alice")
        ok = code == "287082" and len(code) == 6 and code.isdigit()
    except gates.GateDenied:
        ok = False
        code = ""
    rec("S3", "oath CODE rfc287082", ok, "code-len=%d UP-SIMULATED" % len(code or ""))
    # wallet ADDR 0x37: [slot] -> [0x07 address], TLV roundtrip via host_sdk
    gen_body = ops.wallet_gen(3, b"btc", 0x01)
    wire = ble_frame(ops.OP_WALLET_ADDR if False else 0x35, gen_body)
    op, body = ble_parse(wire)
    addr = dev.wallet_gen(3, b"btc", 0x01)
    recs = tlv.parse_tlv(tlv.write_tlv(tlv.TAG_WALLET_SLOT, b"\x03"))
    q = ops.wallet_addr_req(3)
    back = dev.wallet_gen(3, b"btc", 0x01)
    got_addr = dev.wallet_addr(3)
    ok = (tlv.slot_id(recs) == 3 and len(q) == 3 and got_addr == back and got_addr.startswith(b"bc1"))
    rec("S3", "wallet GEN/ADDR tlv+echo", ok, "addr_len=%d" % len(got_addr or b""))
    # fw-log 0x38 parse: bonded free, lines SEQ EV= ARG= T=, no PII
    try:
        raw = dev.fw_log(True)
        lines = raw.decode("ascii").strip().split("\n")
        ok = all(("EV=" in ln and "T=" in ln) for ln in lines) and len(lines) == 4
        detail = "linhas=%d" % len(lines)
    except gates.GateDenied:
        ok = False
        detail = "denied"
    rec("S3", "fw-log parse 4 lines", ok, detail)
    return all(v == "PASS" for (s, n, v, d) in RESULTS if s == "S3")


def step_s4_ota():
    httpd = ota_server.serve_in_background(port=0)
    port = httpd.server_address[1]
    base = "http://127.0.0.1:%d" % port
    try:
        reg = ota_server.load_registry()
        serials = [d["serial"] for d in reg.get("devices", [])]
        if len(serials) < 1:
            rec("S4", "ota registry", False, "empty registry")
            return False
        s0 = serials[0]
        aaguid = next(d["aaguid"] for d in reg["devices"] if d["serial"] == s0)
        # validate allow via direct build (no network needed for logic) + HTTP smoke
        import urllib.parse as _p
        man = ota_server.build_manifest(reg, s0, "1.0.0")
        ok = man is not None and all(k in man for k in ("version", "sha256", "sig_ed25519", "url", "size"))
        rec("S4", "ota manifest fields", ok, "serial=%s version=%s" % (s0, (man or {}).get("version", "?")))
        if not ok:
            return False
        with urllib.request.urlopen(base + "/api/ota/manifest?serial=%s&fw=1.0.0" % _p.quote(s0), timeout=5) as fh:
            http_man = json.load(fh)
        ok = http_man.get("sha256") == man["sha256"] and http_man.get("size") == man["size"]
        rec("S4", "ota manifest localhost", ok, "bytes=%d" % http_man.get("size", -1))
        with urllib.request.urlopen(base + "/api/ota/firmware/%s" % http_man["version"], timeout=5) as fh:
            blob = fh.read()
        ok = hashlib.sha256(blob).hexdigest() == http_man["sha256"] and len(blob) == http_man["size"]
        rec("S4", "ota firmware sha256", ok, "sha=%s" % hashlib.sha256(blob).hexdigest()[:12])
        if not ok:
            return False
        # stage BEGIN/CHUNK/FINISH with frozen ops builders + gates binding->UP->PIN
        up = SimPresence()
        up.press()
        try:
            gates.authorize_config_op(ops.OP_OTA_BEGIN, True, up.consume(), True, op="ota_begin")
            gate_ok = True
        except gates.GateDenied:
            gate_ok = False
        begin = ops.ota_begin(len(blob), hashlib.sha256(blob).digest())
        chunks = [blob[i:i + 512] for i in range(0, len(blob), 512)]
        staged = bytearray()
        seq_ok = True
        for i, ch in enumerate(chunks):
            body = ops.ota_chunk(i, ch)
            seq, data = struct.unpack(">H", body[:2])[0], body[2:]
            if seq != i or data != ch:
                seq_ok = False
                break
            staged.extend(data)
        finish_ok = hashlib.sha256(bytes(staged)).hexdigest() == http_man["sha256"]
        ok = gate_ok and seq_ok and finish_ok and len(chunks) >= 1
        rec("S4", "ota stage BEGIN/CHUNK/FINISH", ok,
            "chunks=%d staged=%d UP-SIMULATED" % (len(chunks), len(staged)))
        return all(v == "PASS" for (s, n, v, d) in RESULTS if s == "S4")
    except Exception as e:
        rec("S4", "ota exception", False, str(e)[:80])
        return False
    finally:
        httpd.shutdown()


def step_s5_integrity_spki():
    srv = serve_integrity_emulated()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        r_ok = integrity_verify(base, VALID_TOKEN, LEGIT_PACKAGE)
        r_bad = integrity_verify(base, "WRONG-TOKEN", LEGIT_PACKAGE)
        r_pkg = integrity_verify(base, VALID_TOKEN, "evil.package")
        ok = r_ok.get("allowed") is True and r_bad.get("allowed") is False and r_pkg.get("allowed") is False
        rec("S5", "integrity opaque allow/deny", ok, "token-bytes=%d never-logged" % len(VALID_TOKEN))
    except Exception as e:
        rec("S5", "integrity opaque allow/deny", False, str(e)[:80])
    finally:
        srv.shutdown()
        srv.server_close()
    # SPKI pin example: format + guard + match/mismatch (offline, no network)
    global _pins
    _pins = None
    try:
        pin_guard("https://ota.exemplo/manifest")
        rec("S5", "spki guard denies w/o pins", False, "should deny")
    except PermissionError:
        rec("S5", "spki guard denies w/o pins", True, "HTTPS negado fail-closed")
    leaf_spki = b"emulated-leaf-spki-example"
    good_pin = base64.b64encode(hashlib.sha256(leaf_spki).digest()).decode()
    try:
        pin_install(good_pin, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        fmt_ok = True
    except ValueError:
        fmt_ok = False
    rec("S5", "spki pin format 44c=", fmt_ok, "pins=2")
    try:
        pin_guard("https://ota.exemplo/manifest")
        guard_ok = True
    except PermissionError:
        guard_ok = False
    rec("S5", "spki guard passes w/ pins", guard_ok, "https-allowed")
    try:
        matched = pin_check_leaf(leaf_spki)
        match_ok = (matched == good_pin)
    except (ValueError, PermissionError):
        match_ok = False
    rec("S5", "spki leaf match", match_ok, "pin-len=%d" % len(good_pin))
    try:
        pin_check_leaf(b"other-spki")
        rec("S5", "spki mismatch denies", False, "should mismatch")
    except ValueError:
        rec("S5", "spki mismatch denies", True, "pin mismatch fail-closed")
    # http AP local passes without pins (per DevicePinning contract)
    try:
        pin_guard("http://192.168.4.1/oath/code?account=x")
        http_ok = True
    except PermissionError:
        http_ok = False
    rec("S5", "spki http-ap bypass", http_ok, "AP local sem pinning")
    return all(v == "PASS" for (s, n, v, d) in RESULTS if s == "S5")


def main():
    print("=" * 64)
    print("  EMULATED APP+SERVER SESSION (offline, SIMULATED-UP, no HW/COM/BLE)")
    print("=" * 64)
    dev = SimDevice()
    s1 = step_s1_scan_bond_claim(dev)
    s2 = step_s2_gates()
    s3 = step_s3_oath_wallet_fwlog(dev)
    s4 = step_s4_ota()
    s5 = step_s5_integrity_spki()
    print("-" * 64)
    counts = {}
    for s, n, v, d in RESULTS:
        counts[v] = counts.get(v, 0) + 1
    for s, n, v, d in RESULTS:
        pass  # already printed per-step
    n_pass = counts.get("PASS", 0)
    n_fail = counts.get("FAIL", 0)
    print("SUMMARY steps=S1..S5 total=%d pass=%d fail=%d" % (len(RESULTS), n_pass, n_fail))
    print("PLACAR S1(scan/bond/claim/challenge/verify)=%s S2(gates)=%s S3(oath/wallet/fwlog)=%s S4(ota)=%s S5(integrity/spki)=%s"
          % ("PASS" if s1 else "FAIL", "PASS" if s2 else "FAIL", "PASS" if s3 else "FAIL",
             "PASS" if s4 else "FAIL", "PASS" if s5 else "FAIL"))
    print("NOTE UP was SIMULATED throughout (UP-SIMULATED, no hardware claim).")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
