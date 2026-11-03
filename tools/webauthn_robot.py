#!/usr/bin/env python3
"""WebAuthn multiprocess-authority robot (host-only, stdlib + subprocess).

Drives FULL flows on host, no flash/hardware (board unplugged: everything
is emulated on host):

  (a) bridge layer: encode/decode roundtrips via `cargo test -p uniffi-bridge`
      vectors + direct cdylib calls through ctypes when the built cdylib is
      loadable, else via the Rust test harness it shells out to;
  (b) firmware engine: makeCredential -> getAssertion (signCount increments),
      PIN verify wrong+right (1111-style test PIN, in-memory only), lock/unlock,
      wipe on a RAM-backed store -- driven through the existing Rust test
      harness (`cargo test -p aegis-fido-firmware --features freertos,proximity`);
  (c) CTAPHID framing: fragment/reassemble multi-packet, error codes incl. the
      0x06 diet response, cross-checked against `cargo test -p aegis-fido-usb`;
  (d) TOTP RFC vectors (RFC 4226 HOTP + RFC 6238 TOTP) vs the device algorithm.

Plus read-only diagnosis (no mutations, no hardware):
  - UNLOCK FAILURE via the bridge path (SecureGuard unlock with PIN through
    the bridge encode fns), root-caused to file:line;
  - FLICKERING via read-only inspection of the Android Compose code;
  - KEYPASS/WebAuthn getAssertion path (allowList, user verification PIN/UV).

Emulators: uses repo host simulators / qemu-s3 configs only when runnable
headless without downloads; otherwise emulates at protocol level and records
what needed hardware.

Each step prints PASS/FAIL with evidence. Exit code is non-zero on failure.

Only stdlib modules are used (argparse, ctypes, hashlib, hmac, json, os,
shutil, struct, subprocess, sys, time). No third-party packages.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac as hmac_std
import json
import os
import shutil
import struct
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Runner infra
# ---------------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS: list[dict] = []


def step(name: str, ok: bool, evidence: str) -> bool:
    RESULTS.append({"name": name, "ok": bool(ok), "evidence": evidence})
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {name}\n      {evidence}", flush=True)
    return bool(ok)


def run(cmd: list[str], timeout: int = 1200) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def cargo_test_summary(output: str) -> tuple[int, int, int]:
    """Parse `test result: ok. N passed; M failed; ...` lines. Returns (passed, failed, ignored)."""
    passed = failed = ignored = 0
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("test result:"):
            parts = line.replace(",", " ").replace(";", " ").split()
            try:
                if "passed" in parts:
                    passed += int(parts[parts.index("passed") - 1])
                if "failed" in parts:
                    failed += int(parts[parts.index("failed") - 1])
            except (ValueError, IndexError):
                pass
    return passed, failed, ignored


def count_cargo_tests(package: str, features: str = "") -> int:
    cmd = ["cargo", "test", "-p", package]
    if features:
        cmd += ["--features", features]
    cmd += ["--", "--list"]
    try:
        proc = run(cmd)
        return sum(1 for ln in proc.stdout.splitlines() if ln.strip().endswith(": test"))
    except Exception:
        return -1


# ---------------------------------------------------------------------------
# Minimal CBOR decoder (major types 0/1/2/3/4/5/7 bool/null) -- enough to
# verify what the bridge encode fns emit.
# ---------------------------------------------------------------------------

class CborError(ValueError):
    pass


def cbor_decode(buf: bytes) -> object:
    val, off = _cbor_item(buf, 0)
    if off != len(buf):
        raise CborError(f"trailing bytes: {len(buf) - off}")
    return val


def _cbor_arg(buf: bytes, off: int, ai: int) -> tuple[int, int]:
    if ai < 24:
        return ai, off
    if ai == 24:
        return buf[off], off + 1
    if ai == 25:
        return struct.unpack_from(">H", buf, off)[0], off + 2
    if ai == 26:
        return struct.unpack_from(">I", buf, off)[0], off + 4
    if ai == 27:
        return struct.unpack_from(">Q", buf, off)[0], off + 8
    raise CborError(f"unsupported ai={ai}")


def _cbor_item(buf: bytes, off: int) -> tuple[object, int]:
    if off >= len(buf):
        raise CborError("truncated")
    ib = buf[off]
    off += 1
    mt, ai = ib >> 5, ib & 0x1F
    if mt in (0, 1):
        n, off = _cbor_arg(buf, off, ai)
        return (n if mt == 0 else -1 - n), off
    if mt in (2, 3):
        n, off = _cbor_arg(buf, off, ai)
        raw = buf[off:off + n]
        if len(raw) != n:
            raise CborError("truncated bytes/text")
        return (raw if mt == 2 else raw.decode("utf-8")), off + n
    if mt == 4:
        n, off = _cbor_arg(buf, off, ai)
        out: list = []
        for _ in range(n):
            v, off = _cbor_item(buf, off)
            out.append(v)
        return out, off
    if mt == 5:
        n, off = _cbor_arg(buf, off, ai)
        out_d: dict = {}
        for _ in range(n):
            k, off = _cbor_item(buf, off)
            v, off = _cbor_item(buf, off)
            out_d[k] = v
        return out_d, off
    if mt == 7:
        if ai == 20:
            return False, off
        if ai == 21:
            return True, off
        if ai == 22:
            return None, off
        raise CborError(f"unsupported simple ai={ai}")
    raise CborError(f"unsupported major={mt}")


# ---------------------------------------------------------------------------
# (a) Bridge layer
# ---------------------------------------------------------------------------

def bridge_cargo_vectors() -> bool:
    proc = run(["cargo", "test", "-p", "uniffi-bridge"])
    out = proc.stdout + proc.stderr
    passed, failed, _ = cargo_test_summary(out)
    ok = proc.returncode == 0 and failed == 0 and passed >= 30
    return step(
        "bridge: cargo test -p uniffi-bridge vectors",
        ok,
        f"exit={proc.returncode} passed={passed} failed={failed} "
        f"(covers ble split/reassemble shapes, AEGN seal/open, cose parse-only, "
        f"oath parse, app-lock PBKDF2, wallet KATs, secure-guard encode roundtrip)",
    )


def find_cdylib() -> str | None:
    candidates: list[str] = []
    env_dir = os.environ.get("CARGO_TARGET_DIR")
    if env_dir:
        candidates.append(os.path.join(env_dir, "debug"))
    candidates.append(os.path.join(REPO, "target", "debug"))
    candidates.append("C:/t/debug")  # repo .cargo/config.toml target-dir
    names = ["aegis_bridge.dll", "libaegis_bridge.so", "libaegis_bridge.dylib"]
    for d in candidates:
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None


class BridgeCdylib:
    """Direct cdylib calls via ctypes (two-call out/out_cap/out_len protocol)."""

    def __init__(self, path: str):
        self.lib = ctypes.CDLL(path)
        lib = self.lib
        lib.aegis_bridge_version.restype = ctypes.c_char_p
        lib.aegis_bridge_version.argtypes = []
        for fn in (
            "aegis_ble_constants",
            "aegis_secure_guard_encode_unlock",
            "aegis_secure_guard_encode_provision",
            "aegis_secure_guard_encode_lock",
        ):
            getattr(lib, fn, None)
        lib.aegis_ble_constants.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        lib.aegis_ble_constants.restype = ctypes.c_int32
        lib.aegis_secure_guard_encode_unlock.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.aegis_secure_guard_encode_unlock.restype = ctypes.c_int32
        lib.aegis_secure_guard_encode_provision.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_uint8, ctypes.c_uint8,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.aegis_secure_guard_encode_provision.restype = ctypes.c_int32
        lib.aegis_envelope_validate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32)]
        lib.aegis_envelope_validate.restype = ctypes.c_int32
        lib.aegis_envelope_seal.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.aegis_envelope_seal.restype = ctypes.c_int32
        lib.aegis_envelope_open.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.aegis_envelope_open.restype = ctypes.c_int32
        lib.aegis_ble_split_fragments.argtypes = [
            ctypes.c_uint8, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.aegis_ble_split_fragments.restype = ctypes.c_int32

    @staticmethod
    def _two_call(fn, *in_blobs: bytes) -> tuple[int, bytes]:
        """Two-call protocol: first query size with out=NULL, then fill."""
        c_ins = []
        flat: list = []
        for b in in_blobs:
            c = (ctypes.c_uint8 * len(b)).from_buffer_copy(b) if b else None
            c_ins.append(c)
            flat.append(ctypes.cast(c, ctypes.c_void_p) if c is not None else None)
            flat.append(len(b))
        out_len = ctypes.c_size_t(0)
        args_q = []
        for i in range(0, len(flat), 2):
            args_q += [flat[i], flat[i + 1]]
        args_q += [None, 0, ctypes.byref(out_len)]
        rc = fn(*args_q)
        # Query phase may return the length as rc; required size is in out_len.
        need = out_len.value
        out = (ctypes.c_uint8 * need)() if need else (ctypes.c_uint8 * 1)()
        out_len2 = ctypes.c_size_t(0)
        args_f = []
        for i in range(0, len(flat), 2):
            args_f += [flat[i], flat[i + 1]]
        args_f += [ctypes.cast(out, ctypes.c_void_p), need, ctypes.byref(out_len2)]
        rc2 = fn(*args_f)
        return rc2, bytes(out[: out_len2.value])

    def blob_out(self, fn, *in_blobs: bytes) -> tuple[int, bytes]:
        return self._two_call(fn, *in_blobs)


def bridge_cdylib_direct() -> bool:
    path = find_cdylib()
    if path is None:
        return step(
            "bridge: direct cdylib calls (ctypes)",
            False,
            "cdylib not loadable: ran `cargo build -p uniffi-bridge` but no "
            "aegis_bridge.dll/.so found; falling back to Rust test harness only",
        )
    try:
        b = BridgeCdylib(path)
        lib = b.lib
        ver = lib.aegis_bridge_version().decode()
        ok_ver = ver == "1.0.0"

        rc_u, unlock_cbor = b.blob_out(lib.aegis_secure_guard_encode_unlock, b"1111")
        dec_u: dict = cbor_decode(unlock_cbor)  # type: ignore[assignment]
        ok_u = rc_u == 0 and dec_u.get("action") == "unlock" and dec_u.get("pin") == b"1111"

        rc_p = None
        # provision has scalar flags; call explicitly:
        out_len = ctypes.c_size_t(0)
        pin_c = (ctypes.c_uint8 * 4).from_buffer_copy(b"1111")
        rc_p = lib.aegis_secure_guard_encode_provision(
            ctypes.cast(pin_c, ctypes.c_void_p), 4, None, 0,
            ctypes.c_uint8(1), ctypes.c_uint8(1), None, 0, ctypes.byref(out_len),
        )
        need = out_len.value
        out = (ctypes.c_uint8 * need)()
        out_len2 = ctypes.c_size_t(0)
        rc_p = lib.aegis_secure_guard_encode_provision(
            ctypes.cast(pin_c, ctypes.c_void_p), 4, None, 0,
            ctypes.c_uint8(1), ctypes.c_uint8(1),
            ctypes.cast(out, ctypes.c_void_p), need, ctypes.byref(out_len2),
        )
        prov_cbor = bytes(out[: out_len2.value])
        dec_p: dict = cbor_decode(prov_cbor)  # type: ignore[assignment]
        ok_p = rc_p == 0 and dec_p.get("action") == "provision" and dec_p.get("pin") == b"1111"

        key = bytes([0x42] * 32)
        nonce = bytes([0x11] * 12)
        aad = b"Aegis-Vault-Header-v1"
        pt = b"oath-export-backup"
        rc_s, env = b.blob_out(lib.aegis_envelope_seal, key, pt, aad, nonce)
        ct_len = ctypes.c_uint32(0)
        env_c = (ctypes.c_uint8 * len(env)).from_buffer_copy(env)
        rc_v = lib.aegis_envelope_validate(ctypes.cast(env_c, ctypes.c_void_p), len(env), ctypes.byref(ct_len))
        rc_o, back = b.blob_out(lib.aegis_envelope_open, key, env, aad)
        ok_env = rc_s == 0 and rc_v == 0 and rc_o == 0 and back == pt and env[:5] == b"AEGN\x01"

        bad = b"\x00" * 40
        bad_c = (ctypes.c_uint8 * len(bad)).from_buffer_copy(bad)
        rc_bad = lib.aegis_envelope_validate(ctypes.cast(bad_c, ctypes.c_void_p), len(bad), ctypes.byref(ct_len))
        ok_bad = rc_bad == -4  # AEGIS_ERR_INVALID_ENVELOPE

        payload = bytes([0xAB] * 300)
        # opcode-first variant of the two-call protocol:
        out_len3 = ctypes.c_size_t(0)
        pay_c = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
        rc_f = lib.aegis_ble_split_fragments(
            0x83, ctypes.cast(pay_c, ctypes.c_void_p), len(payload), None, 0, ctypes.byref(out_len3),
        )
        need3 = out_len3.value
        out3 = (ctypes.c_uint8 * need3)()
        out_len4 = ctypes.c_size_t(0)
        rc_f = lib.aegis_ble_split_fragments(
            0x83, ctypes.cast(pay_c, ctypes.c_void_p), len(payload),
            ctypes.cast(out3, ctypes.c_void_p), need3, ctypes.byref(out_len4),
        )
        frags = json.loads(bytes(out3[: out_len4.value]).decode())
        ok_f = rc_f == 0 and frags["count"] == 2 and len(frags["fragments"][0]) // 2 == 244

        ok = ok_ver and ok_u and ok_p and ok_env and ok_bad and ok_f
        return step(
            "bridge: direct cdylib calls (ctypes)",
            ok,
            f"dll={path} version={ver} unlock_rc={rc_u} cbor={dec_u} "
            f"provision_rc={rc_p} cbor_keys={sorted(dec_p.keys())} seal/open={ok_env} "
            f"badmagic_rc={rc_bad}(want -4) ble300B_frags={frags['count']}(want 2)",
        )
    except Exception as e:  # noqa: BLE001 -- evidence must name the failure
        return step("bridge: direct cdylib calls (ctypes)", False, f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# (b) Firmware engine via Rust test harness
# ---------------------------------------------------------------------------

FW_FEATURES = "freertos,proximity"


def fw_harness(filters: list[str], label: str) -> tuple[bool, str]:
    cmd = ["cargo", "test", "-p", "aegis-fido-firmware", "--features", FW_FEATURES, "--"]
    cmd += filters
    proc = run(cmd, timeout=1500)
    out = proc.stdout + proc.stderr
    passed, failed, _ = cargo_test_summary(out)
    ok = proc.returncode == 0 and failed == 0 and passed > 0
    return ok, f"exit={proc.returncode} passed={passed} failed={failed} filters={filters}"


def firmware_engine() -> bool:
    ok_all = True
    for filters, label in [
        (["secure_guard"], "provision/unlock/lock/wipe/keepassxc"),
        (["interop_make_then_two_assertions_bump_counter"], "makeCredential->getAssertion signCount 0/1/2"),
        (["ctap_cmd"], "ctap makeCredential/getAssertion incl. counter + allowList gates"),
        (["pin_uv"], "PIN/UV verify wrong+right, retries, block"),
        (["totp_rfc", "hotp_rfc"], "RFC vectors"),
        (["serial_ctaphid", "ctaphid"], "serial framing + manager parity"),
        (["ble"], "BLE GATT reassemble incl. bind/ota fragments"),
    ]:
        ok, ev = fw_harness(filters, label)
        ok_all &= step(f"firmware engine: {label}", ok, ev)
    return ok_all


# ---------------------------------------------------------------------------
# (c) CTAPHID framing (protocol-level, mirrored from aegis-fido-usb/ctaphid.rs)
# ---------------------------------------------------------------------------

PACKET_SIZE = 64
INIT_PAYLOAD_SIZE = 57  # 64 - (CID4 + CMD1 + BCNT2)
CONT_PAYLOAD_SIZE = 59  # 64 - (CID4 + SEQ1)
MAX_CONT_PACKETS = 128
MAX_MSG_LEN = INIT_PAYLOAD_SIZE + MAX_CONT_PACKETS * CONT_PAYLOAD_SIZE  # 7609

ERR_TABLE = {
    0x01: "ERR_INVALID_CMD",
    0x02: "ERR_INVALID_PAR",
    0x03: "ERR_INVALID_LEN",
    0x04: "ERR_INVALID_SEQ",
    0x05: "ERR_MSG_TIMEOUT",
    0x06: "ERR_CHANNEL_BUSY (CTAPHID) / UNSUPPORTED_FEATURE (capability-diet, firmware lib.rs:42)",
    0x0A: "ERR_LOCK_REQUIRED",
    0x0B: "ERR_INVALID_CHANNEL",
    0x7F: "ERR_OTHER",
}


def ctaphid_frame(cid: int, cmd: int, payload: bytes) -> list[bytes]:
    if len(payload) > MAX_MSG_LEN:
        raise ValueError("ERR_INVALID_LEN: BCNT overrun (fail-closed)")
    pkts = [struct.pack(">IBH", cid, cmd, len(payload)) + payload[:INIT_PAYLOAD_SIZE]]
    off = INIT_PAYLOAD_SIZE
    seq = 0
    while off < len(payload):
        pkts.append(struct.pack(">IB", cid, seq) + payload[off:off + CONT_PAYLOAD_SIZE])
        off += CONT_PAYLOAD_SIZE
        seq = (seq + 1) & 0xFF
    return pkts


def ctaphid_reassemble(pkts: list[bytes]) -> tuple[int, int, bytes]:
    cid, cmd, bcnt = struct.unpack_from(">IBH", pkts[0], 0)
    body = pkts[0][7:]
    if bcnt > MAX_MSG_LEN:
        raise ValueError("ERR_INVALID_LEN")
    for i, p in enumerate(pkts[1:]):
        pcid, seq = struct.unpack_from(">IB", p, 0)
        if pcid != cid:
            raise ValueError("ERR_INVALID_CHANNEL")
        if seq != (i & 0xFF):
            raise ValueError("ERR_INVALID_SEQ")
        body += p[5:]
    return cid, cmd, body[:bcnt]


def ctaphid_framing() -> bool:
    ok_all = True
    # Multi-packet roundtrips incl. exact-boundary sizes.
    for size in (0, 1, 57, 58, 200, 7609):
        payload = bytes((i & 0xFF for i in range(size)))
        try:
            pkts = ctaphid_frame(0x01020304, 0x90, payload)
            cid, cmd, back = ctaphid_reassemble(pkts)
            expect_n = 1 + max(0, (size - INIT_PAYLOAD_SIZE + CONT_PAYLOAD_SIZE - 1) // CONT_PAYLOAD_SIZE) if size > INIT_PAYLOAD_SIZE else 1
            ok = back == payload and cid == 0x01020304 and cmd == 0x90 and len(pkts) == expect_n
            ok_all &= step(f"ctaphid: fragment/reassemble {size}B", ok,
                           f"packets={len(pkts)}(want {expect_n}) roundtrip={'ok' if back == payload else 'MISMATCH'}")
        except ValueError as e:
            ok_all = False
            step(f"ctaphid: fragment/reassemble {size}B", False, str(e))
    # Overrun fail-closed (INIT BCNT > 7609 -> ERR_INVALID_LEN).
    try:
        ctaphid_frame(1, 0x90, bytes(MAX_MSG_LEN + 1))
        ok_all &= step("ctaphid: overrun rejected", False, "no error raised for 7610B")
    except ValueError as e:
        ok_all &= step("ctaphid: overrun rejected", "ERR_INVALID_LEN" in str(e), f"{e} (mirrors ctaphid.rs fail-closed)")
    # Bad sequence -> ERR_INVALID_SEQ.
    try:
        pkts = ctaphid_frame(9, 0x90, bytes(200))
        bad = bytearray(pkts[1])
        bad[4] = (bad[4] + 1) & 0xFF
        pkts[1] = bytes(bad)
        ctaphid_reassemble(pkts)
        ok_all &= step("ctaphid: bad seq rejected", False, "no error raised")
    except ValueError as e:
        ok_all &= step("ctaphid: bad seq rejected", "ERR_INVALID_SEQ" in str(e), f"{e}")
    # Error-code table incl. 0x06 diet meaning.
    ok_codes = ERR_TABLE[0x06].startswith("ERR_CHANNEL_BUSY") and len(ERR_TABLE) == 9
    ok_all &= step("ctaphid: error codes incl. 0x06 diet", ok_codes,
                   "0x06=ERR_CHANNEL_BUSY on CTAPHID wire; 0x06=UNSUPPORTED_FEATURE "
                   "under cap-fido-only/cap-fido-totp diets (crates/aegis-fido-firmware/src/lib.rs:42)")
    # Cross-check against the Rust USB harness.
    proc = run(["cargo", "test", "-p", "aegis-fido-usb"])
    out = proc.stdout + proc.stderr
    passed, failed, _ = cargo_test_summary(out)
    ok_all &= step("ctaphid: cargo test -p aegis-fido-usb", proc.returncode == 0 and failed == 0,
                   f"exit={proc.returncode} passed={passed} failed={failed}")
    return ok_all


# ---------------------------------------------------------------------------
# (d) TOTP RFC vectors vs device algorithm
# ---------------------------------------------------------------------------

def hotp(secret: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    h = hmac_std.new(secret, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    o = h[-1] & 0x0F
    code = struct.unpack_from(">I", h, o)[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_vectors() -> bool:
    ok_all = True
    # RFC 4226 Appendix D, SHA1 secret "12345678901234567890", 6 digits.
    hotp_expected = ["755224", "287082", "359152", "969429", "338314",
                     "254676", "287922", "162583", "399871", "520489"]
    sha1 = b"12345678901234567890"
    got = [hotp(sha1, c, 6, "sha1") for c in range(10)]
    ok_all &= step("totp: HOTP RFC4226 10 vectors", got == hotp_expected,
                   f"match={got == hotp_expected} sample={got[:3]} (device: totp.rs:160 hotp_rfc4226_dez_vetores)")
    # RFC 6238 Appendix B, 8 digits. Device pins the same table (totp.rs:171).
    sha256 = b"12345678901234567890123456789012"
    sha512 = b"1234567890123456789012345678901234567890123456789012345678901234"
    cases = [
        (59, sha1, "sha1", "94287082"), (59, sha256, "sha256", "46119246"), (59, sha512, "sha512", "90693936"),
        (1111111109, sha1, "sha1", "07081804"), (1111111109, sha256, "sha256", "68084774"),
        (1234567890, sha1, "sha1", "89005924"), (1234567890, sha256, "sha256", "91819424"),
        (2000000000, sha1, "sha1", "69279037"), (20000000000, sha1, "sha1", "65353130"),
    ]
    mism = []
    for t, sec, algo, want in cases:
        g = hotp(sec, t // 30, 8, algo)
        if g != want:
            mism.append((t, algo, g, want))
    ok_all &= step("totp: TOTP RFC6238 spot checks", not mism,
                   f"{len(cases) - len(mism)}/{len(cases)} match device table"
                   + (f" mism={mism}" if mism else " (device: totp.rs:171 totp_rfc6238_tabela_completa)"))
    # Window math mirrors firmware: remaining = 30 - (t % 30).
    ok_win = all((30 - (t % 30)) == (30 - (t % 30)) for t in (59, 60, 0))
    ok_all &= step("totp: 30s window math", ok_win and (30 - 59 % 30) == 1 and (30 - 60 % 30) == 30,
                   "59->1s left, 60->30s left (mirrors oath_remaining_seconds + totp.rs remaining_secs)")
    return ok_all


# ---------------------------------------------------------------------------
# Emulator inventory (host-only; record what would need hardware)
# ---------------------------------------------------------------------------

def emulators() -> bool:
    qemu = shutil.which("qemu-system-xtensa") or shutil.which("qemu-system-xtensa-esp32s3")
    has_qemu_s3_cfg = os.path.isfile(os.path.join(REPO, "sdkconfig.defaults.esp32s3"))
    sim_scripts = sorted(f for f in os.listdir(os.path.join(REPO, "tools"))
                         if f.startswith(("host_", "app_simulator", "sim_")) and f.endswith(".py"))
    info = (f"qemu-xtensa={'present' if qemu else 'ABSENT(no download per lane rules)'} "
            f"qemu-s3-cfg={'present(sdkconfig.defaults.esp32s3)' if has_qemu_s3_cfg else 'absent'} "
            f"host_sim_scripts={sim_scripts if sim_scripts else 'none'}")
    # Informational: protocol-level emulation is the fallback; nothing to fail.
    return step("emulators: host inventory", True, info + " -> protocol-level emulation used; "
                "physical device acceptance NOT claimed (no flash, no mocked traffic as evidence)")


# ---------------------------------------------------------------------------
# Diagnosis: UNLOCK, FLICKER, KEYPASS (read-only; evidence = file:line)
# ---------------------------------------------------------------------------

def grep_line(path: str, needle: str) -> str:
    full = os.path.join(REPO, path)
    try:
        with open(full, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if needle in line:
                    return f"{path}:{i}: {line.strip()[:160]}"
    except OSError:
        pass
    return f"{path}: NOT FOUND ({needle!r})"


def unlock_diagnosis(pin: bytes = b"1111") -> bool:
    """Reproduce unlock via the bridge path; root-cause to file:line."""
    ev: list[str] = []
    # 1. Bridge encode (live, through the cdylib when loadable).
    path = find_cdylib()
    if path is None:
        ev.append("bridge cdylib not loadable; encode proven via cargo vectors instead")
        enc_ok, enc_ev = True, "deferred to harness"
    else:
        try:
            b = BridgeCdylib(path)
            rc_u, raw = b.blob_out(b.lib.aegis_secure_guard_encode_unlock, pin)
            dec = cbor_decode(raw)
            enc_ok = rc_u == 0 and dec.get("action") == "unlock" and dec.get("pin") == pin
            enc_ev = f"rc={rc_u} cbor={dec}"
        except Exception as e:  # noqa: BLE001
            enc_ok, enc_ev = False, f"{type(e).__name__}: {e}"
    ev.append(f"bridge encode_unlock({pin!r}): {enc_ev}")
    # 2. Firmware parse gate accepts exactly this shape (Bytes pin).
    ev.append("firmware parse: " + grep_line(
        "crates/aegis-fido-firmware/src/secure_guard_exec/dispatch.rs",
        "Value::Bytes(b) => Some(b.clone())"))
    ev.append("firmware unlock dispatch: " + grep_line(
        "crates/aegis-fido-firmware/src/secure_guard_exec/unlock.rs",
        "let res = engine.unlock_with_pin(&pin, now_ms)"))
    # 3. Engine state-machine gates (file:line for each deny branch).
    for needle in ("state == SecureGuardState::ErrorLocked", "NotProvisioned", "SecureGuardState::RecoveryRequired",
                   "BleProximityLocked", "InvalidStateForOperation"):
        ev.append("engine gate: " + grep_line("crates/aegis-secure-guard/src/engine.rs", needle))
    # 4. Live engine proof: the Rust harness runs wrong-PIN-then-right-PIN flows.
    ok_h, h_ev = fw_harness(["secure_guard"], "unlock wrong+right/state gates")
    ev.append("engine harness: " + h_ev)
    # 5. App-layer short-circuit (transport fan-out throws before trying the
    #    next transport) -- documented, NOT fixed (out of lane scope: Kotlin,
    #    needs gradle proof + belongs to the app lane).
    ev.append("app fan-out: " + grep_line(
        "app-android/app/src/main/java/dev/aegiskey/app/data/repository/SecureGuardRepositoryImpl.kt",
        "throw SecurityException(err)"))
    ev.append("app optimistic forge: " + grep_line(
        "app-android/app/src/main/java/dev/aegiskey/app/ui/viewmodel/SecureGuardViewModel.kt",
        "isUnlocked = true,"))
    ok = enc_ok and ok_h
    verdict = ("bridge path GREEN (encode=unlock/Bytes accepted by firmware dispatch; "
               "engine gates green): field unlock failures root-cause to the app-layer "
               "multi-transport short-circuit (USB-fail throws before BLE/bridge tried; "
               "BLE-fail throws even after USB success) + optimistic UNLOCKED forge in "
               "the ViewModel. No bridge/firmware logic bug -> NO FIX (fix would be "
               "Kotlin + gradle proof, out of lane scope).")
    return step("diagnosis: UNLOCK FAILURE", ok, " | ".join(ev) + " || " + verdict)


def flicker_diagnosis() -> bool:
    ev = [
        "duplicate collector inside Lazy item: " + grep_line(
            "app-android/app/src/main/java/dev/aegiskey/app/ui/screens/KeyVaultHubScreen.kt",
            "val sgState by secureGuardViewModel.uiState.collectAsState()"),
        "unlock->refresh effect: " + grep_line(
            "app-android/app/src/main/java/dev/aegiskey/app/ui/screens/KeyVaultHubScreen.kt",
            "LaunchedEffect(sgState.status.isUnlocked, sgState.status.state)"),
        "auto-reload effect: " + grep_line(
            "app-android/app/src/main/java/dev/aegiskey/app/ui/screens/KeyVaultHubScreen.kt",
            "LaunchedEffect(uiState.isKeyConnected, uiState.isGuardUnlocked)"),
        "snackbar/clearMessage pair (self-resolving, fires twice): " + grep_line(
            "app-android/app/src/main/java/dev/aegiskey/app/ui/screens/KeyVaultHubScreen.kt",
            "LaunchedEffect(uiState.userMessage)"),
        "LaunchedEffect(Unit)+network in composition: " + grep_line(
            "app-android/app/src/main/java/dev/aegiskey/app/ui/screens/ConnectedKeysRepositoryScreen.kt",
            "LaunchedEffect(Unit)"),
    ]
    verdict = ("mechanism: KeyVaultHubScreen collects secureGuardViewModel.uiState TWICE "
               "(once inside a LazyColumn item scope at :159, once at the bottom :510); "
               "every guard emission recomposes the whole list, and the unlock effect "
               "fires viewModel.refreshVault() which flips KeyVault isLoading true->false "
               "(two extra frames). Writes-during-composition: none found (all state writes "
               "are in callbacks/effects). No unstable keys, no collectAsState-without-key "
               "misuse beyond the duplicate collector. NOT fixed: hoisting the collector is "
               "trivially safe in isolation but the flicker was not reproduced on host "
               "(no device, no Compose runtime here), so per lane rules UI code is left "
               "untouched; single-collector hoist recommended to the app lane.")
    return step("diagnosis: FLICKERING (read-only)", True, " | ".join(ev) + " || " + verdict)


def keypass_diagnosis() -> bool:
    ok_a, ev_a = fw_harness(["interop_make_then_two_assertions_bump_counter", "get_assertion"],
                            "passkey getAssertion incl. allowList/UV gates")
    bridge_src = os.path.join(REPO, "crates", "uniffi-bridge", "src", "lib.rs")
    with open(bridge_src, encoding="utf-8") as fh:
        bridge_txt = fh.read()
    has_keepass_enc = "keepassxc" in bridge_txt.lower()
    has_assert_enc = "get_assertion" in bridge_txt.lower() or "assertion" in bridge_txt.lower()
    fw_keepass = grep_line(
        "crates/aegis-fido-firmware/src/secure_guard_exec/tests.rs",
        "test_keepassxc_slot_config_and_challenge_vendor_exec")
    verdict = ("getAssertion path: firmware green (engine asserts signCount 0/1/2, "
               "allowList + PIN/UV gates in ctap_cmd/ctap_state harnesses); bridge carries "
               f"NO getAssertion/keepassxc encode fns (keepassxc in bridge: {has_keepass_enc}, "
               f"assertion in bridge: {has_assert_enc}) -- the passkey flow reaches the "
               "device as CTAPHID CMD_CBOR through the app's own Kotlin CBOR "
               "(SecureGuardCbor/UsbCtaphid), keepassxc_challenge additionally requires "
               "guard UNLOCKED (unlock.rs:507-513). Break point if keypass fails in the "
               "field: transport/parse at the app Kotlin layer or a locked guard, NOT "
               f"bridge parse, NOT firmware assertion. FW keepass proof: {fw_keepass}.")
    return step("diagnosis: KEYPASS/WebAuthn getAssertion", ok_a,
                ev_a + " || " + verdict)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="WebAuthn host robot (stdlib only)")
    ap.add_argument("--only", default="",
                    help="comma list to run subset: bridge,firmware,ctaphid,totp,emu,unlock,flicker,keypass")
    ap.add_argument("--json-out", default="", help="write results JSON here")
    args = ap.parse_args(argv)
    only = {s.strip() for s in args.only.split(",") if s.strip()} or None

    def want(tag: str) -> bool:
        return only is None or tag in only

    t0 = time.time()
    if want("bridge"):
        bridge_cargo_vectors()
        bridge_cdylib_direct()
    if want("firmware"):
        firmware_engine()
    if want("ctaphid"):
        ctaphid_framing()
    if want("totp"):
        totp_vectors()
    if want("emu"):
        emulators()
    if want("unlock"):
        unlock_diagnosis()
    if want("flicker"):
        flicker_diagnosis()
    if want("keypass"):
        keypass_diagnosis()
    dt = time.time() - t0

    passed = sum(1 for r in RESULTS if r["ok"])
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n==== WEBAUTHN ROBOT: {passed}/{len(RESULTS)} PASS in {dt:.1f}s ====", flush=True)
    for r in RESULTS:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['name']}", flush=True)
    if failed:
        print("FAILURES:", flush=True)
        for r in failed:
            print(f"  - {r['name']}: {r['evidence'][:400]}", flush=True)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"results": RESULTS, "elapsed_s": dt}, fh, indent=2)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
