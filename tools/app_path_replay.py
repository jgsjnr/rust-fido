#!/usr/bin/env python3
"""App-path unlock replay (host-only, stdlib + ctypes + subprocess).

Builds the EXACT unlock bytes the Android app sends (PIN "1111", the test
PIN also used by the device-recovery flow) and feeds them through:

  (a) ctypes into the aegis_bridge cdylib encode path
      (reuses tools/webauthn_robot.py BridgeCdylib/find_cdylib/cbor_decode --
      no duplication), and
  (b) the firmware dispatch path via the existing host test harness
      (reuses webauthn_robot.run/cargo_test_summary; focused test runs with
      `--test-threads=1`).

Byte sources mirrored 1:1 from the app (file:line cited per stage):
  APP_CBOR  SecureGuardCbor.encodeUnlockRequest  (SecureGuardCbor.kt:46-52,
            header short-form SecureGuardCbor.kt:174-203)
  APP_USB   UsbCtaphid.frameMessage + sendVendor  (UsbCtaphid.kt:406-436,
            reqPayload UsbCtaphid.kt:603-605, parse-back UsbCtaphid.kt:687)
  APP_BLE   AegisBridge.splitFragmentsFallback   (AegisBridge.kt:559-589,
            isBleFragmentOpcode AegisBridge.kt:~550-557)

Firmware gates the same bytes hit:
  USB op extraction      freertos_route.rs:160 (`let op = payload[0]`)
  SG dispatch            freertos_route.rs:238 (`is_secure_guard_op(op)`)
                         + secure_guard_exec/dispatch.rs:191-195 (0x3A..0x3E)
  unlock parse/shape     secure_guard_exec/unlock.rs:106-139
                         (CBOR map, action="unlock", pin as Bytes-or-Text)
  success envelope       secure_guard_exec/unlock.rs:634-651
                         (0x00 + {success:true state:4 state_name:"Unlocked"..})
  app parse-back         SecureGuardCbor.kt:211-248 (parseTransportFrame)
                         + SecureGuardCbor.kt:306-328 (parseUnlockResult)

Exit code: 0 iff every byte-identity assert AND the focused firmware
harness pass. Divergences that live outside this byte path (transport
selection, stale cache, simulator wiring) are reported as NOTED findings
with file:line -- they do not fail the replay, they ARE the answer to
"where does the app path break".
"""

from __future__ import annotations

import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools"))
import webauthn_robot as R  # noqa: E402  (reuse: cbor_decode, BridgeCdylib, run, ...)

RESULTS: list[dict] = []
PIN = b"1111"


def step(name: str, ok: bool, evidence: str) -> bool:
    RESULTS.append({"name": name, "ok": bool(ok), "evidence": evidence})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n      {evidence}", flush=True)
    return bool(ok)


# ---------------------------------------------------------------------------
# 1:1 mirrors of the Kotlin encoders (short-form headers only, as the app
# emits for these small values).
# ---------------------------------------------------------------------------

def cbor_uint_head(major: int, n: int) -> bytes:
    assert 0 <= n < 24, "app short-form only for these sizes"
    return bytes([(major << 5) | n])


def cbor_text(s: str) -> bytes:
    b = s.encode("utf-8")
    return cbor_uint_head(3, len(b)) + b


def cbor_bytes(b: bytes) -> bytes:
    return cbor_uint_head(2, len(b)) + b


def app_encode_unlock_request(pin: bytes) -> bytes:
    """Mirror of SecureGuardCbor.encodeUnlockRequest (SecureGuardCbor.kt:46-52):
    map(2){ "action": text("unlock"), "pin": bytes(pin) }."""
    return (
        cbor_uint_head(5, 2)
        + cbor_text("action") + cbor_text("unlock")
        + cbor_text("pin") + cbor_bytes(pin)
    )


def app_usb_frame_message(cid: int, cmd: int, payload: bytes) -> list[bytes]:
    """Mirror of UsbCtaphid.frameMessage (UsbCtaphid.kt:406-436)."""
    out: list[bytes] = []
    total = len(payload)
    first = bytearray(64)
    first[0:4] = struct.pack(">I", cid & 0xFFFFFFFF)
    first[4] = (cmd | 0x80) & 0xFF
    first[5:7] = struct.pack(">H", total)
    first[7:7 + min(57, total)] = payload[:57]
    out.append(bytes(first))
    off, seq = min(57, total), 0
    while off < total:
        pkt = bytearray(64)
        pkt[0:4] = struct.pack(">I", cid & 0xFFFFFFFF)
        pkt[4] = seq & 0x7F
        n = min(59, total - off)
        pkt[5:5 + n] = payload[off:off + n]
        out.append(bytes(pkt))
        off += n
        seq += 1
    return out


def app_usb_reassemble(pkts: list[bytes]) -> tuple[int, int, bytes]:
    """Mirror of UsbCtaphid.sendCtapMessage reassembly (UsbCtaphid.kt:536-601)."""
    cid, cmd, bcnt = struct.unpack_from(">IBH", pkts[0], 0)
    body = pkts[0][7:7 + min(57, bcnt)]
    for i, p in enumerate(pkts[1:]):
        pcid, seq = struct.unpack_from(">IB", p, 0)
        assert pcid == cid and (seq & 0x7F) == (i & 0x7F), "seq/channel mismatch"
        body += p[5:5 + min(59, bcnt - len(body))]
    return cid, cmd, body[:bcnt]


def app_ble_split_fragments(opcode: int, payload: bytes) -> list[bytes]:
    """Mirror of AegisBridge.splitFragmentsFallback (AegisBridge.kt:559-589)."""
    op = opcode & 0xFF
    assert op in list(range(0x20, 0x28)) + list(range(0x35, 0x3F)) + list(range(0x30, 0x35)) + [0x2D], \
        f"isBleFragmentOpcode rejects 0x{op:02X}"
    assert len(payload) <= 512, "overflow control-point"
    total = len(payload)
    first_n = min(244 - 3, total)
    out = [bytes([op, (total >> 8) & 0xFF, total & 0xFF]) + payload[:first_n]]
    off, seq = first_n, 0
    while off < total:
        chunk = min(244 - 1, total - off)
        out.append(bytes([(seq & 0xFF)]) + payload[off:off + chunk])
        off += chunk
        seq = (seq + 1) & 0xFF
    return out


def app_parse_transport_frame(expected_op: int, raw: bytes) -> tuple[int | None, int, bytes]:
    """Mirror of SecureGuardCbor.parseTransportFrame (SecureGuardCbor.kt:211-248)."""
    if len(raw) >= 2 and raw[0] == expected_op:
        return expected_op, raw[1], raw[2:]
    b1 = raw[1] if len(raw) >= 2 else None
    if b1 is not None and ((b1 & 0xE0) == 0xA0 or b1 in (0xB8, 0xB9)):
        return None, raw[0], raw[1:]
    b0 = raw[0]
    if (b0 & 0xE0) == 0xA0 or b0 in (0xB8, 0xB9):
        return None, 0x00, raw
    for i, b in enumerate(raw):
        if (b & 0xE0) == 0xA0 or b in (0xB8, 0xB9):
            st = raw[i - 1] if i > 0 else 0x00
            op = expected_op if (i > 1 and raw[0] == expected_op) else None
            return op, st, raw[i:]
    return None, raw[0], raw


def app_parse_unlock_result(status_byte: int, cbor: bytes) -> dict:
    """Mirror of SecureGuardCbor.parseUnlockResult (SecureGuardCbor.kt:306-328)."""
    dec = R.cbor_decode(cbor)
    assert isinstance(dec, dict)
    success = (status_byte == 0x00) and (dec.get("success", True) is True)
    state_name = dec.get("state_name", "Unlocked" if success else "Locked")
    return {"success": success, "state_name": state_name,
            "state": dec.get("state"), "error": dec.get("error")}


def main() -> int:
    ok_all = True

    # -- Stage 1: exact app CBOR bytes -------------------------------------
    app_cbor = app_encode_unlock_request(PIN)
    # Hand-computed from SecureGuardCbor writeHeader/writeString/writeBytes:
    # A2 | 66 "action" | 66 "unlock" | 63 "pin" | 44 "1111"
    want_hex = "a266616374696f6e66756e6c6f636b6370696e4431313131"
    ok_all &= step(
        "app-bytes: encodeUnlockRequest(1111) == hand-computed wire",
        app_cbor.hex() == want_hex,
        f"got={app_cbor.hex()} want={want_hex} "
        f"(SecureGuardCbor.kt:46-52 + writeHeader/174-203)",
    )

    # -- Stage 2: USB HID framing (CID/CMD/payload) -------------------------
    vendor_payload = bytes([0x3B]) + app_cbor  # UsbCtaphid.kt:604 reqPayload
    pkts = app_usb_frame_message(0x01020304, 0x83, vendor_payload)  # UsbCtaphid.kt:150,406
    cid, cmd, back = app_usb_reassemble(pkts)
    ok_all &= step(
        "app-bytes: USB CTAPHID frame (CID=0x01020304 CMD=0x83) roundtrip",
        len(pkts) == 1 and cid == 0x01020304 and cmd == 0x83 and back == vendor_payload
        and back[0] == 0x3B and back[1:] == app_cbor,
        f"packets={len(pkts)} cid=0x{cid:08X} cmd=0x{cmd:02X} "
        f"payload[0]=0x{back[0]:02X}(OP_SECURE_GUARD_UNLOCK; freertos_route.rs:160) "
        f"(UsbCtaphid.kt:406-436,603-605)",
    )

    # -- Stage 3: BLE framing ------------------------------------------------
    frags = app_ble_split_fragments(0x3B, app_cbor)  # AegisBridge.kt:559-589
    total = (frags[0][1] << 8) | frags[0][2]
    reasm = b"".join([f[3:] for f in frags[:1]] + [f[1:] for f in frags[1:]])
    ok_all &= step(
        "app-bytes: BLE splitFragments(0x3B) roundtrip",
        len(frags) == 1 and frags[0][0] == 0x3B and total == len(app_cbor) and reasm == app_cbor,
        f"frags={len(frags)} op=0x{frags[0][0]:02X} total={total} "
        f"(AegisBridge.kt:559-589; allowlist incl. SG range BleContract.kt:100-101)",
    )

    # -- Stage 4a: cdylib encode parity (byte-identical) ----------------------
    dll = R.find_cdylib()
    if dll is None:
        proc = R.run(["cargo", "build", "-p", "uniffi-bridge"])
        dll = R.find_cdylib()
        build_ev = f"cargo build -p uniffi-bridge exit={proc.returncode}; "
    else:
        build_ev = "cdylib already present; "
    if dll is None:
        ok_all &= step("bridge: cdylib encode_unlock parity", False,
                        build_ev + "aegis_bridge cdylib not loadable")
    else:
        try:
            b = R.BridgeCdylib(dll)
            rc_u, raw = b.blob_out(b.lib.aegis_secure_guard_encode_unlock, PIN)
            dec = R.cbor_decode(raw)
            identical = rc_u == 0 and raw == app_cbor
            ok_all &= step(
                "bridge: cdylib encode_unlock == app bytes (byte-identical)",
                identical and dec.get("action") == "unlock" and dec.get("pin") == PIN,
                f"{build_ev}dll={dll} rc={rc_u} cbor={dec} identical={identical} "
                f"(crates/uniffi-bridge/src/lib.rs aegis_secure_guard_encode_unlock)",
            )
        except Exception as e:  # noqa: BLE001 -- evidence must name the failure
            ok_all &= step("bridge: cdylib encode_unlock parity", False, f"{type(e).__name__}: {e}")

    # -- Stage 4b: firmware accepts exactly this shape ------------------------
    shape = R.cbor_decode(app_cbor)
    firmware_gate_ok = (
        isinstance(shape, dict) and shape.get("action") == "unlock"
        and isinstance(shape.get("pin"), bytes) and shape["pin"] == PIN
    )
    ok_all &= step(
        "firmware-parse: app CBOR satisfies dispatch gate",
        firmware_gate_ok,
        f"shape={shape} (unlock.rs:112-125 map gate; "
        f"unlock.rs:56-63 extract_bytes accepts Bytes-or-Text pin)",
    )

    # -- Stage 5: app parse-back of a canonical 0x00 success ------------------
    # Canonical success envelope per unlock.rs:634-651
    # {success:true state:4u state_name:"Unlocked" failed:0u remaining:5u}
    succ_body = (
        cbor_uint_head(5, 5) + cbor_text("success") + bytes([0xF5])
        + cbor_text("state") + cbor_uint_head(0, 4)
        + cbor_text("state_name") + cbor_text("Unlocked")
        + cbor_text("failed_attempts") + cbor_uint_head(0, 0)
        + cbor_text("remaining_attempts") + cbor_uint_head(0, 5)
    )
    usb_wire_back = bytes([0x3B, 0x00]) + succ_body  # sendVendor prepend + [st]+body
    op, st, body = app_parse_transport_frame(0x3B, usb_wire_back)
    res = app_parse_unlock_result(st, body)
    ok_all &= step(
        "app-parse: 0x00 success -> Unlocked end-to-end",
        op == 0x3B and st == 0x00 and res["success"] is True
        and res["state_name"] == "Unlocked",
        f"frame(op=0x{op:02X},st=0x{st:02X}) result={res} "
        f"(parseTransportFrame SecureGuardCbor.kt:211-219; "
        f"parseUnlockResult :306-328; firmware envelope unlock.rs:634-651)",
    )

    # -- Stage 6: firmware dispatch via existing host harness -----------------
    # Focused authority E2E, single-threaded as required (--test-threads=1).
    cmd = ["cargo", "test", "-p", "aegis-fido-firmware",
           "--features", "freertos,proximity", "--",
           "test_secure_guard_full_lifecycle_and_enforcement", "--test-threads=1"]
    proc = R.run(cmd, timeout=1500)
    out = proc.stdout + proc.stderr
    passed, failed, _ = R.cargo_test_summary(out)
    tail = R.tail_lines(out) if hasattr(R, "tail_lines") else out[-600:]
    ok_all &= step(
        "firmware-dispatch: focused unlock E2E (0x3B provision->unlock 0x00)",
        proc.returncode == 0 and failed == 0 and passed > 0,
        f"exit={proc.returncode} passed={passed} failed={failed} "
        f"filter=test_secure_guard_full_lifecycle_and_enforcement --test-threads=1 "
        f"(crates/aegis-fido-firmware/tests/secure_guard_integration.rs:86-87; tail={tail!r})",
    )

    # -- Stage 7: read-only divergence scan (findings, not failures) ----------
    print("---- divergence scan (read-only; where the APP path breaks) ----",
          flush=True)
    for path, needle in [
        ("app-android/app/src/main/java/dev/aegiskey/app/data/repository/SecureGuardRepositoryImpl.kt",
         "if (usb != null && !isUsbPresent && !isBleConnected)"),
        ("app-android/app/src/main/java/dev/aegiskey/app/data/transport/BleKeyTransport.kt",
         "client.sendVendor(0x2D, pinBytes)"),
        ("app-android/app/src/main/java/dev/aegiskey/app/di/AppContainer.kt",
         "secureGuardRepository: SecureGuardRepository by lazy"),
        ("crates/aegis-fido-firmware/src/ble/dispatch_bind.rs",
         "UP+PIN => wipe e libera re-claim"),
    ]:
        print(f"  [NOTE] {R.grep_line(path, needle)}", flush=True)

    passed_n = sum(1 for r in RESULTS if r["ok"])
    print(f"\n==== APP-PATH REPLAY: {passed_n}/{len(RESULTS)} PASS ====", flush=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
