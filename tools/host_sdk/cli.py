#!/usr/bin/env python3
"""host_sdk CLI: --self-test (offline) and --demo (no hardware)."""
from __future__ import annotations

import argparse
import os
import sys


def _run_self_test() -> int:
    try:
        from tools.host_sdk import tlv, ops, transport, gates
    except ImportError:  # run as file: root on path fallback (offline only)
        import pathlib as _pl
        import sys as _sys
        _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[2]))
        from tools.host_sdk import tlv, ops, transport, gates

    fails = []

    def check(name, fn):
        try:
            fn()
            print("PASS %s" % name)
        except Exception as e:  # noqa: BLE001 - self-test reports only
            print("FAIL %s (%s)" % (name, e))
            fails.append(name)

    def t_tlv_wallet_gen_vector():
        frozen = bytes([0x01, 0x01, 0x03, 0x02, 0x03]) + b"btc" + bytes([0x08, 0x01, 0x01])
        got = tlv.write_tlv(tlv.TAG_WALLET_SLOT, b"\x03") + tlv.write_tlv(tlv.TAG_WALLET_LABEL, b"btc")
        got += tlv.write_tlv(tlv.TAG_WALLET_NETWORK, b"\x01")
        assert got == frozen, (got.hex(), frozen.hex())
        recs = tlv.parse_tlv(frozen)
        assert tlv.slot_id(recs) == 3
        assert tlv.label_bytes(recs) == b"btc"
        assert tlv.single_byte(recs, tlv.TAG_WALLET_NETWORK) == 0x01

    def t_tlv_vendor_gen_vector():
        import struct
        frozen = (bytes([0x01, 0x01, 0x08, 0x02, 0x06]) + b"e2e-t1"
                  + bytes([0x05, 0x04]) + struct.pack(">i", -7) + bytes([0x06, 0x01, 0x03]))
        got = ops.vendor_key_gen(8, b"e2e-t1", -7, 0x03)
        assert got == frozen, (got.hex(), frozen.hex())

    def t_tlv_long_forms():
        out = tlv.write_tlv(0x02, b"\xAB" * 200)
        assert out[:3] == bytes([0x02, 0x81, 0xC8])
        assert len(tlv.parse_tlv(out)[0][1]) == 200
        out = tlv.write_tlv(0x02, b"\xCD" * 300)
        assert out[:4] == bytes([0x02, 0x82, 0x01, 0x2C])
        try:
            tlv.parse_tlv(bytes([0x01, 0x80]))
            raise AssertionError("should reject 0x80")
        except ValueError:
            pass
        try:
            tlv.parse_tlv(bytes([0x01, 0x01]))
            raise AssertionError("should reject truncation")
        except ValueError:
            pass

    def t_framing_roundtrip():
        payload = bytes(i % 256 for i in range(150))
        pkts = transport.frame_message(0xAABBCCDD, transport.CMD_MSG, payload)
        assert all(len(p) == 64 for p in pkts)
        asm = transport.Reassembler()
        got = None
        for p in pkts[:-1]:
            assert asm.feed(p) == ("more", None)
        kind, got = asm.feed(pkts[-1])
        assert kind == "message" and got[2] == payload

    def t_gates_order():
        try:
            gates.authorize_config_op(ops.OP_KEY_DELETE, False, False, False, op="key_delete")
            raise AssertionError("should deny")
        except gates.GateDenied as e:
            assert e.status == gates.NEED_BINDING
        try:
            gates.authorize_config_op(ops.OP_KEY_DELETE, True, False, True, op="key_delete")
            raise AssertionError("should deny UP")
        except gates.GateDenied as e:
            assert e.status == gates.NEED_UP
        try:
            gates.authorize_config_op(ops.OP_KEY_DELETE, True, True, False, op="key_delete")
            raise AssertionError("should deny PIN")
        except gates.GateDenied as e:
            assert e.status == gates.NEED_PIN
        gates.authorize_config_op(ops.OP_KEY_DELETE, True, True, True, op="key_delete")
        gates.authorize_usage_op(True, op="oath_code")
        try:
            gates.authorize_fw_log(False)
            raise AssertionError("should deny fw_log")
        except gates.GateDenied as e:
            assert e.status == gates.NEED_BINDING

    def t_rescue_frame():
        f = ops.rescue_frame(0x06, b"\x01\x02")
        assert f == b"RESC\x01\x06\x00\x02\x01\x02"

    def t_no_hardcoded_secrets():
        import pathlib
        for name in ("tlv.py", "ops.py", "transport.py", "gates.py", "cli.py", "__init__.py"):
            text = pathlib.Path(__file__).with_name(name).read_text(encoding="utf-8")
            assert ("80:" + "65:99") not in text and ("DF:" + "4B:CE") not in text, name

    def t_port_default():
        os.environ.pop("AEGIS_PORT", None)
        assert transport.resolve_port(None) == "COM7"
        assert transport.resolve_port("COM9") == "COM9"
        os.environ["AEGIS_PORT"] = "COM5"
        assert transport.resolve_port(None) == "COM5"
        del os.environ["AEGIS_PORT"]

    def t_ota_vectors():
        b = ops.ota_begin(1024, b"\x00" * 32)
        assert len(b) > 32
        assert ops.ota_chunk(1, b"\xAA")[:2] == b"\x00\x01"
        assert ops.ota_commit() == b"" and ops.ota_abort() == b""

    def t_f3_vectors():
        assert ops.piv_select_aid()[:4] == bytes((0, 0xA4, 4, 0))
        assert ops.otp_typer_input("287082") == b"287082"
        assert ops.ext_route_status("ykman") == bytes((0x6D, 0x00))
        assert ops.prox_walkaway(60) == bytes((0, 60))
        assert ops.piv_strip_ff(bytes((9, 0xFF))) == bytes((9,))
        assert ops.rescue_killswitch_frame("WIPE-ACK")[:4] == b"RESC"
        try:
            ops.killswitch_execute_denied()
            raise AssertionError("should block")
        except PermissionError:
            pass

    for name, fn in [
        ("tlv_wallet_gen_vector", t_tlv_wallet_gen_vector),
        ("tlv_vendor_gen_vector", t_tlv_vendor_gen_vector),
        ("tlv_long_forms", t_tlv_long_forms),
        ("framing_roundtrip", t_framing_roundtrip),
        ("gates_order", t_gates_order),
        ("rescue_frame", t_rescue_frame),
        ("no_hardcoded_secrets", t_no_hardcoded_secrets),
        ("port_default", t_port_default),
        ("ota_vectors", t_ota_vectors),
        ("f3_vectors", t_f3_vectors),
    ]:
        check(name, fn)
    print("self-test: %d failed" % len(fails))
    return 1 if fails else 0


def _run_demo() -> int:
    try:
        from tools.host_sdk import ops, transport
    except ImportError:  # run as file: root on path fallback (offline only)
        import pathlib as _pl
        import sys as _sys
        _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[2]))
        from tools.host_sdk import ops, transport
    gen = ops.wrap_op(ops.OP_WALLET_GEN, ops.wallet_gen(3, b"btc", 0x01))
    print("demo wallet_gen op=%02x tlv_bytes=%d" % (gen[0], len(gen) - 1))
    print("demo tlv_hex=%s" % gen[1:].hex())
    pkts = transport.frame_message(0x11223344, transport.CMD_MSG, gen)
    print("demo ctaphid pkts=%d port=%s" % (len(pkts), transport.resolve_port(None)))
    print("demo fw_log op=0x38 body_bytes=0")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AegisKey host SDK CLI (stdlib-only)")
    ap.add_argument("--self-test", action="store_true", help="offline checks, no hardware")
    ap.add_argument("--demo", action="store_true", help="print frozen vectors, no hardware")
    ap.add_argument("--port", default=None, help="serial port (default AEGIS_PORT or COM7)")
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    if args.demo:
        return _run_demo()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
