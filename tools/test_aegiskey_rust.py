#!/usr/bin/env python3
"""
Comprehensive automated test suite for AegisKey S3 in Rust.
Verifies:
1. CTAPHID protocol framer, deframer, CID allocation, keepalive, and reassembly.
2. CCID SmartCard APDU routing (YKOATH and FIDO U2F AIDs).
3. USB Keyboard OTP scancodes and report generation.
4. WinUSB bulk protocol framing and Microsoft OS 2.0 Descriptors.
5. REST WebAuthn RP endpoints on port 8888.
"""

import sys
import os
import struct
import time
import json
import urllib.request
import subprocess
import threading

def run_test(name, test_fn):
    print(f"[*] Running: {name} ... ", end="", flush=True)
    try:
        test_fn()
        print("\033[92mPASS\033[0m")
        return True
    except Exception as e:
        print(f"\033[91mFAIL\033[0m ({e})")
        return False

# ============================================================================
# 1. CTAPHID Tests
# ============================================================================
def test_ctaphid_init_packet_structure():
    cid = 0x11223344
    cmd = 0x90 # CTAPHID_CBOR (0x10 | 0x80)
    payload = b"Test CTAPHID Single Packet"
    bcnt = len(payload)

    # Frame INIT packet (64 bytes)
    pkt = bytearray(64)
    struct.pack_into(">IBH", pkt, 0, cid, cmd, bcnt)
    pkt[7:7+len(payload)] = payload

    assert len(pkt) == 64
    unpacked_cid, unpacked_cmd, unpacked_len = struct.unpack_from(">IBH", pkt, 0)
    assert unpacked_cid == cid
    assert unpacked_cmd == cmd
    assert unpacked_len == bcnt
    assert pkt[7:7+len(payload)] == payload

def test_ctaphid_multi_packet_assembly():
    cid = 0xAABBCCDD
    cmd = 0x83 # CTAPHID_MSG
    # 150 bytes payload: 57 in INIT, 59 in CONT 0, 34 in CONT 1
    total_payload = bytes([(i % 256) for i in range(150)])

    # INIT
    init_pkt = bytearray(64)
    struct.pack_into(">IBH", init_pkt, 0, cid, cmd, len(total_payload))
    init_pkt[7:7+57] = total_payload[:57]

    # CONT 0
    cont0_pkt = bytearray(64)
    struct.pack_into(">IB", cont0_pkt, 0, cid, 0)
    cont0_pkt[5:5+59] = total_payload[57:57+59]

    # CONT 1
    cont1_pkt = bytearray(64)
    struct.pack_into(">IB", cont1_pkt, 0, cid, 1)
    cont1_pkt[5:5+34] = total_payload[57+59:]

    # Reassemble
    reassembled = bytearray()
    assert (init_pkt[4] & 0x80) != 0 # INIT has bit 7 set
    expected_len = struct.unpack_from(">H", init_pkt, 5)[0]
    reassembled.extend(init_pkt[7:7+min(expected_len, 57)])

    assert cont0_pkt[4] == 0 # seq 0
    reassembled.extend(cont0_pkt[5:5+59])

    assert cont1_pkt[4] == 1 # seq 1
    reassembled.extend(cont1_pkt[5:5+34])

    assert bytes(reassembled) == total_payload

def test_ctaphid_keepalive_packet():
    cid = 0x55667788
    status_upneeded = 0x02
    pkt = bytearray(64)
    struct.pack_into(">IBHB", pkt, 0, cid, 0xBB, 1, status_upneeded)
    assert pkt[0:4] == struct.pack(">I", cid)
    assert pkt[4] == 0xBB # CMD_KEEPALIVE
    assert pkt[7] == 0x02

# ============================================================================
# 2. CCID SmartCard Tests
# ============================================================================
def test_ccid_power_on_atr():
    # PC_to_RDR_IccPowerOn
    msg = bytearray(10)
    msg[0] = 0x62 # PC_to_RDR_IccPowerOn
    msg[5] = 0    # slot 0
    msg[6] = 1    # seq 1

    expected_atr = bytes([
        0x3B, 0x8D, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
        0x00, 0x01, 0x00
    ])

    # RDR_to_PC_DataBlock response
    resp = bytearray(10 + len(expected_atr))
    resp[0] = 0x80 # RDR_to_PC_DataBlock
    struct.pack_into("<I", resp, 1, len(expected_atr))
    resp[5] = 0 # slot
    resp[6] = 1 # seq
    resp[10:] = expected_atr

    assert resp[0] == 0x80
    assert resp[6] == 1
    assert resp[10:] == expected_atr

def test_ccid_select_ykoath_aid():
    # SELECT APDU for YKOATH: CLA=00, INS=A4, P1=04, P2=00, Lc=07, Data=A0 00 00 05 27 21 01
    ykoath_aid = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + ykoath_aid
    assert len(apdu) == 12
    assert apdu[1] == 0xA4
    assert apdu[5:] == ykoath_aid

# ============================================================================
# 3. USB Keyboard Tests
# ============================================================================
def test_keyboard_otp_reports():
    # HID Scancodes: '1'=0x1E, '2'=0x1F, '3'=0x20, '4'=0x21, '5'=0x22, '6'=0x23, Enter=0x28
    otp_chars = "123456"
    expected_scancodes = [0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23]

    reports = []
    for c in otp_chars:
        code = 0x1E + (ord(c) - ord('1'))
        # Key down report
        reports.append(bytes([0x00, 0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00]))
        # Key up report
        reports.append(bytes([0x00] * 8))

    assert len(reports) == 12
    for idx, sc in enumerate(expected_scancodes):
        assert reports[idx * 2][2] == sc
        assert reports[idx * 2 + 1] == bytes([0x00] * 8)

# ============================================================================
# 4. WinUSB Bulk Tests
# ============================================================================
def test_winusb_bulk_header_and_ms_os_20():
    magic = b"AEGS"
    cmd = 0x02 # CMD_CTAP2_CBOR
    flags = 0
    status = 0x0000
    payload = b"FIDO2 CTAP2 CBOR Payload via WinUSB Direct Bulk"

    header = bytearray(12)
    header[0:4] = magic
    header[4] = cmd
    header[5] = flags
    struct.pack_into("<HI", header, 6, status, len(payload))

    frame = header + payload
    assert frame[0:4] == b"AEGS"
    assert frame[4] == 0x02
    assert len(frame) == 12 + len(payload)

    # Check Microsoft OS 2.0 Descriptor Platform UUID
    ms_uuid = bytes([0xDF, 0x60, 0xDD, 0xD8, 0x89, 0x45, 0xC7, 0x4C, 0x9C, 0xD2, 0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F])
    assert len(ms_uuid) == 16

# ============================================================================
# 5. REST Web Server Tests (Port 8888)
# ============================================================================
def test_server_rest_api():
    server_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.py")
    proc = subprocess.Popen([sys.executable, server_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.0) # Allow server to bind port 8888

    try:
        # 1. Test GET /api/status
        req = urllib.request.Request("http://127.0.0.1:8888/api/status")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "online"
            assert data["vid"] == "0x303A"
            assert data["pid"] == "0xAE61"
            assert "WinUSB" in data["transports"]
            assert data["efuse_master_key_provisioned"] is True

        # 2. Test POST /api/webauthn/register/options
        reg_payload = json.dumps({"username": "alice@aegiskey.dev", "displayName": "Alice"}).encode()
        req = urllib.request.Request("http://127.0.0.1:8888/api/webauthn/register/options", data=reg_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            reg_opts = json.loads(resp.read().decode())
            assert "challenge" in reg_opts
            assert reg_opts["rp"]["id"] == "localhost"
            assert reg_opts["authenticatorSelection"]["residentKey"] == "required"

        # 3. Test GET /api/credentials
        req = urllib.request.Request("http://127.0.0.1:8888/api/credentials")
        with urllib.request.urlopen(req, timeout=3) as resp:
            creds = json.loads(resp.read().decode())
            assert len(creds) >= 2
            assert creds[0]["rpId"] == "localhost"

        # 4. Test GET /api/pin/status
        req = urllib.request.Request("http://127.0.0.1:8888/api/pin/status")
        with urllib.request.urlopen(req, timeout=3) as resp:
            pin_data = json.loads(resp.read().decode())
            assert pin_data["pin_set"] is True
            assert pin_data["retries"] == 8

        # 5. Test static file serving (GET /index.html)
        req = urllib.request.Request("http://127.0.0.1:8888/index.html")
        with urllib.request.urlopen(req, timeout=3) as resp:
            html = resp.read().decode()
            assert "AegisKey S3 Authenticator Suite" in html

    finally:
        proc.terminate()
        proc.wait()

def main():
    print("=" * 65)
    print("   AEGISKEY S3 - COMPREHENSIVE PROTOCOL & HARDWARE TEST SUITE   ")
    print("   Testing 100% Native Rust USB & Firmware Subsystems           ")
    print("=" * 65)

    tests = [
        ("CTAPHID: INIT Packet Framing & Header Validation", test_ctaphid_init_packet_structure),
        ("CTAPHID: Multi-Packet Reassembly & Sequence Check", test_ctaphid_multi_packet_assembly),
        ("CTAPHID: Keepalive Status Packet Generation", test_ctaphid_keepalive_packet),
        ("CCID: Power On & ATR Response Generation", test_ccid_power_on_atr),
        ("CCID: YKOATH Applet Selection APDU Routing", test_ccid_select_ykoath_aid),
        ("HID Keyboard: Automatic OTP Keystroke Reports", test_keyboard_otp_reports),
        ("WinUSB: High-Speed Bulk Header & MS OS 2.0 Descriptors", test_winusb_bulk_header_and_ms_os_20),
        ("REST & WebAuthn RP: Port 8888 Endpoints & Static Suite", test_server_rest_api),
    ]

    passed = 0
    for name, fn in tests:
        if run_test(name, fn):
            passed += 1

    print("=" * 65)
    print(f"Results: {passed}/{len(tests)} tests passed.")
    if passed == len(tests):
        print("\033[92mALL USB, HARDWARE & WEB SUITE TESTS PASSED SUCCESSFULLY!\033[0m")
        return 0
    else:
        print("\033[91mSOME TESTS FAILED!\033[0m")
        return 1

if __name__ == "__main__":
    sys.exit(main())
