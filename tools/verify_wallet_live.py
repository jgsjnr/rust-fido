#!/usr/bin/env python3
"""Verify wallet generation, list and address on physical hardware using app_simulator Session."""

import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
WORKTREE_DIR = os.path.dirname(SCRIPT_DIR)
if WORKTREE_DIR not in sys.path:
    sys.path.insert(0, WORKTREE_DIR)

from app_simulator import Session, CMD_MSG
from host_sdk import ops as _ops
from host_sdk import tlv as _tlv

PORT = "COM7"
BAUD = 115200


def main():
    print(f"=== AegisKey Physical Hardware Wallet Test ({PORT} @ {BAUD}) ===")
    sess = Session("http://192.168.4.1", test_mode=True)
    try:
        print(f"1. Connecting to {PORT}...")
        sess.connect(PORT, BAUD)
        print("Connected.")

        cid = sess.cmd_init()
        print(f"2. CID allocated: 0x{cid:08X}")

        # Check dump
        dump = sess.lifetime_dump(timeout_s=3.0)
        uptime = [line for line in dump.splitlines() if "uptime_s=" in line]
        print(f"   Device Lifetime Uptime: {uptime[0] if uptime else 'unknown'}")

        print("\n3. Testing OP_WALLET_LIST (0x36) initially...")
        sess.test_up(timeout_s=3.0)
        status, list_body = sess._exchange(
            CMD_MSG, bytes([_ops.OP_WALLET_LIST]), op="wallet_list", timeout_s=5.0
        )
        print(f"   Status: 0x{status:02X}, Body length: {len(list_body)} B")
        if status == 0x00 and list_body:
            records = _tlv.parse_tlv(list_body)
            print(f"   Existing Wallets in RAM: {records}")

        print("\n4. Opening Pairing Window via TEST_PAIRING_OPEN...")
        p_res = sess.test_pairing_open(timeout_s=4.0)
        print(f"   Pairing result: {p_res.strip()}")

        print("\n5. Generating Wallet Slot 0 (EVM) via OP_WALLET_GEN (0x35)...")
        # Build payload: slot 0, label b"Ethereum0", network 2 (EVM)
        gen_body = _ops.wallet_gen(0, b"Ethereum0", 2)
        sess.test_up(timeout_s=3.0)
        status, gen_resp = sess._exchange(
            CMD_MSG,
            bytes([_ops.OP_WALLET_GEN]) + gen_body,
            op="wallet_gen",
            timeout_s=8.0,
        )
        print(f"   Status: 0x{status:02X}, Resp hex: {gen_resp.hex()}")
        if status == 0x00:
            print("   >>> SUCCESS! Wallet generated on physical ESP32-S3 hardware! <<<")
            records = _tlv.parse_tlv(gen_resp)
            for tag, val in records:
                tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS", 8: "NETWORK"}.get(
                    tag, f"TAG_{tag}"
                )
                if tag in (2, 7):
                    print(
                        f"     {tag_name}: {val.decode('utf-8', errors='replace')}"
                    )
                else:
                    print(f"     {tag_name}: {val.hex()}")

        print("\n6. Listing Wallets via OP_WALLET_LIST (0x36)...")
        sess.test_up(timeout_s=3.0)
        status, list_body = sess._exchange(
            CMD_MSG, bytes([_ops.OP_WALLET_LIST]), op="wallet_list", timeout_s=5.0
        )
        print(f"   Status: 0x{status:02X}, Body length: {len(list_body)} B")
        if status == 0x00:
            records = _tlv.parse_tlv(list_body)
            for tag, val in records:
                tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS"}.get(
                    tag, f"TAG_{tag}"
                )
                if tag in (2, 7):
                    print(
                        f"     {tag_name}: {val.decode('utf-8', errors='replace')}"
                    )
                else:
                    print(f"     {tag_name}: {val.hex()}")

        print("\n7. Querying Wallet Slot 0 Address via OP_WALLET_ADDR (0x37)...")
        addr_body = _ops.wallet_addr_req(0)
        sess.test_up(timeout_s=3.0)
        status, addr_resp = sess._exchange(
            CMD_MSG,
            bytes([_ops.OP_WALLET_ADDR]) + addr_body,
            op="wallet_addr",
            timeout_s=5.0,
        )
        print(f"   Status: 0x{status:02X}, Resp hex: {addr_resp.hex()}")
        if status == 0x00:
            records = _tlv.parse_tlv(addr_resp)
            for tag, val in records:
                tag_name = {7: "ADDRESS"}.get(tag, f"TAG_{tag}")
                print(f"     {tag_name}: {val.decode('utf-8', errors='replace')}")

        print("\n8. Generating Wallet Slot 1 (Solana / Ed25519)...")
        gen_body_sol = _ops.wallet_gen(1, b"SolanaMain", 3)
        sess.test_up(timeout_s=3.0)
        status, gen_resp_sol = sess._exchange(
            CMD_MSG,
            bytes([_ops.OP_WALLET_GEN]) + gen_body_sol,
            op="wallet_gen_sol",
            timeout_s=8.0,
        )
        print(f"   Status: 0x{status:02X}")
        if status == 0x00:
            records = _tlv.parse_tlv(gen_resp_sol)
            for tag, val in records:
                tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS", 8: "NETWORK"}.get(
                    tag, f"TAG_{tag}"
                )
                if tag in (2, 7):
                    print(
                        f"     {tag_name}: {val.decode('utf-8', errors='replace')}"
                    )
                else:
                    print(f"     {tag_name}: {val.hex()}")

        print("\n9. Generating Wallet Slot 2 (Bitcoin / P2WPKH)...")
        gen_body_btc = _ops.wallet_gen(2, b"BtcMain", 1)
        sess.test_up(timeout_s=3.0)
        status, gen_resp_btc = sess._exchange(
            CMD_MSG,
            bytes([_ops.OP_WALLET_GEN]) + gen_body_btc,
            op="wallet_gen_btc",
            timeout_s=8.0,
        )
        print(f"   Status: 0x{status:02X}")
        if status == 0x00:
            records = _tlv.parse_tlv(gen_resp_btc)
            for tag, val in records:
                tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS", 8: "NETWORK"}.get(
                    tag, f"TAG_{tag}"
                )
                if tag in (2, 7):
                    print(
                        f"     {tag_name}: {val.decode('utf-8', errors='replace')}"
                    )
                else:
                    print(f"     {tag_name}: {val.hex()}")

        print("\n10. Final OP_WALLET_LIST (all 3 chains)...")
        sess.test_up(timeout_s=3.0)
        status, list_body = sess._exchange(
            CMD_MSG, bytes([_ops.OP_WALLET_LIST]), op="wallet_list", timeout_s=5.0
        )
        if status == 0x00:
            records = _tlv.parse_tlv(list_body)
            print(f"   Total fields returned: {len(records)}")
            for tag, val in records:
                tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS"}.get(
                    tag, f"TAG_{tag}"
                )
                if tag in (2, 7):
                    print(
                        f"     {tag_name}: {val.decode('utf-8', errors='replace')}"
                    )
                else:
                    print(f"     {tag_name}: {val.hex()}")

    finally:
        sess.close()
        print("\nSession closed.")


if __name__ == "__main__":
    main()
