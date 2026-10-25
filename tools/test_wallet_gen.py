#!/usr/bin/env python3
"""Test OP_WALLET_GEN (0x35) directly on COM7 with real hardware."""

import sys
import time
import serial
from typing import Optional, Tuple

PORT = "COM7"
BAUD = 115200

CMD_MSG = 0x03
OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37

TAG_SLOT = 0x01
TAG_LABEL = 0x02
TAG_ADDRESS = 0x07
TAG_NETWORK = 0x08

NET_BTC = 1
NET_EVM = 2
NET_SOL = 3


def encode_tlv(tag: int, val: bytes) -> bytes:
    length = len(val)
    if length < 0x80:
        return bytes([tag, length]) + val
    elif length <= 0xFF:
        return bytes([tag, 0x81, length]) + val
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + val


def parse_tlvs(data: bytes):
    out = []
    idx = 0
    while idx < len(data):
        tag = data[idx]
        idx += 1
        if idx >= len(data):
            break
        lb = data[idx]
        idx += 1
        if lb < 0x80:
            length = lb
        elif lb == 0x81:
            length = data[idx]
            idx += 1
        elif lb == 0x82:
            length = (data[idx] << 8) | data[idx + 1]
            idx += 2
        else:
            break
        val = data[idx : idx + length]
        idx += length
        out.append((tag, val))
    return out


class SerialCtapSession:
    def __init__(self, ser: serial.Serial):
        self.ser = ser
        self.cid = 0

    def init_channel(self) -> int:
        nonce = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        pkt = bytearray(64)
        pkt[0:4] = b"\xff\xff\xff\xff"
        pkt[4] = 0x86  # CMD_INIT
        pkt[5:7] = (8).to_bytes(2, "big")
        pkt[7:15] = nonce
        self.ser.write(pkt)
        resp = self._read_packet(timeout=2.0)
        if not resp:
            raise RuntimeError("No response to CMD_INIT")
        print(f"DEBUG init resp: len={len(resp)}, hex={resp[:20].hex()}")
        if resp[4] != 0x86 or resp[7:15] != nonce:
            raise RuntimeError(f"Invalid CMD_INIT response: cmd={resp[4]:02x}, nonce={resp[7:15].hex()}")
        self.cid = int.from_bytes(resp[15:19], "big")
        return self.cid

    def _read_packet(self, timeout=2.0) -> Optional[bytes]:
        deadline = time.time() + timeout
        buf = bytearray()
        while time.time() < deadline:
            avail = self.ser.in_waiting
            if avail > 0:
                chunk = self.ser.read(avail)
                buf.extend(chunk)
                while len(buf) >= 64:
                    pkt = bytes(buf[:64])
                    buf = buf[64:]
                    # Check text line
                    non_null = [b for b in pkt if b != 0]
                    if non_null and all(
                        b in (9, 10, 13) or 0x20 <= b <= 0x7E for b in non_null
                    ):
                        try:
                            print(
                                f"  [FIRMWARE LOG] {bytes(non_null).decode('latin-1').strip()}"
                            )
                        except Exception:
                            pass
                        continue
                    return pkt
            time.sleep(0.005)
        return None

    def exchange(self, cmd: int, payload: bytes, timeout=3.0) -> Tuple[int, bytes]:
        if not self.cid:
            self.init_channel()

        total_len = len(payload)
        pkt = bytearray(64)
        pkt[0:4] = self.cid.to_bytes(4, "big")
        pkt[4] = cmd | 0x80
        pkt[5:7] = total_len.to_bytes(2, "big")
        take = min(total_len, 64 - 7)
        pkt[7 : 7 + take] = payload[:take]
        self.ser.write(pkt)
        offset = take
        seq = 0
        while offset < total_len:
            cont = bytearray(64)
            cont[0:4] = self.cid.to_bytes(4, "big")
            cont[4] = seq & 0x7F
            take = min(total_len - offset, 64 - 5)
            cont[5 : 5 + take] = payload[offset : offset + take]
            self.ser.write(cont)
            offset += take
            seq += 1

        deadline = time.time() + timeout
        resp_payload = bytearray()
        resp_len = None
        while time.time() < deadline:
            pkt = self._read_packet(timeout=timeout)
            if not pkt:
                break
            cid = int.from_bytes(pkt[0:4], "big")
            if cid != self.cid:
                continue
            if pkt[4] & 0x80:
                resp_cmd = pkt[4] & 0x7F
                resp_len = int.from_bytes(pkt[5:7], "big")
                take = min(resp_len, 64 - 7)
                resp_payload = bytearray(pkt[7 : 7 + take])
            else:
                if resp_len is None:
                    continue
                rem = resp_len - len(resp_payload)
                take = min(rem, 64 - 5)
                resp_payload.extend(pkt[5 : 5 + take])

            if resp_len is not None and len(resp_payload) >= resp_len:
                return (resp_cmd, bytes(resp_payload[:resp_len]))

        return (0, b"")


def main():
    print(f"Opening {PORT} at {BAUD}...")
    ser = serial.Serial(PORT, BAUD, timeout=0.1)
    time.sleep(0.1)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    sess = SerialCtapSession(ser)
    cid = sess.init_channel()
    print(f"Allocated CID: 0x{cid:08X}")

    # Build wallet gen payload
    # Slot 0, Label "EthMain", Network EVM (2)
    tlv_body = (
        encode_tlv(TAG_SLOT, bytes([0x00]))
        + encode_tlv(TAG_LABEL, b"EthMain")
        + encode_tlv(TAG_NETWORK, bytes([NET_EVM]))
    )
    req = bytes([OP_WALLET_GEN]) + tlv_body

    print("\n--- Test 1: OP_WALLET_GEN without pairing window or UP ---")
    cmd, resp = sess.exchange(CMD_MSG, req)
    print(
        f"Response: cmd=0x{cmd:02X}, len={len(resp)}, raw={resp.hex() if resp else 'empty'}"
    )
    if resp:
        st = resp[0]
        print(f"Status byte: 0x{st:02X} (0x05=NEED_BINDING/PAIRING, 0x01=NEED_UP)")

    print("\n--- Test 2: Send TEST_PAIRING_OPEN, then OP_WALLET_GEN without UP ---")
    ser.write(b"TEST_PAIRING_OPEN\n")
    time.sleep(0.05)
    cmd, resp = sess.exchange(CMD_MSG, req)
    print(
        f"Response: cmd=0x{cmd:02X}, len={len(resp)}, raw={resp.hex() if resp else 'empty'}"
    )
    if resp:
        st = resp[0]
        print(f"Status byte: 0x{st:02X} (0x01=NEED_UP expected)")

    print("\n--- Test 3: Send TEST_UP, then OP_WALLET_GEN with proper TLV ---")
    ser.write(b"TEST_UP\n")
    time.sleep(0.05)
    cmd, resp = sess.exchange(CMD_MSG, req)
    print(
        f"Response: cmd=0x{cmd:02X}, len={len(resp)}, raw={resp.hex() if resp else 'empty'}"
    )
    if resp:
        st = resp[0]
        print(f"Status byte: 0x{st:02X} (0x00=OK expected)")
        if st == 0:
            print("SUCCESS! Decoding TLVs in response:")
            records = parse_tlvs(resp[1:])
            for tag, val in records:
                tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS", 8: "NETWORK"}.get(
                    tag, f"TAG_{tag}"
                )
                if tag in (2, 7):
                    print(f"  {tag_name}: {val.decode('utf-8', errors='replace')}")
                else:
                    print(f"  {tag_name}: {val.hex()}")

    print("\n--- Test 4: OP_WALLET_LIST ---")
    ser.write(b"TEST_UP\n")
    time.sleep(0.05)
    cmd, resp = sess.exchange(CMD_MSG, bytes([OP_WALLET_LIST]))
    print(
        f"Response: cmd=0x{cmd:02X}, len={len(resp)}, raw={resp.hex() if resp else 'empty'}"
    )
    if resp and resp[0] == 0:
        records = parse_tlvs(resp[1:])
        print(f"Wallet List entries ({len(records)} fields):")
        for tag, val in records:
            tag_name = {1: "SLOT", 2: "LABEL", 7: "ADDRESS"}.get(tag, f"TAG_{tag}")
            if tag in (2, 7):
                print(f"  {tag_name}: {val.decode('utf-8', errors='replace')}")
            else:
                print(f"  {tag_name}: {val.hex()}")

    ser.close()


if __name__ == "__main__":
    main()
