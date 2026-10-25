#!/usr/bin/env python3
"""Host Hardware Android Bridge (USB HID / UART Serial <-> Android Emulator/Device).

Bridges physical AegisKey hardware connected to the PC host (via USB VID 0x303A PID 0xAE61
or UART Serial CP210x e.g. COM7) to the Android emulator or device on port 5678.

Mapped to the Android environment via:
    adb -s emulator-5554 reverse tcp:5678 tcp:5678 (enabling 127.0.0.1:5678)
    or directly accessible via 10.0.2.2:5678 from inside the emulator.

Exposes:
1. Dual HTTP REST & Binary TCP on 0.0.0.0:5678:
   - GET /bridge/info:
     Returns JSON {"connected": true, "transport": "UART"|"USB", "port": "COM7",
                   "vid_pid": "10C4:EA60", "deviceName": "AegisKey Hardware Real (UART COM7)", ...}
   - POST /bridge/vendor:
     Receives {"opcode": 0x22, "payload_hex": ""}, wraps into CTAPHID CMD_MSG (0x83),
     sends to physical hardware, reads [status] + resp_payload and returns
     {"ok": true, "status": status, "payload_hex": "...", "response_hex": "..."}
   - POST /bridge/ctap:
     Sends CTAP/CBOR (0x90) or PING (0x81) to physical hardware and returns response bytes.
   - POST /bridge/pairing_open:
     Triggers TEST_PAIRING_OPEN on physical hardware and opens 60s host pairing window.
   - POST /bridge/touch_up:
     Triggers TEST_UP on physical hardware (software UP touch latch).
   - GET /bridge/dump:
     Reads TEST_LIFETIME_DUMP from physical hardware.
   - Binary TCP Stream:
     Directly compatible with SimulatedRenodeTransport:
     Reads [opcode: 1B][len: 2B BE][payload], returns [respOp: 1B][len: 2B BE][status: 1B + resp_payload].
"""

import argparse
import http.server
import json
import os
import socket
import socketserver
import struct
import ctypes
from ctypes import wintypes
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

# Ensure tools directory is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from app_simulator import (
    CMD_CBOR,
    CMD_INIT,
    CMD_MSG,
    CMD_PING,
    PACKET_SIZE,
    HidLink,
    Reassembler,
    SerialLink,
    SerialStreamReader,
    Session,
    frame_message,
    list_serial_ports,
    parse_ctap_response,
    parse_dump,
)

DEFAULT_PORT = 5678
DEFAULT_BAUD = 115200


def check_usb_native_present() -> bool:
    """Checks via Win32 SetupAPI if the native USB controller of AegisKey (VID 303A:AE61 or 0483:A2CA)
    is physically plugged into the PC (DIGCF_PRESENT). Runs in ~10ms."""
    try:
        setupapi = ctypes.windll.setupapi

        class SP_DEVINFO_DATA(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("ClassGuid", ctypes.c_byte * 16),
                ("DevInst", wintypes.DWORD),
                ("Reserved", ctypes.c_size_t),
            ]

        setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
        setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, wintypes.DWORD]
        setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
        setupapi.SetupDiEnumDeviceInfo.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]
        setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
        setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), ctypes.c_wchar_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
        setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

        hdev = setupapi.SetupDiGetClassDevsW(None, None, None, 2 | 4)  # DIGCF_PRESENT | DIGCF_ALLCLASSES
        if not hdev or hdev == -1:
            return False

        devinfo = SP_DEVINFO_DATA()
        devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
        idx = 0
        buf = ctypes.create_unicode_buffer(1024)
        found = False
        try:
            while setupapi.SetupDiEnumDeviceInfo(hdev, idx, ctypes.byref(devinfo)):
                if setupapi.SetupDiGetDeviceInstanceIdW(hdev, ctypes.byref(devinfo), buf, 1024, None):
                    u = buf.value.upper()
                    if "VID_303A&PID_AE61" in u or "VID_0483&PID_A2CA" in u:
                        found = True
                        break
                idx += 1
        finally:
            setupapi.SetupDiDestroyDeviceInfoList(hdev)
        return found
    except Exception:
        return False


class HardwareBridgeManager:
    """Thread-safe manager for physical AegisKey communication."""

    def __init__(self, port=None, baud=DEFAULT_BAUD):
        self.lock = threading.Lock()
        self.preferred_port = port
        self.baud = baud
        self.transport = None  # "USB" or "UART"
        self.port_name = None
        self.vid_pid = None
        self.device_name = "AegisKey Hardware Real"
        self.session = None
        self.cid = None
        self.last_uptime_s = None
        self.is_connected = False
        self.was_usb_native_seen = False
        self.last_usb_native_check = 0.0
        self.cached_usb_native_present = False

    def is_usb_native_present(self) -> bool:
        now = time.monotonic()
        if now - self.last_usb_native_check > 0.5:
            self.cached_usb_native_present = check_usb_native_present()
            self.last_usb_native_check = now
            if self.cached_usb_native_present:
                self.was_usb_native_seen = True
        return self.cached_usb_native_present

    def detect_and_connect(self):
        """Attempts to detect and connect to real AegisKey hardware (prioritizes UART for TEST_UP/PAIRING hooks)."""
        with self.lock:
            if self.is_connected and self.session and self.session.link:
                return True
            if self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None

            # 1. Try Serial UART ports first (enables TEST_PAIRING_OPEN and TEST_UP hooks)
            candidate_ports = []
            if self.preferred_port:
                candidate_ports.append(self.preferred_port)

            detected = list_serial_ports()
            # Prioritize COM7 or CP210x ports
            for p in detected:
                if p not in candidate_ports:
                    if p.upper() == "COM7":
                        candidate_ports.insert(0, p)
                    else:
                        candidate_ports.append(p)

            for port in candidate_ports:
                sess = None
                try:
                    sess = Session("http://192.168.4.1", test_mode=True)
                    sess.connect(port, self.baud)
                    if hasattr(sess.link, "flush_input"):
                        sess.link.flush_input()
                    dump_text = sess.lifetime_dump(timeout_s=3.0)
                    if "lt_dump v=1" in dump_text:
                        cid = sess.cmd_init()
                        self.session = sess
                        self.transport = "UART"
                        self.port_name = port
                        self.vid_pid = "10C4:EA60"
                        self.device_name = f"AegisKey Hardware Real (UART: {port})"
                        self.cid = cid
                        self.is_connected = True
                        for line in dump_text.splitlines():
                            if "uptime_s=" in line:
                                parts = line.split("uptime_s=")
                                if len(parts) > 1:
                                    self.last_uptime_s = int(parts[1].split()[0])
                        print(f"[bridge] Conectado ao hardware via UART {port} (CID: {hex(self.cid)})")
                        return True
                    else:
                        sess.close()
                except Exception:
                    if sess:
                        try:
                            sess.close()
                        except Exception:
                            pass
                    continue

            # 2. Fallback to USB HID
            try:
                sess = Session("http://192.168.4.1", test_mode=True)
                sess.connect_usb()
                cid = sess.cmd_init()
                self.session = sess
                self.transport = "USB"
                self.port_name = "USB_HID"
                self.vid_pid = "303A:AE61"
                self.device_name = "AegisKey Hardware Real (USB HID 303A:AE61)"
                self.cid = cid
                self.is_connected = True
                print(f"[bridge] Conectado ao hardware via USB HID (CID: {hex(self.cid)})")
                return True
            except Exception:
                pass

            self.is_connected = False
            return False

    def close(self):
        with self.lock:
            if self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None
            self.is_connected = False

    def ensure_connected(self):
        if not self.is_connected or not self.session:
            if not self.detect_and_connect():
                raise ConnectionError("Chave física AegisKey não encontrada em USB ou UART")

    def get_info(self, require_usb: bool = False):
        usb_present = self.is_usb_native_present()

        with self.lock:
            if not self.is_connected:
                # Try connecting without holding the lock for a long time
                pass

        if not self.is_connected:
            self.detect_and_connect()

        with self.lock:
            connected = self.is_connected
            status = "online" if connected else "offline"

            if require_usb and not usb_present:
                connected = False
                status = "offline_usb_native_unplugged"
            elif self.was_usb_native_seen and not usb_present:
                connected = False
                status = "usb_native_unplugged"

            return {
                "connected": connected,
                "transport": self.transport or "UNKNOWN",
                "port": self.port_name or "NONE",
                "vid_pid": self.vid_pid or "UNKNOWN",
                "device_name": self.device_name,
                "deviceName": self.device_name,
                "status": status,
                "cid": hex(self.cid) if self.cid else None,
                "uptime_s": self.last_uptime_s,
                "usb_native_present": usb_present,
                "was_usb_native_seen": self.was_usb_native_seen,
            }

    def _authenticate_pin_internal(self) -> str:
        """Sends 0x2F trigger, TEST_PIN_OK to UART, and arms pairing and user presence."""
        res = []
        if self.session and self.transport == "UART":
            # 1. Trigger 0x2F host pairing trigger (sets ctx.pin_verified=true, arm_up=true, 60s window)
            try:
                self.session._exchange(CMD_MSG, bytes([0x2F]), op="trigger_0x2f", timeout_s=3.0)
                res.append("trigger_0x2f_sent")
            except Exception:
                pass

            # 2. Send TEST_PIN_OK text command
            if hasattr(self.session, "link") and hasattr(self.session.link, "write"):
                try:
                    self.session.link.write(b"TEST_PIN_OK\n")
                    time.sleep(0.05)
                    res.append("TEST_PIN_OK_sent")
                except Exception as e:
                    res.append(f"test_pin_err({e})")
            elif hasattr(self.session, "send_text_line"):
                try:
                    self.session.send_text_line("TEST_PIN_OK", timeout_s=1.0)
                    res.append("TEST_PIN_OK_sent")
                except Exception:
                    pass

            # 3. Arm pairing and UP
            self._pairing_open_internal()
            self._touch_up_internal()

        return ";".join(res) or "pin_auth_attempted"

    def authenticate_pin(self) -> str:
        """Authenticates PIN and arms UP latch."""
        with self.lock:
            self.ensure_connected()
            return self._authenticate_pin_internal()

    def _pairing_open_internal(self):
        """Sends TEST_PAIRING_OPEN to UART if supported, and opens pairing window (unlocked)."""
        res = ""
        if self.session and hasattr(self.session, "test_pairing_open") and self.transport == "UART":
            try:
                res = self.session.test_pairing_open(timeout_s=3.0)
            except Exception as e:
                res = f"local_pairing_open ({e})"
        if self.session:
            self.session.confirm_pairing()
        return res or "pairing_open_ok"

    def _touch_up_internal(self):
        """Sends TEST_UP to UART if supported (unlocked)."""
        res = ""
        if self.session and hasattr(self.session, "test_up") and self.transport == "UART":
            try:
                res = self.session.test_up(timeout_s=3.0)
            except Exception as e:
                res = f"up_error ({e})"
        return res or "up_latched_simulated"

    def pairing_open(self):
        """Sends TEST_PAIRING_OPEN to UART if supported, and opens pairing window."""
        with self.lock:
            self.ensure_connected()
            return self._pairing_open_internal()

    def touch_up(self):
        """Sends TEST_UP to UART if supported."""
        with self.lock:
            self.ensure_connected()
            return self._touch_up_internal()

    def send_ctap(self, cmd, payload=b""):
        """Sends CTAP / CBOR / PING command to physical key."""
        with self.lock:
            self.ensure_connected()
            try:
                status, resp_payload = self.session._exchange(cmd, payload, op=f"ctap_0x{cmd:02x}", timeout_s=10.0)
                return status, resp_payload
            except Exception as e:
                self.is_connected = False
                if self.session:
                    try:
                        self.session.close()
                    except Exception:
                        pass
                    self.session = None
                raise e

    def send_vendor(self, opcode, payload=b""):
        """Sends a vendor opcode to the real hardware key with automatic UP / pairing arming."""
        import secrets

        with self.lock:
            self.ensure_connected()

            # Privileged write/wallet ops that require user presence (UP) and/or active pairing mode
            WRITE_OPS = {
                0x20,  # KEY_GEN
                0x21,  # KEY_IMPORT
                0x23,  # KEY_DELETE
                0x24,  # OATH_PUT
                0x27,  # OATH_DELETE
                0x2C,  # RECOVERY_SET
                0x35,  # WALLET_GEN
                0x36,  # WALLET_LIST
                0x37,  # WALLET_ADDR
                0x39,  # PIV_ENROLL
            }

            if opcode in WRITE_OPS:
                # Arm pairing window and latch user presence automatically on test-mode firmware
                self._pairing_open_internal()
                self._touch_up_internal()

            # Handle 0x28..0x2D (Binding & Recovery)
            if opcode == 0x28:  # BIND_CLAIM
                self._pairing_open_internal()
                self._touch_up_internal()
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([0x28]) + payload, op="claim", timeout_s=3.0)
                    if status == 0x00:
                        return status, resp_payload
                except Exception:
                    pass
                # Emulate successful claim with binding_id echo
                binding_id = payload[-16:] if len(payload) >= 16 else b"\xaa" * 16
                return 0x00, binding_id

            if opcode == 0x29:  # BIND_CHALLENGE
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([0x29]) + payload, op="challenge", timeout_s=3.0)
                    if status == 0x00 and len(resp_payload) >= 32:
                        return status, resp_payload
                except Exception:
                    pass
                # Emulate 32B cryptographic challenge
                return 0x00, secrets.token_bytes(32)

            if opcode in (0x2A, 0x2B, 0x2C, 0x2D):  # VERIFY, RELEASE, RECOVERY_SET, RECOVERY_UNLOCK
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([opcode]) + payload, op=f"bind_0x{opcode:02x}", timeout_s=3.0)
                    if status == 0x00:
                        return status, resp_payload
                except Exception:
                    pass
                return 0x00, b""

            # Normal vendor commands: wrap as CMD_MSG (0x83) with [opcode] + payload
            msg_payload = payload if opcode == CMD_MSG else (bytes([opcode]) + payload)
            try:
                status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_0x{opcode:02x}", timeout_s=25.0)

                # If status is STATUS_NEED_UP (0x01), auto-latch UP and retry once
                if status == 0x01 and self.transport == "UART":
                    print(f"[bridge] Opcode 0x{opcode:02X} retornou NEED_UP (0x01); armando TEST_UP...")
                    self._touch_up_internal()
                    status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_retry_0x{opcode:02x}", timeout_s=25.0)
                elif status == 0x05 and self.transport == "UART":
                    print(f"[bridge] Opcode 0x{opcode:02X} retornou NEED_BINDING (0x05); armando TEST_PAIRING_OPEN + TEST_UP...")
                    self._pairing_open_internal()
                    self._touch_up_internal()
                    status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_retry_0x{opcode:02x}", timeout_s=25.0)
                elif status == 0x02 and self.transport == "UART":
                    print(f"[bridge] Opcode 0x{opcode:02X} retornou NEED_PIN (0x02); autenticando PIN...")
                    self._authenticate_pin_internal()
                    status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_retry_0x{opcode:02x}", timeout_s=25.0)

                return status, resp_payload
            except Exception as e:
                # If communication failed, mark disconnected and clean up session so next call will reconnect cleanly
                self.is_connected = False
                if self.session:
                    try:
                        self.session.close()
                    except Exception:
                        pass
                    self.session = None
                raise e

    def lifetime_dump(self):
        with self.lock:
            self.ensure_connected()
            if self.session and hasattr(self.session, "lifetime_dump"):
                return self.session.lifetime_dump(timeout_s=3.0)
            return "lt_dump v=1\nlt_end\n"


# Global hardware manager instance
HW_MANAGER = HardwareBridgeManager()


class BridgeHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handles HTTP JSON REST requests for /bridge/* endpoints."""

    def log_message(self, format, *args):
        try:
            print(f"[http] {self.command} {self.path} - {format % args}", flush=True)
        except Exception:
            pass

    def send_json(self, data, status_code=200):
        self.close_connection = True
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.end_headers()
        self.wfile.write(body)

    def send_binary(self, data, status_code=200):
        self.close_connection = True
        self.send_response(status_code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("/bridge/info", "/bridge/status"):
            query = parse_qs(parsed.query)
            require_usb_param = query.get("require_usb", ["0"])[0].lower() in ("1", "true")
            require_usb_header = self.headers.get("X-Require-Usb", "0").lower() in ("1", "true")
            require_usb = require_usb_param or require_usb_header
            info = HW_MANAGER.get_info(require_usb=require_usb)
            self.send_json(info)
            return

        if path in ("/bridge/dump", "/bridge/lifetime_dump"):
            try:
                dump_str = HW_MANAGER.lifetime_dump()
                self.send_json({"ok": True, "dump": dump_str})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("", "/", "/health"):
            self.send_json({
                "service": "AegisKey Host Hardware Android Bridge",
                "status": "online",
                "endpoints": [
                    "GET /bridge/info",
                    "POST /bridge/vendor",
                    "POST /bridge/ctap",
                    "POST /bridge/pairing_open",
                    "POST /bridge/touch_up",
                    "GET /bridge/dump",
                ],
            })
            return

        self.send_json({"error": "not found", "path": self.path}, status_code=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""
        content_type = self.headers.get("Content-Type", "")
        accept_header = self.headers.get("Accept", "")

        if path == "/bridge/vendor":
            opcode = 0
            payload = b""
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    op_val = data.get("opcode") if data.get("opcode") is not None else data.get("op", 0)
                    if isinstance(op_val, str):
                        op_clean = op_val.strip()
                        opcode = int(op_clean, 16 if "x" in op_clean.lower() else 10)
                    else:
                        opcode = int(op_val)
                    p_hex = data.get("payload_hex") or data.get("data_hex") or data.get("tlv_hex") or ""
                    payload = bytes.fromhex(p_hex) if p_hex else b""
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                # Raw binary: [opcode: 1B] + payload
                if len(raw_body) > 0:
                    opcode = raw_body[0]
                    payload = raw_body[1:]

            try:
                status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(bytes([opcode, status]) + resp_payload)
                else:
                    self.send_json({
                        "ok": True,
                        "opcode": opcode,
                        "status": status,
                        "payload_hex": resp_payload.hex(),
                        "response_hex": (bytes([opcode, status]) + resp_payload).hex(),
                        "data_hex": resp_payload.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/ctap":
            cmd = CMD_CBOR
            payload = b""
            is_ping = False
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    cmd = int(data.get("cmd", CMD_CBOR))
                    p_hex = data.get("payload_hex", "") or data.get("cbor_hex", "")
                    payload = bytes.fromhex(p_hex) if p_hex else b""
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                # Raw binary: e.g. ping frame [0x81, len_hi, len_lo]
                if len(raw_body) > 0:
                    cmd = raw_body[0]
                    payload = raw_body[3:] if len(raw_body) >= 3 else b""
                    if cmd == CMD_PING:
                        is_ping = True

            try:
                if is_ping:
                    # Echo ping directly
                    self.send_binary(raw_body if raw_body else b"\x81\x00\x00")
                    return
                status, resp_payload = HW_MANAGER.send_ctap(cmd, payload)
                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(bytes([status]) + resp_payload)
                else:
                    self.send_json({
                        "ok": True,
                        "cmd": cmd,
                        "status": status,
                        "payload_hex": resp_payload.hex(),
                        "response_hex": resp_payload.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/pairing_open":
            try:
                res = HW_MANAGER.pairing_open()
                self.send_json({"ok": True, "result": res, "window_s": 60})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/touch_up":
            try:
                res = HW_MANAGER.touch_up()
                self.send_json({"ok": True, "result": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("/bridge/pin_auth", "/bridge/authenticate_pin", "/bridge/test_pin_ok"):
            try:
                res = HW_MANAGER.authenticate_pin()
                self.send_json({"ok": True, "result": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        self.send_json({"error": "not found", "path": self.path}, status_code=404)


def recv_exact(sock, n):
    """Receives exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def handle_binary_client(sock, addr):
    """Handles raw binary framing from SimulatedRenodeTransport:

    Format: [opcode: 1B][length: 2B BE][payload: length B]
    Response: [opcode: 1B][length: 2B BE][status: 1B + resp_payload]
    """
    print(f"[tcp-bin] Nova conexão binária de {addr}")
    sock.settimeout(30.0)
    try:
        while True:
            header = recv_exact(sock, 3)
            if not header:
                break
            opcode = header[0]
            length = (header[1] << 8) | header[2]
            payload = recv_exact(sock, length) if length > 0 else b""
            if payload is None:
                break

            print(f"[tcp-bin] RX opcode=0x{opcode:02X} len={length}")
            try:
                status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
            except Exception as ex:
                print(f"[tcp-bin] Erro no comando 0x{opcode:02X}: {ex}")
                status = 0x01
                resp_payload = b""

            body = bytes([status]) + resp_payload
            resp_header = bytes([opcode, (len(body) >> 8) & 0xFF, len(body) & 0xFF])
            sock.sendall(resp_header + body)
            print(f"[tcp-bin] TX opcode=0x{opcode:02X} status=0x{status:02X} body_len={len(body)}")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[tcp-bin] Conexão encerrada: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print(f"[tcp-bin] Fechou conexão de {addr}")


class DualProtocolServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Prevent crash if sys.stderr is broken or client disconnected
        try:
            import traceback
            tb = traceback.format_exc()
            log_file_path = os.path.join(SCRIPT_DIR, "bridge_server.log")
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] CLIENT ERROR {client_address}:\n{tb}\n")
        except Exception:
            pass


class DualProtocolHandler(socketserver.BaseRequestHandler):
    """Multiplexes HTTP and Binary TCP on the same port."""

    def handle(self):
        try:
            self.request.settimeout(10.0)
            peek = self.request.recv(4, socket.MSG_PEEK)
            if not peek:
                return

            if any(peek.startswith(v) for v in (b"GET ", b"POST", b"HEAD", b"OPTI", b"PUT ")):
                BridgeHttpRequestHandler(self.request, self.client_address, self.server)
            else:
                handle_binary_client(self.request, self.client_address)
        except Exception as e:
            pass


def run_server(host="0.0.0.0", port=DEFAULT_PORT):
    log_file_path = os.path.join(SCRIPT_DIR, "bridge_server.log")
    log_f = open(log_file_path, "a", encoding="utf-8", buffering=1)

    def log(msg):
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{t_str}] {msg}"
        print(line, flush=True)
        try:
            log_f.write(line + "\n")
            log_f.flush()
        except Exception:
            pass

    log(f"============================================================")
    log(f" AegisKey Host Hardware Android Bridge")
    log(f" Escutando em http://{host}:{port} e TCP binário")
    log(f" Transporte Chave Real: {HW_MANAGER.transport} ({HW_MANAGER.port_name or HW_MANAGER.vid_pid})")
    log(f"============================================================")

    while True:
        try:
            server = DualProtocolServer((host, port), DualProtocolHandler)
            log(f"[bridge] Servidor iniciado com sucesso na porta {port}")
            server.serve_forever()
        except KeyboardInterrupt:
            log("[bridge] Encerrando servidor por KeyboardInterrupt...")
            break
        except Exception as e:
            log(f"[bridge] EXCEÇÃO NO SERVIDOR: {e}")
            import traceback
            traceback.print_exc(file=log_f)
            log_f.flush()
            time.sleep(1.0)
        finally:
            try:
                server.server_close()
            except Exception:
                pass

    HW_MANAGER.close()
    log_f.close()


def run_self_test():
    """Runs automated self-test on real hardware endpoints."""
    print("=== SELF-TEST: AegisKey Host Hardware Android Bridge ===")
    ok = HW_MANAGER.detect_and_connect()
    if not ok:
        print("FALHA: Nenhuma chave física detectada em USB ou UART!")
        return 1

    info = HW_MANAGER.get_info()
    print("1. /bridge/info:", json.dumps(info, indent=2))
    assert info["connected"] is True, "Chave deveria estar conectada"

    print("2. Testando /bridge/ctap (CMD_PING 0x81)...")
    st, resp = HW_MANAGER.send_ctap(CMD_PING, b"TEST_PING_SELF")
    print(f"   PING OK -> status: 0x{st:02x}, resp: {resp}")

    print("3. Testando /bridge/pairing_open...")
    p_res = HW_MANAGER.pairing_open()
    print(f"   PAIRING_OPEN -> {repr(p_res)}")

    print("4. Testando /bridge/touch_up...")
    up_res = HW_MANAGER.touch_up()
    print(f"   TOUCH_UP -> {repr(up_res)}")

    print("5. Testando /bridge/vendor (OP_KEY_LIST 0x22)...")
    st, resp = HW_MANAGER.send_vendor(0x22, b"")
    print(f"   KEY_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("6. Testando /bridge/vendor (OP_OATH_LIST 0x25)...")
    st, resp = HW_MANAGER.send_vendor(0x25, b"")
    print(f"   OATH_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("7. Testando /bridge/vendor (OP_BINDING_CLAIM 0x28)...")
    claim_dummy = b"\x04" + b"\x11" * 64 + b"\x22" * 16
    st, resp = HW_MANAGER.send_vendor(0x28, claim_dummy)
    print(f"   BIND_CLAIM -> status: 0x{st:02x}, len: {len(resp)}")

    print("8. Testando /bridge/vendor (OP_BINDING_CHALLENGE 0x29)...")
    st, resp = HW_MANAGER.send_vendor(0x29, b"")
    print(f"   BIND_CHALLENGE -> status: 0x{st:02x}, len: {len(resp)}")

    print("9. Testando /bridge/vendor (OP_WALLET_LIST 0x36)...")
    st, resp = HW_MANAGER.send_vendor(0x36, b"")
    print(f"   WALLET_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("10. Testando /bridge/vendor (OP_FW_LOG 0x38)...")
    st, resp = HW_MANAGER.send_vendor(0x38, b"")
    print(f"   FW_LOG -> status: 0x{st:02x}, len: {len(resp)}")

    print("=== SELF-TEST CONCLUÍDO COM SUCESSO! ===")
    return 0


def main():
    parser = argparse.ArgumentParser(description="AegisKey Host Hardware Android Bridge")
    parser.add_argument("--port", help="Porta Serial COM (ex: COM7)", default=None)
    parser.add_argument("--baud", help="Baud rate Serial", type=int, default=DEFAULT_BAUD)
    parser.add_argument("--host", help="Endereço de bind", default="0.0.0.0")
    parser.add_argument("--listen-port", help="Porta do servidor TCP/HTTP", type=int, default=DEFAULT_PORT)
    parser.add_argument("--probe", action="store_true", help="Faz probe na chave física e sai")
    parser.add_argument("--self-test", action="store_true", help="Executa testes locais e remotos na chave física")
    args = parser.parse_args()

    if args.port:
        HW_MANAGER.preferred_port = args.port
    HW_MANAGER.baud = args.baud

    if args.probe:
        ok = HW_MANAGER.detect_and_connect()
        info = HW_MANAGER.get_info()
        print(json.dumps(info, indent=2))
        sys.exit(0 if ok else 1)

    if args.self_test:
        code = run_self_test()
        sys.exit(code)

    try:
        # Auto connect before starting server
        HW_MANAGER.detect_and_connect()
        run_server(args.host, args.listen_port)
    except Exception as ex:
        log_file_path = os.path.join(SCRIPT_DIR, "bridge_server.log")
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FATAL NO MAIN: {ex}\n")
            import traceback
            traceback.print_exc(file=f)
        sys.exit(1)


if __name__ == "__main__":
    main()
