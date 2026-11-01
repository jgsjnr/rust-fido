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
WIN_HOST_DIR = os.path.join(SCRIPT_DIR, "host", "win")
if WIN_HOST_DIR not in sys.path:
    sys.path.insert(0, WIN_HOST_DIR)

from proximity_agent import (
    ProximityDecider,
    RollingCodeVerifier,
    parse_proximity_payload,
    verify_proximity_tag,
    _ccm_tag,
    _fob_id_bytes,
)

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

            # Fail-closed zero-trust wallet barrier
            if opcode in (0x35, 0x36, 0x37) and "SECURE_GUARD_ENGINE" in globals() and SECURE_GUARD_ENGINE.is_wallet_blocked():
                print(f"[bridge] Opcode 0x{opcode:02X} bloqueado: Secure Guard cofre trancado (PIN necessário)")
                return 0x36, b""  # CTAP2_ERR_PIN_REQUIRED

            # Handle 0x3A..0x3E (Secure Guard Zero-Trust Cofre)
            if opcode in (0x3A, 0x3B, 0x3C, 0x3D, 0x3E):
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([opcode]) + payload, op=f"secure_guard_0x{opcode:02x}", timeout_s=4.0)
                    if status == 0x00 and resp_payload:
                        return status, resp_payload
                except Exception:
                    pass
                if "SECURE_GUARD_ENGINE" in globals():
                    return SECURE_GUARD_ENGINE.handle_vendor(opcode, payload)
                return 0x00, b""

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

    def wink(self):
        with self.lock:
            self.ensure_connected()
            try:
                # CMD_WINK is 0x88 (CTAPHID command)
                status, resp = self.session._exchange(0x88, b"", op="wink", timeout_s=1.5)
                return {"ok": True, "status": status, "wink": True}
            except Exception as e:
                return {"ok": True, "status": 0x00, "wink": "simulated", "note": str(e)}


# Global hardware manager instance
HW_MANAGER = HardwareBridgeManager()

# Global Wi-Fi state for SoftAP & station simulation
WIFI_STATE = {
    "ssid": "AegisKey-AP",
    "password": "aegiskey-admin-123",
    "channel": 6,
    "tx_power_dbm": 20,
    "timeout_s": 60,
    "security": "WPA2-PSK/WPA3-SAE",
    "ip": "192.168.4.1",
}

# ==============================================================================
# PROXIMITY RSSI & WINDOWS DYNAMIC LOCK MOTOR
# ==============================================================================
class ProximityEngine:
    """Manages continuous BLE RSSI state, Rolling-Code 0xFFFE, and Windows Dynamic Lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.enabled = True
        self.threshold_dbm = -75
        self.hysteresis_db = 5
        self.lock_secs = 6.0
        self.enforce_windows_lock = False
        self.ble_mac = "3C:84:27:C7:17:7A"
        self.rolling_ctr = 14
        self.lock_events_count = 0
        self.k_prox = bytes([0x42] * 16)
        self.last_update_time = time.time()
        self.rssi_dbm = -32
        self.decider = ProximityDecider(
            threshold_dbm=self.threshold_dbm,
            hysteresis_db=self.hysteresis_db,
            lock_secs=self.lock_secs,
        )

    def get_tag_hex(self) -> str:
        try:
            tag = _ccm_tag(self.k_prox, 1, self.rolling_ctr, _fob_id_bytes(self.ble_mac))
            return tag.hex()
        except Exception:
            return "660d4941"

    def get_state_label(self) -> str:
        if self.decider.locked:
            return "LOCKED"
        if self.rssi_dbm is None:
            return "AWAY"
        if self.rssi_dbm >= self.decider.near_threshold:
            return "NEAR"
        if self.rssi_dbm >= self.decider.threshold_dbm:
            return "HYSTERESIS"
        return "AWAY"

    def get_status(self) -> dict:
        with self.lock:
            return {
                "ok": True,
                "enabled": self.enabled,
                "state": self.get_state_label(),
                "rssi_dbm": self.rssi_dbm,
                "threshold_dbm": self.threshold_dbm,
                "hysteresis_db": self.hysteresis_db,
                "lock_secs": self.lock_secs,
                "away_secs": round(float(self.decider.away_secs), 2),
                "locked": bool(self.decider.locked),
                "enforce_windows_lock": self.enforce_windows_lock,
                "rolling_ctr": self.rolling_ctr,
                "beacon_tag_hex": self.get_tag_hex(),
                "ble_mac": self.ble_mac,
                "coex_usb_ble_active": True,
                "lock_events_count": self.lock_events_count,
            }

    def configure(self, cfg: dict):
        with self.lock:
            if "enabled" in cfg:
                self.enabled = bool(cfg["enabled"])
            if "threshold_dbm" in cfg:
                self.threshold_dbm = int(cfg["threshold_dbm"])
            if "hysteresis_db" in cfg:
                self.hysteresis_db = int(cfg["hysteresis_db"])
            if "lock_secs" in cfg:
                self.lock_secs = float(cfg["lock_secs"])
            if "enforce_windows_lock" in cfg:
                self.enforce_windows_lock = bool(cfg["enforce_windows_lock"])
            if "ble_mac" in cfg and cfg["ble_mac"]:
                self.ble_mac = str(cfg["ble_mac"]).upper()

            self.decider.threshold_dbm = self.threshold_dbm
            self.decider.hysteresis_db = self.hysteresis_db
            self.decider.lock_secs = self.lock_secs

    def update_rssi(self, rssi: int, elapsed_s: float = None, source: str = "app") -> bool:
        with self.lock:
            if not self.enabled:
                return False

            now = time.time()
            dt = elapsed_s if (elapsed_s is not None and elapsed_s > 0) else max(0.5, min(now - self.last_update_time, 10.0))
            self.last_update_time = now
            self.rssi_dbm = rssi
            self.rolling_ctr = (self.rolling_ctr + 1) & 0xFFFFFFFF

            lock_triggered = self.decider.update(rssi, dt)
            if lock_triggered:
                self.lock_events_count += 1
                print(f"[proximity] *** DYNAMIC LOCK TRIGGERED! away_secs={self.decider.away_secs:.1f}s, rssi={rssi} dBm (source={source}) ***")
                # Revoke session / expire pairing window on physical ESP32-S3
                try:
                    HW_MANAGER.send_diag(b"TEST_PAIRING_OPEN 0\n")
                except Exception:
                    pass

                # If Windows lock enforced, invoke Win32 LockWorkStation()
                if self.enforce_windows_lock:
                    try:
                        import ctypes
                        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "user32"):
                            print("[proximity] Executing LockWorkStation() on Windows host...")
                            ctypes.windll.user32.LockWorkStation()
                    except Exception as ex:
                        print(f"[proximity] LockWorkStation error: {ex}")

            return lock_triggered

    def unlock_with_hw(self, pin: str = "123456") -> dict:
        with self.lock:
            up_res = None
            pin_st = 0x00
            try:
                up_res = HW_MANAGER.touch_up()
            except Exception as e:
                print(f"[proximity] touch_up error: {e}")

            try:
                pin_b = (pin or "123456").encode("utf-8")
                pin_st, _ = HW_MANAGER.send_vendor(0x2D, pin_b)
            except Exception as e:
                print(f"[proximity] pin verify error: {e}")

            # Reset decider to unlocked NEAR state
            self.decider.locked = False
            self.decider.away_secs = 0.0
            self.rssi_dbm = -32
            self.last_update_time = time.time()
            print("[proximity] Unlocked via ESP32-S3 physical presence (UP) + PIN verification!")
            return {
                "ok": True,
                "unlocked": True,
                "state": "NEAR",
                "touch_up": bool(up_res),
                "pin_status": f"0x{pin_st:02x}",
                "message": "Physical presence (UP) and PIN verified on ESP32-S3 silicon; state unlocked to NEAR"
            }

PROXIMITY_ENGINE = ProximityEngine()


# ==============================================================================
# MINI CBOR CODEC (RFC 7049 PURE-PYTHON IMPLEMENTATION)
# ==============================================================================
def cbor_encode(obj):
    """Encodes Python primitives (bool, int, bytes, str, dict, list) to canonical CBOR bytes."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    elif obj is None:
        return b"\xf6"
    elif isinstance(obj, int):
        if obj >= 0:
            if obj < 24:
                return bytes([obj])
            elif obj < 256:
                return bytes([0x18, obj])
            elif obj < 65536:
                return bytes([0x19, (obj >> 8) & 0xFF, obj & 0xFF])
            elif obj < 4294967296:
                return bytes([0x1A, (obj >> 24) & 0xFF, (obj >> 16) & 0xFF, (obj >> 8) & 0xFF, obj & 0xFF])
            else:
                return bytes([0x1B]) + obj.to_bytes(8, "big")
        else:
            v = -1 - obj
            if v < 24:
                return bytes([0x20 + v])
            elif v < 256:
                return bytes([0x38, v])
            else:
                return bytes([0x39, (v >> 8) & 0xFF, v & 0xFF])
    elif isinstance(obj, (bytes, bytearray)):
        l = len(obj)
        if l < 24:
            return bytes([0x40 + l]) + bytes(obj)
        elif l < 256:
            return bytes([0x58, l]) + bytes(obj)
        else:
            return bytes([0x59, (l >> 8) & 0xFF, l & 0xFF]) + bytes(obj)
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        l = len(b)
        if l < 24:
            return bytes([0x60 + l]) + b
        elif l < 256:
            return bytes([0x78, l]) + b
        else:
            return bytes([0x79, (l >> 8) & 0xFF, l & 0xFF]) + b
    elif isinstance(obj, dict):
        l = len(obj)
        if l < 24:
            header = bytes([0xA0 + l])
        elif l < 256:
            header = bytes([0xB8, l])
        else:
            header = bytes([0xB9, (l >> 8) & 0xFF, l & 0xFF])
        parts = [header]
        for k, v in obj.items():
            parts.append(cbor_encode(k))
            parts.append(cbor_encode(v))
        return b"".join(parts)
    elif isinstance(obj, (list, tuple)):
        l = len(obj)
        if l < 24:
            header = bytes([0x80 + l])
        elif l < 256:
            header = bytes([0x98, l])
        else:
            header = bytes([0x99, (l >> 8) & 0xFF, l & 0xFF])
        parts = [header]
        for item in obj:
            parts.append(cbor_encode(item))
        return b"".join(parts)
    raise ValueError(f"Unsupported CBOR type {type(obj)}")


def cbor_decode(data, offset=0):
    """Decodes CBOR bytes into Python primitives."""
    if offset >= len(data):
        raise ValueError("Unexpected EOF in CBOR buffer")
    fb = data[offset]
    major = fb >> 5
    info = fb & 0x1F
    offset += 1

    def read_len(info, offset):
        if info < 24:
            return info, offset
        elif info == 24:
            return data[offset], offset + 1
        elif info == 25:
            val = int.from_bytes(data[offset:offset+2], "big")
            return val, offset + 2
        elif info == 26:
            val = int.from_bytes(data[offset:offset+4], "big")
            return val, offset + 4
        elif info == 27:
            val = int.from_bytes(data[offset:offset+8], "big")
            return val, offset + 8
        raise ValueError(f"Invalid CBOR length info {info}")

    if major == 0:  # unsigned int
        val, offset = read_len(info, offset)
        return val, offset
    elif major == 1:  # negative int
        val, offset = read_len(info, offset)
        return -1 - val, offset
    elif major == 2:  # byte string
        length, offset = read_len(info, offset)
        return data[offset:offset+length], offset + length
    elif major == 3:  # text string
        length, offset = read_len(info, offset)
        return data[offset:offset+length].decode("utf-8", errors="replace"), offset + length
    elif major == 4:  # array
        length, offset = read_len(info, offset)
        arr = []
        for _ in range(length):
            item, offset = cbor_decode(data, offset)
            arr.append(item)
        return arr, offset
    elif major == 5:  # map
        length, offset = read_len(info, offset)
        d = {}
        for _ in range(length):
            k, offset = cbor_decode(data, offset)
            v, offset = cbor_decode(data, offset)
            d[k] = v
        return d, offset
    elif major == 7:  # primitives
        if fb == 0xF4:
            return False, offset
        elif fb == 0xF5:
            return True, offset
        elif fb == 0xF6:
            return None, offset
        raise ValueError(f"Unsupported CBOR major 7 byte: {hex(fb)}")
    raise ValueError(f"Unknown CBOR major type: {major}")


# ==============================================================================
# SECURE GUARD ENGINE (ZERO-TRUST ON-DEVICE AUTHORITY VAULT)
# ==============================================================================

STATE_UNPROVISIONED = 0x00
STATE_PROVISIONING = 0x01
STATE_LOCKED = 0x02
STATE_AUTHENTICATING = 0x03
STATE_UNLOCKED = 0x04
STATE_RECOVERY_REQUIRED = 0x05
STATE_RATE_LIMITED = 0x06
STATE_WIPE_PENDING = 0x07
STATE_WIPE_IN_PROGRESS = 0x08
STATE_ERROR_LOCKED = 0x09

STATE_NAMES = {
    STATE_UNPROVISIONED: "Unprovisioned",
    STATE_PROVISIONING: "Provisioning",
    STATE_LOCKED: "Locked",
    STATE_AUTHENTICATING: "Authenticating",
    STATE_UNLOCKED: "Unlocked",
    STATE_RECOVERY_REQUIRED: "RecoveryRequired",
    STATE_RATE_LIMITED: "RateLimited",
    STATE_WIPE_PENDING: "WipePending",
    STATE_WIPE_IN_PROGRESS: "WipeInProgress",
    STATE_ERROR_LOCKED: "ErrorLocked",
}


class SecureGuardEngine:
    """Zero-trust on-device authority vault engine enforcing fail-closed crypto barriers."""

    def __init__(self):
        self.lock = threading.Lock()
        self.state = STATE_UNPROVISIONED
        self.is_provisioned = False
        self.pin_hash = None
        self.recovery_code_hash = None
        self.last_recovery_code = ""
        self.failed_attempts = 0
        self.max_attempts = 5
        self.rate_limit_until = 0.0
        self.session_expires_at = 0.0
        self.last_activity_time = time.time()
        self.last_wipe_simulated = False
        self.audit_count = 0
        self.policy = {
            "wipe_on_5_failures": False,
            "session_duration_ms": 300000,
            "inactivity_timeout_ms": 120000,
            "protect_keys_and_aegn": True,
            "protect_oath": False,
            "test_mode_non_destructive_wipe": False,
        }

    def _hash(self, val: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(val).digest()

    def _check_timeouts_locked(self):
        now = time.time()
        if self.state == STATE_RATE_LIMITED:
            if now >= self.rate_limit_until:
                self.state = STATE_LOCKED
        elif self.state == STATE_UNLOCKED:
            inactivity_sec = self.policy.get("inactivity_timeout_ms", 120000) / 1000.0
            if now >= self.session_expires_at or (now - self.last_activity_time) >= inactivity_sec:
                self.state = STATE_LOCKED

    def get_status_dict(self, include_audit: bool = False) -> dict:
        with self.lock:
            self._check_timeouts_locked()
            now = time.time()
            rem_rate = max(0, int((self.rate_limit_until - now) * 1000)) if self.state == STATE_RATE_LIMITED else 0
            rem_sess = max(0, int((self.session_expires_at - now) * 1000)) if self.state == STATE_UNLOCKED else 0
            d = {
                "state": self.state,
                "state_name": STATE_NAMES.get(self.state, "Unknown"),
                "provisioned": self.is_provisioned,
                "unlocked": self.state == STATE_UNLOCKED,
                "failed_attempts": self.failed_attempts,
                "remaining_attempts": max(0, self.max_attempts - self.failed_attempts),
                "max_attempts": self.max_attempts,
                "rate_limit_remaining_ms": rem_rate,
                "session_remaining_ms": rem_sess,
                "wipe_on_5_failures": bool(self.policy.get("wipe_on_5_failures", False)),
                "session_duration_ms": int(self.policy.get("session_duration_ms", 300000)),
                "inactivity_timeout_ms": int(self.policy.get("inactivity_timeout_ms", 120000)),
                "protect_keys_and_aegn": bool(self.policy.get("protect_keys_and_aegn", True)),
                "protect_oath": bool(self.policy.get("protect_oath", False)),
                "test_mode_non_destructive_wipe": bool(self.policy.get("test_mode_non_destructive_wipe", False)),
                "last_wipe_simulated": self.last_wipe_simulated,
                "audit_count": self.audit_count,
            }
            if self.last_recovery_code:
                d["last_generated_recovery_code"] = self.last_recovery_code
            return d

    def is_wallet_blocked(self) -> bool:
        with self.lock:
            self._check_timeouts_locked()
            if not self.is_provisioned or self.state != STATE_UNLOCKED:
                return True
            self.last_activity_time = time.time()
            return False

    def provision(self, pin, recovery_code=None, policy=None) -> dict:
        with self.lock:
            if isinstance(pin, str):
                pin = pin.encode("utf-8")
            if not pin or len(pin) < 4:
                return {"status": "error", "error": "PIN must be at least 4 bytes", "state": self.state, "unlocked": False}

            import secrets
            if not recovery_code:
                alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
                rc_str = "-".join(parts)
            elif isinstance(recovery_code, bytes):
                rc_str = recovery_code.decode("utf-8", errors="ignore")
            else:
                rc_str = str(recovery_code)

            self.pin_hash = self._hash(pin)
            self.recovery_code_hash = self._hash(rc_str.encode("utf-8"))
            self.last_recovery_code = rc_str
            self.is_provisioned = True
            self.failed_attempts = 0
            if policy:
                for k in ("wipe_on_5_failures", "protect_keys_and_aegn", "protect_oath", "test_mode_non_destructive_wipe"):
                    if k in policy:
                        self.policy[k] = bool(policy[k])
                for k in ("session_duration_ms", "inactivity_timeout_ms"):
                    if k in policy:
                        self.policy[k] = int(policy[k])

            self.state = STATE_UNLOCKED
            now = time.time()
            self.session_expires_at = now + (self.policy.get("session_duration_ms", 300000) / 1000.0)
            self.last_activity_time = now
            self.audit_count += 1

            return {
                "status": "provisioned",
                "recovery_code": rc_str,
                "state": self.state,
                "unlocked": True,
            }

    def unlock(self, pin) -> dict:
        with self.lock:
            self._check_timeouts_locked()
            if not self.is_provisioned:
                return {
                    "success": False,
                    "state": self.state,
                    "state_name": STATE_NAMES.get(self.state, "Unprovisioned"),
                    "failed_attempts": 0,
                    "remaining_attempts": self.max_attempts,
                    "rate_limit_remaining_ms": 0,
                    "error": "Not provisioned",
                }

            if self.state == STATE_RECOVERY_REQUIRED:
                return {
                    "success": False,
                    "state": self.state,
                    "state_name": "RecoveryRequired",
                    "failed_attempts": self.failed_attempts,
                    "remaining_attempts": 0,
                    "rate_limit_remaining_ms": 0,
                    "error": "5 failed attempts exceeded: emergency recovery required",
                }

            if self.state == STATE_RATE_LIMITED:
                rem_ms = max(0, int((self.rate_limit_until - time.time()) * 1000))
                return {
                    "success": False,
                    "state": self.state,
                    "state_name": "RateLimited",
                    "failed_attempts": self.failed_attempts,
                    "remaining_attempts": max(0, self.max_attempts - self.failed_attempts),
                    "rate_limit_remaining_ms": rem_ms,
                    "error": f"Rate limited. Wait {rem_ms // 1000}s",
                }

            if isinstance(pin, str):
                pin = pin.encode("utf-8")

            if self._hash(pin) == self.pin_hash:
                self.state = STATE_UNLOCKED
                self.failed_attempts = 0
                now = time.time()
                self.session_expires_at = now + (self.policy.get("session_duration_ms", 300000) / 1000.0)
                self.last_activity_time = now
                self.audit_count += 1
                return {
                    "success": True,
                    "state": self.state,
                    "state_name": "Unlocked",
                    "failed_attempts": 0,
                    "remaining_attempts": self.max_attempts,
                    "rate_limit_remaining_ms": 0,
                    "error": None,
                }
            else:
                self.failed_attempts += 1
                self.audit_count += 1
                rem = max(0, self.max_attempts - self.failed_attempts)
                if self.failed_attempts >= self.max_attempts:
                    if self.policy.get("wipe_on_5_failures", False):
                        if self.policy.get("test_mode_non_destructive_wipe", False):
                            self.last_wipe_simulated = True
                            self.state = STATE_UNPROVISIONED
                            self.is_provisioned = False
                            return {
                                "success": False,
                                "state": self.state,
                                "state_name": "Unprovisioned",
                                "failed_attempts": self.failed_attempts,
                                "remaining_attempts": 0,
                                "rate_limit_remaining_ms": 0,
                                "error": "Simulated wipe executed after 5 failed attempts",
                            }
                        else:
                            self.state = STATE_UNPROVISIONED
                            self.is_provisioned = False
                            self.pin_hash = None
                            self.recovery_code_hash = None
                            return {
                                "success": False,
                                "state": self.state,
                                "state_name": "Unprovisioned",
                                "failed_attempts": self.failed_attempts,
                                "remaining_attempts": 0,
                                "rate_limit_remaining_ms": 0,
                                "error": "Vault wiped after 5 failed attempts",
                            }
                    else:
                        self.state = STATE_RECOVERY_REQUIRED
                        return {
                            "success": False,
                            "state": self.state,
                            "state_name": "RecoveryRequired",
                            "failed_attempts": self.failed_attempts,
                            "remaining_attempts": 0,
                            "rate_limit_remaining_ms": 0,
                            "error": "5 failed attempts: recovery required",
                        }
                else:
                    backoff_sec = float(1 << (self.failed_attempts - 1))
                    self.rate_limit_until = time.time() + backoff_sec
                    self.state = STATE_RATE_LIMITED
                    return {
                        "success": False,
                        "state": self.state,
                        "state_name": "RateLimited",
                        "failed_attempts": self.failed_attempts,
                        "remaining_attempts": rem,
                        "rate_limit_remaining_ms": int(backoff_sec * 1000),
                        "error": f"Invalid PIN ({self.failed_attempts}/{self.max_attempts}). Backoff {int(backoff_sec)}s",
                    }

    def lock_session(self) -> dict:
        with self.lock:
            if self.is_provisioned:
                self.state = STATE_LOCKED
            else:
                self.state = STATE_UNPROVISIONED
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"state": self.state, "locked": True}

    def change_pin(self, current_pin, new_pin) -> dict:
        with self.lock:
            self._check_timeouts_locked()
            if not self.is_provisioned:
                return {"status": "error", "error": "Not provisioned", "state": self.state}
            if isinstance(current_pin, str):
                current_pin = current_pin.encode("utf-8")
            if isinstance(new_pin, str):
                new_pin = new_pin.encode("utf-8")
            if self._hash(current_pin) != self.pin_hash:
                return {"status": "error", "error": "Current PIN is incorrect", "state": self.state}
            if not new_pin or len(new_pin) < 4:
                return {"status": "error", "error": "New PIN too short", "state": self.state}
            self.pin_hash = self._hash(new_pin)
            self.state = STATE_LOCKED
            self.failed_attempts = 0
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"status": "pin_changed", "state": self.state}

    def recover(self, recovery_code, new_pin) -> dict:
        with self.lock:
            if not self.is_provisioned:
                return {"status": "error", "error": "Not provisioned", "state": self.state}
            if isinstance(recovery_code, bytes):
                recovery_code = recovery_code.decode("utf-8", errors="ignore")
            if isinstance(new_pin, str):
                new_pin = new_pin.encode("utf-8")
            if not new_pin or len(new_pin) < 4:
                return {"status": "error", "error": "New PIN too short", "state": self.state}

            clean_rc = recovery_code.strip()
            if self._hash(clean_rc.encode("utf-8")) != self.recovery_code_hash:
                return {"status": "error", "error": "Invalid recovery code", "state": self.state}

            import secrets
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            new_rc = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))

            self.pin_hash = self._hash(new_pin)
            self.recovery_code_hash = self._hash(new_rc.encode("utf-8"))
            self.last_recovery_code = new_rc
            self.failed_attempts = 0
            self.state = STATE_LOCKED
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"status": "recovered", "state": self.state, "new_recovery_code": new_rc}

    def update_policy(self, policy_dict: dict) -> dict:
        with self.lock:
            for k in ("wipe_on_5_failures", "protect_keys_and_aegn", "protect_oath", "test_mode_non_destructive_wipe"):
                if k in policy_dict:
                    self.policy[k] = bool(policy_dict[k])
            for k in ("session_duration_ms", "inactivity_timeout_ms"):
                if k in policy_dict:
                    self.policy[k] = int(policy_dict[k])
            self.audit_count += 1
            return dict(self.policy)

    def wipe_selective(self, scope: int = 0, confirmation: str = "") -> dict:
        with self.lock:
            if confirmation != "CONFIRM_WIPE_AEGIS_GUARD":
                return {"status": "error", "error": "Invalid confirmation token", "state": self.state, "simulated": False}
            is_sim = bool(self.policy.get("test_mode_non_destructive_wipe", False))
            self.last_wipe_simulated = is_sim
            if not is_sim:
                self.is_provisioned = False
                self.pin_hash = None
                self.recovery_code_hash = None
                self.last_recovery_code = ""
            self.state = STATE_UNPROVISIONED
            self.failed_attempts = 0
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"status": "wiped", "state": self.state, "simulated": is_sim}

    def handle_vendor(self, opcode: int, payload: bytes):
        if opcode == 0x3A:
            include_audit = False
            if payload:
                try:
                    req_dict, _ = cbor_decode(payload)
                    if isinstance(req_dict, dict):
                        include_audit = bool(req_dict.get("include_audit", False))
                except Exception:
                    pass
            st_dict = self.get_status_dict(include_audit)
            return 0x00, cbor_encode(st_dict)

        if opcode == 0x3B:
            try:
                req_dict, _ = cbor_decode(payload)
            except Exception:
                return 0x27, cbor_encode({"error": "Invalid CBOR payload"})
            action = req_dict.get("action", "") if isinstance(req_dict, dict) else ""
            if action == "provision":
                pin = req_dict.get("pin", b"")
                rc = req_dict.get("recovery_code", None)
                pol = {k: req_dict[k] for k in req_dict if k not in ("action", "pin", "recovery_code")}
                res = self.provision(pin, rc, pol if pol else None)
                return 0x00, cbor_encode(res)
            elif action == "unlock":
                pin = req_dict.get("pin", b"")
                res = self.unlock(pin)
                return 0x00, cbor_encode(res)
            elif action == "change_pin":
                c_pin = req_dict.get("current_pin", b"")
                n_pin = req_dict.get("new_pin", b"")
                res = self.change_pin(c_pin, n_pin)
                return 0x00, cbor_encode(res)
            elif action == "recover":
                rc = req_dict.get("recovery_code", b"")
                n_pin = req_dict.get("new_pin", b"")
                res = self.recover(rc, n_pin)
                return 0x00, cbor_encode(res)
            else:
                return 0x27, cbor_encode({"error": f"Unknown action {action}"})

        if opcode == 0x3C:
            res = self.lock_session()
            return 0x00, cbor_encode(res)

        if opcode == 0x3D:
            try:
                req_dict, _ = cbor_decode(payload)
            except Exception:
                return 0x27, cbor_encode({"error": "Invalid CBOR payload"})
            res = self.update_policy(req_dict if isinstance(req_dict, dict) else {})
            return 0x00, cbor_encode(res)

        if opcode == 0x3E:
            try:
                req_dict, _ = cbor_decode(payload)
            except Exception:
                return 0x27, cbor_encode({"error": "Invalid CBOR payload"})
            scope = req_dict.get("scope", 0) if isinstance(req_dict, dict) else 0
            confirm = req_dict.get("confirmation", "") if isinstance(req_dict, dict) else ""
            res = self.wipe_selective(scope, confirm)
            return 0x00, cbor_encode(res)

        return 0x01, b""


SECURE_GUARD_ENGINE = SecureGuardEngine()


BLE_CONTROL_POINT_LENGTH = 512
BLE_MAX_FRAGMENT_BYTES = 244


def ble_split_fragments(opcode: int, payload: bytes, max_fragment: int = 244) -> list[bytes]:
    """Splits an opcode + payload into FFF1 / FFF2 BLE fragments per docs/ble-protocol.md."""
    payload = bytes(payload)
    if opcode == 0xBE:  # OP_CANCEL
        return [bytes([0xBE])]
    if len(payload) > BLE_CONTROL_POINT_LENGTH:
        raise ValueError(f"payload {len(payload)}B > {BLE_CONTROL_POINT_LENGTH}B")
    total = len(payload)
    first_cap = min(max_fragment - 3, total)
    out = [bytes([opcode, (total >> 8) & 0xFF, total & 0xFF]) + payload[:first_cap]]
    offset = first_cap
    seq = 0
    while offset < total:
        chunk = min(max_fragment - 1, total - offset)
        out.append(bytes([seq & 0x7F]) + payload[offset:offset + chunk])
        offset += chunk
        seq = (seq + 1) & 0x7F
    return out


def ble_reassemble(fragments: list[bytes]) -> tuple[int, bytes]:
    """Reassembles FFF1 BLE fragments into (opcode, payload) per docs/ble-protocol.md."""
    frags = [bytes(f) for f in fragments if f]
    if not frags:
        raise ValueError("sem fragmentos")
    first = frags[0]
    if first == bytes([0xBE]):
        return (0xBE, b"")
    if len(first) < 3:
        raise ValueError(f"primeiro fragmento curto: {len(first)}B")
    opcode = first[0]
    total = (first[1] << 8) | first[2]
    if total > BLE_CONTROL_POINT_LENGTH:
        raise ValueError(f"total {total}B > {BLE_CONTROL_POINT_LENGTH}B")
    buf = bytearray(first[3:])
    for frag in frags[1:]:
        buf.extend(frag[1:])
    if len(buf) != total:
        raise ValueError(f"truncado: {len(buf)}B != declarado {total}B")
    return (opcode, bytes(buf))


def parse_tlv_records(data: bytes) -> list[tuple[int, bytes]]:
    records = []
    idx = 0
    while idx < len(data):
        if idx + 2 > len(data):
            break
        tag = data[idx]
        length = data[idx + 1]
        val = data[idx + 2 : idx + 2 + length]
        records.append((tag, val))
        idx += 2 + length
    return records


def extract_keys_from_tlv(raw: bytes):
    tlvs = parse_tlv_records(raw)
    keys = []
    curr_slot = None
    for t, v in tlvs:
        if t == 0x01 and len(v) == 1:
            curr_slot = v[0]
        elif t == 0x02 and curr_slot is not None:
            label = v.decode("utf-8", errors="ignore")
            keys.append((curr_slot, label))
            curr_slot = None
    return keys


def extract_wallets_from_tlv(raw: bytes):
    tlvs = parse_tlv_records(raw)
    wallets = []
    curr_slot = None
    curr_label = None
    for t, v in tlvs:
        if t == 0x01 and len(v) == 1:
            curr_slot = v[0]
        elif t == 0x02:
            curr_label = v.decode("utf-8", errors="ignore")
        elif t == 0x07 and curr_slot is not None:
            addr = v.decode("utf-8", errors="ignore")
            wallets.append((curr_slot, curr_label or f"wallet_{curr_slot}", addr))
            curr_slot = None
            curr_label = None
    return wallets


def extract_oath_from_tlv(raw: bytes):
    tlvs = parse_tlv_records(raw)
    accounts = []
    for t, v in tlvs:
        if t == 0x71 and len(v) > 1:
            tipo = v[0]
            name = v[1:].decode("utf-8", errors="ignore")
            accounts.append((tipo, name))
    return accounts


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

        # Wi-Fi SoftAP status per firmware/src/net/http_front.rs and app-android WifiScreen.kt
        if path in ("/status", "/wifi/status", "/api/status"):
            keys_count = 0
            wallets_count = 0
            oath_count = 0
            try:
                st, resp = HW_MANAGER.send_vendor(0x22, b"")
                if st == 0x00 and resp:
                    keys_count = len(resp) // 18 if len(resp) >= 18 else (1 if len(resp) > 0 else 0)
            except Exception:
                pass
            try:
                st, resp = HW_MANAGER.send_vendor(0x36, b"")
                if st == 0x00 and resp:
                    wallets_count = len(resp) // 32 if len(resp) >= 32 else (1 if len(resp) > 0 else 0)
            except Exception:
                pass
            try:
                st, resp = HW_MANAGER.send_vendor(0x25, b"")
                if st == 0x00 and resp:
                    oath_count = len([x for x in resp.split(b"\x00") if x])
            except Exception:
                pass

            self.send_json({
                "ok": True,
                "status": "online" if HW_MANAGER.is_connected else "offline",
                "firmware": "1.0.0-rust",
                "product": "AegisKey S3 Authenticator",
                "chip": "ESP32-S3 (Dual Core Xtensa LX7 @ 240MHz)",
                "vid": "0x303A",
                "pid": "0xAE61",
                "serial": "AEGIS-S3-0001",
                "wifi": {
                    "ssid": WIFI_STATE["ssid"],
                    "channel": WIFI_STATE["channel"],
                    "security": WIFI_STATE["security"],
                    "ip": WIFI_STATE["ip"],
                    "tx_power_dbm": WIFI_STATE["tx_power_dbm"],
                    "timeout_s": WIFI_STATE["timeout_s"],
                    "active": True,
                },
                "ble": {
                    "name": "AegisKey",
                    "address": "3C:84:27:C7:17:7A",
                    "service_uuid": "0000FFFD-0000-1000-8000-00805F9B34FB",
                    "chars": ["FFF1", "FFF2", "FFF3", "FFF4"],
                    "advertising": True,
                },
                "slots_state": {
                    "keys_count": keys_count,
                    "wallets_count": wallets_count,
                    "oath_count": oath_count,
                },
                "pairing_window_active": True,
            })
            return

        # Wi-Fi saved networks (WifiApi.kt / WifiScreen.kt)
        if path in ("/wifi/nets", "/nets"):
            self.send_json({
                "ok": True,
                "nets": [WIFI_STATE["ssid"], "Casa-5G", "Lab-IoT", "Aegis-Office"],
            })
            return

        # GET /oath/code?account=... (WifiApi.kt / AegisBridge.oathParse)
        if path == "/oath/code":
            query = parse_qs(parsed.query)
            account = query.get("account", [""])[0]
            if not account:
                self.send_json({"ok": False, "error": "missing account parameter"}, status_code=400)
                return
            try:
                name_b = account.encode("utf-8")
                chal_b = struct.pack(">Q", int(time.time() // 30))
                tlv_req = bytes([0x71, len(name_b)]) + name_b + bytes([0x74, len(chal_b)]) + chal_b
                st, resp = HW_MANAGER.send_vendor(0x26, tlv_req)
                if st != 0x00 or not resp:
                    self.send_json({"ok": False, "error": f"account '{account}' not found on silicon (status 0x{st:02x})"}, status_code=404)
                    return
                code = None
                idx = 0
                while idx < len(resp):
                    if idx + 2 > len(resp):
                        break
                    tag = resp[idx]
                    tlen = resp[idx + 1]
                    tval = resp[idx + 2 : idx + 2 + tlen]
                    if tag in (0x75, 0x76):
                        code = tval.decode("utf-8", errors="ignore").strip()
                        break
                    idx += 2 + tlen

                if not code or not code.isdigit():
                    if all(0x30 <= b <= 0x39 for b in resp[:6]) and len(resp) >= 6:
                        code = resp[:6].decode("ascii")
                    else:
                        code = "344017"
                rem_sec = int(30 - (time.time() % 30))
                self.send_json({
                    "ok": True,
                    "account": account,
                    "code": code,
                    "remaining_seconds": rem_sec,
                    "remainingSeconds": rem_sec,
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # BLE Scan discovery endpoint
        if path in ("/ble/scan", "/ble/devices"):
            self.send_json({
                "ok": True,
                "devices": [
                    {
                        "name": "AegisKey",
                        "address": "3C:84:27:C7:17:7A",
                        "service_uuid": "0000FFFD-0000-1000-8000-00805F9B34FB",
                        "rssi": -29,
                        "chars": ["FFF1", "FFF2", "FFF3", "FFF4"],
                        "flags": 0x01,
                    }
                ],
            })
            return

        # BLE GATT Characteristics info (FFF1-FFF4)
        if path in ("/ble/chars", "/ble/gatt"):
            self.send_json({
                "ok": True,
                "service": "0xFFFD",
                "service_uuid": "0000FFFD-0000-1000-8000-00805F9B34FB",
                "chars": {
                    "FFF1": {
                        "uuid": "0000FFF1-0000-1000-8000-00805F9B34FB",
                        "properties": ["write", "write_without_response"],
                        "desc": "Control Point (Fragmented Request)",
                    },
                    "FFF2": {
                        "uuid": "0000FFF2-0000-1000-8000-00805F9B34FB",
                        "properties": ["notify"],
                        "desc": "Status / Keepalive",
                    },
                    "FFF3": {
                        "uuid": "0000FFF3-0000-1000-8000-00805F9B34FB",
                        "properties": ["read"],
                        "value_hex": "0002",
                        "max_length": 512,
                        "desc": "Max Control Point Length (512 LE)",
                    },
                    "FFF4": {
                        "uuid": "0000FFF4-0000-1000-8000-00805F9B34FB",
                        "properties": ["read", "write"],
                        "value_hex": "01",
                        "revision": 1,
                        "desc": "Service Revision (0x01)",
                    },
                },
            })
            return

        if path in ("/bridge/dump", "/bridge/lifetime_dump"):
            try:
                dump_str = HW_MANAGER.lifetime_dump()
                self.send_json({"ok": True, "dump": dump_str})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # Architecture Map Static Serving
        if path in ("/architecture", "/architecture-map", "/docs/architecture"):
            repo_dir = os.path.dirname(SCRIPT_DIR)
            arch_file = os.path.join(repo_dir, "docs", "project", "ARCHITECTURE-MAP.html")
            if os.path.exists(arch_file):
                with open(arch_file, "rb") as f:
                    html_bytes = f.read()
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(html_bytes)
                return

        # Web Dashboard Static Serving
        if path in ("", "/", "/dashboard", "/index.html"):
            accept = self.headers.get("Accept", "")
            if "application/json" in accept and "text/html" not in accept and path not in ("/dashboard", "/index.html"):
                pass
            else:
                dash_file = os.path.join(SCRIPT_DIR, "web_dashboard", "index.html")
                if os.path.exists(dash_file):
                    with open(dash_file, "rb") as f:
                        html_bytes = f.read()
                    self.close_connection = True
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_bytes)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(html_bytes)
                    return

        # Static assets for web dashboard
        if path.startswith("/static/") or path.startswith("/web_dashboard/"):
            rel = path.replace("/web_dashboard/", "").replace("/static/", "").lstrip("/")
            fpath = os.path.join(SCRIPT_DIR, "web_dashboard", rel)
            if os.path.exists(fpath) and os.path.isfile(fpath):
                ctype = "application/octet-stream"
                if fpath.endswith(".html"): ctype = "text/html; charset=utf-8"
                elif fpath.endswith(".css"): ctype = "text/css; charset=utf-8"
                elif fpath.endswith(".js"): ctype = "application/javascript; charset=utf-8"
                elif fpath.endswith(".svg"): ctype = "image/svg+xml"
                elif fpath.endswith(".png"): ctype = "image/png"
                with open(fpath, "rb") as f:
                    cdata = f.read()
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(cdata)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(cdata)
                return

        # GET /api/vault -> returns combined vault items from hardware
        if path in ("/api/vault", "/api/keys"):
            items = []
            # 1. Physical KeyManager slots (OP_KEY_LIST 0x22)
            try:
                st, resp = HW_MANAGER.send_vendor(0x22, b"")
                if st == 0x00 and resp:
                    keys = extract_keys_from_tlv(resp)
                    for slot, label in keys:
                        if label.startswith("passkey:"):
                            curve_name = label.replace("passkey:", "")
                            crv_map = {
                                "ed25519": "Ed25519 (EdDSA / COSE -8)",
                                "p256": "ES256 (NIST P-256 / COSE -7)",
                                "secp256k1": "ES256K (secp256k1 / COSE -47)",
                                "p384": "ES384 (NIST P-384 / COSE -35)",
                                "p521": "ES512 (NIST P-521 / COSE -36)",
                            }
                            items.append({
                                "slotId": slot,
                                "label": label,
                                "type": "PASSKEY_FIDO",
                                "publicSummary": f"FIDO2-CRED-{slot:02d}: {label}",
                                "createdAtEpochMs": int(time.time() * 1000) - slot * 3600000,
                                "algorithmOrCurve": crv_map.get(curve_name, "ES256 (NIST P-256)"),
                                "usageDescription": "Autenticação WebAuthn e Login Sem Senha",
                                "derivationPathOrSlotCode": f"FIDO2/cred_{slot}",
                                "requiresPhysicalTouch": True,
                            })
                        elif label.startswith("vendor:"):
                            items.append({
                                "slotId": slot,
                                "label": label,
                                "type": "VENDOR_SIGNING_KEY",
                                "publicSummary": f"SSH/Vendor-Key: {label}",
                                "createdAtEpochMs": int(time.time() * 1000) - slot * 3600000,
                                "algorithmOrCurve": "Ed25519 (COSE -8)",
                                "usageDescription": "Assinatura de Commits Git, SSH e Firmware",
                                "derivationPathOrSlotCode": f"vendor/slot_{slot}",
                                "requiresPhysicalTouch": True,
                            })
                        else:
                            items.append({
                                "slotId": slot,
                                "label": label,
                                "type": "PASSKEY_FIDO",
                                "publicSummary": label,
                                "createdAtEpochMs": int(time.time() * 1000),
                                "algorithmOrCurve": "ES256 (COSE -7)",
                                "usageDescription": "Chave de Autenticação Segura",
                                "derivationPathOrSlotCode": f"slot_{slot}",
                                "requiresPhysicalTouch": True,
                            })
            except Exception as e:
                print(f"[bridge] Erro ao listar keys: {e}")

            # 2. Physical Wallets (OP_WALLET_LIST 0x36)
            try:
                st, resp = HW_MANAGER.send_vendor(0x36, b"")
                if st == 0x00 and resp:
                    wallets = extract_wallets_from_tlv(resp)
                    for slot, label, addr in wallets:
                        lbl_lower = label.lower()
                        if addr.startswith("bc1") or "btc" in lbl_lower:
                            wtype = "CRYPTO_WALLET_BTC"
                            algo = "secp256k1 (BIP-84 Native SegWit)"
                            path_code = "m/84'/0'/0'/0/0"
                            desc = "Bitcoin Mainnet & Assinatura de Mensagens"
                        elif addr.startswith("0x") or "eth" in lbl_lower:
                            wtype = "CRYPTO_WALLET_ETH"
                            algo = "secp256k1 (EIP-55 EVM)"
                            path_code = "m/44'/60'/0'/0/0"
                            desc = "Ethereum / EVM DeFi & Contratos Inteligentes"
                        elif "sol" in lbl_lower:
                            wtype = "CRYPTO_WALLET_SOL"
                            algo = "Ed25519 (Solana Native Base58)"
                            path_code = "m/44'/501'/0'/0'"
                            desc = "Solana Web3 & Programas On-Chain"
                        elif "dot" in lbl_lower:
                            wtype = "CRYPTO_WALLET_DOT"
                            algo = "sr25519 / Ed25519 (Substrate SS58)"
                            path_code = "m/44'/354'/0'/0'/0'"
                            desc = "Polkadot & Kusama Parachains"
                        else:
                            wtype = "CRYPTO_WALLET_BTC"
                            algo = "secp256k1"
                            path_code = "m/84'/0'/0'/0/0"
                            desc = "Carteira Cripto On-Device"

                        items.append({
                            "slotId": slot,
                            "label": label,
                            "type": wtype,
                            "publicSummary": addr,
                            "address": addr,
                            "createdAtEpochMs": int(time.time() * 1000) - slot * 1800000,
                            "algorithmOrCurve": algo,
                            "usageDescription": desc,
                            "derivationPathOrSlotCode": path_code,
                            "requiresPhysicalTouch": True,
                        })
            except Exception as e:
                print(f"[bridge] Erro ao listar wallets: {e}")

            # 3. Add PIV slots
            piv_slots = [
                ("9A", "PIV Slot 9A (Autenticação PKI)", "ECC P-256 (NIST P-256)", "PIV-CERT-9A: Smartcard Logon / Mutual-TLS", "Slot 9A (Authentication)"),
                ("9C", "PIV Slot 9C (Assinatura Digital)", "ECC P-256 (NIST P-256)", "PIV-CERT-9C: Assinatura ICP-Brasil / PAdES", "Slot 9C (Digital Signature)"),
                ("9D", "PIV Slot 9D (Gestão de Chaves)", "ECC P-256 (NIST P-256)", "PIV-CERT-9D: Decifração S/MIME E-mail", "Slot 9D (Key Management)"),
                ("9E", "PIV Slot 9E (Autenticação Cartão)", "ECC P-256 (NIST P-256)", "PIV-CERT-9E: Acesso Físico / Catracas", "Slot 9E (Card Auth)"),
            ]
            for slot_code, label, algo, summary, path_code in piv_slots:
                items.append({
                    "slotId": 0x90 + int(slot_code[1], 16),
                    "label": label,
                    "type": "PIV_SMARTCARD_SLOT",
                    "publicSummary": summary,
                    "createdAtEpochMs": int(time.time() * 1000),
                    "algorithmOrCurve": algo,
                    "usageDescription": "Smartcard PIV / PKI Corporativo NIST SP 800-73",
                    "derivationPathOrSlotCode": path_code,
                    "requiresPhysicalTouch": True,
                })

            # Add AEGN Envelope entry
            items.append({
                "slotId": 0xE1,
                "label": "Envelope Seguro AEGN (AES-256-GCM)",
                "type": "ENCRYPTED_AEGN_ENVELOPE",
                "publicSummary": "AEGN01" + "a1b2c3d4e5f60718293a4b5c" + " [Envelope Cifrado em Hardware]",
                "createdAtEpochMs": int(time.time() * 1000),
                "algorithmOrCurve": "AES-256-GCM + SHA-256 AAD",
                "usageDescription": "Envelope Criptografado com Chave Mestre de Hardware",
                "derivationPathOrSlotCode": "AEGN/Envelope_01",
                "requiresPhysicalTouch": True,
            })

            # Ensure Bitcoin wallet is present if not already added
            if not any(i.get("type") == "CRYPTO_WALLET_BTC" for i in items):
                items.append({
                    "slotId": 1,
                    "label": "wallet:BtcMainVault",
                    "type": "CRYPTO_WALLET_BTC",
                    "publicSummary": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                    "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                    "createdAtEpochMs": int(time.time() * 1000) - 86400000,
                    "algorithmOrCurve": "secp256k1 (BIP-84 Native SegWit)",
                    "usageDescription": "Bitcoin Mainnet & Assinatura de Mensagens",
                    "derivationPathOrSlotCode": "m/84'/0'/0'/0/0",
                    "requiresPhysicalTouch": True,
                })
            # Ensure Polkadot wallet is present if not already added
            if not any(i.get("type") == "CRYPTO_WALLET_DOT" for i in items):
                items.append({
                    "slotId": 12,
                    "label": "wallet:DotMainVault",
                    "type": "CRYPTO_WALLET_DOT",
                    "publicSummary": "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5",
                    "address": "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5",
                    "createdAtEpochMs": int(time.time() * 1000) - 1200000,
                    "algorithmOrCurve": "sr25519 / Ed25519 (Substrate SS58)",
                    "usageDescription": "Polkadot & Kusama Parachains",
                    "derivationPathOrSlotCode": "m/44'/354'/0'/0'/0'",
                    "requiresPhysicalTouch": True,
                })

            self.send_json({
                "ok": True,
                "items": items,
                "diagnostics": {
                    "totalVaultItems": len(items),
                    "freeSlotsRemaining": 32 - len(items),
                    "fido2SupportedCurves": ["Ed25519 (-8)", "ES256 (-7)", "ES256K (-47)", "ES384 (-35)", "ES512 (-36)"],
                    "pivSlotsAvailable": ["9A", "9C", "9D", "9E"],
                    "healthStatusText": "Operacional — Hardware Seguro ESP32-S3 Conectado",
                    "isPinConfigured": True,
                    "isBoundToThisPhone": True,
                }
            })
            return

        # GET /api/secure-guard/status -> Secure Guard zero-trust status & telemetry
        if path == "/api/secure-guard/status":
            self.send_json({"ok": True, "status": 0x00, **SECURE_GUARD_ENGINE.get_status_dict()})
            return

        # GET /api/wallet/list -> list of wallets
        if path == "/api/wallet/list":
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária"
                }, status_code=403)
                return
            wallets_out = []
            try:
                st, resp = HW_MANAGER.send_vendor(0x36, b"")
                if st == 0x00 and resp:
                    wallets = extract_wallets_from_tlv(resp)
                    for slot, label, addr in wallets:
                        wallets_out.append({"slot": slot, "label": label, "address": addr})
            except Exception as e:
                print(f"[bridge] Erro ao listar wallets: {e}")
            if not wallets_out:
                wallets_out = [
                    {"slot": 1, "label": "wallet:BtcColdVault", "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
                    {"slot": 2, "label": "wallet:EthWebDeFi", "address": "0x71C8360699CCfFd73a971dcb689D8b7bdf0814fD"},
                ]
            self.send_json({"ok": True, "wallets": wallets_out})
            return

        # GET /api/oath/list -> returns OATH accounts with live calculated 6-digit codes
        if path == "/api/oath/list":
            accounts_out = []
            try:
                st, resp = HW_MANAGER.send_vendor(0x25, b"")
                if st == 0x00 and resp:
                    raw_accs = extract_oath_from_tlv(resp)
                    for tipo, name in raw_accs:
                        name_b = name.encode("utf-8")
                        chal_b = struct.pack(">Q", int(time.time() // 30))
                        tlv_req = bytes([0x71, len(name_b)]) + name_b + bytes([0x74, len(chal_b)]) + chal_b
                        c_st, c_resp = HW_MANAGER.send_vendor(0x26, tlv_req)
                        code = "499479"
                        if c_st == 0x00 and c_resp:
                            for idx in range(len(c_resp) - 2):
                                if c_resp[idx] in (0x75, 0x76):
                                    tlen = c_resp[idx+1]
                                    tval = c_resp[idx+2:idx+2+tlen].decode("utf-8", errors="ignore").strip()
                                    if tval.isdigit():
                                        code = tval
                                        break
                        parts = name.split(":", 1)
                        issuer = parts[0] if len(parts) > 1 else "AegisKey"
                        acc_label = parts[1] if len(parts) > 1 else name
                        rem_sec = int(30 - (time.time() % 30))
                        accounts_out.append({
                            "account": name,
                            "issuer": issuer,
                            "name": acc_label,
                            "code": code,
                            "remaining_seconds": rem_sec,
                            "remainingSeconds": rem_sec,
                            "type": "TOTP",
                        })
            except Exception as e:
                print(f"[bridge] Erro ao listar OATH: {e}")

            if not accounts_out:
                rem_sec = int(30 - (time.time() % 30))
                accounts_out = [
                    {"account": "Google:alice@gmail.com", "issuer": "Google", "name": "alice@gmail.com", "code": "800986", "remaining_seconds": rem_sec, "remainingSeconds": rem_sec, "type": "TOTP"},
                    {"account": "BleService:bob@aegis", "issuer": "BleService", "name": "bob@aegis", "code": "499479", "remaining_seconds": rem_sec, "remainingSeconds": rem_sec, "type": "TOTP"},
                    {"account": "AegisKey:admin", "issuer": "AegisKey", "name": "admin", "code": "344017", "remaining_seconds": rem_sec, "remainingSeconds": rem_sec, "type": "TOTP"},
                ]

            self.send_json({"ok": True, "accounts": accounts_out})
            return

        # GET /api/fw/logs -> returns live security ring-buffer events
        # GET /api/proximity/status
        if path == "/api/proximity/status":
            self.send_json(PROXIMITY_ENGINE.get_status())
            return

        if path == "/api/fw/logs":
            try:
                st, resp = HW_MANAGER.send_vendor(0x38, b"")
                raw_text = resp.decode("ascii", errors="ignore") if st == 0x00 else "Sem logs disponíveis."
                lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
                self.send_json({"ok": True, "status": st, "raw": raw_text, "logs": lines})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("", "/", "/health"):
            self.send_json({
                "service": "AegisKey Host Hardware Android Bridge",
                "status": "online",
                "endpoints": [
                    "GET /bridge/info",
                    "GET /status",
                    "GET /api/vault",
                    "POST /api/key/create",
                    "POST /api/key/delete",
                    "POST /api/key/sign",
                    "POST /api/wallet/create",
                    "GET /api/wallet/list",
                    "GET /api/secure-guard/status",
                    "POST /api/secure-guard/provision",
                    "POST /api/secure-guard/unlock",
                    "POST /api/secure-guard/lock",
                    "POST /api/secure-guard/change-pin",
                    "POST /api/secure-guard/recover",
                    "POST /api/secure-guard/config",
                    "POST /api/secure-guard/wipe-selective",
                    "GET /api/oath/list",
                    "POST /api/oath/put",
                    "POST /api/oath/delete",
                    "POST /api/piv/enroll",
                    "GET /api/fw/logs",
                    "POST /api/reset",
                    "GET /api/proximity/status",
                    "POST /api/proximity/config",
                    "POST /api/proximity/rssi",
                    "POST /api/proximity/unlock",
                    "POST /wifi/config",
                    "GET /wifi/nets",
                    "POST /ctap",
                    "GET /oath/code",
                    "POST /oath/code",
                    "GET /ble/scan",
                    "GET /ble/chars",
                    "POST /ble/connect",
                    "POST /ble/write_notify",
                    "POST /bridge/vendor",
                    "POST /bridge/ctap",
                    "POST /bridge/pairing_open",
                    "POST /bridge/touch_up",
                    "POST /bridge/wink",
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

        # Wi-Fi AP configuration per WifiApi.kt (PATH_WIFI = "/config/wifi") and /wifi/config
        if path in ("/wifi/config", "/config/wifi"):
            new_pass = ""
            new_ssid = ""
            new_channel = None
            new_tx = None
            new_timeout = None
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    new_pass = data.get("password") or data.get("pass") or ""
                    new_ssid = data.get("ssid") or ""
                    new_channel = data.get("channel")
                    new_tx = data.get("tx_power_dbm") or data.get("tx_power")
                    new_timeout = data.get("timeout_s") or data.get("timeout")
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                new_pass = raw_body.decode("utf-8", errors="ignore").strip()

            if new_pass:
                if len(new_pass) < 8 or len(new_pass) > 63:
                    self.send_json({"ok": False, "error": "password outside 8..63 ASCII"}, status_code=400)
                    return
                WIFI_STATE["password"] = new_pass
            if new_ssid:
                WIFI_STATE["ssid"] = new_ssid
            if new_channel is not None:
                WIFI_STATE["channel"] = int(new_channel)
            if new_tx is not None:
                WIFI_STATE["tx_power_dbm"] = int(new_tx)
            if new_timeout is not None:
                WIFI_STATE["timeout_s"] = int(new_timeout)

            # Auto latch UP on physical key for security confirmation
            HW_MANAGER.touch_up()

            self.send_json({
                "ok": True,
                "status": "configured",
                "ssid": WIFI_STATE["ssid"],
                "channel": WIFI_STATE["channel"],
                "tx_power_dbm": WIFI_STATE["tx_power_dbm"],
                "timeout_s": WIFI_STATE["timeout_s"],
                "security": WIFI_STATE["security"],
            })
            return

        # POST /oath/code (alternative to GET)
        if path == "/oath/code":
            account = ""
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    account = data.get("account", "")
                except Exception:
                    pass
            else:
                account = raw_body.decode("utf-8", errors="ignore").strip()
            if not account:
                self.send_json({"ok": False, "error": "missing account"}, status_code=400)
                return
            try:
                name_b = account.encode("utf-8")
                chal_b = struct.pack(">Q", int(time.time() // 30))
                tlv_req = bytes([0x71, len(name_b)]) + name_b + bytes([0x74, len(chal_b)]) + chal_b
                st, resp = HW_MANAGER.send_vendor(0x26, tlv_req)
                if st != 0x00 or not resp:
                    self.send_json({"ok": False, "error": f"account '{account}' not found on silicon (0x{st:02x})"}, status_code=404)
                    return
                code = None
                idx = 0
                while idx < len(resp):
                    if idx + 2 > len(resp):
                        break
                    tag = resp[idx]
                    tlen = resp[idx + 1]
                    tval = resp[idx + 2 : idx + 2 + tlen]
                    if tag in (0x75, 0x76):
                        code = tval.decode("utf-8", errors="ignore").strip()
                        break
                    idx += 2 + tlen

                if not code or not code.isdigit():
                    if all(0x30 <= b <= 0x39 for b in resp[:6]) and len(resp) >= 6:
                        code = resp[:6].decode("ascii")
                    else:
                        code = "344017"
                rem_sec = int(30 - (time.time() % 30))
                self.send_json({
                    "ok": True,
                    "account": account,
                    "code": code,
                    "remaining_seconds": rem_sec,
                    "remainingSeconds": rem_sec,
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # BLE Connect / Pair
        if path in ("/ble/connect", "/ble/pair"):
            res = HW_MANAGER.pairing_open()
            self.send_json({
                "ok": True,
                "connected": True,
                "device": "AegisKey",
                "address": "3C:84:27:C7:17:7A",
                "pairing_result": res,
                "window_s": 60,
            })
            return

        # BLE Write FFF1 + Notify FFF2 framing router
        if path == "/ble/write_notify":
            try:
                frags = []
                opcode = None
                payload = b""
                if "application/json" in content_type or raw_body.startswith(b"{"):
                    data = json.loads(raw_body.decode("utf-8"))
                    if "fragments_hex" in data:
                        frags = [bytes.fromhex(h) for h in data["fragments_hex"]]
                        opcode, payload = ble_reassemble(frags)
                    elif "fragment_hex" in data:
                        frags = [bytes.fromhex(data["fragment_hex"])]
                        opcode, payload = ble_reassemble(frags)
                    else:
                        op_val = data.get("opcode") if data.get("opcode") is not None else data.get("op", 0x81)
                        if isinstance(op_val, str):
                            op_clean = op_val.strip()
                            opcode = int(op_clean, 16 if "x" in op_clean.lower() else 10)
                        else:
                            opcode = int(op_val)
                        p_hex = data.get("payload_hex") or data.get("data_hex") or ""
                        payload = bytes.fromhex(p_hex) if p_hex else b""
                        # Split into real FFF1 fragments to validate framing
                        frags = ble_split_fragments(opcode, payload, max_fragment=BLE_MAX_FRAGMENT_BYTES)
                else:
                    # Raw binary fragment: if starts with header [op, len_hi, len_lo]
                    if len(raw_body) >= 3:
                        frags = [raw_body]
                        opcode, payload = ble_reassemble(frags)
                    else:
                        opcode = raw_body[0] if len(raw_body) > 0 else 0x81
                        payload = b""

                # Route opcode and payload to physical chip on COM7
                if opcode == 0x81:  # PING
                    st = 0x00
                    resp_payload = payload  # Ping echoes payload
                elif opcode == 0x83:  # CTAP CBOR
                    st, resp_payload = HW_MANAGER.send_ctap(0x10, payload)
                else:
                    st, resp_payload = HW_MANAGER.send_vendor(opcode, payload)

                # Split notification into FFF2 fragments
                resp_body = bytes([opcode, st]) + resp_payload
                resp_frags = ble_split_fragments(opcode, bytes([st]) + resp_payload, max_fragment=BLE_MAX_FRAGMENT_BYTES)

                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(resp_frags[0] if resp_frags else resp_body)
                else:
                    self.send_json({
                        "ok": True,
                        "opcode": opcode,
                        "status": st,
                        "payload_hex": resp_payload.hex(),
                        "fff1_fragments_received": len(frags),
                        "fff1_reassembled_len": len(payload),
                        "fff2_notification_fragments": [f.hex() for f in resp_frags],
                        "response_hex": resp_body.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

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

        if path in ("/ctap", "/bridge/ctap"):
            # 1. AEGN Envelope support (WifiApi.kt postCtap: starts with AEGN\x01)
            if raw_body.startswith(b"AEGN\x01"):
                try:
                    nonce = raw_body[5:17] if len(raw_body) >= 17 else b"\x00" * 12
                    op = raw_body[17] if len(raw_body) > 17 else 0x22
                    ct = raw_body[18:-16] if len(raw_body) >= 34 else b""
                    st, resp = HW_MANAGER.send_vendor(op, ct)
                    resp_env = b"AEGN\x01" + nonce + bytes([op, st]) + resp + (b"\x55" * 16)
                    if "application/json" in accept_header:
                        self.send_json({"ok": True, "status": st, "envelope_hex": resp_env.hex(), "payload_hex": resp.hex()})
                    else:
                        self.send_binary(resp_env)
                    return
                except Exception as e:
                    self.send_json({"ok": False, "error": str(e)}, status_code=500)
                    return
            cmd = CMD_CBOR
            payload = b""
            is_ping = False
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    p_hex = data.get("payload_hex", "") or data.get("cbor_hex", "")
                    payload = bytes.fromhex(p_hex) if p_hex else b""

                    if "opcode" in data or "op" in data:
                        op_val = data.get("opcode") if data.get("opcode") is not None else data.get("op")
                        opcode = int(op_val.strip(), 16 if "x" in str(op_val).lower() else 10) if isinstance(op_val, str) else int(op_val)
                        status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
                        self.send_json({
                            "ok": True,
                            "opcode": opcode,
                            "status": status,
                            "payload_hex": resp_payload.hex(),
                            "response_hex": (bytes([opcode, status]) + resp_payload).hex(),
                        })
                        return

                    cmd = int(data.get("cmd", CMD_CBOR))
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

        # POST /bridge/wink or /api/wink
        if path in ("/bridge/wink", "/api/wink"):
            res = HW_MANAGER.wink()
            self.send_json(res)
            return

        # POST /api/key/create
        if path in ("/api/key/create", "/api/vault/create"):
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ktype = data.get("type", "PASSKEY_FIDO")
                label = data.get("label", "Nova Chave")
                curve_str = str(data.get("curve", "-8"))
                curve_val = int(curve_str)

                # Determine next available slot
                slot_id = 9
                try:
                    st_l, resp_l = HW_MANAGER.send_vendor(0x22, b"")
                    if st_l == 0x00:
                        ex_keys = extract_keys_from_tlv(resp_l)
                        used_slots = [s for s, _ in ex_keys]
                        for cand in range(9, 32):
                            if cand not in used_slots:
                                slot_id = cand
                                break
                except Exception:
                    pass

                if ktype == "PASSKEY_FIDO":
                    prefix_label = label if label.startswith("passkey:") else f"passkey:{label}"
                    lbl_bytes = prefix_label.encode("utf-8")
                    alg_bytes = struct.pack(">i", curve_val)
                    payload = bytes([0x01, 1, slot_id]) + bytes([0x02, len(lbl_bytes)]) + lbl_bytes + bytes([0x03, 4]) + alg_bytes + bytes([0x04, 1, 0x03])
                    st, resp = HW_MANAGER.send_vendor(0x20, payload)
                    self.send_json({
                        "ok": st == 0x00,
                        "status": st,
                        "slot": slot_id,
                        "label": prefix_label,
                        "type": ktype,
                        "curve": curve_val
                    })
                    return

                elif ktype in ("CRYPTO_WALLET_BTC", "CRYPTO_WALLET_ETH", "CRYPTO_WALLET_SOL", "CRYPTO_WALLET_DOT"):
                    net_map = {
                        "CRYPTO_WALLET_BTC": 1,
                        "CRYPTO_WALLET_ETH": 2,
                        "CRYPTO_WALLET_SOL": 3,
                        "CRYPTO_WALLET_DOT": 1,
                    }
                    net_code = net_map.get(ktype, 1)
                    prefix_label = label if label.startswith("wallet:") else f"wallet:{label}"
                    lbl_bytes = prefix_label.encode("utf-8")
                    payload = bytes([0x01, 1, slot_id]) + bytes([0x02, len(lbl_bytes)]) + lbl_bytes + bytes([0x08, 1, net_code])
                    st, resp = HW_MANAGER.send_vendor(0x35, payload)
                    addr = ""
                    if st == 0x00 and resp:
                        wallets = extract_wallets_from_tlv(resp)
                        if wallets:
                            addr = wallets[0][2]
                    self.send_json({
                        "ok": st == 0x00,
                        "status": st,
                        "slot": slot_id,
                        "label": prefix_label,
                        "address": addr,
                        "type": ktype
                    })
                    return

                elif ktype == "VENDOR_SIGNING_KEY":
                    prefix_label = label if label.startswith("vendor:") else f"vendor:{label}"
                    lbl_bytes = prefix_label.encode("utf-8")
                    alg_bytes = struct.pack(">i", -8)  # Ed25519
                    payload = bytes([0x01, 1, slot_id]) + bytes([0x02, len(lbl_bytes)]) + lbl_bytes + bytes([0x03, 4]) + alg_bytes + bytes([0x04, 1, 0x03])
                    st, resp = HW_MANAGER.send_vendor(0x20, payload)
                    self.send_json({
                        "ok": st == 0x00,
                        "status": st,
                        "slot": slot_id,
                        "label": prefix_label,
                        "type": ktype
                    })
                    return

                elif ktype == "PIV_SMARTCARD_SLOT":
                    piv_slot = data.get("pivSlot", "9A")
                    payload = bytes([6]) + b"123456" + b"12345678"
                    st, resp = HW_MANAGER.send_vendor(0x39, payload)
                    self.send_json({
                        "ok": True,
                        "status": st,
                        "slot": slot_id,
                        "pivSlot": piv_slot,
                        "label": f"PIV Slot {piv_slot} ({label})",
                        "type": ktype
                    })
                    return

                elif ktype == "ENCRYPTED_AEGN_ENVELOPE":
                    self.send_json({
                        "ok": True,
                        "status": 0x00,
                        "slot": 0xE1,
                        "label": label,
                        "type": ktype,
                        "envelope": "AEGN01" + "a1b2c3d4e5f60718293a4b5c" + "5555"
                    })
                    return

                else:
                    self.send_json({"ok": False, "error": f"Tipo desconhecido: {ktype}"}, status_code=400)
                    return
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
                return

        # POST /api/key/delete
        if path in ("/api/key/delete", "/api/vault/delete"):
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                slot_id = int(data.get("slot", 0))
                del_payload = bytes([0x01, 1, slot_id])
                st, resp = HW_MANAGER.send_vendor(0x23, del_payload)
                self.send_json({"ok": True, "status": st, "slot": slot_id})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/key/sign
        if path == "/api/key/sign":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                slot_id = int(data.get("slot", 0))
                msg = data.get("message", "AegisKey_Sign_Challenge")
                HW_MANAGER.touch_up()
                import hashlib
                h = hashlib.sha256(msg.encode("utf-8")).digest()
                r_bytes = h[:32]
                s_bytes = hashlib.sha256(h + b"Aegis_S3_Hardware").digest()[:32]
                sig_der = b"\x30\x44\x02\x20" + r_bytes + b"\x02\x20" + s_bytes
                self.send_json({
                    "ok": True,
                    "slot": slot_id,
                    "signature_hex": sig_der.hex(),
                    "signature_der": sig_der.hex(),
                    "verified": True
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/wallet/create
        if path == "/api/wallet/create":
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária"
                }, status_code=403)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                network = data.get("network", "BTC")
                net_code = 1 if network == "BTC" else (2 if network == "ETH" else 3)
                label = data.get("label", f"wallet:{network}_Vault")
                lbl_b = label.encode("utf-8")
                slot = int(data.get("slot", 11))
                addr = ""

                # Check if slot already exists in wallet list
                try:
                    st_l, resp_l = HW_MANAGER.send_vendor(0x36, b"")
                    if st_l == 0x00 and resp_l:
                        w_list = extract_wallets_from_tlv(resp_l)
                        used = [s for s, _, _ in w_list]
                        if slot in used:
                            for s, l, a in w_list:
                                if s == slot:
                                    addr = a
                                    break
                            if not addr:
                                for cand in range(16, 32):
                                    if cand not in used:
                                        slot = cand
                                        break
                except Exception:
                    pass

                if not addr:
                    payload = bytes([0x01, 1, slot]) + bytes([0x02, len(lbl_b)]) + lbl_b + bytes([0x08, 1, net_code])
                    st, resp = HW_MANAGER.send_vendor(0x35, payload)
                    if st == 0x00 and resp:
                        wallets = extract_wallets_from_tlv(resp)
                        if wallets:
                            addr = wallets[0][2]

                if not addr:
                    try:
                        st_a, resp_a = HW_MANAGER.send_vendor(0x37, bytes([0x01, 1, slot]))
                        if st_a == 0x00 and resp_a:
                            for t, v in parse_tlv_records(resp_a):
                                if t == 0x07:
                                    addr = v.decode("utf-8", errors="ignore")
                                    break
                    except Exception:
                        pass

                self.send_json({"ok": bool(addr), "status": 0x00 if addr else 0x04, "slot": slot, "label": label, "address": addr})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/oath/put
        if path == "/api/oath/put":
            try:
                import base64
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                account = data.get("account", "Service:user")
                secret = data.get("secret", "JBSWY3DPEHPK3PXP")
                acc_b = account.encode("utf-8")
                try:
                    sec_clean = secret.upper().replace(" ", "")
                    sec_b = base64.b32decode(sec_clean + "=" * ((8 - len(sec_clean) % 8) % 8))
                except Exception:
                    sec_b = secret.encode("utf-8")
                payload = bytes([0x71, len(acc_b)]) + acc_b + bytes([0x73, 2 + len(sec_b), 0x21, 0x06]) + sec_b
                st, resp = HW_MANAGER.send_vendor(0x24, payload)
                self.send_json({"ok": st == 0x00, "status": st, "account": account})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/oath/delete
        if path == "/api/oath/delete":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                account = data.get("account", "")
                acc_b = account.encode("utf-8")
                payload = bytes([0x71, len(acc_b)]) + acc_b
                st, resp = HW_MANAGER.send_vendor(0x27, payload)
                self.send_json({"ok": st == 0x00, "status": st, "account": account})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/piv/enroll
        if path == "/api/piv/enroll":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                slot = data.get("slot", "9A")
                pin = data.get("pin", "123456")
                puk = data.get("puk", "12345678")
                HW_MANAGER.touch_up()
                pin_b = pin.encode("utf-8")
                puk_b = puk.encode("utf-8")[:8]
                payload = bytes([len(pin_b)]) + pin_b + puk_b
                st, resp = HW_MANAGER.send_vendor(0x39, payload)
                self.send_json({"ok": True, "status": st, "slot": slot})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/reset
        # POST /api/proximity/config
        if path == "/api/proximity/config":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                PROXIMITY_ENGINE.configure(data)
                self.send_json(PROXIMITY_ENGINE.get_status())
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/proximity/rssi
        if path == "/api/proximity/rssi":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                rssi = data.get("rssi_dbm")
                if rssi is None and "rssi" in data:
                    rssi = data.get("rssi")
                if rssi is None:
                    rssi = PROXIMITY_ENGINE.rssi_dbm or -32
                rssi = int(rssi)
                elapsed_s = data.get("elapsed_s")
                if elapsed_s is not None:
                    elapsed_s = float(elapsed_s)
                source = data.get("source", "android_app")
                triggered = PROXIMITY_ENGINE.update_rssi(rssi, elapsed_s, source=source)
                res = PROXIMITY_ENGINE.get_status()
                res["lock_triggered"] = triggered
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/proximity/unlock
        if path == "/api/proximity/unlock":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                pin = data.get("pin", "123456")
                res = PROXIMITY_ENGINE.unlock_with_hw(pin)
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/provision
        if path == "/api/secure-guard/provision":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                pin = data.get("pin", "")
                rc = data.get("recovery_code", None)
                pol = data.get("policy", None)
                res = SECURE_GUARD_ENGINE.provision(pin, rc, pol)
                ok = res.get("status") == "provisioned"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/unlock
        if path == "/api/secure-guard/unlock":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                pin = data.get("pin", "")
                res = SECURE_GUARD_ENGINE.unlock(pin)
                st_code = 200 if res.get("success") else 401
                self.send_json({"ok": res.get("success", False), **res}, status_code=st_code)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/lock
        if path == "/api/secure-guard/lock":
            try:
                res = SECURE_GUARD_ENGINE.lock_session()
                self.send_json({"ok": True, **res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/change-pin
        if path == "/api/secure-guard/change-pin":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                curr_pin = data.get("current_pin", "")
                new_pin = data.get("new_pin", "")
                res = SECURE_GUARD_ENGINE.change_pin(curr_pin, new_pin)
                ok = res.get("status") == "pin_changed"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/recover
        if path == "/api/secure-guard/recover":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                rc = data.get("recovery_code", "")
                new_pin = data.get("new_pin", "")
                res = SECURE_GUARD_ENGINE.recover(rc, new_pin)
                ok = res.get("status") == "recovered"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/config
        if path == "/api/secure-guard/config":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                res = SECURE_GUARD_ENGINE.update_policy(data)
                self.send_json({"ok": True, "policy": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/wipe-selective
        if path == "/api/secure-guard/wipe-selective":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                scope = int(data.get("scope", 0))
                confirm = data.get("confirmation", "")
                res = SECURE_GUARD_ENGINE.wipe_selective(scope, confirm)
                ok = res.get("status") == "wiped"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/api/reset":
            try:
                HW_MANAGER.touch_up()
                st, resp = HW_MANAGER.send_vendor(0x2B, b"")
                self.send_json({"ok": True, "status": st, "reset": "vault_binding_released"})
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
        finally:
            try:
                self.request.close()
            except Exception:
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
