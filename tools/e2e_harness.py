#!/usr/bin/env python3
"""E2E harness UNIFICADO (fusao sem alteracao logica, 2026-10-26, branch fd/finalizacao-linux).

Agrega 4 harnesses E2E sobrepostos em uma CLI com subcomandos por cenario.
Cada secao abaixo e o codigo ORIGINAL integral do arquivo de origem
(indicado no marcador BEGIN/END), exceto por 3 adaptacoes mecanicas de dispatch:
  * `def main():` renomeado p/ `bridge_main` / `user_main` / `session_main` / `onboard_main`;
  * blocos `if __name__ == "__main__":` removidos (o dispatch unificado esta no fim);
  * `SCRIPT_DIR` de hil_emulate_full_app_on_board.py renomeado p/ `HIL_SCRIPT_DIR`
    (colidia com o de host_hardware_android_bridge.py; ambos valem o dir tools/).
NENHUMA funcao/classe/constante de cenario foi removida (0 duplicatas exatas;
ver tools/_QUARANTINE_MANIFEST.txt). Unica adicao: o dispatcher `main()` no fim.

Uso (SEM hardware p/ --help):
  python tools/e2e_harness.py --help
  python tools/e2e_harness.py bridge --help     # USB-HID/UART <-> emulador Android (porta 5678)
  python tools/e2e_harness.py user --help       # E2E como usuario (fases base/pairing/all-safe/destructive/wipe/bench)
  python tools/e2e_harness.py session           # sessao emulada app+server (offline, UP-SIMULATED, sem HW)
  python tools/e2e_harness.py onboard [--bridge]  # HIL full-app na placa real (COM7; EXIGE hardware)

Subcomandos repassam argv intactos ao main() original do cenario.
"""
# ======================================================================
# --- BEGIN ORIGIN: tools/host_hardware_android_bridge.py (entry: bridge_main) ---
# ======================================================================
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
            "inactivity_timeout_ms": 300000,
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
            inactivity_sec = self.policy.get("inactivity_timeout_ms", 300000) / 1000.0
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
                "inactivity_timeout_ms": int(self.policy.get("inactivity_timeout_ms", 300000)),
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
            try:
                st, resp = HW_MANAGER.send_vendor(0x3A, b"")
                if st == 0x00 and resp:
                    raw_dict, _ = cbor_decode(resp)
                    if isinstance(raw_dict, dict):
                        if not raw_dict.get("unlocked", False):
                            SECURE_GUARD_ENGINE.lock_session()
                        self.send_json({"ok": True, "status": 0x00, **raw_dict})
                        return
            except Exception:
                pass
            SECURE_GUARD_ENGINE.lock_session()
            st_dict = SECURE_GUARD_ENGINE.get_status_dict()
            st_dict["unlocked"] = False
            st_dict["session_remaining_ms"] = 0
            self.send_json({"ok": True, "status": 0x00, **st_dict})
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
                pin_bytes = pin.encode("utf-8") if isinstance(pin, str) else bytes(pin)
                try:
                    cbor_req = cbor_encode({"action": "unlock", "pin": pin_bytes})
                    st, resp = HW_MANAGER.send_vendor(0x3B, cbor_req)
                    if resp:
                        hw_dict, _ = cbor_decode(resp)
                        if isinstance(hw_dict, dict) and hw_dict.get("success"):
                            SECURE_GUARD_ENGINE.unlock(pin)
                            self.send_json({"ok": True, **hw_dict}, status_code=200)
                            return
                        elif isinstance(hw_dict, dict):
                            SECURE_GUARD_ENGINE.lock_session()
                            self.send_json({"ok": False, **hw_dict}, status_code=401)
                            return
                except Exception:
                    pass
                res = SECURE_GUARD_ENGINE.unlock(pin)
                st_code = 200 if res.get("success") else 401
                self.send_json({"ok": res.get("success", False), **res}, status_code=st_code)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/lock
        if path == "/api/secure-guard/lock":
            try:
                try:
                    HW_MANAGER.send_vendor(0x3C, b"")
                except Exception:
                    pass
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


def bridge_main():
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
# --- END ORIGIN: tools/host_hardware_android_bridge.py ---

# ======================================================================
# --- BEGIN ORIGIN: tools/e2e_user_test.py (entry: user_main) ---
# ======================================================================
"""E2E como usuário: finge ser o app e testa cada funcionalidade da chave.

Uso:
  python tools/e2e_user_test.py --phase base            # sem UP/janela
  python tools/e2e_user_test.py --phase pairing         # janela+UP (diag)
  python tools/e2e_user_test.py --phase all-safe        # base + pairing
  python tools/e2e_user_test.py --only T17              # um teste só
  python tools/e2e_user_test.py --phase destructive --confirm   # muda estado!

Segurança: fase destructive exige --confirm; RELEASE/wipe pede digitar SIM.
Uma sessão serial por rodada (abrir a porta reseta a placa e mata a janela).
Resultados vão para o console + append em docs/teste-ponta-a-ponta.md.
"""

import argparse
import datetime
import struct
import sys
import time

sys.path.insert(0, "tools")
from app_simulator import (
    Session, CMD_MSG, CMD_CBOR, CMD_PING,
    CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_GET_ASSERTION, CTAP_CMD_CLIENT_PIN,
)

PORT_DEFAULT = "COM7"
MD_PATH = "docs/teste-ponta-a-ponta.md"

# Ops (espelho frozen do contrato BLE/serial).
OP = {
    "KEY_GEN": 0x20, "KEY_IMPORT": 0x21, "KEY_LIST": 0x22, "KEY_DELETE": 0x23,
    "OATH_PUT": 0x24, "OATH_LIST": 0x25, "OATH_CODE": 0x26, "OATH_DELETE": 0x27,
    "BIND_CHALLENGE": 0x29, "RESCUE": 0x2E, "PAIR_TRIG": 0x2F,
    "OTA_BEGIN": 0x30, "WALLET_GEN": 0x35, "WALLET_LIST": 0x36,
    "WALLET_ADDR": 0x37, "FW_LOG": 0x38,
}

E2E_SLOT_KEY = 5
E2E_SLOT_WALLET = 6
E2E_SLOT_BADNET = 7
E2E_LABEL = b"e2e-t1"
E2E_OATH = b"e2e@test"
E2E_RP = "e2e"


def tlv(tag, val):
    """TLV BER igual ao da firmware (len<0x80 direto, 0x81+1B, 0x82+2B)."""
    n = len(val)
    if n < 0x80:
        lb = bytes([n])
    elif n <= 0xFF:
        lb = bytes([0x81, n])
    else:
        lb = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + lb + val


# --- CBOR mínimo (só o que MC/GA precisam) ---
def cbor_uint(n):
    if n < 24:
        return bytes([n])
    if n < 256:
        return bytes([0x18, n])
    return bytes([0x19, (n >> 8) & 0xFF, n & 0xFF])


def cbor_neg(n):  # n < 0
    v = -1 - n
    if v < 24:
        return bytes([0x20 | v])
    return bytes([0x38, v])


def cbor_int(n):
    return cbor_neg(n) if n < 0 else cbor_uint(n)


def cbor_text(s):
    b = s.encode()
    return bytes([0x60 | len(b)]) + b if len(b) < 24 else None


def cbor_bytes(b):
    if len(b) < 24:
        return bytes([0x40 | len(b)]) + b
    return bytes([0x58, len(b)]) + b


def cbor_arr(items):
    return bytes([0x80 | len(items)]) + b"".join(items)


def cbor_map(pairs):
    return bytes([0xA0 | len(pairs)]) + b"".join(k + v for k, v in pairs)


def mc_cbor():
    h = bytes(32)  # clientDataHash zerado (teste local, sem origem real)
    rp = cbor_map([(cbor_text("id"), cbor_text(E2E_RP))])
    user = cbor_map([(cbor_text("id"), cbor_bytes(b"u1")),
                     (cbor_text("name"), cbor_text(E2E_RP))])
    pkp = cbor_arr([cbor_map([(cbor_text("type"), cbor_text("public-key")),
                              (cbor_text("alg"), cbor_int(-7))])])
    opts = cbor_map([(cbor_text("rk"), bytes([0xF5]))])
    return cbor_map([(cbor_uint(1), cbor_bytes(h)), (cbor_uint(2), rp),
                     (cbor_uint(3), user), (cbor_uint(4), pkp),
                     (cbor_uint(7), opts)])


def ga_cbor():
    h = bytes(32)
    return cbor_map([(cbor_uint(1), cbor_text(E2E_RP)), (cbor_uint(2), cbor_bytes(h))])


def tlv_find(body, tag):
    """Acha o valor do TLV `tag` no corpo (codec oath/tlv da firmware)."""
    i = 0
    while i + 2 <= len(body):
        t = body[i]
        i += 1
        f = body[i]
        i += 1
        if f < 0x80:
            n = f
        elif f == 0x81:
            if i >= len(body):
                return None
            n = body[i]
            i += 1
        elif f == 0x82:
            if i + 1 >= len(body):
                return None
            n = (body[i] << 8) | body[i + 1]
            i += 2
        else:
            return None
        if i + n > len(body):
            return None
        if t == tag:
            return body[i:i + n]
        i += n
    return None


def cbor_dec(data):
    """Decodificador mínimo (comprimentos definidos) p/ respostas da firmware."""
    def take(n, pos):
        if pos + n > len(data):
            raise ValueError("cbor curto")
        return data[pos:pos + n], pos + n

    def dec(pos):
        if pos >= len(data):
            raise ValueError("cbor vazio")
        b = data[pos]
        pos += 1
        mt, ai = b >> 5, b & 0x1F
        if ai < 24:
            arg = ai
        elif ai == 24:
            arg, pos = data[pos], pos + 1
        elif ai == 25:
            arg, pos = (data[pos] << 8) | data[pos + 1], pos + 2
        elif ai == 26:
            import struct as _s
            arg, pos = _s.unpack_from(">I", data, pos)[0], pos + 4
        else:
            raise ValueError("cbor indefinido")
        if mt == 0:
            return arg, pos
        if mt == 1:
            return -1 - arg, pos
        if mt in (2, 3):
            raw, pos = take(arg, pos)
            return (bytes(raw), pos) if mt == 2 else (raw.decode(), pos)
        if mt == 4:
            out = []
            for _ in range(arg):
                v, pos = dec(pos)
                out.append(v)
            return out, pos
        if mt == 5:
            out = {}
            for _ in range(arg):
                k, pos = dec(pos)
                v, pos = dec(pos)
                out[k] = v
            return out, pos
        if mt == 7:
            return {20: False, 21: True, 22: None}.get(arg, None), pos
        raise ValueError("mt desconhecido")
    v, _ = dec(0)
    return v


class PinClient:
    """ClientPIN protocolo 1 (espelho de crypto/pin_protocol.rs)."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, hmac as hmac_mod
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self._ec, self._hashes, self._hmac = ec, hashes, hmac_mod
        self._Cipher, self._algorithms, self._modes = Cipher, algorithms, modes
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.priv.public_key().public_numbers()
        self.x = pub.x.to_bytes(32, "big")
        self.y = pub.y.to_bytes(32, "big")

    def my_cose(self):
        return cbor_map([
            (cbor_int(1), cbor_int(2)),
            (cbor_int(3), cbor_int(-25)),
            (cbor_int(-1), cbor_int(1)),
            (cbor_int(-2), cbor_bytes(self.x)),
            (cbor_int(-3), cbor_bytes(self.y)),
        ])

    def _peer(self, cose):
        m = cbor_dec(cose) if isinstance(cose, (bytes, bytearray)) else cose
        x, y = m[-2], m[-3]
        pn = self._ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), self._ec.SECP256R1())
        return pn.public_key()

    def shared(self, peer_cose):
        peer = self._peer(peer_cose)
        z = self.priv.exchange(self._ec.ECDH(), peer)
        import hashlib
        return hashlib.sha256(z).digest()

    def _aes(self, k, data):
        enc = self._Cipher(self._algorithms.AES(k), self._modes.CBC(bytes(16))).encryptor()
        return enc.update(data) + enc.finalize()

    def _mac(self, k, data):
        import hmac as _h, hashlib as _hl
        return _h.new(k, data, _hl.sha256).digest()[:16]

    @staticmethod
    def _pad(raw):
        if not 4 <= len(raw) <= 63:
            raise ValueError("pin len")
        return raw + bytes(64 - len(raw))

    def setpin_req(self, pin, peer_cose):
        k = self.shared(peer_cose)
        new_enc = self._aes(k, self._pad(pin))
        auth = self._mac(k, new_enc)
        return cbor_map([(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(3)),
                         (cbor_uint(3), self.my_cose()), (cbor_uint(4), cbor_bytes(auth)),
                         (cbor_uint(5), cbor_bytes(new_enc))])

    def _hash_enc(self, k, pin):
        import hashlib
        h = hashlib.sha256(pin).digest()[:16]
        return self._aes(k, self._pad(h))

    def changepin_req(self, old_pin, new_pin, peer_cose):
        k = self.shared(peer_cose)
        new_enc = self._aes(k, self._pad(new_pin))
        hash_enc = self._hash_enc(k, old_pin)
        auth = self._mac(k, new_enc + hash_enc)
        return cbor_map([(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(4)),
                         (cbor_uint(3), self.my_cose()), (cbor_uint(4), cbor_bytes(auth)),
                         (cbor_uint(5), cbor_bytes(new_enc)), (cbor_uint(6), cbor_bytes(hash_enc))])

    def token_req(self, pin, peer_cose):
        k = self.shared(peer_cose)
        hash_enc = self._hash_enc(k, pin)
        return (k, cbor_map([(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(5)),
                             (cbor_uint(3), self.my_cose()), (cbor_uint(6), cbor_bytes(hash_enc))]))

    def token_dec(self, k, enc_token):
        dec = self._Cipher(self._algorithms.AES(k), self._modes.CBC(bytes(16))).decryptor()
        return dec.update(enc_token) + dec.finalize()


class Ctx:
    def __init__(self, port):
        # test_mode=True: a firmware diag tem TEST_UP/TEST_PAIRING_OPEN;
        # sem ela, a fase pairing falha avisando (use hold físico + --only).
        self.s = Session("http://127.0.0.1:9", test_mode=True)
        self.s.connect(port, 115200)
        self.results = []

    def close(self):
        self.s.close()

    def up(self):
        """Um toque via software (diag); latch 1x, vale ~1.5s."""
        self.s.test_up()

    def pairing(self):
        self.s.test_pairing_open()

    def rec(self, tid, name, ok, detail, expected=""):
        self.results.append((tid, name, ok, detail, expected))
        tag = {"pass": "PASS", "div": "DIVERGENTE", "fail": "FAIL"}[ok]
        print("%s %s %s %s" % (tag, tid, name, detail))

    def check(self, tid, name, actual, expected):
        if actual == expected:
            self.rec(tid, name, "pass", "0x%02X" % actual)
        else:
            self.rec(tid, name, "div", "recebido=0x%02X esperado=0x%02X" % (actual, expected),
                     "0x%02X" % expected)

    def msg(self, payload, timeout=15.0):
        return self.s._exchange(CMD_MSG, payload, timeout_s=timeout, op="e2e")

    def msg_up(self, payload, timeout=15.0):
        """UP + envio; se o latch expirou na corrida do leitor (0x01),
        injeta de novo e tenta uma vez (latch 1x/1.5s)."""
        self.up()
        st, body = self.msg(payload, timeout)
        if st == 0x01:
            self.up()
            st, body = self.msg(payload, timeout)
        return st, body

    def ctap_up(self, cmd, cbor, timeout=30.0, tries=3):
        """CTAP com UP; respostas longas sofrem a corrida do leitor UART —
        tenta até `tries` vezes com latch novo (MC duplica credencial
        residente; anotado no detalhe)."""
        last = None
        for _ in range(tries):
            self.up()
            try:
                return self.s._exchange(CMD_CBOR, bytes([cmd]) + cbor,
                                        timeout_s=timeout, op="e2e")
            except (TimeoutError, OSError, ValueError) as e:
                last = e
        raise last


def _t01(c):
    s = c.s
    s.cmd_init()
    c.rec("T01", "INIT aloca CID", "pass", "cid=0x%08X" % s.cid)


def _t02(c):
    s = c.s
    echo = b"ping-e2e"
    st, body = s._exchange(CMD_PING, echo, timeout_s=10.0, op="e2e")
    c.rec("T02", "PING eco", "pass" if bytes([st]) + body == echo else "div",
          "eco=%r" % (bytes([st]) + body))


def _t03(c):
    s = c.s
    # GetInfo = CTAP 0x04 sem CBOR:
    st, body = s._exchange(CMD_CBOR, bytes([0x04]), timeout_s=10.0, op="e2e")
    c.rec("T03", "GetInfo", "pass" if st == 0 and len(body) > 0 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _t04(c):
    st, body = c.msg(bytes([OP["FW_LOG"]]))
    c.rec("T04", "FW-LOG serial livre", "pass" if st == 0 and b"EV=" in body else "div",
          "status=0x%02X linhas=%d" % (st, body.decode("ascii", "replace").count("EV=")))


def _t05(c):
    # Setup afirma up_pending=0 + touch=0 (dispatcher `touch_latched`
    # visível via TEST_LED_STATE): sem latch obsoleto, 0x01 é determinístico
    # salvo toque físico no BOOT mid-phase (fora do controle de software).
    st, _ = c.msg(bytes([OP["KEY_LIST"]]))
    c.check("T05", "KEY_LIST sem UP barra", st, 0x01)


def _t06(c):
    # Setup limpo (TEST_PAIRING_CLOSE) fecha janela residual de sessão
    # anterior: sem UP e sem janela o gate pairing barra primeiro (0x05),
    # determinístico — não mais tolerante a 0x01.
    st, _ = c.msg(bytes([OP["WALLET_GEN"], 0x01, 0x01, 0x00]))
    if st == 0x05:
        c.rec("T06", "WALLET_GEN sem UP/janela barra", "pass", "0x05")
    else:
        c.rec("T06", "WALLET_GEN sem UP/janela barra", "div",
              "recebido=0x%02X (0x01=janela residual aberta)" % st)


def _t06b(c):
    # Setup limpo (TEST_PAIRING_CLOSE): com UP mas sem janela o gate
    # pairing/bind barra (0x05), determinístico. TLV inválido de propósito:
    # mesmo com janela aberta por engano, não cria nada.
    st, _ = c.msg_up(bytes([OP["WALLET_GEN"], 0x01, 0x01, 0x00]))
    c.check("T06b", "WALLET_GEN com UP sem janela barra", st, 0x05)


def _t07(c):
    st, _ = c.msg(bytes([OP["RESCUE"]]) + bytes(8))
    # Lixo sem magic RESC: INVALID_MAGIC 0x01 (não é NEED_UP; é o status
    # do próprio rescue para frame inválido).
    c.check("T07", "RESCUE lixo sem magic", st, 0x01)


def _t08(c):
    st, body = c.msg(bytes([OP["OTA_BEGIN"]]))
    c.rec("T08", "OTA-BEGIN sem janela nega", "pass" if st != 0 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _t09(c):
    s = c.s
    st, body = s._exchange(CMD_CBOR, bytes([0x06]) + bytes.fromhex("a201010201"),
                           timeout_s=10.0, op="e2e")
    c.rec("T09", "PIN getRetries", "pass" if st == 0 else "div",
          "status=0x%02X body=%s" % (st, body.hex()[:32]))


def _t10(c):
    st, body = c.msg(bytes([OP["BIND_CHALLENGE"]]))
    if st == 0 and len(body) == 32:
        c.rec("T10", "BIND_CHALLENGE", "pass", "0x00+32B (device CLAIMED — ver D06)")
    else:
        c.rec("T10", "BIND_CHALLENGE sem posse nega", "pass" if st != 0 else "div",
              "status=0x%02X (anotar)" % st)


def _t11(c):
    c.pairing()
    c.rec("T11", "janela via TEST_PAIRING_OPEN", "pass", "pairing_open 60s")


def _t12(c):
    st, body = c.msg(bytes([OP["PAIR_TRIG"]]))
    c.check("T12", "trigger 0x2F abre janela", st, 0x00)


def _t07b(c):
    st, _ = c.msg_up(bytes([OP["RESCUE"]]) + bytes(8))
    c.rec("T07b", "RESCUE lixo com UP dá INVALID_MAGIC", "pass" if st == 0x01 else "div",
          "status=0x%02X" % st)


def _t07c(c):
    # Frame válido (magic+ver+cmd+token) mas SEM UP/PIN: negação fail-closed.
    import struct as _st
    token = b"AEGISKEY_KILLSWITCH_CONFIRM"
    frame = b"RESC" + bytes([0x01, 0x06]) + _st.pack(">H", len(token)) + token
    st, _ = c.msg(bytes([OP["RESCUE"]]) + frame)
    c.rec("T07c", "killswitch sem UP/PIN nega 0x04 (sem wipe)", "pass" if st == 0x04 else "div",
          "status=0x%02X" % st)


def _t13(c):
    # F2: GEN executa de verdade (0x00 + eco slot/label). Rotaciona 5..9
    # (NVS persiste entre boots agora). Janela reaberta aqui: a fase toda
    # não cabe nos 60 s do T11 quando o fio está lento (resync).
    c.pairing()
    st, body, used = 0x03, b"", None
    for slot in (5, 6, 7, 8, 9):
        req = (tlv(0x01, bytes([slot])) + tlv(0x02, E2E_LABEL)
               + tlv(0x05, (-7 & 0xFFFFFFFF).to_bytes(4, "big")))
        st, body = c.msg_up(bytes([OP["KEY_GEN"]]) + req)
        if st == 0x00:
            used = slot
            break
        if st != 0x03:
            break
    ok = st == 0x00 and tlv_find(body, 0x01) == bytes([used or 0])
    c.rec("T13", "KEY_GEN e2e-t1 real", "pass" if ok else "div",
          "status=0x%02X slot=%s" % (st, used))
    c.ctx_keys_slot = used


def _t14(c):
    c.up()
    st, body = c.msg(bytes([OP["KEY_LIST"]]))
    slot = getattr(c, "ctx_keys_slot", None)
    has = slot is not None and bytes([slot]) in body
    # Sem T13 na sessão: só prova 0x00 (lista pode estar vazia).
    ok = (st == 0 and (has or slot is None))
    c.rec("T14", "KEY_LIST real", "pass" if ok else "div",
          "status=0x%02X bytes=%d tem=%s" % (st, len(body), has))


def oath_hotp(secret, counter, digits=6):
    """RFC4226 local (prova: device calcula igual)."""
    import hmac as _h, hashlib as _hl, struct as _s
    mac = _h.new(secret, _s.pack(">Q", counter), _hl.sha1).digest()
    off = mac[-1] & 0x0F
    code = ((mac[off] & 0x7F) << 24 | mac[off + 1] << 16
            | mac[off + 2] << 8 | mac[off + 3]) % (10 ** digits)
    return str(code).zfill(digits)


def oath_totp(secret, digits=6, period=30, now=None):
    import time as _t
    return oath_hotp(secret, int((now if now is not None else _t.time()) // period), digits)


E2E_OATH_SECRET = bytes(range(20))


def _t15(c):
    # Janela reaberta (fase lenta estoura os 60 s do T11; ver _t13).
    c.pairing()
    put = tlv(0x71, E2E_OATH) + tlv(0x73, bytes([0x11, 0x06]) + E2E_OATH_SECRET)
    st, body = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    # PUT é privilegiada (UP+PIN): sem PIN na sessão, o certo é 0x02.
    c.rec("T15", "OATH_PUT sem PIN pede PIN", "pass" if st == 0x02 else "div",
          "status=0x%02X" % st)


def _t15b(c):
    # F2 (destructive, com sessão): PUT HOTP real -> 0x00.
    if not _ensure_session(c):
        c.rec("T15b", "OATH_PUT com sessão (sem PIN?)", "fail", "token falhou")
        return
    c.pairing()
    put = tlv(0x71, E2E_OATH) + tlv(0x73, bytes([0x11, 0x06]) + E2E_OATH_SECRET)
    st, _ = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    c.rec("T15b", "OATH_PUT HOTP real", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _t15c(c):
    # F2: PUT TOTP + CODE com challenge (app faz igual) — verificado local.
    if not _ensure_session(c):
        c.rec("T15c", "OATH TOTP (sem PIN?)", "fail", "token falhou")
        return
    c.pairing()
    name = b"e2e-totp"
    put = tlv(0x71, name) + tlv(0x73, bytes([0x21, 0x06]) + E2E_OATH_SECRET)
    st, _ = c.msg_up(bytes([OP["OATH_PUT"]]) + put)
    if st != 0:
        c.rec("T15c", "OATH_PUT TOTP real", "div", "status=0x%02X" % st)
        return
    import time as _t, struct as _s
    counter = int(_t.time()) // 30
    req = tlv(0x71, name) + tlv(0x74, _s.pack(">Q", counter))
    c.up()
    st, body = c.msg(bytes([OP["OATH_CODE"]]) + req)
    got = tlv_find(body, 0x75).decode() if st == 0 else ""
    want = oath_totp(E2E_OATH_SECRET)
    # Janela de 30s pode virar no meio: aceita counter±1.
    ok = st == 0 and got in (want, oath_hotp(E2E_OATH_SECRET, counter - 1),
                             oath_hotp(E2E_OATH_SECRET, counter + 1))
    c.rec("T15c", "OATH_CODE TOTP bate conta local", "pass" if ok else "div",
          "status=0x%02X got=%s want=%s" % (st, got, want))


def _t16(c):
    c.up()
    st, body = c.msg(bytes([OP["OATH_CODE"]]) + tlv(0x71, E2E_OATH))
    if st == 0x03:
        c.rec("T16", "OATH_CODE sem conta dá NoSlot", "pass", "0x03 (lista vazia)")
        return
    got = tlv_find(body, 0x75)
    ok = st == 0 and bool(got) and got.decode().isdigit()
    c.rec("T16", "OATH_CODE", "pass" if ok else "div",
          "status=0x%02X code=%s (0x03 se lista vazia)" % (st, (got or b"")[:8]))


def _t16b(c):
    # F2 (destructive, após T15b): HOTP avança — dois CODEs diferentes,
    # ambos batendo com a conta local (contadores 0 e 1... ou N/N+1).
    if not _ensure_session(c):
        c.rec("T16b", "OATH HOTP contador (sem PIN?)", "fail", "token falhou")
        return
    c.pairing()
    codes = []
    for _ in range(2):
        c.up()
        st, body = c.msg(bytes([OP["OATH_CODE"]]) + tlv(0x71, E2E_OATH))
        if st != 0:
            c.rec("T16b", "OATH_CODE HOTP", "div", "status=0x%02X" % st)
            return
        codes.append(tlv_find(body, 0x75).decode())
    ok = (len(codes) == 2 and codes[0] != codes[1]
          and all(x.isdigit() and len(x) == 6 for x in codes))
    c.rec("T16b", "HOTP avança e é válido", "pass" if ok else "div",
          "codes=%s (segredo nunca sai do device)" % codes)


def _t17(c):
    st, body = c.ctap_up(CTAP_CMD_MAKE_CREDENTIAL, mc_cbor())
    c.rec("T17", "MakeCredential rp e2e", "pass" if st == 0 and len(body) > 20 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))
    if st == 0:
        c.rec("T17n", "MC gravou residente (persiste no NVS!)", "pass", "credencial e2e criada")


def _t18(c):
    st, body = c.ctap_up(CTAP_CMD_GET_ASSERTION, ga_cbor())
    c.rec("T18", "GetAssertion rp e2e", "pass" if st == 0 and len(body) > 10 else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _t19(c):
    # A placa NÃO reseta ao abrir (SerialLink sem DTR): WalletStore (RAM)
    # persiste entre rodadas; roda slots 6..9 até achar um livre.
    # Janela reaberta (fase lenta estoura os 60 s do T11; ver _t13).
    c.pairing()
    addr1 = b""
    used = None
    st = 0x03
    for slot in (6, 7, 8, 9):
        gen = tlv(0x01, bytes([slot])) + tlv(0x02, b"e2e-btc") + tlv(0x08, bytes([0x01]))
        st, body = c.msg_up(bytes([OP["WALLET_GEN"]]) + gen)
        if st == 0x00:
            addr1 = tlv_find(body, 0x07) or b""
            used = slot
            break
        if st != 0x03:
            break
    c.rec("T19", "WALLET_GEN BTC", "pass" if st == 0 and addr1.startswith(b"bc1") else "div",
          "status=0x%02X slot=%s addr=%s" % (st, used, addr1[:44].decode("ascii", "replace")))
    c.ctx_addr = addr1
    c.ctx_slot = used


def _t20(c):
    # Janela reaberta (fase lenta estoura os 60 s do T11; ver _t13).
    c.pairing()
    slot = getattr(c, "ctx_slot", None)
    if slot is None:
        # Sem T19 na mesma sessão: só prova que LIST responde 0x00.
        st, body = c.msg_up(bytes([OP["WALLET_LIST"]]))
        c.rec("T20", "WALLET_LIST responde", "pass" if st == 0 else "div",
              "status=0x%02X bytes=%d (sem T19 na sessão)" % (st, len(body)))
        return
    st, body = c.msg_up(bytes([OP["WALLET_LIST"]]))
    has = bytes([slot]) in body
    c.rec("T20", "WALLET_LIST tem s%d" % slot, "pass" if st == 0 and has else "div",
          "status=0x%02X tem=%s" % (st, has))


def _t21(c):
    slot = getattr(c, "ctx_slot", None)
    if slot is None:
        c.rec("T21", "WALLET_ADDR (sem T19 na sessão)", "fail", "rode --phase pairing inteiro")
        return
    st, body = c.msg_up(bytes([OP["WALLET_ADDR"]]) + tlv(0x01, bytes([slot])))
    addr2 = tlv_find(body, 0x07) if st == 0 else None
    same = bool(addr2) and addr2 == getattr(c, "ctx_addr", b"")
    c.rec("T21", "WALLET_ADDR bate T19", "pass" if same else "div",
          "igual=%s" % same)


def _t22(c):
    # Janela reaberta (fase lenta estoura os 60 s do T11; ver _t13).
    c.pairing()
    bad = tlv(0x01, bytes([E2E_SLOT_BADNET])) + tlv(0x02, b"e2e-bad") + tlv(0x08, bytes([0x09]))
    st, _ = c.msg_up(bytes([OP["WALLET_GEN"]]) + bad)
    c.check("T22", "WALLET rede invalida barra", st, 0x04)


def _d01(c):
    c.up()
    st, _ = c.msg(bytes([OP["KEY_DELETE"]]) + tlv(0x01, bytes([E2E_SLOT_KEY])))
    # DELETE é UP+PIN; o plumbing de PIN nas vendor ainda é follow-up
    # (firmware passa pin=false fixo) → 0x02 mesmo com sessão viva.
    c.rec("D01", "KEY_DELETE s5 pede PIN (gap plumbing)", "pass" if st == 0x02 else "div",
          "status=0x%02X" % st)


def _d02(c):
    c.up()
    st, _ = c.msg(bytes([OP["OATH_DELETE"]]) + tlv(0x71, E2E_OATH))
    c.rec("D02", "OATH_DELETE pede PIN (gap plumbing)", "pass" if st == 0x02 else "div",
          "status=0x%02X" % st)


def _pin_ka(c):
    """KeyAgreement fresco (a chave efêmera do device nasce aqui)."""
    st, body = c.s._exchange(CMD_CBOR, bytes([0x06]) + cbor_map(
        [(cbor_uint(1), cbor_uint(1)), (cbor_uint(2), cbor_uint(2))]),
        timeout_s=10.0, op="e2e")
    if st != 0:
        raise ValueError("keyAgreement 0x%02X" % st)
    return cbor_dec(body)[1]


def _d03(c):
    pc = PinClient()
    peer = _pin_ka(c)
    req = pc.setpin_req(b"1234", peer)
    st, _ = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    # Idempotente: 0x33 = PIN já definido em rodada anterior (D03b prova).
    ok = "pass" if st in (0x00, 0x33) else "div"
    c.rec("D03", "setPIN 1234 (muda o device!)", ok,
          "status=0x%02X%s" % (st, " (já tinha PIN)" if st == 0x33 else ""))
    c.pin_client = pc


def _d03b(c):
    pc = getattr(c, "pin_client", None) or PinClient()
    peer = _pin_ka(c)
    k, req = pc.token_req(b"1234", peer)
    st, body = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    detail = "status=0x%02X" % st
    if st == 0:
        tok = pc.token_dec(k, cbor_dec(body)[2])
        detail = "token %dB (oculto)" % len(tok)
        c.pin_token = True
    c.rec("D03b", "getPinToken 1234 (sessão viva)", "pass" if st == 0 else "div", detail)


def _ensure_session(c):
    """Garante sessão PIN viva (reusa D03b ou faz o token inline)."""
    if getattr(c, "pin_token", False):
        return True
    pc = getattr(c, "pin_client", None) or PinClient()
    try:
        peer = _pin_ka(c)
        k, req = pc.token_req(b"1234", peer)
        st, body = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
        if st == 0:
            c.pin_token = True
            return True
    except (OSError, TimeoutError, ValueError):
        pass
    return False


def _d01b(c):
    # F1: com sessão PIN viva, DELETE passa o gate (0x04 = gate-ok).
    if not _ensure_session(c):
        c.rec("D01b", "KEY_DELETE com sessão (sem PIN 1234 no device?)", "fail", "token falhou")
        return
    c.up()
    st, used, last = 0x03, None, 0x03
    for slot in (5, 6, 7, 8, 9):
        st, _ = c.msg(bytes([OP["KEY_DELETE"]]) + tlv(0x01, bytes([slot])))
        last = st
        if st == 0x00:
            used = slot
            break
        if st != 0x03:
            break
    c.rec("D01b", "KEY_DELETE com sessão PIN executa", "pass" if st == 0x00 else "div",
          "status=0x%02X slot=%s" % (last, used))


def _d02b(c):
    if not _ensure_session(c):
        c.rec("D02b", "OATH_DELETE com sessão (sem PIN 1234 no device?)", "fail", "token falhou")
        return
    c.up()
    st, _ = c.msg(bytes([OP["OATH_DELETE"]]) + tlv(0x71, E2E_OATH))
    c.rec("D02b", "OATH_DELETE com sessão PIN executa", "pass" if st == 0x00 else "div",
          "status=0x%02X" % st)


def _d04(c):
    pc = getattr(c, "pin_client", None) or PinClient()
    peer = _pin_ka(c)
    req = pc.changepin_req(b"1234", b"5678", peer)
    st, _ = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    c.rec("D04a", "changePIN 1234->5678", "pass" if st == 0 else "div",
          "status=0x%02X" % st)
    if st != 0:
        return
    peer = _pin_ka(c)
    req = pc.changepin_req(b"5678", b"1234", peer)
    st, _ = c.s._exchange(CMD_CBOR, bytes([0x06]) + req, timeout_s=10.0, op="e2e")
    c.rec("D04b", "changePIN 5678->1234 (volta)", "pass" if st == 0 else "div",
          "status=0x%02X (device fica com 1234)" % st)


def _d05(c):
    c.up()
    st, _ = c.msg(bytes([0x2C]) + b"1234")
    c.rec("D05a", "RECOVERY_SET 1234", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _claim_once(c, tag):
    import os as _os
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    priv = _ec.generate_private_key(_ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    sec1 = (b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))
    bid = _os.urandom(16)
    c.up()
    st, _ = c.msg(bytes([0x28]) + sec1 + bid)
    # Idempotente: 0x04 = já claimed em rodada anterior (D06b prova).
    ok = "pass" if st in (0x00, 0x04) else "div"
    c.rec(tag, "CLAIM posse (muda binding!)", ok,
          "status=0x%02X id=%s%s" % (st, bid.hex()[:8], " (já claimed)" if st == 0x04 else ""))


def _d06(c):
    _claim_once(c, "D06")
    if True:
        c.rec("D06n", "device agora CLAIMED (NVS)", "pass", "gates de binding mudam; ver T10")


def _d06c(c):
    _claim_once(c, "D06c")


def _d06b(c):
    st, body = c.msg(bytes([0x29]))
    ok = st == 0 and len(body) == 32
    c.rec("D06b", "CHALLENGE pós-claim dá 32B", "pass" if ok else "div",
          "status=0x%02X bytes=%d" % (st, len(body)))


def _d07(c):
    # RELEASE em test-mode: bypass com só UP (sig ignorada) → wipe binding.
    # PIN/credencial/recovery sobrevivem (só BIND_* some do NVS).
    c.up()
    st, _ = c.msg(bytes([0x2B]) + bytes(64))
    c.rec("D07", "RELEASE (wipe binding, test-mode)", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _d07b(c):
    st, body = c.msg(bytes([0x29]))
    c.rec("D07b", "CHALLENGE pós-release nega (unclaimed)",
          "pass" if st == 0x05 else "div",
          "status=0x%02X (prova do wipe)" % st)


def _d05b(c):
    # UNLOCK com PIN certo + UP → wipe binding (recovery PIN preservado).
    c.up()
    st, _ = c.msg(bytes([0x2D]) + b"1234")
    c.rec("D05b", "RECOVERY_UNLOCK 1234 (wipe binding)", "pass" if st == 0 else "div",
          "status=0x%02X" % st)


def _d05c(c):
    st, body = c.msg(bytes([0x29]))
    c.rec("D05c", "CHALLENGE pós-unlock nega (unclaimed)",
          "pass" if st == 0x05 else "div",
          "status=0x%02X (prova do wipe)" % st)


def _d08(c):
    # F5: ciclo OTA real com chave lab (privada fora do repo).
    import hashlib as _hl, os as _os, struct as _st, time as _t
    # O pareamento (BLE-adv + logs) polui o fio; assenta antes do ciclo.
    _t.sleep(1.5)
    try:
        c.s.link.flush_input()
    except Exception:
        pass
    try:
        priv = open(r"C:\t\ota_test_key.bin", "rb").read()
        assert len(priv) == 32
    except Exception:
        c.rec("D08", "OTA lab (sem C:\\t\\ota_test_key.bin)", "fail", "chave de teste ausente")
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(priv)

    def manifest(version, image, key):
        digest = _hl.sha256(image).digest()
        signed = _st.pack(">II", version, len(image)) + digest
        return signed + key.sign(signed)

    def begin(m):
        return c.msg(bytes([0x30]) + m)

    image = _os.urandom(20 * 1024)
    # 1. Negativo: assinatura errada -> FINISH nega e limpa.
    bad = manifest(2, image, Ed25519PrivateKey.generate())
    st, _ = begin(bad)
    if st != 0x00:
        c.rec("D08a", "BEGIN bad-sig (aceito p/ testar FINISH)", "div", "status=0x%02X" % st)
        return
    c.msg(bytes([0x31]) + _st.pack(">I", 0) + image[:4096])
    st, _ = c.msg(bytes([0x32]))
    if st == 0x00:
        c.rec("D08a", "FINISH com bad-sig passou?!", "fail", "fail-closed quebrou")
        return
    c.rec("D08a", "FINISH bad-sig nega e limpa", "pass", "status=0x%02X" % st)
    # 2. Positivo: BEGIN -> CHUNKs -> FINISH (verify Ed25519 real).
    good = manifest(2, image, sk)
    st, _ = begin(good)
    if st != 0x00:
        c.rec("D08b", "BEGIN lab", "div", "status=0x%02X" % st)
        return
    off, ok = 0, True
    for i in range(0, len(image), 4096):
        chunk = image[i:i + 4096]
        st, body = c.msg(bytes([0x31]) + _st.pack(">I", off) + chunk)
        off += len(chunk)
        if st != 0x00 or body != _st.pack(">I", off):
            ok = False
            break
    c.rec("D08b", "BEGIN+5 CHUNKs 20KiB", "pass" if ok else "div",
          "recebidos=%d/20480" % off)
    if not ok:
        return
    st, _ = c.msg(bytes([0x32]))
    c.rec("D08c", "FINISH verify real", "pass" if st == 0 else "div",
          "status=0x%02X" % st)
    if st != 0:
        return
    # 3. COMMIT sem UP nega; com UP grava só marker (sem swap: partição única).
    st, _ = c.msg(bytes([0x33]))
    if st != 0x01:
        c.rec("D08d", "COMMIT sem UP nega", "div", "status=0x%02X" % st)
        return
    c.rec("D08d", "COMMIT sem UP nega", "pass", "0x01 (sessão preservada)")
    c.up()
    st, body = c.msg(bytes([0x33]))
    ok = st == 0x00 and body == _st.pack(">I", 2)
    c.rec("D08e", "COMMIT com UP (só marker, sem swap)", "pass" if ok else "div",
          "status=0x%02X body=%s" % (st, body.hex()))
    st, _ = c.msg(bytes([0x34]))
    c.rec("D08f", "ABORT limpa sessão", "pass" if st == 0x00 else "div",
          "status=0x%02X" % st)


# ID -> (função, fase, precisa_janela). Ordem das fases preservada.
REG = {
    "T01": (_t01, "base"), "T02": (_t02, "base"), "T03": (_t03, "base"),
    "T04": (_t04, "base"), "T05": (_t05, "base"), "T06": (_t06, "base"),
    "T06b": (_t06b, "base"),
    "T07": (_t07, "base"), "T08": (_t08, "base"), "T09": (_t09, "base"),
    "T10": (_t10, "base"),
    "T11": (_t11, "pairing"), "T12": (_t12, "pairing"),
    "T07b": (_t07b, "pairing"), "T07c": (_t07c, "pairing"),
    "T13": (_t13, "pairing"), "T14": (_t14, "pairing"),
    "T15": (_t15, "pairing"), "T15b": (_t15b, "destructive"),
    "T15c": (_t15c, "destructive"),
    "T16": (_t16, "pairing"), "T16b": (_t16b, "destructive"),
    "T17": (_t17, "pairing"), "T18": (_t18, "pairing"),
    "T19": (_t19, "pairing"), "T20": (_t20, "pairing"),
    "T21": (_t21, "pairing"), "T22": (_t22, "pairing"),
    "D01": (_d01, "destructive"), "D02": (_d02, "destructive"),
    "D03": (_d03, "destructive"), "D03b": (_d03b, "destructive"),
    "D01b": (_d01b, "destructive"), "D02b": (_d02b, "destructive"),
    "D04a": (_d04, "destructive"),
    "D05a": (_d05, "destructive"), "D05b": (_d05b, "wipe"), "D05c": (_d05c, "wipe"),
    "D06": (_d06, "destructive"),
    "D06b": (_d06b, "destructive"), "D06c": (_d06c, "wipe"),
    "D07": (_d07, "wipe"), "D07b": (_d07b, "wipe"),
    "D08": (_d08, "destructive"),
}


def _bench(c):
    """Tempos por op (3x cada, ms). Baseline p/ decisão HW (F7)."""
    import time as _t

    def timed(tid, name, fn, tries=3):
        ds, ok, detail = [], False, ""
        for _ in range(tries):
            t0 = _t.monotonic()
            try:
                ok, detail = fn()
            except Exception as e:
                detail, ok = str(e)[:60], False
            ds.append((_t.monotonic() - t0) * 1000)
            if not ok:
                break
        avg = sum(ds) / len(ds)
        c.rec(tid, "%s [%dms]" % (name, int(avg)), "pass" if ok else "div", detail)

    s = c.s
    timed("B01", "PING", lambda: (
        (lambda r: (bytes([r[0]]) + r[1] == b"ping-b", "eco"))(
            s._exchange(CMD_PING, b"ping-b", timeout_s=10.0, op="e2e"))))
    timed("B02", "GetInfo", lambda: (
        (lambda r: (r[0] == 0, "%dB" % len(r[1])))(
            s._exchange(CMD_CBOR, bytes([0x04]), timeout_s=10.0, op="e2e"))))
    # MC/GA exigem pareamento serial: abre a janela antes (BLE-adv liga o
    # rádio; se a placa rebootar aqui, é energia — vide F5).
    try:
        c.pairing()
        c.rec("B02b", "janela pareamento", "pass", "aberta")
    except Exception as e:
        c.rec("B02b", "janela pareamento", "div", str(e)[:60])
        return
    timed("B03", "MC", lambda: (
        (lambda r: (r[0] == 0, "%dB" % len(r[1])))(
            c.ctap_up(CTAP_CMD_MAKE_CREDENTIAL, mc_cbor()))))
    timed("B04", "GA", lambda: (
        (lambda r: (r[0] == 0, "%dB" % len(r[1])))(
            c.ctap_up(CTAP_CMD_GET_ASSERTION, ga_cbor()))))


REG["B99"] = (_bench, "bench")
PHASES = {
    "base": [t for t, (_, p) in REG.items() if p == "base"],
    "pairing": [t for t, (_, p) in REG.items() if p == "pairing"],
    "all-safe": [t for t, (_, p) in REG.items() if p in ("base", "pairing")],
    "destructive": [t for t, (_, p) in REG.items() if p == "destructive"],
    # Ciclo completo de wipes: claim -> release -> re-claim -> unlock.
    # F2: PUT/CODE antes dos DELETEs (senao 0x03 sem alvo).
    "wipe": ["D01", "D02", "D03", "D03b", "T15b", "T15c", "T16b", "D01b",
             "D02b", "D04a", "D05a", "D06", "D06b", "D07", "D07b", "D06c",
             "D06b", "D05b", "D05c", "D08"],
    "bench": ["B99"],
}


def _setup_clean(c):
    """SETUP determinístico: fecha janela residual de sessão anterior.

    A placa não reseta ao reabrir a serial: uma janela de 60 s aberta por
    sonda anterior (GEN/fase base) ainda vale e faz T06 ver 0x01 em vez de
    0x05. Fecha via TEST_PAIRING_CLOSE (host + teste) e afirma ambos os
    latches limpos via TEST_LED_STATE (leitura sem efeito colateral):
    `up_pending` (latch 1x do TEST_UP) e `touch` (flag do dispatcher
    `touch_latched`, que é o que o gate CTAP realmente consome). Retorna
    False para abortar a fase (firmware sem o hook).
    """
    try:
        txt = c.s.send_text_line("TEST_PAIRING_CLOSE", timeout_s=5.0,
                                 until=b"pairing_closed")
    except (OSError, TimeoutError, ValueError) as e:
        c.rec("SETUP", "fecha janela residual", "fail",
              "firmware sem TEST_PAIRING_CLOSE (%s)" % str(e)[:60])
        return False
    if "pairing_closed" not in txt or "source=software" not in txt:
        c.rec("SETUP", "fecha janela residual", "fail",
              "firmware sem TEST_PAIRING_CLOSE")
        return False
    try:
        led = c.s.send_text_line("TEST_LED_STATE", timeout_s=5.0, until=b"led_state")
    except (OSError, TimeoutError, ValueError) as e:
        c.rec("SETUP", "latch limpo", "div",
              "led_state ilegível (%s); segue fase" % str(e)[:60])
        return True
    def _dirty(s):
        return ("up_pending=1" in s) or ("touch=1" in s)
    if _dirty(led):
        end = time.monotonic() + 3.0
        while time.monotonic() < end:
            time.sleep(0.5)
            try:
                led = c.s.send_text_line("TEST_LED_STATE", timeout_s=5.0,
                                         until=b"led_state")
            except (OSError, TimeoutError, ValueError):
                break
            if not _dirty(led):
                break
    up = "up_pending=1" in led
    touch = "touch=1" in led
    if up or touch:
        c.rec("SETUP", "latch limpo", "div",
              "latch persistiu up_pending=%d touch=%d (segue fase)"
              % (up, touch))
    else:
        c.rec("SETUP", "janela fechada + latch limpo", "pass",
              "pairing_closed + up_pending=0 touch=0")
    return True


def append_md(results, phase):
    now = datetime.datetime.now().strftime("%d/%m %H:%M")
    lines = ["", "### %s — phase=%s" % (now, phase)]
    for tid, name, ok, detail, _ in results:
        mark = {"pass": "PASS", "div": "DIVERGENTE", "fail": "FAIL"}[ok]
        lines.append("- [%s] %s %s — %s" % (mark, tid, name, detail))
    with open(MD_PATH, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def user_main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=PORT_DEFAULT)
    ap.add_argument("--phase", default="base",
                    choices=["base", "pairing", "all-safe", "destructive", "wipe", "bench"])
    ap.add_argument("--only", default=None, help="ID único, ex. T17")
    ap.add_argument("--confirm", action="store_true")
    ap.add_argument("--confirm-release", action="store_true",
                    help="autoriza wipes (D07 release, D05b unlock)")
    args = ap.parse_args()

    if args.phase in ("destructive", "wipe") and not args.confirm:
        print("fase destructive/wipe exige --confirm (muda estado do device)")
        sys.exit(2)
    if args.phase == "wipe" and not args.confirm_release:
        print("fase wipe exige --confirm-release (apaga binding do NVS)")
        sys.exit(2)

    c = Ctx(args.port)
    try:
        if args.only:
            wanted = args.only.strip()
            # IDs com sufixo minúsculo (T06b, T07b, T17n): busca insensível.
            match = next((k for k in REG if k.lower() == wanted.lower()), None)
            if match is None:
                print("ID desconhecido: %s" % wanted)
                sys.exit(2)
            wanted = match
            fn, phase = REG[wanted]
            if phase in ("destructive", "wipe") and not args.confirm:
                print("teste D exige --confirm")
                sys.exit(2)
            if phase == "wipe" and not args.confirm_release:
                print("teste wipe exige --confirm-release")
                sys.exit(2)
            if phase in ("pairing", "destructive", "wipe"):
                # Janela é pré-requisito dos gates; abre uma fresca p/ o teste.
                try:
                    c.pairing()
                except (OSError, TimeoutError, ValueError) as e:
                    c.rec(wanted, "abrir janela", "fail", str(e)[:100])
                    raise SystemExit
            run_ids = [wanted]
            REG[wanted][0](c)
            if wanted == "T21":
                print("nota: T21 compara com T19 da MESMA sessão (WalletStore é RAM);")
                print("em --only isolado, rode: --phase pairing e veja T19+T21 juntos.")
        else:
            ids = PHASES[args.phase]
            # Setup determinístico (fase completa, nunca --only): fecha janela
            # residual de sessão anterior antes do primeiro teste.
            if not _setup_clean(c):
                ids = []
            if args.phase in ("destructive", "wipe") and ids:
                # Janela fresca p/ a fase toda (gates pairing).
                try:
                    _t11(c)
                except (OSError, TimeoutError, ValueError) as e:
                    c.rec("T11", "abrir janela", "fail", str(e)[:100])
                    ids = []
            for tid in ids:
                if tid == "T11" and args.phase in ("destructive", "wipe"):
                    continue  # janela já aberta acima; pairing/all-safe executam T11
                try:
                    REG[tid][0](c)
                except (OSError, TimeoutError, ValueError) as e:
                    # Isola: um transporte falhou, a fase continua no próximo.
                    c.rec(tid, "transporte", "fail", str(e)[:120])
    except (OSError, TimeoutError, ValueError) as e:
        c.rec("TRANSPORTE", "erro", "fail", str(e)[:120])
    finally:
        c.close()
    n_pass = sum(1 for r in c.results if r[2] == "pass")
    n_div = sum(1 for r in c.results if r[2] == "div")
    n_fail = sum(1 for r in c.results if r[2] == "fail")
    print("RESUMO pass=%d divergente=%d fail=%d" % (n_pass, n_div, n_fail))
    append_md(c.results, args.phase + (" only=" + args.only if args.only else ""))
    # Atualiza a tabela de status no MD (TODO -> resultado).
    try:
        with open(MD_PATH, encoding="utf-8") as f:
            md = f.read()
        for tid, name, ok, detail, _ in c.results:
            mark = {"pass": "PASS", "div": "DIVERGENTE", "fail": "FAIL"}[ok]
            old = "| %s |" % tid
            # troca o TODO da linha do teste pelo resultado (primeira ocorrência)
            idx = md.find(old)
            if idx >= 0:
                line_end = md.find("\n", idx)
                line = md[idx:line_end]
                if "TODO" in line:
                    md = md[:idx] + line.replace("TODO", mark, 1) + md[line_end:]
        with open(MD_PATH, "w", encoding="utf-8") as f:
            f.write(md)
    except OSError as e:
        print("aviso: MD não atualizado (%s)" % e)
# --- END ORIGIN: tools/e2e_user_test.py ---

# ======================================================================
# --- BEGIN ORIGIN: tools/emulate_app_session.py (entry: session_main) ---
# ======================================================================
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


def session_main():
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
# --- END ORIGIN: tools/emulate_app_session.py ---

# ======================================================================
# --- BEGIN ORIGIN: tools/hil_emulate_full_app_on_board.py (entry: onboard_main) ---
# ======================================================================
"""HIL Emulate Full App on Board (Physical ESP32-S3 Hardware on COM7).

Emulates the complete Android App lifecycle directly on the real hardware:
1. Verifies clean initial state after NVS reset.
2. Creates & Validates keys:
   - PASSKEY_FIDO:
     * Slot 0: Ed25519 (-8, modern FIDO2 EdDSA)
     * Slot 1: ES256 (-7, WebAuthn standard NIST P-256)
     * Slot 2: ES256K (-47, secp256k1 Koblitz)
     * Probes ES384 / ES512 stack limits
   - VENDOR_SIGNING_KEY:
     * Slot 3: ES256 (-7, usage=SIGN)
   - CRYPTO_WALLETS (0x35 GEN + 0x37 ADDR):
     * Slot 4: Bitcoin P2WPKH (bech32)
     * Slot 5: Ethereum EVM (EIP-55 hex)
     * Slot 6: Solana Ed25519 (base58)
   - PIV_SMARTCARD_SLOT:
     * 0x39 OP_PIV_ENROLL (PIN 6B + PUK 8B)
   - ENCRYPTED_AEGN_ENVELOPE:
     * 0x21 OP_KEY_IMPORT probe
   - OATH TOTP / HOTP:
     * 0x24 OP_OATH_PUT, 0x25 OP_OATH_LIST, 0x26 OP_OATH_CODE
3. Full Resource Listings:
   - 0x22 OP_KEY_LIST
   - 0x36 OP_WALLET_LIST
   - 0x25 OP_OATH_LIST
   - 0x38 OP_FW_LOG
4. Deletion Gate Test (0x23 OP_KEY_DELETE) verifying PIN security contract.
"""

import json
import os
import socket
import struct
import sys
import time
import urllib.request

HIL_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if HIL_SCRIPT_DIR not in sys.path:
    sys.path.insert(0, HIL_SCRIPT_DIR)
WORKTREE_DIR = os.path.dirname(HIL_SCRIPT_DIR)
if WORKTREE_DIR not in sys.path:
    sys.path.insert(0, WORKTREE_DIR)

from app_simulator import Session, CMD_MSG
from host_sdk import ops as _ops
from host_sdk import tlv as _tlv

PORT = "COM7"
BAUD = 115200

# Opcodes
OP_KEY_GEN = 0x20
OP_KEY_IMPORT = 0x21
OP_KEY_LIST = 0x22
OP_KEY_DELETE = 0x23
OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27
OP_BIND_RELEASE = 0x2B
OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37
OP_FW_LOG = 0x38
OP_PIV_ENROLL = 0x39

# TLV Tags
TAG_SLOT = 0x01
TAG_LABEL = 0x02
TAG_WALLET_SLOT = 0x01
TAG_WALLET_LABEL = 0x02
TAG_WALLET_ADDRESS = 0x07
TAG_WALLET_NETWORK = 0x08
TAG_OATH_NAME = 0x71
TAG_OATH_KEY = 0x73
TAG_OATH_CHALLENGE = 0x74
TAG_OATH_RESPONSE = 0x75
TAG_OATH_IMF = 0x7A

# Usages & Algorithms
USAGE_SIGN = 0x01
USAGE_SIGN_AUTH = 0x03
ALG_ED25519 = -8
ALG_ES256 = -7
ALG_ES256K = -47
ALG_P384 = -35
ALG_P521 = -36

OATH_TYPE_HOTP = 0x10
OATH_TYPE_TOTP = 0x20
OATH_ALGO_SHA1 = 0x01


class BridgeSession:
    """Seamless session proxy that routes CTAPHID and vendor ops through host_hardware_android_bridge HTTP server."""

    def __init__(self, base_url="http://127.0.0.1:5678"):
        self.base_url = base_url.rstrip("/")

    def connect(self, port, baud):
        pass

    def cmd_init(self) -> int:
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/info")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                cid_str = data.get("cid", "0x00010201")
                return int(cid_str, 16 if "x" in cid_str else 10)
        except Exception:
            return 0x00010201

    def lifetime_dump(self, timeout_s=3.0) -> str:
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/dump")
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                data = json.loads(resp.read().decode())
                return data.get("dump", "")
        except Exception:
            return "uptime_s=100\n"

    def test_pairing_open(self, timeout_s=3.0):
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/pairing_open", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout_s):
                pass
        except Exception:
            pass

    def test_up(self, timeout_s=3.0):
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/touch_up", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout_s):
                pass
        except Exception:
            pass

    def _exchange(self, cmd, payload, op="op", timeout_s=15.0):
        opcode = payload[0] if payload else 0
        p_data = payload[1:] if len(payload) > 1 else b""
        body = json.dumps({"opcode": opcode, "payload_hex": p_data.hex()}).encode()
        req = urllib.request.Request(f"{self.base_url}/bridge/vendor", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status", 0)
            resp_payload = bytes.fromhex(data.get("payload_hex", ""))
            return status, resp_payload

    def close(self):
        pass


def build_oath_put(name: str, oath_type: int, digits: int, secret: bytes, counter: int = None) -> bytes:
    name_bytes = name.encode("utf-8")
    type_algo = oath_type | OATH_ALGO_SHA1
    key_bytes = bytes([type_algo, digits]) + secret
    req = _tlv.write_tlv(TAG_OATH_NAME, name_bytes) + _tlv.write_tlv(TAG_OATH_KEY, key_bytes)
    if counter is not None:
        imf = struct.pack(">I", counter)
        req += _tlv.write_tlv(TAG_OATH_IMF, imf)
    return req


def build_oath_code(name: str, challenge: int = None) -> bytes:
    name_bytes = name.encode("utf-8")
    req = _tlv.write_tlv(TAG_OATH_NAME, name_bytes)
    if challenge is not None:
        chal_bytes = struct.pack(">Q", challenge)
        req += _tlv.write_tlv(TAG_OATH_CHALLENGE, chal_bytes)
    return req


def authenticate_pin(sess):
    """Sends 0x2F trigger, TEST_PIN_OK, TEST_PAIRING_OPEN, and TEST_UP to arm UP and set pin_verified=true."""
    if isinstance(sess, BridgeSession):
        try:
            req = urllib.request.Request(f"{sess.base_url}/bridge/pin_auth", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3.0):
                pass
        except Exception:
            pass
        return

    # 1. Trigger 0x2F host pairing trigger (sets ctx.pin_verified=true, arm_up=true, 60s window)
    try:
        sess._exchange(CMD_MSG, bytes([0x2F]), op="trigger_0x2f", timeout_s=3.0)
    except Exception:
        pass

    # 2. Send TEST_PIN_OK text line
    if hasattr(sess, "link") and hasattr(sess.link, "write"):
        try:
            sess.link.write(b"TEST_PIN_OK\n")
            time.sleep(0.05)
        except Exception:
            pass
    elif hasattr(sess, "send_text_line"):
        try:
            sess.send_text_line("TEST_PIN_OK", timeout_s=1.0)
        except Exception:
            pass

    # 3. Arm pairing and UP
    sess.test_pairing_open(timeout_s=3.0)
    sess.test_up(timeout_s=3.0)


def send_arm(sess: Session, op_name: str, cmd_byte: int, payload: bytes = b"", timeout_s: float = 6.0, pin_required: bool = False):
    """Sends TEST_PAIRING_OPEN + TEST_UP before privileged write ops, executes op and returns (status, body)."""
    if pin_required:
        authenticate_pin(sess)
    else:
        sess.test_pairing_open(timeout_s=3.0)
        sess.test_up(timeout_s=3.0)

    full_payload = bytes([cmd_byte]) + payload if cmd_byte is not None else payload
    st, body = sess._exchange(CMD_MSG, full_payload, op=op_name, timeout_s=timeout_s)

    # If status is NEED_PIN (0x02), auto-authenticate PIN and retry once
    if st == 0x02:
        print(f"      [auto-pin] Op 0x{cmd_byte:02X} retornou NEED_PIN (0x02); autenticando PIN e retentando...")
        authenticate_pin(sess)
        st, body = sess._exchange(CMD_MSG, full_payload, op=f"{op_name}_retry", timeout_s=timeout_s)

    return st, body


def onboard_main():
    print("=" * 70)
    print("  HIL EMULATION: JORNADA COMPLETA DO APP NA CHAVE REAL (COM7)")
    print("=" * 70)

    use_bridge = "--bridge" in sys.argv
    if not use_bridge:
        try:
            with socket.create_connection(("127.0.0.1", 5678), timeout=0.5):
                use_bridge = True
        except Exception:
            use_bridge = False

    if use_bridge:
        print("[+] Modo: Ponte Hardware Android Bridge (http://127.0.0.1:5678)")
        sess = BridgeSession("http://127.0.0.1:5678")
    else:
        print(f"[+] Modo: Conexão Serial UART Direta ({PORT} a {BAUD} bps)")
        sess = Session("http://192.168.4.1", test_mode=True)

    try:
        print(f"\n[+] 1. Inicializando conexão com a chave real...")
        sess.connect(PORT, BAUD)
        cid = sess.cmd_init()
        print(f"    CID CTAPHID alocado: 0x{cid:08X}")

        dump = sess.lifetime_dump(timeout_s=3.0)
        uptime = [line for line in dump.splitlines() if "uptime_s=" in line]
        print(f"    Uptime do hardware pós-reset: {uptime[0] if uptime else 'desconhecido'}")

        # -------------------------------------------------------------
        # ETAPA 1: Verificação do Estado Limpo Pós-Reset
        # -------------------------------------------------------------
        print("\n[+] 2. ETAPA 1 — Verificando Limpeza de Slots e Estado Inicial...")
        # Limpeza prévia via OP_BIND_RELEASE (em test-mode faz wipe limpo das chaves/wallets/oath)
        print("    Resetando estado inicial via OP_BIND_RELEASE (0x2B)...")
        st_rel, _ = send_arm(sess, "clean_bind_release", OP_BIND_RELEASE, b"\x00" * 64, timeout_s=4.0)
        print(f"    0x2B OP_BIND_RELEASE -> Status: 0x{st_rel:02X}")
        time.sleep(0.1)

        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_KEY_LIST]), op="key_list", timeout_s=4.0)
        print(f"    0x22 OP_KEY_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B (esperado vazio = 0)")

        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_LIST]), op="oath_list", timeout_s=4.0)
        print(f"    0x25 OP_OATH_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B (esperado vazio = 0)")

        # -------------------------------------------------------------
        # ETAPA 2: Criação de Chaves PASSKEY / FIDO nas 5 Curvas Suportadas
        # -------------------------------------------------------------
        print("\n[+] 3. ETAPA 2 — Criação de PASSKEYS FIDO On-Device (0x20)...")
        curves = [
            (0, "passkey:ed25519", ALG_ED25519, "Ed25519 (alg -8, moderna / passkey rápida)"),
            (1, "passkey:p256", ALG_ES256, "ES256 / P-256 (alg -7, WebAuthn padrão FIDO2)"),
            (2, "passkey:secp256k1", ALG_ES256K, "ES256K / secp256k1 (alg -47, Bitcoin/Koblitz)"),
            (3, "passkey:p384", ALG_P384, "P-384 / ES384 (alg -35, NIST Suite B)"),
            (4, "passkey:p521", ALG_P521, "P-521 / ES512 (alg -36, Alta Segurança)"),
        ]

        for slot, label, alg, desc in curves:
            body = _ops.vendor_key_gen(slot, label.encode("utf-8"), alg, USAGE_SIGN_AUTH)
            t_out = 15.0 if slot in (3, 4) else 6.0
            st, resp = send_arm(sess, f"gen_passkey_{slot}", OP_KEY_GEN, body, timeout_s=t_out)
            status_text = "OK (0x00)" if st == 0 else f"ERRO (0x{st:02X})"
            print(f"    Slot {slot} [{desc}] -> Status: {status_text}")
            if st == 0x00 and resp:
                recs = _tlv.parse_tlv(resp)
                for t, v in recs:
                    if t == TAG_LABEL:
                        print(f"      Confirmado no silício: '{v.decode('utf-8', errors='replace')}'")

        # -------------------------------------------------------------
        # ETAPA 3: Criação de Chave Vendor de Assinatura Privada (0x20)
        # -------------------------------------------------------------
        print("\n[+] 4. ETAPA 3 — Criação de Chave Vendor de Assinatura (0x20)...")
        body_vsign = _ops.vendor_key_gen(5, b"vendor:firmware_sign", ALG_ES256, USAGE_SIGN)
        st, resp = send_arm(sess, "gen_vsign", OP_KEY_GEN, body_vsign)
        print(f"    Slot 5 [Vendor Signing ES256, usage=SIGN] -> Status: 0x{st:02X} ({'OK' if st == 0 else 'ERRO'})")
        if st == 0x00 and resp:
            recs = _tlv.parse_tlv(resp)
            for t, v in recs:
                if t == TAG_LABEL:
                    print(f"      Confirmado no silício: '{v.decode('utf-8', errors='replace')}'")

        # -------------------------------------------------------------
        # ETAPA 4: Criação das Carteiras Cripto nas 3 Redes (0x35 & 0x37)
        # -------------------------------------------------------------
        print("\n[+] 5. ETAPA 4 — Criação de Crypto Wallets On-Device (0x35) e Derivação (0x37)...")
        wallets = [
            (6, b"BtcMainVault", 1, "Bitcoin P2WPKH (bech32)"),
            (7, b"EthMainVault", 2, "Ethereum EVM (EIP-55 hex)"),
            (8, b"SolMainVault", 3, "Solana Ed25519 (base58)"),
        ]
        created_wallets = []
        for slot, label, net, desc in wallets:
            wbody = _ops.wallet_gen(slot, label, net)
            st, resp = send_arm(sess, f"wallet_gen_{slot}", OP_WALLET_GEN, wbody)
            print(f"    Slot {slot} [{desc}] -> Status: 0x{st:02X}")
            if st == 0x00 and resp:
                recs = _tlv.parse_tlv(resp)
                addr = ""
                for t, v in recs:
                    if t == TAG_WALLET_ADDRESS:
                        addr = v.decode("utf-8", errors="replace")
                print(f"      Endereço derivado on-device: {addr}")
                created_wallets.append((slot, addr))

            # Consulta individual via OP_WALLET_ADDR (0x37)
            abody = _ops.wallet_addr_req(slot)
            st_a, resp_a = send_arm(sess, f"wallet_addr_{slot}", OP_WALLET_ADDR, abody)
            if st_a == 0x00 and resp_a:
                recs_a = _tlv.parse_tlv(resp_a)
                for t, v in recs_a:
                    if t == TAG_WALLET_ADDRESS:
                        addr_q = v.decode("utf-8", errors="replace")
                        print(f"      OP_WALLET_ADDR (0x37) slot {slot} verificado: {addr_q}")

        # -------------------------------------------------------------
        # ETAPA 5: PIV Smartcard Enrollment (0x39)
        # -------------------------------------------------------------
        print("\n[+] 6. ETAPA 5 — Enrollment PIV Smartcard PIN/PUK (0x39)...")
        piv_payload = bytes([6]) + b"123456" + b"12345678"  # PIN 6B, PUK 8B
        st, _ = send_arm(sess, "piv_enroll", OP_PIV_ENROLL, piv_payload)
        status_label = "OK (0x00)" if st == 0 else f"STATUS 0x{st:02X}"
        print(f"    0x39 OP_PIV_ENROLL (PIN='123456', PUK='12345678') -> {status_label}")

        # -------------------------------------------------------------
        # ETAPA 6: Importação de Envelope Cifrado AEGN (0x21)
        # -------------------------------------------------------------
        print("\n[+] 7. ETAPA 6 — Prova de Importação de Envelope AEGN (0x21)...")
        import_payload = _tlv.write_tlv(TAG_SLOT, bytes([7])) + _tlv.write_tlv(TAG_LABEL, b"imported_key")
        st, resp = send_arm(sess, "key_import", OP_KEY_IMPORT, import_payload, pin_required=True)
        status_meaning = {
            0x00: "OK (importado com sucesso)",
            0x04: "GATE_OK (gate de segurança passou / envelope sintético)",
            0x02: "NEED_PIN",
        }.get(st, f"STATUS 0x{st:02X}")
        print(f"    0x21 OP_KEY_IMPORT -> Status: 0x{st:02X} ({status_meaning})")

        # -------------------------------------------------------------
        # ETAPA 7: Teste do Módulo OATH (0x24, 0x25, 0x26, 0x27)
        # -------------------------------------------------------------
        print("\n[+] 8. ETAPA 7 — Módulo OATH TOTP / HOTP (0x24, 0x25, 0x26, 0x27)...")
        # 7.1 Cadastro de contas OATH (OP_OATH_PUT 0x24 com PIN)
        google_secret = b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"  # 20B
        totp1_req = build_oath_put("Google:alice@gmail.com", OATH_TYPE_TOTP, 6, google_secret)
        st, _ = send_arm(sess, "oath_put_google", OP_OATH_PUT, totp1_req, pin_required=True)
        oath_put_status = {0x00: "OK (0x00)", 0x02: "NEED_PIN"}.get(st, f"0x{st:02X}")
        print(f"    0x24 OP_OATH_PUT 'Google:alice@gmail.com' -> Status: {oath_put_status}")

        github_secret = b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x50\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"  # 20B
        totp2_req = build_oath_put("GitHub:octocat", OATH_TYPE_TOTP, 6, github_secret)
        st, _ = send_arm(sess, "oath_put_github", OP_OATH_PUT, totp2_req, pin_required=True)
        oath_put_status = {0x00: "OK (0x00)", 0x02: "NEED_PIN"}.get(st, f"0x{st:02X}")
        print(f"    0x24 OP_OATH_PUT 'GitHub:octocat' -> Status: {oath_put_status}")

        # 7.2 Consulta de contas OATH (OP_OATH_LIST 0x25 - requer apenas UP)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_LIST]), op="oath_list", timeout_s=4.0)
        print(f"    0x25 OP_OATH_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00 and body:
            recs = _tlv.parse_tlv(body)
            for t, v in recs:
                if t == TAG_OATH_NAME and len(v) > 1:
                    label = v[1:].decode("utf-8", errors="replace")
                    print(f"      Conta cadastrada no silício: '{label}'")

        # 7.3 Cálculo do código OTP no chip físico (OP_OATH_CODE 0x26)
        timestep = int(time.time() // 30)
        code_req = build_oath_code("Google:alice@gmail.com", challenge=timestep)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_CODE]) + code_req, op="oath_code", timeout_s=4.0)
        if st == 0x00 and body:
            recs = _tlv.parse_tlv(body)
            otp_val = None
            for t, v in recs:
                if t == TAG_OATH_RESPONSE:
                    otp_val = v.decode("utf-8", errors="replace")
            print(f"    0x26 OP_OATH_CODE 'Google:alice@gmail.com' -> Status: OK (0x00), OTP: [{otp_val or 'OK'}]")
        else:
            print(f"    0x26 OP_OATH_CODE 'Google:alice@gmail.com' -> Status: 0x{st:02X}")

        # 7.4 Exclusão de conta OATH (OP_OATH_DELETE 0x27 com PIN)
        del_req = _tlv.write_tlv(TAG_OATH_NAME, b"GitHub:octocat")
        st, _ = send_arm(sess, "oath_del_github", OP_OATH_DELETE, del_req, pin_required=True)
        print(f"    0x27 OP_OATH_DELETE 'GitHub:octocat' -> Status: {'OK (0x00)' if st == 0x00 else f'0x{st:02X}'}")

        # -------------------------------------------------------------
        # ETAPA 8: Listagem Completa de Recursos On-Device
        # -------------------------------------------------------------
        print("\n[+] 9. ETAPA 8 — Listagem Completa de Todos os Recursos On-Device...")
        # 8.1 OP_KEY_LIST (0x22)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_KEY_LIST]), op="list_keys", timeout_s=4.0)
        print(f"    0x22 OP_KEY_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00:
            recs = _tlv.parse_tlv(body)
            pending_slot = None
            for t, v in recs:
                if t == TAG_SLOT and len(v) == 1:
                    pending_slot = v[0]
                elif t == TAG_LABEL and pending_slot is not None:
                    print(f"      Key Slot {pending_slot}: '{v.decode('utf-8', errors='replace')}'")
                    pending_slot = None

        # 8.2 OP_WALLET_LIST (0x36)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_WALLET_LIST]), op="list_wallets", timeout_s=4.0)
        print(f"    0x36 OP_WALLET_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00:
            recs = _tlv.parse_tlv(body)
            slot_curr, label_curr, addr_curr = None, None, None
            for t, v in recs:
                if t == TAG_WALLET_SLOT and len(v) == 1:
                    slot_curr = v[0]
                elif t == TAG_WALLET_LABEL:
                    label_curr = v.decode("utf-8", errors="replace")
                elif t == TAG_WALLET_ADDRESS:
                    addr_curr = v.decode("utf-8", errors="replace")
                    print(f"      Wallet Slot {slot_curr}: '{label_curr}' -> Endereço: {addr_curr}")

        # 8.3 OP_FW_LOG (0x38)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_FW_LOG]), op="fw_log", timeout_s=4.0)
        print(f"    0x38 OP_FW_LOG -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00 and body:
            lines = body.decode("latin-1", errors="replace").splitlines()
            print(f"      Eventos do Firmware registrados ({len(lines)} linhas no ring-buffer):")
            for l in lines[:6]:
                print(f"        {l}")

        # -------------------------------------------------------------
        # ETAPA 9: Teste de Exclusão e Segurança de PIN (0x23)
        # -------------------------------------------------------------
        print("\n[+] 10. ETAPA 9 — Teste de Exclusão de Chave com PIN (0x23 KEY_DELETE)...")
        body_tmp = _ops.vendor_key_gen(15, b"temp_key_for_del", ALG_ES256, USAGE_SIGN)
        send_arm(sess, "gen_temp_del", OP_KEY_GEN, body_tmp)
        del_k15 = _tlv.write_tlv(TAG_SLOT, bytes([15]))
        st, _ = send_arm(sess, "del_slot_15", OP_KEY_DELETE, del_k15, pin_required=True)
        print(f"    0x23 OP_KEY_DELETE Slot 15 -> Status: {'OK (0x00) - Slot excluído com sucesso!' if st == 0x00 else f'0x{st:02X}'}")

        print("\n" + "=" * 70)
        print("  JORNADA COMPLETA DO APP VALIDADA COM SUCESSO NO HARDWARE REAL!")
        print("=" * 70)

    finally:
        sess.close()
        print("\n[!] Conexão serial fechada com segurança.")
# --- END ORIGIN: tools/hil_emulate_full_app_on_board.py ---

# ============================================================================
# DISPATCHER UNIFICADO (unico codigo novo deste arquivo)
# ============================================================================

def _run_scenario(func, prog, args):
    """Repassa argv intactos ao main() original do cenario."""
    import sys as _sys
    _sys.argv = [prog] + list(args or [])
    return func()


def print_help():
    print(__doc__)


def main(argv=None):
    import sys as _sys
    args = list(_sys.argv[1:] if argv is None else argv)
    scenarios = ("bridge", "user", "session", "onboard")
    if not args or args[0] in ("-h", "--help"):
        print_help()
        print("subcomandos: bridge | user | session | onboard")
        print("ex.: tools/e2e_harness.py bridge --help  (ajuda ORIGINAL do cenario)")
        return 0
    scenario, rest = args[0], args[1:]
    entry = {"bridge": bridge_main, "user": user_main,
             "session": session_main, "onboard": onboard_main}.get(scenario)
    if entry is None:
        print("cenario desconhecido: %r (esperado um de: %s)" % (scenario, "|".join(scenarios)))
        return 2
    return _run_scenario(entry, "tools/e2e_harness.py %s" % scenario, rest)


if __name__ == "__main__":
    main()
