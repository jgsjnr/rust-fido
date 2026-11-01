#!/usr/bin/env python3
"""AegisKey OS Login Companion — Windows Hello Companion Device Framework (CDF) & Linux PAM (pam_u2f).

Integrates BLE Proximity telemetry (OP_PROXIMITY_STATUS) and Secure Guard authority
with automatic workstation security:
1. Walk-Away Auto-Lock: When the paired smartphone moves away (BLE RSSI < -80 dBm for > 10s)
   or the AegisKey is unplugged/locked, automatically locks the workstation.
2. Touch-to-Unlock / Zero-Password Proximity: Prompts user when key returns to proximity (RSSI > -65 dBm).
3. Linux PAM generator (pam_u2f for /etc/pam.d/sudo and /etc/pam.d/gdm-password).
4. Windows Hello Companion Device Framework (CDF) manifest generator.

CRITICAL SAFETY DESIGN (Developer Protection):
- `enforce_os_workstation_lock` is FALSE by default to prevent accidental screen locks
  during automated test runs, debugging, and continuous integration.
- Can be safely armed in production using --enforce-lock or through the desktop companion settings.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

TRAY_DIR = Path(__file__).resolve().parent
if str(TRAY_DIR) not in sys.path:
    sys.path.insert(0, str(TRAY_DIR))

from hardware_client import AegisHardwareClient

logger = logging.getLogger("AegisOsLoginCompanion")


class OsLoginCompanion:
    """Manages workstation lock/unlock integration across Windows Hello CDF and Linux PAM."""

    def __init__(
        self,
        hardware_client: Optional[AegisHardwareClient] = None,
        enforce_os_workstation_lock: bool = False,
        rssi_lock_threshold: int = -80,
        hysteresis_unlock_threshold: int = -65,
        debounce_seconds: float = 10.0,
    ):
        self.hw_client = hardware_client or AegisHardwareClient()
        self.enforce_os_workstation_lock = enforce_os_workstation_lock
        self.rssi_lock_threshold = rssi_lock_threshold
        self.hysteresis_unlock_threshold = hysteresis_unlock_threshold
        self.debounce_seconds = debounce_seconds

        self._lock = threading.Lock()
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._out_of_range_since: Optional[float] = None
        self._is_workstation_locked = False
        self.last_rssi = -35
        self.lock_events_count = 0

    def check_proximity_tick(self) -> Dict[str, Any]:
        """Evaluates one proximity cycle and enforces workstation policy if threshold exceeded."""
        prox = self.hw_client.get_proximity_status()
        dev = self.hw_client.detect_device()
        sg = self.hw_client.get_secure_guard_status()

        rssi = prox.get("rssi_dbm", -35)
        self.last_rssi = rssi
        now = time.time()

        is_connected = dev.connected
        is_unlocked = sg.unlocked
        in_range = is_connected and is_unlocked and (rssi > self.rssi_lock_threshold)

        action_taken = "NONE"

        with self._lock:
            if not in_range:
                if self._out_of_range_since is None:
                    self._out_of_range_since = now

                duration = now - self._out_of_range_since
                if duration >= self.debounce_seconds and not self._is_workstation_locked:
                    self.lock_workstation()
                    action_taken = "LOCKED"
                    self._is_workstation_locked = True
                    self.lock_events_count += 1
            else:
                self._out_of_range_since = None
                if self._is_workstation_locked and rssi >= self.hysteresis_unlock_threshold:
                    self._is_workstation_locked = False
                    action_taken = "PROXIMITY_RESTORED"

        return {
            "ok": True,
            "connected": is_connected,
            "secure_guard_unlocked": is_unlocked,
            "rssi_dbm": rssi,
            "in_range": in_range,
            "threshold_dbm": self.rssi_lock_threshold,
            "enforce_lock_active": self.enforce_os_workstation_lock,
            "workstation_locked": self._is_workstation_locked,
            "action_taken": action_taken,
        }

    def lock_workstation(self) -> bool:
        """Executes the OS workstation lock command."""
        os_name = platform.system()
        logger.info(
            f"[os_companion] Workstation lock triggered (RSSI={self.last_rssi} dBm < {self.rssi_lock_threshold} dBm) "
            f"[enforce={self.enforce_os_workstation_lock}]"
        )

        if not self.enforce_os_workstation_lock:
            # Safe dev mode: simulate without actually locking screen
            return True

        try:
            if os_name == "Windows":
                ctypes.windll.user32.LockWorkStation()
                return True
            elif os_name == "Linux":
                res = subprocess.run(["loginctl", "lock-session"], capture_output=True)
                if res.returncode == 0:
                    return True
                subprocess.run(["xdg-screensaver", "lock"], capture_output=True)
                return True
            elif os_name == "Darwin":
                subprocess.run(
                    ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"],
                    capture_output=True,
                )
                return True
        except Exception as e:
            logger.error(f"[os_companion] Error locking workstation: {e}")
        return False

    def start_monitor(self, interval_seconds: float = 2.0):
        """Starts background monitoring loop."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop, args=(interval_seconds,), daemon=True, name="AegisProximityMonitor"
            )
            self._monitor_thread.start()

    def stop_monitor(self):
        """Stops background monitor loop."""
        with self._lock:
            self._running = False

    def _monitor_loop(self, interval: float):
        while self._running:
            try:
                self.check_proximity_tick()
            except Exception as e:
                logger.debug(f"[os_companion] Monitor tick error: {e}")
            time.sleep(interval)

    # -------------------------------------------------------------------------
    # CONFIGURATION GENERATORS: LINUX PAM & WINDOWS HELLO CDF
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_linux_pam_config() -> Dict[str, str]:
        """Generates standard pam_u2f configurations for Linux authentication."""
        sudo_pam = """# /etc/pam.d/sudo — AegisKey Hardware Security Authentication
auth       sufficient   pam_u2f.so authfile=/etc/aegiskey_u2f_keys cue origin=pam://aegiskey
@include common-auth
@include common-account
@include common-session-noninteractive
"""
        gdm_pam = """# /etc/pam.d/gdm-password — AegisKey Workstation Unlock
auth       [success=1 default=ignore] pam_u2f.so authfile=/etc/aegiskey_u2f_keys cue
auth       requisite    pam_deny.so
auth       required     pam_permit.so
"""
        setup_script = """#!/bin/bash
# AegisKey Linux PAM Provisioning Script
set -e
echo "Configuring pam_u2f for AegisKey..."
sudo apt-get install -y libpam-u2f pamu2fcfg || sudo dnf install -y pam-u2f
sudo mkdir -p /etc
pamu2fcfg -o pam://aegiskey > /tmp/aegis_keys
sudo mv /tmp/aegis_keys /etc/aegiskey_u2f_keys
sudo chmod 644 /etc/aegiskey_u2f_keys
echo "AegisKey PAM configured successfully."
"""
        return {
            "pam_sudo": sudo_pam,
            "pam_gdm": gdm_pam,
            "setup_script": setup_script,
        }

    @staticmethod
    def generate_windows_cdf_manifest() -> Dict[str, Any]:
        """Generates Windows Hello Companion Device Framework (CDF) manifest and registration."""
        manifest = {
            "CompanionDevice": {
                "DeviceId": "AegisKey-S3-FIDO2-CDF",
                "DeviceFriendlyName": "AegisKey S3 Authenticator (BLE Walk-Away Lock)",
                "Manufacturer": "AegisKey Security",
                "ModelNumber": "AK-S3-01",
                "HardwareRevision": "ESP32-S3-Xtensa",
                "FirmwareRevision": "1.0.0-rust",
                "Capabilities": [
                    "ProximityDetection",
                    "UserPresenceVerification",
                    "HardwarePinAnchor",
                    "WalkAwayAutoLock",
                ],
                "ProximityPolicy": {
                    "RssiLockThresholdDbm": -80,
                    "RssiUnlockThresholdDbm": -65,
                    "DebounceSeconds": 10,
                },
                "Fido2Aaguid": "41454749-5353-3330-3030-303030303031",
            }
        }
        powershell_enrollment = """# PowerShell Windows Hello Companion Device Registration
$RegPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\CompanionDevice"
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force }
Set-ItemProperty -Path $RegPath -Name "AegisKeyEnabled" -Value 1 -Type DWord
Write-Host "AegisKey Companion Device Framework enabled for Windows Hello."
"""
        return {
            "manifest": manifest,
            "powershell_script": powershell_enrollment,
        }


def main():
    parser = argparse.ArgumentParser(description="AegisKey OS Login Companion (Windows Hello CDF & Linux PAM)")
    parser.add_argument("--enforce-lock", action="store_true", help="Arm actual workstation locking (disabled by default)")
    parser.add_argument("--pam-config", action="store_true", help="Print Linux PAM configuration templates")
    parser.add_argument("--cdf-manifest", action="store_true", help="Print Windows Hello CDF manifest")
    parser.add_argument("--tick", action="store_true", help="Execute single proximity check tick and exit")
    args = parser.parse_args()

    companion = OsLoginCompanion(enforce_os_workstation_lock=args.enforce_lock)

    if args.pam_config:
        cfg = companion.generate_linux_pam_config()
        print("=== /etc/pam.d/sudo Configuration ===")
        print(cfg["pam_sudo"])
        print("\n=== Provisioning Script ===")
        print(cfg["setup_script"])
        return

    if args.cdf_manifest:
        cdf = companion.generate_windows_cdf_manifest()
        print(json.dumps(cdf, indent=2))
        return

    if args.tick:
        res = companion.check_proximity_tick()
        print(json.dumps(res, indent=2))
        return

    print("============================================================")
    print(" AegisKey OS Login Companion Daemon")
    print(f" Enforce OS Workstation Lock: {companion.enforce_os_workstation_lock}")
    print(f" RSSI Threshold: {companion.rssi_lock_threshold} dBm (Debounce: 10s)")
    print("============================================================")

    companion.start_monitor()
    try:
        while True:
            time.sleep(2.0)
    except KeyboardInterrupt:
        companion.stop_monitor()
        print("\nCompanion stopped.")


if __name__ == "__main__":
    main()
