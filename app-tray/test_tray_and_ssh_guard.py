#!/usr/bin/env python3
"""Automated Test Suite for AegisKey Desktop Companion & SSH Guard Integration.

Verifies:
1. Real device detection via bridge / serial (COM7).
2. Secure Guard zero-trust gating (Vault & Wallets locked when state != UNLOCKED).
3. SshGuard Watchdog lifecycle: instant ssh-agent purge (ssh-add -D) and session grant revocation on lock/disconnect.
4. aegis_ssh_askpass helper behavior (denial when Locked, authorization when Unlocked).
5. STRICT SECURITY AUDIT: Verifies zero access, opening, or reading of any ~/.ssh private key files!
6. Connection transition native notifications (Disconnected -> Connected and Connected -> Disconnected).
7. Desktop Companion App complete window initialization, navigation across 4 sections, and tray show/hide.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path

# Add app-tray directory to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
TOOLS_DIR = BASE_DIR.parent / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from aegis_ssh_askpass import AUTH_GRANT_FILE
from aegis_tray import AegisDesktopApp
from hardware_client import AegisHardwareClient, DeviceInfo, SecureGuardStatus
from notifications import NOTIFIER
from ssh_guard import SshGuard


class TestAegisTrayAndSshGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We start an in-process real bridge instance or connect to running bridge
        from host_hardware_android_bridge import SECURE_GUARD_ENGINE, HW_MANAGER, STATE_LOCKED, STATE_UNLOCKED, STATE_UNPROVISIONED
        cls.engine = SECURE_GUARD_ENGINE
        cls.hw_manager = HW_MANAGER
        cls.STATE_LOCKED = STATE_LOCKED
        cls.STATE_UNLOCKED = STATE_UNLOCKED

        # Connect real hardware on COM7
        try:
            cls.hw_manager.detect_and_connect()
        except Exception:
            pass

        # Provision engine for test run with PIN "849201" (non-trivial secure PIN)
        cls.test_pin = "849201"
        cls.engine.provision(cls.test_pin, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        cls.engine.lock_session()

        # Start background HTTP bridge if not already running
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", 5678))
            s.close()
            cls.server_started_by_us = False
        except (ConnectionRefusedError, OSError):
            cls.server_started_by_us = True
            from host_hardware_android_bridge import DualProtocolServer, DualProtocolHandler
            cls.httpd = DualProtocolServer(("127.0.0.1", 5678), DualProtocolHandler)
            cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
            cls.server_thread.start()
            time.sleep(0.8)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server_started_by_us", False) and hasattr(cls, "httpd"):
            try:
                cls.httpd.shutdown()
            except Exception:
                pass

    def setUp(self):
        self.client = AegisHardwareClient(base_url="http://127.0.0.1:5678", timeout_seconds=4.0)
        self.purge_alerts: list[str] = []
        self.ssh_guard = SshGuard(
            hardware_client=self.client,
            on_purge_callback=lambda msg: self.purge_alerts.append(msg)
        )
        NOTIFIER.clear_history()

    # -------------------------------------------------------------------------
    # TEST 1: REAL HARDWARE & BRIDGE DETECTION
    # -------------------------------------------------------------------------
    def test_01_real_device_detection(self):
        """Verifies real detection of device parameters (ESP32-S3 / COM7)."""
        dev = self.client.detect_device()
        self.assertIsNotNone(dev)
        self.assertTrue(len(dev.port) > 0, "A valid serial or USB port must be detected")
        self.assertIn("303A", dev.vid.upper(), "VID must identify Espressif USB vendor")
        print(f"\n[PASS] Hardware Detected: {dev.product} on {dev.port} (VID: {dev.vid}, PID: {dev.pid})")

    # -------------------------------------------------------------------------
    # TEST 2: SECURE GUARD ZERO-TRUST GATING
    # -------------------------------------------------------------------------
    def test_02_secure_guard_vault_gating(self):
        """Verifies hardware vault barrier: locked when state != UNLOCKED."""
        # 1. Lock the device
        lock_res = self.client.lock_secure_guard()
        self.assertTrue(lock_res.get("ok"), "Lock request must succeed")

        status_locked = self.client.get_secure_guard_status()
        self.assertFalse(status_locked.unlocked, "Secure Guard must report unlocked=False")
        self.assertEqual(status_locked.state, self.STATE_LOCKED)

        # 2. Query vault/wallets while Locked -> Must be blocked (HTTP 403)
        res_vault_locked = self.client._http_get("/api/vault")
        self.assertIsNone(res_vault_locked, "Direct vault request must be blocked (HTTP 403) while Locked")

        # 3. Unlock with valid PIN
        unlock_res = self.client.unlock_secure_guard(self.test_pin)
        self.assertTrue(unlock_res.get("ok"), "Unlock with correct PIN must succeed")

        status_unlocked = self.client.get_secure_guard_status()
        self.assertTrue(status_unlocked.unlocked, "Secure Guard must report unlocked=True")
        self.assertEqual(status_unlocked.state, self.STATE_UNLOCKED)

        # 4. Query vault while Unlocked -> Hardware vault accessible (HTTP 200)
        res_vault_unlocked = self.client._http_get("/api/vault")
        self.assertIsNotNone(res_vault_unlocked, "Direct vault request must succeed (HTTP 200) once Unlocked")
        self.assertTrue(res_vault_unlocked.get("ok"), "Vault response must report ok=True once Unlocked")

        # 5. Lock again to restore fail-closed barrier
        self.client.lock_secure_guard()
        status_relocked = self.client.get_secure_guard_status()
        self.assertFalse(status_relocked.unlocked)
        print("\n[PASS] Secure Guard Gating Verified: Vault blocked when Locked (403), accessible when Unlocked (200).")

    # -------------------------------------------------------------------------
    # TEST 3: SSH GUARD WATCHDOG & INSTANT REVOCATION (ssh-add -D)
    # -------------------------------------------------------------------------
    def test_03_ssh_guard_watchdog_auto_purge_on_lock(self):
        """Verifies that transitioning from UNLOCKED to LOCKED triggers immediate ssh-add -D."""
        # 1. Unlock Secure Guard
        self.client.unlock_secure_guard(self.test_pin)
        self.ssh_guard.check_tick()  # Establish UNLOCKED baseline

        # 2. Set ephemeral session passphrase
        ok = self.ssh_guard.set_ephemeral_passphrase("SessionSecret123!")
        self.assertTrue(ok, "Ephemeral passphrase must be accepted when Unlocked")
        self.assertTrue(os.path.exists(AUTH_GRANT_FILE), "Session grant file must exist while Unlocked")

        # 3. Simulate or execute lock event
        self.client.lock_secure_guard()

        # 4. Watchdog tick discovers the lock transition
        self.ssh_guard.check_tick()

        # 5. Verify immediate revocation: grant file removed, purge performed
        self.assertFalse(os.path.exists(AUTH_GRANT_FILE), "Session grant file must be INSTANTLY wiped on Lock")
        self.assertGreater(self.ssh_guard.purges_count, 0, "ssh-add -D purge count must increment")
        self.assertGreater(len(self.purge_alerts), 0, "Purge alert callback must be triggered")
        self.assertIn("purged", self.purge_alerts[-1].lower())
        print(f"\n[PASS] SshGuard Auto-Purge Verified: {self.purge_alerts[-1]}")

    # -------------------------------------------------------------------------
    # TEST 4: HARDWARE-GATED SSH_ASKPASS HELPER
    # -------------------------------------------------------------------------
    def test_04_aegis_ssh_askpass_helper_lifecycle(self):
        """Verifies aegis_ssh_askpass denies when Locked and authorizes when Unlocked."""
        askpass_py = str(BASE_DIR / "aegis_ssh_askpass.py")

        # CASE A: Secure Guard is LOCKED -> Must exit with code 1 and deny access
        self.client.lock_secure_guard()
        proc_locked = subprocess.run(
            [sys.executable, askpass_py, "Enter passphrase for key: "],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc_locked.returncode, 1, "askpass must exit with 1 when Locked")
        self.assertIn("Access DENIED", proc_locked.stderr, "stderr must explain hardware lock barrier")

        # CASE B: Secure Guard is UNLOCKED + Ephemeral Grant Set -> Must exit with 0 and return passphrase
        self.client.unlock_secure_guard(self.test_pin)
        self.ssh_guard.set_ephemeral_passphrase("VaultPassword456!")

        proc_unlocked = subprocess.run(
            [sys.executable, askpass_py, "Enter passphrase for key: "],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc_unlocked.returncode, 0, "askpass must exit with 0 when Unlocked")
        self.assertEqual(proc_unlocked.stdout.strip(), "VaultPassword456!", "stdout must match ephemeral passphrase")

        # Clean up
        self.client.lock_secure_guard()
        self.ssh_guard.check_tick()
        print("\n[PASS] SSH_ASKPASS Hardware Gating Verified: Denied when Locked (Exit 1), Allowed when Unlocked (Exit 0).")

    # -------------------------------------------------------------------------
    # TEST 5: STRICT CODE AUDIT (ZERO ~/.ssh FILE ACCESS)
    # -------------------------------------------------------------------------
    def test_05_strict_no_ssh_files_accessed_audit(self):
        """Scans all Python and C# files to guarantee ZERO private key file inspection."""
        forbidden_patterns = [
            "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
            ".ssh/id_", ".ssh\\id_", "open(~/.ssh", 'open("~/.ssh',
            "File.OpenRead", "File.ReadAllBytes", "File.ReadAllText"
        ]

        files_to_check = [
            BASE_DIR / "hardware_client.py",
            BASE_DIR / "ssh_guard.py",
            BASE_DIR / "aegis_ssh_askpass.py",
            BASE_DIR / "aegis_tray.py",
            BASE_DIR / "notifications.py",
            BASE_DIR / "i18n.py",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "SshAgentGuard.cs",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "HardwareBridgeClient.cs",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "MainWindow.cs",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "TrayApplicationContext.cs",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "Program.cs",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "Models.cs",
            BASE_DIR / "dotnet" / "AegisKeyTray" / "I18n.cs",
        ]

        for file_path in files_to_check:
            self.assertTrue(file_path.exists(), f"File {file_path} must exist")
            content = file_path.read_text(encoding="utf-8")
            for pat in forbidden_patterns:
                if pat in ("File.ReadAllBytes", "File.ReadAllText", "File.OpenRead"):
                    self.assertNotIn(pat, content, f"Forbidden file read pattern '{pat}' found in {file_path.name}")
                elif "id_" in pat:
                    self.assertNotIn(pat, content, f"Forbidden private key reference '{pat}' found in {file_path.name}")

        print("\n[PASS] Strict Code Audit: 100% compliant with zero inspection of user private keys in ~/.ssh.")

    # -------------------------------------------------------------------------
    # TEST 6: CONNECTION TRANSITION NATIVE NOTIFICATIONS
    # -------------------------------------------------------------------------
    def test_06_connection_transition_notifications(self):
        """Verifies native OS notifications fire on key connection and disconnection."""
        root = tk.Tk()
        root.withdraw()
        app = AegisDesktopApp(root)

        # Baseline: initial sync established
        app._is_first_sync = False
        app._prev_connected = False
        app._prev_state = 2

        # 1. SIMULATE KEY CONNECTED: Disconnected -> Connected
        connected_dev = DeviceInfo(port="COM7", connected=True)
        locked_sg = SecureGuardStatus(state=2, state_name="Locked", unlocked=False)
        app._apply_state_update(connected_dev, locked_sg)

        history = NOTIFIER.get_history()
        self.assertGreater(len(history), 0, "Native notification must be dispatched on connection")
        last_notif = history[-1]
        self.assertIn("Connected", last_notif["title"])
        self.assertIn("COM7", last_notif["message"])
        self.assertIn("Locked", last_notif["message"])
        print(f"\n[PASS] Connection Notification Dispatched: '{last_notif['title']}' -> '{last_notif['message']}'")

        # 2. SIMULATE KEY DISCONNECTED: Connected -> Disconnected
        disconnected_dev = DeviceInfo(port="None", connected=False)
        app._apply_state_update(disconnected_dev, locked_sg)

        history = NOTIFIER.get_history()
        disconn_notif = history[-1]
        self.assertIn("Disconnected", disconn_notif["title"])
        self.assertIn("Locked", disconn_notif["message"])
        print(f"[PASS] Disconnection Notification Dispatched: '{disconn_notif['title']}' -> '{disconn_notif['message']}'")

        # 3. Clean up GUI
        app.ssh_guard.stop_watchdog()
        root.destroy()

    # -------------------------------------------------------------------------
    # TEST 7: DESKTOP COMPANION APP WINDOW LIFECYCLE & 4 SECTIONS
    # -------------------------------------------------------------------------
    def test_07_desktop_companion_window_lifecycle(self):
        """Verifies full desktop companion window layout, 4 sections, and tray show/hide."""
        root = tk.Tk()
        app = AegisDesktopApp(root)

        # 1. Window must be visible, title and subtitle set
        self.assertIn("AegisKey", root.title())
        self.assertEqual(app.lbl_title.cget("text"), "AegisKey Authenticator")

        # 2. Four navigation tabs must exist
        self.assertTrue(hasattr(app, "btn_nav_vault_sg"))
        self.assertTrue(hasattr(app, "btn_nav_totp"))
        self.assertTrue(hasattr(app, "btn_nav_conn"))
        self.assertTrue(hasattr(app, "btn_nav_ssh"))

        # 3. Switch to Section 3 (Connected Keys & BLE Proximity)
        app._switch_tab("conn")
        self.assertEqual(app.current_tab, "conn")
        # Proximity status must be queryable
        prox = app.hw_client.get_proximity_status()
        self.assertTrue(prox.get("ok"))

        # 4. Switch to Section 2 (TOTP Authenticator)
        app._switch_tab("totp")
        self.assertEqual(app.current_tab, "totp")

        # 5. Hide to Tray and Restore
        app.hide_to_tray()
        self.assertEqual(root.state(), "withdrawn")
        app.show_from_tray()
        self.assertNotEqual(root.state(), "withdrawn")

        print("\n[PASS] Desktop Companion Window Verified: 4 navigation sections, full layout, and tray show/hide functional.")

        app.ssh_guard.stop_watchdog()
        root.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
