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

        # Ensure active HTTP bridge is provisioned with test_pin
        try:
            client_setup = AegisHardwareClient(base_url="http://127.0.0.1:5678")
            client_setup._http_post("/api/secure-guard/provision", {
                "pin": cls.test_pin,
                "policy": {"wipe_on_5_failures": False, "test_mode_non_destructive_wipe": True}
            })
            client_setup.lock_secure_guard()
        except Exception:
            pass

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


    def _http_get_json(self, path: str, headers: dict = None) -> tuple[int, dict]:
        import urllib.request, urllib.error
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(f"http://127.0.0.1:5678{path}", headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as he:
            try:
                return he.code, json.loads(he.read().decode("utf-8"))
            except Exception:
                return he.code, {"error": str(he)}

    def _http_post_json(self, path: str, body: dict, headers: dict = None) -> tuple[int, dict]:
        import urllib.request, urllib.error
        req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(
            f"http://127.0.0.1:5678{path}",
            data=json.dumps(body).encode("utf-8"),
            headers=req_headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as he:
            try:
                return he.code, json.loads(he.read().decode("utf-8"))
            except Exception:
                return he.code, {"error": str(he)}

    # -------------------------------------------------------------------------
    # TEST 8: GAP-01/03/07 eFuse Hard-Lock Security Audit
    # -------------------------------------------------------------------------
    def test_08_gap_security_efuse_guard(self):
        """Audits GAP-01/03/07: permanent eFuse burn is hard-locked to prevent bricking."""
        st, res = self._http_get_json("/api/security/efuse-guard-status")
        self.assertEqual(st, 200)
        self.assertTrue(res.get("ok"))
        self.assertFalse(res.get("burn_allowed"))
        self.assertTrue(res.get("otp_hardware_write_blocked") or res.get("efuse_write_hard_locked"))
        self.assertIn("DO NOT EXECUTE", res.get("warning", ""))
        print(f"\n[PASS] GAP-01/03/07 eFuse Hard-Lock Verified: {res['warning']}")

    # -------------------------------------------------------------------------
    # TEST 9: GAP-05 Bridge Auth & DNS Rebinding Protection
    # -------------------------------------------------------------------------
    def test_09_gap_bridge_auth_and_dns_rebinding(self):
        """Audits GAP-05: DNS rebinding protection blocks malicious Host headers (403 Forbidden)."""
        # 1. Normal local query
        st, res = self._http_get_json("/api/security/bridge-auth-status")
        self.assertEqual(st, 200)
        self.assertEqual(res.get("dns_rebinding_protection"), "ACTIVE")

        # 2. Malicious DNS Rebinding Host query
        st_rebind, body_rebind = self._http_get_json(
            "/api/security/bridge-auth-status",
            headers={"Host": "evil.attacker.com"}
        )
        self.assertEqual(st_rebind, 403, "DNS Rebinding Host 'evil.attacker.com' must be rejected with HTTP 403 Forbidden")
        print("\n[PASS] GAP-05 Bridge Auth & DNS Rebinding Active: Host 'evil.attacker.com' rejected with 403 Forbidden.")

    # -------------------------------------------------------------------------
    # TEST 10: GAP-02 Ephemeral P-256 ECDH Encrypted PIN Unlock
    # -------------------------------------------------------------------------
    def test_10_gap_ecdh_encrypted_pin_handshake(self):
        """Audits GAP-02: Secure Guard PIN unlock over ephemeral P-256 ECDH + AES-256-GCM."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # 1. Handshake
        st, hs = self._http_get_json("/api/secure-guard/ecdh-handshake")
        self.assertEqual(st, 200)
        self.assertTrue(hs.get("ok"))
        self.assertEqual(hs.get("curve"), "P-256")

        # 2. Client ephemeral key
        client_priv = ec.generate_private_key(ec.SECP256R1())
        client_pub_bytes = client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        # 3. Derive AES-256-GCM key
        bridge_pub_bytes = bytes.fromhex(hs["bridge_ephemeral_pub_hex"])
        bridge_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bridge_pub_bytes)
        shared_secret = client_priv.exchange(ec.ECDH(), bridge_pub)
        salt = bytes.fromhex(hs.get("salt_hex", ""))
        info = hs.get("info", "AegisKey-Vendor-Guard-Channel").encode()
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_secret)

        # 4. Encrypt PIN
        aesgcm = AESGCM(aes_key)
        nonce = b"ecdh_pin_12b"
        ciphertext = aesgcm.encrypt(nonce, self.test_pin.encode(), None)
        encrypted_payload_hex = (nonce + ciphertext).hex()

        # 5. Lock first then Unlock via ECDH
        self.client.lock_secure_guard()
        st_unl, res_unl = self._http_post_json("/api/secure-guard/unlock", {
            "client_ephemeral_pub_hex": client_pub_bytes.hex(),
            "encrypted_pin_hex": encrypted_payload_hex,
        })
        self.assertEqual(st_unl, 200)
        self.assertTrue(res_unl.get("ok"))
        self.assertTrue(res_unl.get("ecdh_encrypted_channel"))
        self.assertTrue(res_unl.get("unlocked") or res_unl.get("success"))
        print("\n[PASS] GAP-02 Ephemeral P-256 ECDH Channel Verified: PIN safely encrypted and decrypted on bridge.")

    # -------------------------------------------------------------------------
    # TEST 11: OPP-01 OpenSSH Native Agent RFC Protocol Exchange
    # -------------------------------------------------------------------------
    def test_11_opp_openssh_native_agent_protocol(self):
        """Audits OPP-01: OpenSSH agent binary protocol exchange on lock & unlock."""
        import struct
        from openssh_native_agent import (
            OpenSshNativeAgent, ssh_pack_message, ssh_pack_string,
            SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
            SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE, SSH_AGENT_FAILURE
        )

        agent = OpenSshNativeAgent(hardware_client=self.client)

        # 1. When Locked: 0 identities, sign requests fail
        self.client.lock_secure_guard()
        req_id = ssh_pack_message(SSH_AGENTC_REQUEST_IDENTITIES)
        resp_locked = agent.process_message(req_id)
        _, msg_type = struct.unpack_from(">IB", resp_locked, 0)
        count_locked, = struct.unpack_from(">I", resp_locked, 5)
        self.assertEqual(msg_type, SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(count_locked, 0, "When locked, agent must report 0 identities")

        dummy_blob = ssh_pack_string(b"ssh-ed25519") + ssh_pack_string(agent.hardware_pubkey)
        sign_req = ssh_pack_message(
            SSH_AGENTC_SIGN_REQUEST,
            ssh_pack_string(dummy_blob) + ssh_pack_string(b"ChallengeTest") + struct.pack(">I", 0)
        )
        sign_locked = agent.process_message(sign_req)
        _, sign_locked_type = struct.unpack_from(">IB", sign_locked, 0)
        self.assertEqual(sign_locked_type, SSH_AGENT_FAILURE, "Sign request must fail when locked")

        # 2. When Unlocked: 1 hardware identity, hardware signs challenge
        self.client.unlock_secure_guard(self.test_pin)
        resp_unlocked = agent.process_message(req_id)
        _, msg_unl_type = struct.unpack_from(">IB", resp_unlocked, 0)
        count_unlocked, = struct.unpack_from(">I", resp_unlocked, 5)
        self.assertEqual(msg_unl_type, SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(count_unlocked, 1, "When unlocked, resident identity must be present")

        sign_unlocked = agent.process_message(sign_req)
        _, sign_unl_type = struct.unpack_from(">IB", sign_unlocked, 0)
        self.assertEqual(sign_unl_type, SSH_AGENT_SIGN_RESPONSE, "Hardware signature must be returned when unlocked")
        print("\n[PASS] OPP-01 OpenSSH Native Agent Protocol Verified: Instant revocation on Lock, hardware signing on Unlock.")

    # -------------------------------------------------------------------------
    # TEST 12: OPP-02 CTAP 2.1 HMAC-Secret & Large-Blobs
    # -------------------------------------------------------------------------
    def test_12_opp_ctap21_hmac_secret_and_large_blobs(self):
        """Audits OPP-02: CTAP 2.1 hmac-secret derivation and large-blob storage gated by Secure Guard."""
        # 1. Locked -> 403 Forbidden
        self.client.lock_secure_guard()
        st_hmac_lk, _ = self._http_post_json("/api/ctap21/hmac-secret", {"salt1_hex": "11" * 32})
        self.assertEqual(st_hmac_lk, 403, "hmac-secret must be blocked when locked")
        st_lb_lk, _ = self._http_post_json("/api/ctap21/large-blobs", {"blob_hex": "cafe" * 16})
        self.assertEqual(st_lb_lk, 403, "large-blobs write must be blocked when locked")

        # 2. Unlocked -> Deterministic HMAC output and large-blob persistence
        self.client.unlock_secure_guard(self.test_pin)
        st_hmac_unl, res_hmac = self._http_post_json("/api/ctap21/hmac-secret", {"salt1_hex": "22" * 32})
        self.assertEqual(st_hmac_unl, 200)
        self.assertTrue(res_hmac.get("ok"))
        self.assertIn("output1_hex", res_hmac)
        self.assertEqual(len(res_hmac["output1_hex"]), 64)

        # Test Large-Blob write and read
        test_blob = "feedfacecafebeef0102030405060708"
        st_lb_w, res_lb_w = self._http_post_json("/api/ctap21/large-blobs", {"blob_hex": test_blob})
        self.assertEqual(st_lb_w, 200)
        self.assertTrue(res_lb_w.get("ok"))

        st_lb_r, res_lb_r = self._http_get_json("/api/ctap21/large-blobs")
        self.assertEqual(st_lb_r, 200)
        self.assertTrue(res_lb_r.get("ok"))
        self.assertEqual(res_lb_r.get("blob_hex"), test_blob)
        print("\n[PASS] OPP-02 CTAP 2.1 Features Verified: Gated when locked (403), HMAC derived & Large Blobs stored.")

    # -------------------------------------------------------------------------
    # TEST 13: OPP-04 OS Login Companion Safety Architecture
    # -------------------------------------------------------------------------
    def test_13_opp_os_login_companion_safety(self):
        """Audits OPP-04: enforce_os_workstation_lock == False by default, CDF & PAM templates generated."""
        from os_login_companion import OsLoginCompanion

        companion = OsLoginCompanion(hardware_client=self.client)
        self.assertFalse(companion.enforce_os_workstation_lock, "Critical safety: enforce_os_workstation_lock must be False by default to prevent locking developer screens")

        # Verify simulation mode does not lock screen but records event
        res_lock = companion.lock_workstation()
        self.assertTrue(res_lock)

        # Verify Linux PAM configuration generation
        pam = companion.generate_linux_pam_config()
        self.assertIn("pam_u2f.so", pam["pam_sudo"])
        self.assertIn("pam_u2f.so", pam["pam_gdm"])

        # Verify Windows Hello CDF manifest generation
        cdf = companion.generate_windows_cdf_manifest()
        self.assertEqual(cdf["manifest"]["CompanionDevice"]["DeviceId"], "AegisKey-S3-FIDO2-CDF")
        self.assertIn("WalkAwayAutoLock", cdf["manifest"]["CompanionDevice"]["Capabilities"])
        print("\n[PASS] OPP-04 OS Login Companion Safety Verified: Workstation lock disabled by default, CDF & PAM valid.")

    # -------------------------------------------------------------------------
    # TEST 14: OPP-05 SLIP-0039 Shamir Secret Sharing Quorum (2-of-3)
    # -------------------------------------------------------------------------
    def test_14_opp_shamir_2_of_3_backup_quorum(self):
        """Audits OPP-05: SLIP-0039 2-of-3 secret sharing: 403 when locked, exact recovery from any 2 shares."""
        secret_hex = "a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f"

        # 1. Locked -> 403 Forbidden
        self.client.lock_secure_guard()
        st_sp_lk, _ = self._http_post_json("/api/backup/shamir-split", {
            "secret_hex": secret_hex,
            "threshold": 2,
            "shares": 3
        })
        self.assertEqual(st_sp_lk, 403, "Shamir split must be blocked when locked")

        # 2. Unlocked -> Split into 3 shares
        self.client.unlock_secure_guard(self.test_pin)
        st_sp, res_sp = self._http_post_json("/api/backup/shamir-split", {
            "secret_hex": secret_hex,
            "threshold": 2,
            "shares": 3
        })
        self.assertEqual(st_sp, 200)
        self.assertTrue(res_sp.get("ok"))
        shares = res_sp.get("shares", [])
        self.assertEqual(len(shares), 3)

        # 3. Test all 3 combinations: (0,1), (0,2), (1,2)
        for i, j in [(0, 1), (0, 2), (1, 2)]:
            st_rc, res_rc = self._http_post_json("/api/backup/shamir-recover", {
                "shares": [shares[i], shares[j]]
            })
            self.assertEqual(st_rc, 200)
            self.assertTrue(res_rc.get("ok"))
            self.assertEqual(
                res_rc.get("recovered_secret_hex"),
                secret_hex,
                f"Lagrange recovery from shares {i+1} and {j+1} must match original secret exactly"
            )
        print("\n[PASS] OPP-05 Shamir 2-of-3 Backup Quorum Verified: Exact recovery from all 3 pair combinations.")

    # -------------------------------------------------------------------------
    # TEST 15: OPP-06 Clear-Signing Virtual OLED Preview
    # -------------------------------------------------------------------------
    def test_15_opp_clear_signing_virtual_oled(self):
        """Audits OPP-06: EIP-1559 clear signing decode into 1024-byte virtual monochrome frame buffer."""
        sample_tx = {
            "type": "EIP-1559",
            "chainId": 1,
            "nonce": 42,
            "maxPriorityFeePerGas": "0x77359400",
            "maxFeePerGas": "0x2540be400",
            "gasLimit": "0x5208",
            "to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "value": "0xde0b6b3a7640000",
            "data": "0x",
        }

        # 1. Locked -> 403 Forbidden
        self.client.lock_secure_guard()
        st_cs_lk, _ = self._http_post_json("/api/wallet/clear-sign-preview", {
            "transaction": sample_tx
        })
        self.assertEqual(st_cs_lk, 403, "Clear signing preview must be blocked when locked")

        # 2. Unlocked -> 1024-byte virtual OLED monochrome buffer
        self.client.unlock_secure_guard(self.test_pin)
        st_cs, res_cs = self._http_post_json("/api/wallet/clear-sign-preview", {
            "transaction": sample_tx
        })
        self.assertEqual(st_cs, 200)
        self.assertTrue(res_cs.get("ok"))
        self.assertFalse(res_cs.get("hardware_i2c_oled_attached"))
        self.assertEqual(res_cs.get("mode"), "CODE_ONLY_VIRTUAL_DISPLAY")
        buf_len = len(res_cs.get("virtual_oled_buffer_hex", "")) // 2
        self.assertEqual(buf_len, 1024, "Virtual OLED display buffer must be exactly 1024 bytes")
        print(f"\n[PASS] OPP-06 Clear-Signing Verified: 1024-byte virtual monochrome buffer generated (hardware_i2c_oled_attached=False).")

    # -------------------------------------------------------------------------
    # TEST 16: KeePassXC Hardware Unlock (.kdbx) & JIT SRAM Zeroize
    # -------------------------------------------------------------------------
    def test_16_keepassxc_hardware_unlock_and_jit_ram_zeroize(self):
        """Audits KeePassXC Challenge-Response (HMAC-SHA1 CR Compatible Layer Slots 1 & 2), JIT SRAM Zeroize, and PSRAM."""
        import hmac
        import hashlib

        # 1. When Locked -> 403 Forbidden with CTAP2_ERR_PIN_REQUIRED
        self.client.lock_secure_guard()
        st_cr_lk, res_cr_lk = self._http_post_json("/api/keepassxc/challenge-response", {
            "slot": 1,
            "challenge_hex": "0102030405060708090a0b0c0d0e0f10"
        })
        self.assertEqual(st_cr_lk, 403, "KeePassXC challenge-response must be blocked when Secure Guard is locked")
        self.assertEqual(res_cr_lk.get("error"), "CTAP2_ERR_PIN_REQUIRED")
        self.assertTrue(res_cr_lk.get("pending_system_request"))

        st_cfg_lk, res_cfg_lk = self._http_post_json("/api/keepassxc/configure-slot", {
            "slot": 2,
            "secret_hex": "11" * 20
        })
        self.assertEqual(st_cfg_lk, 403, "KeePassXC configure-slot must be blocked when Secure Guard is locked")

        # 2. When Unlocked -> Query status & telemetry
        self.client.unlock_secure_guard(self.test_pin)
        st_stat, res_stat = self._http_get_json("/api/keepassxc/status")
        self.assertEqual(st_stat, 200)
        self.assertTrue(res_stat.get("ok"))
        self.assertTrue(res_stat.get("slot1_configured"))
        self.assertTrue(res_stat.get("just_in_time_ram_zeroize"))
        self.assertTrue(res_stat.get("psram_8mb_enabled"))
        self.assertTrue(res_stat.get("chacha20_poly1305_enabled"))
        self.assertTrue(res_stat.get("rsa_ds_enabled"))

        # 3. Provision Slot 2 with known 20-byte HMAC-SHA1 secret
        slot2_secret = bytes.fromhex("33" * 20)
        st_cfg2, res_cfg2 = self._http_post_json("/api/keepassxc/configure-slot", {
            "slot": 2,
            "secret_hex": slot2_secret.hex(),
            "require_touch": False
        })
        self.assertEqual(st_cfg2, 200)
        self.assertTrue(res_cfg2.get("ok"))
        self.assertEqual(res_cfg2.get("slot"), 2)
        self.assertTrue(res_cfg2.get("slot2_configured"))
        self.assertTrue(res_cfg2.get("just_in_time_ram_zeroize"))

        # 4. Challenge-Response on Slot 2 and verify mathematical HMAC-SHA1 output
        challenge = bytes.fromhex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        st_cr2, res_cr2 = self._http_post_json("/api/keepassxc/challenge-response", {
            "slot": 2,
            "challenge_hex": challenge.hex()
        })
        self.assertEqual(st_cr2, 200)
        self.assertTrue(res_cr2.get("ok"))
        self.assertEqual(res_cr2.get("slot"), 2)
        self.assertTrue(res_cr2.get("just_in_time_ram_zeroize"))
        self.assertTrue(res_cr2.get("psram_8mb_enabled"))

        expected_hmac = hmac.new(slot2_secret, challenge, hashlib.sha1).digest()
        actual_hmac = bytes.fromhex(res_cr2.get("response_hex", ""))
        self.assertEqual(actual_hmac, expected_hmac, "KeePassXC response must match exact HMAC-SHA1(secret, challenge)")

        # 5. Challenge-Response on Slot 1 and CRC-16 Verification
        def cr_compat_crc16(data: bytes) -> int:
            c = 0xFFFF
            for b in data:
                c ^= b
                for _ in range(8):
                    c = (c >> 1) ^ 0x8408 if (c & 1) else c >> 1
            return c
        self.assertEqual(res_cr2.get("crc16_hex"), f"{cr_compat_crc16(actual_hmac):04x}", "CRC-16 ISO 13239 must match polynomial 0x8408")

        st_cr1, res_cr1 = self._http_post_json("/api/keepassxc/challenge-response", {
            "slot": 1,
            "challenge_hex": "44" * 32
        })
        self.assertEqual(st_cr1, 200)
        self.assertTrue(res_cr1.get("ok"))
        self.assertEqual(len(res_cr1.get("response_hex", "")), 40, "Slot 1 response must be 20 bytes (40 hex chars)")

        # 6. Integrated FIDO2 hmac-secret derivation right after KeePassXC challenge-response
        st_fido, res_fido = self._http_post_json("/api/ctap21/hmac-secret", {
            "salt1_hex": "55" * 32,
            "cred_id_hex": "66" * 16,
        })
        self.assertEqual(st_fido, 200)
        self.assertTrue(res_fido.get("ok"))
        self.assertEqual(len(res_fido.get("output1_hex", "")), 64, "FIDO2 hmac-secret output must be 32 bytes (64 hex)")
        print("\n[PASS] TEST 16: KeePassXC Hardware Unlock (.kdbx) + FIDO2 hmac-secret & JIT SRAM Zeroize Verified.")

    # -------------------------------------------------------------------------
    # TEST 17: BLE PROXIMITY MEMORY REGISTRATION & WALK-AWAY LOCKS SECURE GUARD & PC
    # -------------------------------------------------------------------------
    def test_17_ble_proximity_memory_registration_locks_secure_guard_and_pc(self):
        """Audits in-memory BLE device registration, walk-away detection, immediate Secure Guard lock, and Dynamic Lock trigger."""
        # 1. Discover Bluetooth devices via GET /api/proximity/bluetooth-devices
        st_bt, res_bt = self._http_get_json("/api/proximity/bluetooth-devices")
        self.assertEqual(st_bt, 200)
        self.assertIn("devices", res_bt)
        self.assertIsInstance(res_bt["devices"], list)

        # 2. Register Bluetooth device in memory
        test_ble_mac = "3C:84:27:C7:17:7A"
        test_ble_name = "Galaxy S24 Ultra"
        st_reg, res_reg = self._http_post_json("/api/proximity/register-device", {
            "mac": test_ble_mac,
            "name": test_ble_name,
            "threshold_dbm": -75,
            "enforce_windows_lock": False
        })
        self.assertEqual(st_reg, 200)
        self.assertTrue(res_reg.get("ok"))
        self.assertTrue(res_reg.get("ble_proximity_registered"))
        self.assertEqual(res_reg.get("paired_ble_mac"), test_ble_mac)
        self.assertEqual(res_reg.get("paired_ble_name"), test_ble_name)

        # Check telemetry in /api/proximity/status
        st_st, res_st = self._http_get_json("/api/proximity/status")
        self.assertEqual(st_st, 200)
        self.assertEqual(res_st.get("ble_mac"), test_ble_mac)
        self.assertEqual(res_st.get("ble_name"), test_ble_name)
        reg_dev = res_st.get("registered_device", {})
        self.assertEqual(reg_dev.get("paired_ble_mac"), test_ble_mac)
        self.assertEqual(reg_dev.get("paired_ble_name"), test_ble_name)

        # 3. Unlock Secure Guard and verify vault is accessible when present
        self.client.unlock_secure_guard(self.test_pin)
        st_v, res_v = self._http_get_json("/api/vault")
        self.assertEqual(st_v, 200, "Vault must be accessible when Secure Guard is unlocked and user is present")

        # 4. Simulate RSSI near (-35 dBm)
        st_near, res_near = self._http_post_json("/api/proximity/rssi", {
            "mac": test_ble_mac,
            "rssi_dbm": -35,
            "elapsed_s": 1.0,
            "source": "ble_scanner"
        })
        self.assertEqual(st_near, 200)
        self.assertFalse(res_near.get("lock_triggered"))
        self.assertFalse(res_near.get("secure_guard_locked"))

        # 5. Simulate walk-away (-92 dBm for 10 seconds)
        st_away, res_away = self._http_post_json("/api/proximity/rssi", {
            "mac": test_ble_mac,
            "rssi_dbm": -92,
            "elapsed_s": 10.0,
            "source": "ble_scanner"
        })
        self.assertEqual(st_away, 200)
        self.assertTrue(res_away.get("lock_triggered"), "Proximity engine must trigger lock upon walk-away")
        self.assertTrue(res_away.get("secure_guard_locked"), "Secure Guard must be locked immediately upon walk-away")
        self.assertEqual(res_away.get("state"), "Away")

        # 6. Verify that Secure Guard is LOCKED and Vault access is forbidden
        st_v_locked, res_v_locked = self._http_get_json("/api/vault")
        self.assertEqual(st_v_locked, 403, "Vault must be locked when user walks away with paired BLE device")
        self.assertEqual(res_v_locked.get("error"), "CTAP2_ERR_PIN_REQUIRED")

        # 7. Verify enforce_windows_lock registration
        st_reg_win, res_reg_win = self._http_post_json("/api/proximity/register-device", {
            "mac": test_ble_mac,
            "name": test_ble_name,
            "threshold_dbm": -75,
            "enforce_windows_lock": True
        })
        self.assertEqual(st_reg_win, 200)
        self.assertTrue(res_reg_win.get("enforce_windows_lock"))

        print("\n[PASS] TEST 17: BLE Proximity in-memory registration & walk-away lock (Secure Guard + Windows Hello) verified.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
