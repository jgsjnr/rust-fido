#!/usr/bin/env python3
"""AegisKey SSH Guard — Zero-Password SSH Session Lifespan & Security Watchdog.

Auditable security module enforcing zero-password SSH access while AegisKey Secure Guard
is UNLOCKED, with INSTANT identity revocation (ssh-add -D) when LOCKED or unplugged.

CRITICAL PRIVACY GUARANTEE:
- NEVER opens, reads, copies, or inspects any user private key file in ~/.ssh/ or anywhere else!
- Interacts strictly with the public OpenSSH agent API (`ssh-add -l`, `ssh-add -D`, `ssh-add -K`)
  and the hardware-gated `SSH_ASKPASS` protocol.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("AegisSshGuard")

AUTH_GRANT_FILE = os.path.join(tempfile.gettempdir(), "aegis_ssh_session_grant.json")


class SshGuard:
    """Manages ssh-agent synchronization tied to AegisKey Secure Guard state."""

    def __init__(
        self,
        hardware_client=None,
        on_purge_callback: Optional[Callable[[str], None]] = None,
        on_state_change_callback: Optional[Callable[[bool], None]] = None,
    ):
        self.hw_client = hardware_client
        self.on_purge = on_purge_callback
        self.on_state_change = on_state_change_callback

        self._lock = threading.Lock()
        self._running = False
        self._watchdog_thread: Optional[threading.Thread] = None

        self.last_state = -1
        self.last_connected = False
        self.purges_count = 0
        self.last_purge_time: Optional[float] = None
        self.ephemeral_passphrase: Optional[str] = None
        self.ssh_add_bin = self._find_ssh_add()

    def _find_ssh_add(self) -> str:
        """Locates the system ssh-add binary cross-platform."""
        candidate = shutil.which("ssh-add")
        if candidate:
            return candidate
        if platform.system() == "Windows":
            win_candidate = r"C:\WINDOWS\System32\OpenSSH\ssh-add.exe"
            if os.path.exists(win_candidate):
                return win_candidate
        return "ssh-add"

    def start_watchdog(self, interval_seconds: float = 2.0):
        """Starts the background thread monitoring hardware state."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop, args=(interval_seconds,), daemon=True, name="AegisSshWatchdog"
            )
            self._watchdog_thread.start()
            logger.info("AegisKey SSH Guard Watchdog started.")

    def stop_watchdog(self):
        """Stops the background watchdog."""
        with self._lock:
            self._running = False

    def _watchdog_loop(self, interval: float):
        while self._running:
            try:
                self.check_tick()
            except Exception as e:
                logger.debug(f"Watchdog tick error: {e}")
            time.sleep(interval)

    def check_tick(self):
        """Performs one cycle of Secure Guard verification."""
        if not self.hw_client:
            return

        dev = self.hw_client.detect_device()
        sg = self.hw_client.get_secure_guard_status()

        is_connected = dev.connected
        current_state = sg.state
        is_unlocked = is_connected and (current_state == 4)  # STATE_UNLOCKED = 0x04

        with self._lock:
            was_unlocked = (self.last_state == 4) and self.last_connected

            # TRANSITION: UNLOCKED -> LOCKED or DISCONNECTED
            # Immediate revocation barrier
            if was_unlocked and not is_unlocked:
                reason = "Hardware Key Disconnected" if not is_connected else f"Secure Guard Locked ({sg.state_name})"
                self._execute_immediate_revocation(reason)

            # Update cache
            self.last_state = current_state
            self.last_connected = is_connected

            if is_unlocked and self.ephemeral_passphrase:
                self._write_session_grant(self.ephemeral_passphrase)

    def _execute_immediate_revocation(self, reason: str):
        """Purges all unlocked keys from ssh-agent and revokes askpass tokens."""
        logger.warning(f"[SSH-GUARD REVOCATION] {reason}. Purging identities from ssh-agent RAM...")
        purge_out = self.purge_ssh_agent()
        self._revoke_session_grant()
        self.purges_count += 1
        self.last_purge_time = time.time()

        if self.on_purge:
            try:
                self.on_purge(f"{reason} — SSH identities purged ({purge_out})")
            except Exception:
                pass

    def purge_ssh_agent(self) -> str:
        """Executes `ssh-add -D` to clear all identities from the running ssh-agent."""
        try:
            res = subprocess.run(
                [self.ssh_add_bin, "-D"],
                capture_output=True,
                text=True,
                timeout=3.0,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            out = (res.stdout or res.stderr or "").strip()
            return out or "All identities removed."
        except Exception as e:
            return f"Error executing ssh-add -D: {e}"

    def get_agent_identities_count(self) -> Tuple[int, str]:
        """Queries `ssh-add -l` to check how many keys are currently cached in RAM.

        Never reads the disk key files; only inspects the agent's public fingerprint list.
        """
        try:
            res = subprocess.run(
                [self.ssh_add_bin, "-l"],
                capture_output=True,
                text=True,
                timeout=3.0,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            out = res.stdout.strip()
            if "The agent has no identities." in out or res.returncode == 1:
                return 0, "No identities cached"
            if res.returncode == 2:
                return 0, "Could not open connection to your authentication agent."

            lines = [l for l in out.splitlines() if l.strip()]
            return len(lines), f"{len(lines)} identity/identities cached in RAM"
        except Exception as e:
            return 0, f"ssh-add -l error: {e}"

    def load_resident_fido2_keys(self) -> Tuple[bool, str]:
        """Loads FIDO2 resident keys from the physical AegisKey silicon via `ssh-add -K`.

        Allowed ONLY when Secure Guard is UNLOCKED.
        """
        if not self.is_secure_guard_unlocked():
            return False, "Secure Guard is LOCKED. Unlock Secure Guard before loading resident keys."

        try:
            res = subprocess.run(
                [self.ssh_add_bin, "-K"],
                capture_output=True,
                text=True,
                timeout=5.0,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            out = (res.stdout or res.stderr or "").strip()
            success = res.returncode == 0
            return success, out or ("Resident keys loaded successfully" if success else "Failed to load keys")
        except Exception as e:
            return False, f"Execution failed: {e}"

    def set_ephemeral_passphrase(self, passphrase: str) -> bool:
        """Caches user passphrase in RAM for the duration of the UNLOCKED session.

        Instantly wiped when Secure Guard locks or device unplugs.
        """
        if not self.is_secure_guard_unlocked():
            return False

        with self._lock:
            self.ephemeral_passphrase = passphrase
            self._write_session_grant(passphrase)
        return True

    def clear_ephemeral_passphrase(self):
        """Immediately removes the cached passphrase."""
        with self._lock:
            self.ephemeral_passphrase = None
            self._revoke_session_grant()

    def _write_session_grant(self, passphrase: str):
        try:
            data = {
                "created_at": time.time(),
                "revoked": False,
                "ephemeral_passphrase": passphrase,
            }
            with open(AUTH_GRANT_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
            # Tighten file permissions where possible
            if platform.system() != "Windows":
                os.chmod(AUTH_GRANT_FILE, 0o600)
        except Exception as e:
            logger.debug(f"Failed to write grant file: {e}")

    def _revoke_session_grant(self):
        try:
            if os.path.exists(AUTH_GRANT_FILE):
                os.remove(AUTH_GRANT_FILE)
        except Exception:
            pass

    def is_secure_guard_unlocked(self) -> bool:
        """Returns True only if physical key is connected and Secure Guard state is UNLOCKED."""
        if not self.hw_client:
            return False
        dev = self.hw_client.detect_device()
        if not dev.connected:
            return False
        sg = self.hw_client.get_secure_guard_status()
        return sg.unlocked and (sg.state == 4)

    def get_askpass_path(self) -> str:
        """Returns the platform-specific path to the AegisKey SSH_ASKPASS wrapper."""
        base_dir = os.path.abspath(os.path.dirname(__file__))
        if platform.system() == "Windows":
            bat_path = os.path.join(base_dir, "aegis_ssh_askpass.bat")
            if os.path.exists(bat_path):
                return bat_path
        sh_path = os.path.join(base_dir, "aegis_ssh_askpass.sh")
        if os.path.exists(sh_path):
            return sh_path
        return os.path.join(base_dir, "aegis_ssh_askpass.py")

    def get_environment_setup_script(self) -> Dict[str, str]:
        """Provides copy-paste configuration commands for Windows PowerShell and Linux Bash."""
        askpass = self.get_askpass_path()
        return {
            "powershell": (
                f'[Environment]::SetEnvironmentVariable("SSH_ASKPASS", "{askpass}", "User");\n'
                f'[Environment]::SetEnvironmentVariable("SSH_ASKPASS_REQUIRE", "force", "User")'
            ),
            "bash": (
                f'export SSH_ASKPASS="{askpass}"\n'
                f'export SSH_ASKPASS_REQUIRE="force"\n'
                f'# Add to ~/.bashrc or ~/.zshrc'
            ),
            "cmd": (
                f'setx SSH_ASKPASS "{askpass}"\n'
                f'setx SSH_ASKPASS_REQUIRE force'
            ),
        }
