#!/usr/bin/env python3
"""AegisKey SSH_ASKPASS Helper — Hardware-Gated SSH Authorization.

Invoked by OpenSSH whenever SSH needs key authorization, passphrase, or confirmation.
STRICT PRIVACY GUARANTEE:
- NEVER opens, reads, copies, or inspects any user private key in ~/.ssh or elsewhere!
- Gated 100% by the physical AegisKey Secure Guard status.
- Returns authorization ONLY when the physical key is connected and Secure Guard is UNLOCKED.
- Immediately rejects authentication if Secure Guard is LOCKED, RATE_LIMITED, or DISCONNECTED.
- If LOCKED, invokes the visual C# popup (AegisKeyTray.exe --askpass) to prompt for the PIN!
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.request

AUTH_GRANT_FILE = os.path.join(tempfile.gettempdir(), "aegis_ssh_session_grant.json")
BRIDGE_URL = "http://127.0.0.1:5678/api/secure-guard/status"


def check_secure_guard_unlocked() -> bool:
    """Verifies that the physical hardware Secure Guard is in UNLOCKED state (0x04)."""
    try:
        req = urllib.request.Request(BRIDGE_URL, headers={"User-Agent": "AegisSshAskPass/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok") and data.get("state") == 4 and data.get("unlocked") is True:
                return True
    except Exception:
        pass
    return False


def get_ephemeral_grant() -> str:
    """Reads the ephemeral session passphrase if authorized and active."""
    if not os.path.exists(AUTH_GRANT_FILE):
        return ""
    try:
        with open(AUTH_GRANT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if data.get("revoked", False):
                return ""
            return data.get("ephemeral_passphrase", "")
    except Exception:
        return ""


def try_invoke_csharp_askpass(prompt: str) -> bool:
    """Invokes AegisKeyTray.exe --askpass to trigger the visual TopMost PIN dialog."""
    candidates = [
        os.path.join(os.path.dirname(__file__), "dotnet", "AegisKeyTray", "bin", "Debug", "net9.0-windows", "AegisKeyTray.exe"),
        os.path.join(os.path.dirname(__file__), "dotnet", "AegisKeyTray", "bin", "Release", "net9.0-windows", "AegisKeyTray.exe"),
        "AegisKeyTray.exe",
    ]
    for exe in candidates:
        if os.path.exists(exe):
            try:
                proc = subprocess.run([exe, "--askpass", prompt or "OpenSSH / Git Authentication"], timeout=45)
                return proc.returncode == 0
            except Exception:
                pass
    return False


def main():
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""

    # Hardware barrier: check if Secure Guard is UNLOCKED
    if not check_secure_guard_unlocked():
        # Attempt to prompt visually via C# Desktop Companion dialog
        if try_invoke_csharp_askpass(prompt) and check_secure_guard_unlocked():
            pass
        else:
            sys.stderr.write(
                "[AegisKey SSH Guard] Access DENIED: Physical key is LOCKED or DISCONNECTED.\n"
                "Unlock Secure Guard in the AegisKey System Tray to enable SSH authentication.\n"
            )
            sys.stderr.flush()
            sys.exit(1)

    # Secure Guard is UNLOCKED: retrieve the ephemeral session authorization
    passphrase = get_ephemeral_grant()

    # Output authorization to OpenSSH
    if passphrase:
        sys.stdout.write(passphrase + "\n")
        sys.stdout.flush()
        sys.exit(0)
    else:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(0)


if __name__ == "__main__":
    main()
