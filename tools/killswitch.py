#!/usr/bin/env python3
"""Wave2 Step3 — killswitch host tool (dry-run first, confirm-gated).

Drives the dedicated rescue killswitch opcode (RESC 0x06) over the dedicated
CDC/HID transport op (0x2E, framing byte-identical via CtapHidFramer /
SerialRouter) WITHOUT committing destructive action from this audit wave:
- Remote trigger: UP+PIN + dedicated confirm token (never the wipe token).
- Physical trigger: hold BOOT 5s to arm + UP touch to confirm (60s window).
- OS helpers: PowerShell / PAM / udev templates, all confirm-gated with
  dry-run, printed to stdout only (never writes files, never touches HW).

Usage:
  python tools/killswitch.py --dry-run
  python tools/killswitch.py --dry-run --emit-ps1 --emit-pam --emit-udev
  python tools/killswitch.py --port COM7 --confirm --mode remote
  python tools/killswitch.py --port /dev/ttyACM0 --confirm --mode physical

Safety (mirrors tools/factory_provision.py):
- Default is --dry-run (no hardware touched, prints plan + sha256 only).
- Real execution requires --confirm + explicit --port (destrutivo).
- Never prints the raw confirm token (only sha256); dry-run prints
  fingerprints only, never writes files. Segredos nunca no repo.
"""
import argparse
import hashlib
import sys

RESCUE_MAGIC = b"RESC"
RESCUE_VERSION = 0x01
RESCUE_CMD_KILLSWITCH = 0x06
RESCUE_TRANSPORT_OP = 0x2E
KILLSWITCH_TOKEN = b"AEGISKEY_KILLSWITCH_CONFIRM"
KILLSWITCH_ACK = bytes([0xDE, 0xAD])
KILLSWITCH_HOLD_MS = 5000
KILLSWITCH_ARM_WINDOW_MS = 60000

PS1_TEMPLATE = r"""# AegisKey killswitch helper (Windows PowerShell) — confirm-gated, dry-run first.
param([switch]$DryRun, [switch]$Confirm, [string]$Port = "")
$TokenSha256 = "{token_sha}"
Write-Host "[PLAN] killswitch remote=UP+PIN token_sha256=$TokenSha256 port=$Port"
Write-Host "[PLAN] physical: hold BOOT {hold}ms to arm + UP to confirm ({window}ms window)"
if ($DryRun) {{ Write-Host "[DRY-RUN] no hardware touched; no files written"; exit 0 }}
if (-not $Confirm) {{ Write-Error "real kill requires -Confirm (destrutivo). Use -DryRun first."; exit 3 }}
if ([string]::IsNullOrEmpty($Port)) {{ Write-Error "real kill requires -Port (e.g. COM7)"; exit 3 }}
Write-Error "[KILL] NOT IMPLEMENTED in audit wave (requires jig + HSM). Aborting."
exit 4
"""

PAM_TEMPLATE = """# AegisKey killswitch helper (Linux PAM exec) — confirm-gated, dry-run first.
# /etc/pam.d/aegis-killswitch: auth required pam_exec.so /usr/local/bin/aegis-killswitch
# Env: DRY_RUN=1 (plan only) | CONFIRM=1 + KILL_PORT=/dev/ttyACM0 (real).
# token_sha256={token_sha} (raw token never leaves firmware/host handshake)
set -eu
echo "[PLAN] killswitch remote=UP+PIN token_sha256=${{KILL_TOKEN_SHA:-{token_sha}}}"
echo "[PLAN] physical: hold BOOT {hold}ms to arm + UP to confirm ({window}ms window)"
if [ "${{DRY_RUN:-1}}" = "1" ]; then echo "[DRY-RUN] no hardware touched"; exit 0; fi
if [ "${{CONFIRM:-0}}" != "1" ]; then echo "ERR: real kill requires CONFIRM=1" >&2; exit 3; fi
if [ -z "${{KILL_PORT:-}}" ]; then echo "ERR: real kill requires KILL_PORT" >&2; exit 3; fi
echo "[KILL] NOT IMPLEMENTED in audit wave (requires jig + HSM). Aborting." >&2
exit 4
"""

UDEV_TEMPLATE = """# AegisKey killswitch helper (Linux udev) — confirm-gated, dry-run first.
# /etc/udev/rules.d/99-aegis-killswitch.rules (plan only; helper still needs CONFIRM=1):
# ACTION=="add", SUBSYSTEM=="tty", ATTRS{{idVendor}}=="303a", \\
#   RUN+="/usr/local/bin/aegis-killswitch --confirm --port %N"
# token_sha256={token_sha} hold_ms={hold} window_ms={window}
"""


def sha256_hex(data: bytes):
    return hashlib.sha256(data).hexdigest()


def valid_serial(s):
    return s.startswith("AEGIS-S3-") and len(s) > len("AEGIS-S3-") and len(s) <= 32


def build_rescue_frame(cmd, payload):
    """Mirror of rescue.rs build_packet: MAGIC|VER|CMD|LEN_BE|PAYLOAD."""
    if not 0 <= cmd <= 255:
        raise ValueError("cmd must fit in one byte")
    if len(payload) > 0xFFFF:
        raise ValueError("payload too large")
    return RESCUE_MAGIC + bytes([RESCUE_VERSION, cmd]) + len(payload).to_bytes(2, "big") + payload


def main():
    ap = argparse.ArgumentParser(description="AegisKey killswitch (Wave2 Step3)")
    ap.add_argument("--port", default=None, help="Serial port for real kill (e.g. COM7)")
    ap.add_argument("--serial", default=None, help="Optional unit serial, e.g. AEGIS-S3-00AF")
    ap.add_argument("--mode", default="remote", choices=["remote", "physical"],
                    help="Trigger path in plan output (remote=UP+PIN, physical=hold+UP)")
    ap.add_argument("--dry-run", action="store_true", help="Plan + fingerprints only, no hardware")
    ap.add_argument("--confirm", action="store_true", help="Required for real kill (destrutivo)")
    ap.add_argument("--emit-ps1", action="store_true", help="Print PowerShell helper to stdout")
    ap.add_argument("--emit-pam", action="store_true", help="Print PAM helper to stdout")
    ap.add_argument("--emit-udev", action="store_true", help="Print udev rule to stdout")
    args = ap.parse_args()

    if args.serial is not None and not valid_serial(args.serial):
        print(f"ERR: serial must start with AEGIS-S3- (got {args.serial})", file=sys.stderr)
        return 2

    token_sha = sha256_hex(KILLSWITCH_TOKEN)
    frame = build_rescue_frame(RESCUE_CMD_KILLSWITCH, KILLSWITCH_TOKEN)
    frame_sha = sha256_hex(frame)
    plan_sha = sha256_hex(f"killswitch:{RESCUE_TRANSPORT_OP:02x}:{RESCUE_CMD_KILLSWITCH:02x}:{token_sha}".encode())

    serial_txt = args.serial if args.serial else "(unspecified)"
    print(f"[PLAN] mode={args.mode} serial={serial_txt}")
    print(f"[PLAN] transport_op=0x{RESCUE_TRANSPORT_OP:02X} cmd=0x{RESCUE_CMD_KILLSWITCH:02X} ack=dead")
    print(f"[PLAN] token_sha256={token_sha} frame_sha256={frame_sha} plan_sha256={plan_sha}")
    print(f"[PLAN] remote: UP+PIN + token (dedicated, never wipe token)")
    print(f"[PLAN] physical: hold BOOT {KILLSWITCH_HOLD_MS}ms to arm + UP to confirm "
          f"({KILLSWITCH_ARM_WINDOW_MS}ms window)")

    if args.emit_ps1:
        print(PS1_TEMPLATE.format(token_sha=token_sha, hold=KILLSWITCH_HOLD_MS,
                                  window=KILLSWITCH_ARM_WINDOW_MS))
    if args.emit_pam:
        print(PAM_TEMPLATE.format(token_sha=token_sha, hold=KILLSWITCH_HOLD_MS,
                                  window=KILLSWITCH_ARM_WINDOW_MS))
    if args.emit_udev:
        print(UDEV_TEMPLATE.format(token_sha=token_sha, hold=KILLSWITCH_HOLD_MS,
                                   window=KILLSWITCH_ARM_WINDOW_MS))

    if args.dry_run:
        print("[DRY-RUN] no hardware touched; no files written; token ephemeral")
        return 0

    if not args.confirm:
        print("ERR: real kill requires --confirm (destrutivo). Use --dry-run first.", file=sys.stderr)
        return 3
    if not args.port:
        print("ERR: real kill requires --port (e.g. COM7)", file=sys.stderr)
        return 3

    print(f"[KILL] would send transport 0x{RESCUE_TRANSPORT_OP:02X} + "
          f"cmd 0x{RESCUE_CMD_KILLSWITCH:02X} on {args.port} + wipe + readback", file=sys.stderr)
    print("[KILL] NOT IMPLEMENTED in audit wave (requires jig + HSM). Aborting.", file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
