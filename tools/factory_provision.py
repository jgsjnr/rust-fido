#!/usr/bin/env python3
"""Wave3 P3 — factory provisioning (dry-run first, dual-slot aware).

Generates per-unit identity + eFuse OTP payload WITHOUT committing secrets:
- AAGUID/serial por unidade (nunca reutilizar)
- BLOCK7 master key (32B TRNG) + BLOCK8 salt (32B TRNG) via secrets
- Dual-slot NVS layout (slot_a/slot_b/backup) + verify-after-write
- Readback SHA256 for audit

Usage:
  python tools/factory_provision.py --serial AEGIS-S3-00AF --dry-run
  python tools/factory_provision.py --serial AEGIS-S3-00AF --slot-a cred_slot_a --confirm

Safety:
- Default is --dry-run (no hardware touched, prints plan + sha256).
- Real write requires --confirm + explicit --port (eFuse irreversivel).
- Never prints raw keys in non-dry-run logs (only sha256); dry-run prints
  fingerprints only, never writes files. Segredos nunca no repo.
"""
import argparse
import hashlib
import secrets
import sys


def gen_hex(nbytes):
    return secrets.token_hex(nbytes)


def sha256_hex(data: bytes):
    return hashlib.sha256(data).hexdigest()


def valid_serial(s):
    return s.startswith("AEGIS-S3-") and len(s) > len("AEGIS-S3-") and len(s) <= 32


def main():
    ap = argparse.ArgumentParser(description="AegisKey S3 factory provision (Wave3 P3)")
    ap.add_argument("--serial", required=True, help="Per-unit serial, e.g. AEGIS-S3-00AF")
    ap.add_argument("--aaguid", default=None, help="32 hex chars (16B); default TRNG")
    ap.add_argument("--slot-a", default="cred_slot_a", help="Slot A prefix")
    ap.add_argument("--slot-b", default="cred_slot_b", help="Slot B prefix")
    ap.add_argument("--dry-run", action="store_true", help="Plan + fingerprints only, no hardware")
    ap.add_argument("--confirm", action="store_true", help="Required for real eFuse burn")
    ap.add_argument("--port", default=None, help="Serial port for real burn (e.g. COM7)")
    args = ap.parse_args()

    if not valid_serial(args.serial):
        print(f"ERR: serial must start with AEGIS-S3- (got {args.serial})", file=sys.stderr)
        return 2

    aaguid_hex = args.aaguid if args.aaguid else secrets.token_hex(16)
    if len(aaguid_hex) != 32:
        print("ERR: --aaguid must be 32 hex chars (16 bytes)", file=sys.stderr)
        return 2
    try:
        bytes.fromhex(aaguid_hex)
    except ValueError:
        print("ERR: --aaguid not hex", file=sys.stderr)
        return 2
    if aaguid_hex == "00" * 16:
        print("ERR: aaguid must not be all-zero", file=sys.stderr)
        return 2

    master_hex = secrets.token_hex(32)
    salt_hex = secrets.token_hex(32)
    master_sha = sha256_hex(bytes.fromhex(master_hex))
    salt_sha = sha256_hex(bytes.fromhex(salt_hex))
    plan_sha = sha256_hex(f"{args.serial}:{aaguid_hex}:{master_sha}:{salt_sha}".encode())

    print(f"[PLAN] serial={args.serial} aaguid={aaguid_hex}")
    print(f"[PLAN] slots: a={args.slot_a} b={args.slot_b} backup=cred_backup")
    print(f"[PLAN] master_sha256={master_sha}")
    print(f"[PLAN] salt_sha256={salt_sha}")
    print(f"[PLAN] plan_sha256={plan_sha}")
    print("[PLAN] efuse: BLOCK7=master BLOCK8=salt (write-once, verify-after-write)")

    if args.dry_run:
        print("[DRY-RUN] no hardware touched; no files written; keys ephemeral")
        return 0

    if not args.confirm:
        print("ERR: real burn requires --confirm (eFuse irreversivel). Use --dry-run first.", file=sys.stderr)
        return 3
    if not args.port:
        print("ERR: real burn requires --port (e.g. COM7)", file=sys.stderr)
        return 3

    print(f"[BURN] would burn BLOCK7/BLOCK8 on {args.port} + NVS dual-slot + readback sha256", file=sys.stderr)
    print("[BURN] NOT IMPLEMENTED in audit wave (requires factory jig + HSM). Aborting.", file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
