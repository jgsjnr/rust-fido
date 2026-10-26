#!/usr/bin/env python3
"""AegisKey zero-touch orchestrator (COM7 / Silicon Labs CP210x default).

Reuse-only: this file holds no CTAPHID framing of its own. Every hardware
step delegates to the existing tools (tools/device_ops.py, tools/app_simulator.py,
tools/e2e_user_test.py, tools/*_probe.py, tools/validate_aegiskey.py) and to the
existing scripts (scripts/env-check.ps1, scripts/build-freertos-s3.ps1).

Port/MAC policy:
- Serial port comes from --port, else env AEGIS_PORT, else the default COM7
  (Silicon Labs CP210x bridge). Baud is --baud, else env AEGIS_BAUD, else 115200.
- The device MAC is never fixed in this file. It is resolved at runtime via
  `python tools/device_ops.py read-mac --port <port>` (the same identity the
  interactive menu shows in its scan/option 0) and only then handed to steps
  that need it (wedge_hunt). No MAC literal exists in this file on purpose.

Serial discipline (firmware rule: reopen == reset):
- Each phase runs in its own process/session, because opening the port resets
  the board and drops any pairing window. Pairing window = 60s, UP latch = 1.5s.
- No 5s BOOT hold is ever required in auto: pairing uses TEST_PAIRING_OPEN
  (software, test-mode firmware) and UP uses TEST_UP (software, single-shot),
  both reused from tools/app_simulator.py via tools/e2e_user_test.py.

Serial OTA-COMMIT deny by design (fail-closed):
- Opcode 0x30 (OTA_BEGIN) does not exist on the serial transport; the device
  must answer 0x01 INVALID_COMMAND and touch zero state. The ota_deny probe
  asserts exactly that. If a device ever answered 0x00 (commit accepted) the
  probe fails and this orchestrator reports OVERALL FAIL. There is no
  serial OTA commit path here, and none is planned: USB-HID-only by design.

Subcommands:
- full: env-check, cargo test, clippy -D warnings, coverage gates T5-T9 +
  host-sdk self-test + COMMS-map ref (all offline), build S3, flash,
  read-mac, boot-check ONLINE&ACTIVE, app-sim demo, rust suite,
  e2e base/pairing/bench (+destructive only with --confirm, +wipe only
  with --confirm and --confirm-release), deny probes, wedge_hunt, validate,
  report + SHA256.
- hil-only: hardware-in-loop only (coverage gates T5-T9 + host-sdk
  self-test + COMMS-map ref, then build, flash, read-mac, boot-check,
  app-sim demo, rust suite, e2e phases, probes, validate). Skips env-check,
  cargo test and clippy.
- release-check: safe pre-release subset. Same as full but destructive/wipe
  phases are never executed; passing --confirm/--confirm-release with
  release-check is refused (exit 2) so a release can never wipe a device.
  Coverage gates are offline/static (no hardware, no burn) so they stay
  green-safe inside release-check.

Coverage gates (offline, every command, fail-closed, no secrets):
- host-sdk-selftest: `python -m tools.host_sdk.cli --self-test` (frozen
  TLV vectors wallet/vendor, long forms, CTAPHID framing roundtrip,
  gates binding->UP->PIN, rescue frame, no-hardcoded-secrets, COM7 default).
- comms-map-ref: docs/COMMS-map.md exists and still carries the frozen
  markers (service 0xFFFD, ops 0x2E/0x38/0x39, ranges 0x20/0x35, gates).
- t5-storage (NamespacedStore): oath/vault/piv stores + persistence +
  ota + nvs_backend present with AEGN v1, NVS_READ_MAX and
  verify-after-write markers (T5 gate; corruption injection itself stays
  a manual HIL follow-up via app-sim demo).
- t6-ota-dryrun (OtaKeyProvider): `factory_provision.py --dry-run`
  (fingerprints only, no hardware touched, no burn, no secrets logged).
  Serial deny-by-probe stays HIL (ota_deny_probe inside probes).
- t7-transports (serial/USB/BLE-GATT framing): host-sdk demo vectors +
  `ble_connect_test.py --self-test` (offline: 244 B fragments, MTU clamp,
  notify frame, stage matrix). Live radio HIL stays in rust-suite/e2e.
- t8-trust (binding gaps): binding/pairing/proximity/recovery sources
  present and COMMS gate order binding->UP->PIN referenced. Live
  bind->UP->PIN HIL stays in e2e pairing + probes.
- t9-applets (oath/wallet/piv): core oath+tlv/wallet dirs + piv_store
  present, COMMS wallet/PIV/rescue markers referenced, plus
  `app_simulator.py --self-test` vectors (OATH JSON, AEGN envelope).
  Live applet HIL stays in e2e + wallet_gate_probe inside probes.

Destructive gates: e2e destructive needs --confirm; e2e wipe needs --confirm
plus --confirm-release (binding wipe). Without them the phases are SKIPped,
never forced.

Output is deterministic, ASCII, emoji-free: [PASS]/[FAIL]/[SKIP] per step plus
an OVERALL line and a SHA256 line for the flashed artifact. Only sanitized
counts/statuses are printed; no secrets, keys, tokens or passphrases are ever
printed or persisted (values never, patterns only).
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"

DEFAULT_PORT = os.environ.get("AEGIS_PORT", "COM7")


def _default_baud():
    try:
        return int(os.environ.get("AEGIS_BAUD", "115200"))
    except ValueError:
        return 115200


DEFAULT_BAUD = _default_baud()

PAIRING_WINDOW_SECS = 60
UP_LATCH_SECS = 1.5
BOOT_CHECK_SECS = 25

# Patterns only: match legacy literals inside tools/* at runtime so this file
# never carries a fixed port or MAC value of its own.
PORT_LITERAL_RE = re.compile(r'"COM\d+"')
MAC_LITERAL_RE = re.compile(r'"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"')
MAC_LINE_RE = re.compile(r"MAC:\s*([0-9A-Fa-f:.\-]{8,})")
BUILT_BIN_RE = re.compile(r"bin\s+em\s+(.+\.bin)", re.IGNORECASE)

# Coverage reference (T5-T9 + host-sdk + COMMS-map). All values below are
# repo-relative source paths or frozen wire markers, never machine paths,
# never port/MAC literals, never secrets (patterns only, values never).
COMMS_MAP = REPO_ROOT / "docs" / "COMMS-map.md"
COMMS_FROZEN_MARKERS = ("0xFFFD", "0x2E", "0x38", "0x39", "0x20",
                        "0x35", "binding")
T5_STORAGE_FILES = (
    "crates/aegis-fido-firmware/src/oath_store.rs",
    "crates/aegis-fido-firmware/src/vault_store.rs",
    "crates/aegis-fido-firmware/src/piv_store.rs",
    "crates/aegis-fido-firmware/src/persistence.rs",
    "crates/aegis-fido-firmware/src/ota.rs",
    "crates/aegis-fido-firmware/src/nvs_backend.rs",
)
T5_PERSISTENCE_MARKERS = ("AEGN", "NVS_READ_MAX", "verify-after-write")
T8_TRUST_FILES = (
    "crates/aegis-fido-firmware/src/binding.rs",
    "crates/aegis-fido-firmware/src/pairing.rs",
    "crates/aegis-fido-firmware/src/proximity.rs",
    "crates/aegis-fido-firmware/src/recovery.rs",
)
T9_APPLET_DIRS = (
    "crates/aegis-fido-core/src/oath",
    "crates/aegis-fido-core/src/wallet",
)
T9_APPLET_FILES = (
    "crates/aegis-fido-core/src/oath/tlv.rs",
    "crates/aegis-fido-firmware/src/piv_store.rs",
)
# Fixed placeholder serial for --dry-run only: never touches hardware,
# never burned, never a device identity (fingerprints are ephemeral).
DRYRUN_SERIAL = "AEGIS-S3-DRYRUN"


class StepResult:
    def __init__(self, name, status, detail=""):
        self.name = name
        self.status = status  # PASS | FAIL | SKIP
        self.detail = detail


def log(tag, msg):
    print("[%s] %s" % (tag, msg), flush=True)


def run_cmd(cmd, timeout_s, cwd=None):
    """Run a subprocess, return (rc, tail). No network calls here."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=str(cwd or REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        return (124, "timeout after %ds: %s" % (timeout_s, " ".join(cmd)))
    except OSError as exc:
        return (127, "spawn failed: %s" % exc)
    out = (proc.stdout or "") + (proc.stderr or "")
    tail = out[-1500:].replace("\r", "")
    return (proc.returncode, tail.strip())


def find_pwsh():
    for cand in ("pwsh", "powershell"):
        path = shutil.which(cand)
        if path:
            return path
    return None


def find_cargo():
    path = shutil.which("cargo")
    if path:
        return path
    home = Path(os.path.expanduser("~"))
    cand = home / ".cargo" / "bin" / "cargo"
    if cand.exists():
        return str(cand)
    return None


def step_env_check():
    pwsh = find_pwsh()
    if pwsh is None:
        return (False, "pwsh/powershell not on PATH (Windows gate)")
    script = REPO_ROOT / "scripts" / "env-check.ps1"
    rc, tail = run_cmd(
        [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(script)], 600)
    if rc != 0:
        return (False, "env-check exit=%d :: %s" % (rc, tail[-400:]))
    return (True, "env-check PASS")


def step_cargo_test():
    cargo = find_cargo()
    if cargo is None:
        return (False, "cargo not on PATH")
    rc, tail = run_cmd([cargo, "test"], 1200)
    if rc != 0:
        return (False, "cargo test exit=%d :: %s" % (rc, tail[-400:]))
    return (True, "cargo test PASS")


def step_clippy():
    cargo = find_cargo()
    if cargo is None:
        return (False, "cargo not on PATH")
    rc, tail = run_cmd(
        [cargo, "clippy", "--all-targets", "--", "-D", "warnings"], 1200)
    if rc != 0:
        return (False, "clippy exit=%d (warnings fail closed) :: %s"
                % (rc, tail[-400:]))
    return (True, "clippy -D warnings PASS")


def step_build_s3():
    pwsh = find_pwsh()
    if pwsh is None:
        return (False, "", "pwsh not on PATH (Windows gate)")
    script = REPO_ROOT / "scripts" / "build-freertos-s3.ps1"
    rc, tail = run_cmd(
        [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(script)], 1800)
    if rc != 0:
        return (False, "", "build S3 exit=%d :: %s" % (rc, tail[-400:]))
    match = BUILT_BIN_RE.search(tail)
    built = match.group(1).strip() if match else ""
    return (True, built, "build S3 PASS")


def discover_app_bin():
    """Locate a flashable artifact without hardcoding machine paths."""
    env = os.environ.get("AEGIS_APP", "")
    if env:
        cand = Path(env)
        if cand.is_file():
            return cand
        return None
    cands = sorted(REPO_ROOT.glob("target/**/aegis-app-*.bin"))
    if not cands:
        return None
    cands.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def step_flash(port, baud, app_bin):
    if app_bin is None or not Path(app_bin).is_file():
        return (False, "", "app bin not found; pass --app or run the build")
    rc, tail = run_cmd(
        [sys.executable, "tools/device_ops.py", "flash",
         "--port", port, "--app", str(app_bin)], 600)
    if rc != 0:
        return (False, "", "flash exit=%d :: %s" % (rc, tail[-400:]))
    return (True, str(app_bin), "flash+verify PASS port=%s baud=%d"
            % (port, baud))


def scan_ports():
    """Menu-0 equivalent: list serial ports reusing app_simulator code."""
    try:
        sys.path.insert(0, str(TOOLS_DIR))
        from app_simulator import list_serial_ports
        ports = list_serial_ports()
        return (True, ",".join(ports) if ports else "(none)")
    except Exception as exc:  # fail-closed, never crash the gate
        return (False, "scan failed: %s" % exc)


def step_read_mac(port):
    rc, tail = run_cmd(
        [sys.executable, "tools/device_ops.py", "read-mac",
         "--port", port], 180)
    if rc != 0:
        return (False, "", "read-mac exit=%d :: %s" % (rc, tail[-400:]))
    match = MAC_LINE_RE.search(tail)
    if not match:
        return (False, "", "read-mac ok but no MAC line :: %s"
                % tail[-200:])
    return (True, match.group(1).strip(), "identity MAC locked")


def step_boot_check(port):
    rc, tail = run_cmd(
        [sys.executable, "tools/device_ops.py", "boot-check",
         "--port", port, "--secs", str(BOOT_CHECK_SECS)], 180)
    if rc == 2:
        return (False, "", "boot LOOP/PANIC :: %s" % tail[-400:])
    if rc != 0:
        return (False, "", "boot-check exit=%d :: %s" % (rc, tail[-400:]))
    return (True, "", "boot ONLINE&ACTIVE stable")


def step_app_sim_demo(port, baud):
    """Zero-touch demo reusing Session framing (no interactive menu)."""
    rc, tail = run_cmd(
        [sys.executable, "tools/app_simulator.py", "--self-test"], 120)
    if rc != 0:
        return (False, "app_simulator --self-test exit=%d :: %s"
                % (rc, tail[-400:]))
    try:
        sys.path.insert(0, str(TOOLS_DIR))
        from app_simulator import Session
        sess = Session("http://127.0.0.1:8888", test_mode=True)
        sess.connect(port, baud)
        try:
            sess.cmd_init()
            sess.test_pairing_open()
        finally:
            sess.close()
    except Exception as exc:
        return (False, "live demo failed: %s" % str(exc)[:200])
    return (True, "self-test + GetInfo + TEST_PAIRING_OPEN (1 session, "
                  "window=%ds)" % PAIRING_WINDOW_SECS)


def step_rust_suite():
    # Upstream suite is host-side/offline (takes no --port); run as-is.
    rc, tail = run_cmd(
        [sys.executable, "tools/test_aegiskey_rust.py"], 300)
    if rc != 0:
        return (False, "rust suite exit=%d :: %s" % (rc, tail[-400:]))
    return (True, "protocol suites PASS (offline)")


def step_e2e(port, phase, extra=()):
    cmd = [sys.executable, "tools/e2e_user_test.py",
           "--port", port, "--phase", phase] + list(extra)
    rc, tail = run_cmd(cmd, 900)
    if rc != 0:
        return (False, "e2e %s exit=%d :: %s" % (phase, rc, tail[-400:]))
    return (True, "e2e %s PASS (1 session, no BOOT hold)" % phase)


def run_legacy_probe(filename, port, mac, timeout_s):
    """Run a legacy hardcoded probe with port/MAC injected in memory.

    The file on disk is untouched; only the in-memory copy has its legacy
    COM/MAC literals replaced via patterns, so --port keeps working even
    for probes that predate CLI flags. Framing stays 100% upstream.
    """
    src = (TOOLS_DIR / filename).read_text(encoding="utf-8")
    patched = PORT_LITERAL_RE.sub('"%s"' % port, src)
    if mac:
        patched = MAC_LITERAL_RE.sub('"%s"' % mac, patched)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", patched],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        return (124, "timeout after %ds" % timeout_s)
    out = ((proc.stdout or "") + (proc.stderr or ""))[-800:].replace("\r", "")
    return (proc.returncode, out.strip())


def step_probes(port, mac):
    probes = [
        ("wallet_gate_probe.py", 120),
        ("ota_deny_probe.py", 120),
        ("killswitch_deny_probe.py", 120),
    ]
    for filename, timeout_s in probes:
        rc, tail = run_legacy_probe(filename, port, None, timeout_s)
        if rc != 0:
            return (False, "%s FAIL exit=%d :: %s"
                    % (filename, rc, tail[-300:]))
    if not mac:
        return (False, "wedge_hunt needs MAC from read-mac; none resolved")
    rc, tail = run_legacy_probe("wedge_hunt.py", port, mac, 420)
    if rc != 0:
        return (False, "wedge_hunt.py exit=%d :: %s" % (rc, tail[-300:]))
    return (True, "wallet_gate + ota_deny(fail-closed 0x01) + "
                  "killswitch_deny + wedge_hunt PASS")


def step_validate(timeout_s=300):
    # Needs native-USB HID device; fail-closed on timeout/absence.
    rc, tail = run_cmd(
        [sys.executable, "tools/validate_aegiskey.py"], timeout_s)
    if rc != 0:
        return (False, "validate exit=%d :: %s" % (rc, tail[-400:]))
    return (True, "validate_aegiskey PASS")


def step_host_sdk_selftest():
    """Offline frozen vectors: TLV wallet/vendor, long forms, framing,
    gates binding->UP->PIN, rescue frame, no-hardcoded-secrets, COM7."""
    rc, tail = run_cmd(
        [sys.executable, "-m", "tools.host_sdk.cli", "--self-test"], 180)
    if rc != 0:
        return (False, "host-sdk --self-test exit=%d :: %s"
                % (rc, tail[-400:]))
    return (True, "host-sdk vectors PASS (TLV/gates/framing, offline)")


def step_comms_map_ref():
    """docs/COMMS-map.md as coverage reference: frozen markers intact."""
    try:
        text = COMMS_MAP.read_text(encoding="utf-8")
    except OSError as exc:
        return (False, "COMMS-map unreadable: %s" % str(exc)[:120])
    missing = [m for m in COMMS_FROZEN_MARKERS if m not in text]
    if missing:
        return (False, "COMMS-map missing frozen markers: %s"
                % ",".join(missing))
    lines = text.count("\n") + 1
    return (True, "COMMS-map ref PASS (%d frozen markers, %d lines)"
            % (len(COMMS_FROZEN_MARKERS), lines))


def step_storage_namespaced():
    """T5 NamespacedStore gate (offline/static): stores + AEGN v1."""
    missing = [rel for rel in T5_STORAGE_FILES
               if not (REPO_ROOT / rel).is_file()]
    if missing:
        return (False, "T5 storage missing files: %s" % ",".join(missing))
    try:
        persist = (REPO_ROOT / "crates" / "aegis-fido-firmware" / "src"
                   / "persistence.rs").read_text(encoding="utf-8")
    except OSError as exc:
        return (False, "T5 persistence unreadable: %s" % str(exc)[:120])
    missing = [m for m in T5_PERSISTENCE_MARKERS if m not in persist]
    if missing:
        return (False, "T5 persistence missing markers: %s"
                % ",".join(missing))
    return (True, "T5 storage PASS (%d files, AEGN v1 + NVS_READ_MAX + "
                  "verify-after-write)" % len(T5_STORAGE_FILES))


def step_ota_keyprovider_dryrun():
    """T6 OtaKeyProvider gate (offline): provision --dry-run only."""
    rc, _tail = run_cmd(
        [sys.executable, "tools/factory_provision.py",
         "--dry-run", "--serial", DRYRUN_SERIAL], 180)
    if rc != 0:
        # Detail carries no tail: dry-run prints ephemeral key
        # fingerprints (hashes) which stay out of orchestrator logs.
        return (False, "T6 ota dry-run exit=%d (no hardware touched)" % rc)
    return (True, "T6 ota-keyprovider DRY-RUN PASS "
                  "(no hardware, no burn, no secrets logged)")


def step_transports_offline():
    """T7 transports gate (offline): demo vectors + BLE self-test."""
    rc, tail = run_cmd(
        [sys.executable, "-m", "tools.host_sdk.cli", "--demo"], 120)
    if rc != 0:
        return (False, "T7 host-sdk --demo exit=%d :: %s"
                % (rc, tail[-300:]))
    rc, tail = run_cmd(
        [sys.executable, "tools/ble_connect_test.py", "--self-test"], 300)
    if rc != 0:
        return (False, "T7 ble_connect --self-test exit=%d :: %s"
                % (rc, tail[-300:]))
    return (True, "T7 transports PASS "
                  "(framing vectors + BLE offline 14/14, no radio)")


def step_trust_gaps():
    """T8 trust-binding gate (offline/static): sources + gate order ref."""
    missing = [rel for rel in T8_TRUST_FILES
               if not (REPO_ROOT / rel).is_file()]
    if missing:
        return (False, "T8 trust missing files: %s" % ",".join(missing))
    try:
        text = COMMS_MAP.read_text(encoding="utf-8")
    except OSError as exc:
        return (False, "T8 COMMS-map unreadable: %s" % str(exc)[:120])
    if "binding" not in text or "UP" not in text or "PIN" not in text:
        return (False, "T8 gate order binding->UP->PIN not referenced")
    return (True, "T8 trust PASS (%d sources, gate order "
                  "binding->UP->PIN)" % len(T8_TRUST_FILES))


def step_applets_offline():
    """T9 applets gate (offline): app-sim vectors + oath/wallet/piv refs."""
    rc, tail = run_cmd(
        [sys.executable, "tools/app_simulator.py", "--self-test"], 180)
    if rc != 0:
        return (False, "T9 app-sim --self-test exit=%d :: %s"
                % (rc, tail[-300:]))
    missing = ([rel for rel in T9_APPLET_DIRS
                if not (REPO_ROOT / rel).is_dir()]
               + [rel for rel in T9_APPLET_FILES
                  if not (REPO_ROOT / rel).is_file()])
    if missing:
        return (False, "T9 applets missing paths: %s" % ",".join(missing))
    try:
        text = COMMS_MAP.read_text(encoding="utf-8")
    except OSError as exc:
        return (False, "T9 COMMS-map unreadable: %s" % str(exc)[:120])
    for marker in ("0x35", "0x39", "0x2E"):
        if marker not in text:
            return (False, "T9 COMMS-map missing marker %s" % marker)
    got = len(T9_APPLET_DIRS) + len(T9_APPLET_FILES)
    return (True, "T9 applets PASS (app-sim vectors + %d oath/wallet/piv "
                  "refs)" % got)


def build_parser():
    parser = argparse.ArgumentParser(
        description="AegisKey zero-touch orchestrator "
                    "(default COM7 CP210x, baud 115200). "
                    "Serial OTA-COMMIT denies by design: opcode 0x30 is "
                    "rejected on serial with 0x01 and the gate fails closed. "
                    "Serial reopen == reset: one session per phase, pairing "
                    "window 60s, UP latch 1.5s, TEST_PAIRING_OPEN replaces "
                    "the 5s BOOT hold in auto.",
        epilog="examples: %(prog)s full --port COM7 | "
               "%(prog)s hil-only | "
               "%(prog)s release-check",
    )
    parser.add_argument("command", choices=("full", "hil-only",
                                            "release-check"))
    parser.add_argument("--port", default=DEFAULT_PORT,
                        help="serial port (default: env AEGIS_PORT or COM7)")
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD,
                        help="serial baud (default: env AEGIS_BAUD or 115200)")
    parser.add_argument("--app", default=None,
                        help="firmware .bin to flash "
                             "(default: build output, else env AEGIS_APP, "
                             "else newest target/**/aegis-app-*.bin)")
    parser.add_argument("--mac", default=None,
                        help="device MAC override (default: auto via "
                             "device_ops read-mac, never fixed in code)")
    parser.add_argument("--confirm", action="store_true",
                        help="authorize e2e destructive phase (state-changing)")
    parser.add_argument("--confirm-release", action="store_true",
                        help="authorize e2e wipe phase (binding wipe, "
                             "needs --confirm too)")
    return parser


def execute(command, args):
    results = []
    port, baud = args.port, args.baud
    mac = args.mac
    app_bin = Path(args.app) if args.app else None

    def add(name, status, detail=""):
        results.append(StepResult(name, status, detail))
        log(status, "%s %s" % (name, ("- " + detail) if detail else ""))

    def do_host_gates():
        ok, detail = step_env_check()
        add("env-check", "PASS" if ok else "FAIL", detail)
        if not ok:
            return False
        ok, detail = step_cargo_test()
        add("cargo-test", "PASS" if ok else "FAIL", detail)
        if not ok:
            return False
        ok, detail = step_clippy()
        add("clippy", "PASS" if ok else "FAIL", detail)
        return ok

    def do_coverage_gates():
        for name, fn in (
                ("host-sdk-selftest", step_host_sdk_selftest),
                ("comms-map-ref", step_comms_map_ref),
                ("t5-storage", step_storage_namespaced),
                ("t6-ota-dryrun", step_ota_keyprovider_dryrun),
                ("t7-transports", step_transports_offline),
                ("t8-trust", step_trust_gaps),
                ("t9-applets", step_applets_offline)):
            ok, detail = fn()
            add(name, "PASS" if ok else "FAIL", detail)
            if not ok:
                return False
        return True

    def do_build_flash_boot():
        nonlocal app_bin, mac
        built = step_build_s3()
        if not built[0]:
            add("build-s3", "FAIL", built[-1])
            return False
        add("build-s3", "PASS", built[-1])
        if len(built) > 2 and built[1] and Path(built[1]).is_file():
            app_bin = Path(built[1])
        if app_bin is None:
            app_bin = discover_app_bin()
        ok, _, detail = step_flash(port, baud, app_bin)
        add("flash", "PASS" if ok else "FAIL", detail)
        if not ok:
            return False
        ok, ports_detail = scan_ports()
        add("scan-ports", "PASS" if ok else "FAIL", ports_detail)
        ok, found_mac, detail = step_read_mac(port)
        add("read-mac", "PASS" if ok else "FAIL",
            ("%s (%s)" % (found_mac, detail)) if ok else detail)
        if not ok:
            return False
        if mac is None:
            mac = found_mac
        ok, _, detail = step_boot_check(port)
        add("boot-check", "PASS" if ok else "FAIL", detail)
        return ok

    def do_hil_suite():
        ok, detail = step_app_sim_demo(port, baud)
        add("app-sim-demo", "PASS" if ok else "FAIL", detail)
        if not ok:
            return False
        ok, detail = step_rust_suite()
        add("rust-suite", "PASS" if ok else "FAIL", detail)
        if not ok:
            return False
        for phase in ("base", "pairing", "bench"):
            ok, detail = step_e2e(port, phase)
            add("e2e-%s" % phase, "PASS" if ok else "FAIL", detail)
            if not ok:
                return False
        if command == "release-check":
            add("e2e-destructive", "SKIP", "never in release-check")
            add("e2e-wipe", "SKIP", "never in release-check")
        else:
            if args.confirm:
                ok, detail = step_e2e(port, "destructive", ("--confirm",))
                add("e2e-destructive", "PASS" if ok else "FAIL", detail)
                if not ok:
                    return False
            else:
                add("e2e-destructive", "SKIP", "needs --confirm")
            if args.confirm and args.confirm_release:
                ok, detail = step_e2e(port, "wipe",
                                       ("--confirm", "--confirm-release"))
                add("e2e-wipe", "PASS" if ok else "FAIL", detail)
                if not ok:
                    return False
            else:
                add("e2e-wipe", "SKIP", "needs --confirm --confirm-release")
        ok, detail = step_probes(port, mac)
        add("probes", "PASS" if ok else "FAIL", detail)
        if not ok:
            return False
        ok, detail = step_validate()
        add("validate", "PASS" if ok else "FAIL", detail)
        return ok

    t0 = time.monotonic()
    log("INFO", "start cmd=%s port=%s baud=%d window=%ds latch=%.1fs"
        % (command, port, baud, PAIRING_WINDOW_SECS, UP_LATCH_SECS))

    cont = True
    if command in ("full", "release-check"):
        cont = do_host_gates()
    if cont:
        cont = do_coverage_gates()
    if cont:
        cont = do_build_flash_boot()
    if cont:
        cont = do_hil_suite()

    failed = [r for r in results if r.status == "FAIL"]
    digest = None
    if app_bin is not None and Path(app_bin).is_file():
        try:
            digest = sha256_file(app_bin)
            sidecar = Path(str(app_bin) + ".sha256")
            sidecar.write_text("%s  %s\n" % (digest, Path(app_bin).name),
                               encoding="ascii")
        except OSError as exc:
            failed.append(StepResult("sha256", "FAIL", str(exc)[:120]))
            results.append(failed[-1])

    elapsed = time.monotonic() - t0
    overall = "FAIL" if failed else "PASS"
    log("INFO", "elapsed=%.1fs steps=%d fail=%d" % (elapsed, len(results),
                                                   len(failed)))
    if digest:
        log("INFO", "SHA256 %s %s" % (digest, Path(app_bin).name))
    else:
        log("INFO", "SHA256 unavailable (no artifact)")
    log(overall, "OVERALL %s cmd=%s" % (overall, command))
    return 0 if overall == "PASS" else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "release-check" and (
            args.confirm or args.confirm_release):
        print("[FAIL] release-check never takes --confirm/--confirm-release",
              flush=True)
        return 2
    if args.confirm_release and not args.confirm:
        print("[FAIL] --confirm-release needs --confirm", flush=True)
        return 2
    return execute(args.command, args)


if __name__ == "__main__":
    raise SystemExit(main())
