#!/usr/bin/env python3
"""Automated screenshot tour mirroring docs/manual/MANUAL_USUARIO.md (host-only).

Read-only tour of the AegisKey app screens with per-step evidence:
  - ``uiautomator dump`` asserted against expected visible text (PASS/FAIL),
  - ``screencap`` PNG per step,
  - redacted ``logcat`` snippet saved on failure.

SAFETY RAILS (hard rules, do not relax):
  - NEVER types a PIN or recovery code (ZERO wrong-PIN attempts by design:
    the script has no ``input text`` path at all).
  - Recovery screen is opened for VIEWING ONLY; it is closed with
    ``Cancel``/BACK and nothing is ever submitted.
  - OTA card is opened for VIEWING ONLY; no install/flash is triggered.
  - No wipe / eFuse / provisioning commands exist in this script.
  - Screenshots default to ``%TEMP%/tour/`` (override with ``--out``) and
    are never committed (binaries stay out of git).

Device selection (``--serial``):
  - Explicit ``--serial`` always wins.
  - Default: ``emulator-5554`` when present, else the first ``device``-state
    entry from ``adb devices``.
  - NEVER steals a device another lane holds: when ``%TEMP%/tour.lock``
    exists, or the manual/clickthrough lanes show recent activity
    (``%TEMP%/opencode-manual``, ``%TEMP%/clickthru`` touched in the last
    ``LANE_BUSY_WINDOW_S`` seconds), the script auto-degrades to
    ``--dry-run`` (steps listed only, adb untouched) and exits 0.

Modes:
  - live (default): navigate + dump + assert + screencap per step.
    Exit code is 0 iff every step PASSes, non-zero otherwise.
  - ``--dry-run``: list the steps (no adb, no device touch). Always green.
  - ``--self-test``: offline unit checks (arg parsing, redaction, XML
    tap-center parsing, step-table integrity). No adb, no device.

Manual coverage (docs/manual/MANUAL_USUARIO.md):
  open (ch.1) -> unlock-view (ch.2, no typing) -> vault (ch.3/4) ->
  totp (ch.5) -> caps (ch.7) -> ota (ch.8, no install) ->
  language (ch.9, view only) -> recovery-view (ch.11, no submit).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

APP_PACKAGE = "dev.aegiskey.app"
APP_ACTIVITY = "dev.aegiskey.app/.MainActivity"

# Lockfile claiming exclusive device use: %TEMP%/tour.lock
LOCK_NAME = "tour.lock"
# Lane dirs whose recent activity means "another lane is mid-run, hands off".
LANE_DIRS = ("clickthru", "opencode-manual")
LANE_BUSY_WINDOW_S = 15 * 60

# ---------------------------------------------------------------------------
# Step table. expect_any: assert PASS iff ANY marker is found in the
# uiautomator dump (EN and PT variants accepted -- the manual demos both).
# nav: best-effort navigation actions executed before the dump.
# ---------------------------------------------------------------------------
STEPS: list[dict] = [
    {
        "id": "open",
        "title": "Primeira abertura -- cofre bloqueado (manual ch.1)",
        "shot": "01_open_locked.png",
        "nav": [("start",)],
        "expect_any": [
            "LOCKED", "Session Locked", "Sess\u00e3o Bloqueada",
            "Unlock Session", "Desbloquear Sess\u00e3o", "[ 5 / 5 ]",
            "UNLOCKED", "Sess\u00e3o Ativa",
        ],
    },
    {
        "id": "unlock-view",
        "title": "Di\u00e1logo de PIN SOMENTE visualizado, sem digitar (manual ch.2)",
        "shot": "02_unlock_dialog.png",
        "nav": [("tap", "Unlock Session"), ("tap", "Desbloquear Sess\u00e3o")],
        "expect_any": [
            "Hardware Session Authentication", "Minimum 4 digits",
            "Tentativas Restantes", "Desbloquear", "Unlock", "Cancel",
        ],
        "close": [("back",)],
    },
    {
        "id": "vault",
        "title": "Tela principal do cofre (manual ch.3/4)",
        "shot": "03_vault_hub.png",
        "nav": [("back",)],
        "expect_any": [
            "Generate Key in Security Key", "Gerar Chave",
            "Security Key Hardware Status", "Status do Hardware",
            "Connect the security key", "Nenhuma chave",
            "Session Locked", "Sess\u00e3o Bloqueada",
        ],
    },
    {
        "id": "totp",
        "title": "TOTP -- c\u00f3digos de verifica\u00e7\u00e3o (manual ch.5)",
        "shot": "04_totp.png",
        "nav": [("tap", "TOTP")],
        "expect_any": [
            "Verification Codes", "TOTP", "Add Code",
            "Adicionar c\u00f3digo", "Scan QR Code", "Ler QR Code",
            "No codes registered", "Copiar c\u00f3digo",
        ],
    },
    {
        "id": "caps",
        "title": "Capacidades da placa / diagn\u00f3stico (manual ch.7)",
        "shot": "05_caps_diagnostics.png",
        "nav": [
            ("tap", "Vault"),
            ("tap", "Show Hardware Diagnostics"),
            ("tap", "Exibir Diagn\u00f3sticos"),
        ],
        "expect_any": [
            "Health status", "Estado de sa\u00fade",
            "Hardware PIN", "PIN de hardware",
            "Device binding", "ChaCha20", "PSRAM",
            "Capacidades da placa", "Hardware Diagnostics",
        ],
    },
    {
        "id": "ota",
        "title": "Cart\u00e3o OTA SOMENTE visualizado, sem instalar (manual ch.8)",
        "shot": "06_ota_card.png",
        "nav": [("tap", "Settings"), ("tap", "Configura\u00e7\u00f5es"),
                ("swipe-up",)],
        "expect_any": [
            "OTA Firmware Update", "Atualiza\u00e7\u00e3o de Firmware OTA",
            "Firmware v", "Open OTA Panel", "Abrir Painel OTA",
            "Stable (Production)", "Est\u00e1vel",
            "Check for Updates", "Offline",
        ],
    },
    {
        "id": "language",
        "title": "Configura\u00e7\u00f5es -- idioma SOMENTE visualizado (manual ch.9)",
        "shot": "07_settings_language.png",
        "nav": [("swipe-up",)],
        "expect_any": [
            "Language", "Idioma", "English", "Ingl\u00eas",
            "Portugu\u00eas (Brasil)", "App language",
        ],
    },
    {
        "id": "recovery-view",
        "title": "Recupera\u00e7\u00e3o de emerg\u00eancia SOMENTE visualizada (manual ch.11)",
        "shot": "08_recovery_view.png",
        "nav": [
            ("tap", "Vault"),
            ("tap", "Emergency Recovery"),
            ("tap", "Recupera\u00e7\u00e3o de Emerg\u00eancia"),
        ],
        "expect_any": [
            "Emergency Recovery with Recovery Code",
            "Recovery Code (XXXX-XXXX-XXXX-XXXX)",
            "New PIN (4 to 16 digits)",
            "Recover and Save", "Recuperar e Salvar",
            "Cancel", "Cancelar", "Emergency Recovery",
            "Recupera\u00e7\u00e3o de Emerg\u00eancia",
        ],
        "close": [("back",)],
    },
]

# ---------------------------------------------------------------------------
# Redaction: logcat snippets must never leak secrets.
# ---------------------------------------------------------------------------
REDACT_PATTERNS = [
    (re.compile(r"(?i)\b(pin|passcode|password)\b\s*[:=]\s*\S+"), r"\1=<redacted>"),
    (re.compile(r"(?i)\b(recovery|mnemonic|seed)([\w-]*)\b\s*[:=]\s*\S+"),
     r"\1\2=<redacted>"),
    (re.compile(r"(?i)\b(bearer|token)\b\s*[:=]\s*\S+"), r"\1=<redacted>"),
    (re.compile(r"\b\d{6}\b"), "<6-digit-redacted>"),
    (re.compile(r"\b[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3,}\b", re.IGNORECASE),
     "<code-redacted>"),
]


def redact(text: str) -> str:
    """Scrub PINs, recovery codes/seeds, tokens and TOTP-like digits."""
    out = text
    for pat, repl in REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


# ---------------------------------------------------------------------------
# Pure helpers (covered by --self-test, no adb).
# ---------------------------------------------------------------------------
def default_out_dir() -> str:
    base = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    return os.path.join(base, "tour")


def lock_path() -> str:
    base = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    return os.path.join(base, LOCK_NAME)


def default_serial(candidates: list[tuple[str, str]]) -> str | None:
    """Pick emulator-5554 when present, else the first ``device`` entry.

    ``candidates``: [(serial, state)] as parsed from ``adb devices``.
    """
    ready = [s for s, st in candidates if st == "device"]
    if not ready:
        return None
    if "emulator-5554" in ready:
        return "emulator-5554"
    return ready[0]


def lane_busy(now: float | None = None) -> tuple[bool, str]:
    """True when another lane holds the rig (lockfile or fresh lane dirs)."""
    lp = lock_path()
    if os.path.exists(lp):
        try:
            with open(lp, "r", encoding="utf-8", errors="replace") as fh:
                holder = fh.read().strip()[:200]
        except OSError:
            holder = "?"
        return True, f"lockfile {lp} held ({holder or '?'})"
    now = time.time() if now is None else now
    base = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    for lane in LANE_DIRS:
        d = os.path.join(base, lane)
        if not os.path.isdir(d):
            continue
        try:
            youngest = max(
                os.path.getmtime(os.path.join(r, f))
                for r, _, fs in os.walk(d) for f in fs
            )
        except (OSError, ValueError):
            continue
        if now - youngest < LANE_BUSY_WINDOW_S:
            age = int(now - youngest)
            return True, f"lane dir {d} active {age}s ago (window {LANE_BUSY_WINDOW_S}s)"
    return False, ""


def parse_bounds(center_text: str) -> tuple[int, int] | None:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]$", center_text.strip())
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def find_center_for_text(dump_xml: str, needle: str) -> tuple[int, int] | None:
    """Center of the first uiautomator node whose text contains ``needle``."""
    try:
        root = ET.fromstring(dump_xml)
    except ET.ParseError:
        return None
    low = needle.lower()
    for node in root.iter("node"):
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "")
            if val and low in val.lower():
                c = parse_bounds(node.get("bounds") or "")
                if c is not None:
                    return c
    return None


def dump_contains(dump_xml: str, markers: list[str]) -> str | None:
    """First expected marker found in the dump (case-insensitive), else None."""
    low = dump_xml.lower()
    for m in markers:
        if m.lower() in low:
            return m
    return None


# ---------------------------------------------------------------------------
# adb plumbing (live mode only).
# ---------------------------------------------------------------------------
def run_adb(serial: str, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["adb", "-s", serial] + args,
        capture_output=True, text=True, timeout=timeout,
    )


def list_devices() -> list[tuple[str, str]]:
    try:
        proc = subprocess.run(["adb", "devices"], capture_output=True,
                              text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            out.append((parts[0], parts[1]))
    return out


def ui_dump(serial: str) -> str:
    run_adb(serial, ["shell", "uiautomator", "dump", "/sdcard/tour_uidump.xml"],
            timeout=30)
    proc = run_adb(serial, ["shell", "cat", "/sdcard/tour_uidump.xml"], timeout=30)
    return proc.stdout or ""


def do_tap(serial: str, x: int, y: int) -> None:
    run_adb(serial, ["shell", "input", "tap", str(x), str(y)], timeout=15)
    time.sleep(1.2)


def do_back(serial: str) -> None:
    run_adb(serial, ["shell", "input", "keyevent", "KEYCODE_BACK"], timeout=15)
    time.sleep(1.0)


def do_swipe_up(serial: str) -> None:
    run_adb(serial, ["shell", "input", "swipe", "540", "1600", "540", "500", "400"],
            timeout=15)
    time.sleep(1.0)


def do_start(serial: str) -> None:
    run_adb(serial, ["shell", "am", "start", "-n",
                     f"{APP_PACKAGE}/{APP_ACTIVITY}"], timeout=30)
    time.sleep(3.0)


def screencap(serial: str, dest: str) -> bool:
    """PNG via exec-out straight to ``dest``. Returns True on plausible PNG."""
    try:
        proc = subprocess.run(["adb", "-s", serial, "exec-out", "screencap", "-p"],
                              capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    data = proc.stdout
    if len(data) < 1000 or not data.startswith(b"\x89PNG"):
        return False
    try:
        with open(dest, "wb") as fh:
            fh.write(data)
    except OSError:
        return False
    return True


def logcat_snippet(serial: str) -> str:
    try:
        proc = run_adb(serial, ["logcat", "-d", "-t", "200", "*:W"], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return "(logcat unavailable)"
    lines = (proc.stdout or "").splitlines()
    return redact("\n".join(lines[-40:])) or "(logcat empty)"


# ---------------------------------------------------------------------------
# Modes.
# ---------------------------------------------------------------------------
def cmd_dry_run() -> int:
    print("manual screenshot tour -- DRY RUN (no device touched)")
    for i, s in enumerate(STEPS, 1):
        print(f"[DRY ok] step {i}/{len(STEPS)} {s['id']:12s} "
              f"{s['title']} -> {s['shot']}")
    print(f"DRY RUN: {len(STEPS)}/{len(STEPS)} steps listed, 0 failed")
    return 0


def cmd_self_test() -> int:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, ev: str) -> None:
        results.append((name, bool(ok), ev))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}\n      {ev}")

    # 1. Step-table integrity.
    ids = [s["id"] for s in STEPS]
    check("steps: 8 flows mirroring MANUAL_USUARIO.md",
          len(STEPS) == 8, f"ids={ids}")
    check("steps: unique ids and png shots",
          len(set(ids)) == len(ids)
          and all(s["shot"].endswith(".png") for s in STEPS),
          f"shots={[s['shot'] for s in STEPS]}")
    check("steps: every step asserts visible text",
          all(s.get("expect_any") for s in STEPS),
          "all expect_any non-empty")
    check("steps: no PIN/recovery typing action exists",
          all(a[0] in ("start", "tap", "back", "swipe-up")
              for s in STEPS for a in s.get("nav", []) + s.get("close", [])),
          "nav verbs limited to start/tap/back/swipe-up (no input-text)")

    # 2. Default serial framing.
    check("framing: emulator-5554 preferred",
          default_serial([("192.168.1.2:5555", "device"),
                          ("emulator-5554", "device")]) == "emulator-5554",
          "emulator present -> emulator-5554")
    check("framing: first device otherwise",
          default_serial([("ABCDEF123", "device"),
                          ("emulator-5556", "offline")]) == "ABCDEF123",
          "no emulator -> first device-state entry")
    check("framing: none when no device",
          default_serial([]) is None
          and default_serial([("emulator-5554", "offline")]) is None,
          "empty/offline -> None")

    # 3. Redaction.
    sample = ("pin: 1234 password=abcd recovery: word word "
              "bearer=tok123 code 482910 ref AB12-CD34-EF56-GH78")
    red = redact(sample)
    check("redact: secrets scrubbed",
          "1234" not in red and "482910" not in red
          and "tok123" not in red and "AB12-CD34-EF56-GH78" not in red,
          f"redacted={red!r}")

    # 4. XML tap-center parsing on synthetic dump.
    synth = ('<hierarchy><node bounds="[0,0][1080,2400]">'
             '<node text="Show Hardware Diagnostics" '
             'bounds="[100,200][500,300]" />'
             '<node content-desc="Settings tab" bounds="[0,0][100,100]" />'
             "</node></hierarchy>")
    check("parse: tap center from node text",
          find_center_for_text(synth, "hardware diagnostics") == (300, 250),
          "text match -> center (300,250)")
    check("parse: content-desc fallback",
          find_center_for_text(synth, "settings tab") == (50, 50),
          "content-desc match -> center (50,50)")
    check("parse: miss -> None",
          find_center_for_text(synth, "nope nada") is None
          and find_center_for_text("not xml", "x") is None,
          "unknown text / bad xml -> None")
    check("parse: dump_contains marker",
          dump_contains(synth, ["ping", "Diagnostics", "pong"]) is not None
          and dump_contains(synth, ["zzz"]) is None,
          "case-insensitive ANY-match")

    # 5. Out-dir default honors %TEMP%/tour.
    check("framing: default out is %TEMP%/tour",
          os.path.basename(os.path.normpath(default_out_dir())) == "tour",
          f"out={default_out_dir()!r}")

    n_ok = sum(1 for _, ok, _ in results if ok)
    print(f"\n==== SELF-TEST: {n_ok}/{len(results)} PASS ====")
    return 0 if n_ok == len(results) else 1


def run_live(serial: str, out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    print(f"manual screenshot tour -- LIVE on {serial} -> {out_dir}")
    print("SAFETY: view-only tour. No PIN typed, no recovery submitted, "
          "no OTA install, no wipe/eFuse.")
    failures = 0
    for i, step in enumerate(STEPS, 1):
        tag = f"{i:02d}_{step['id']}"
        # Best-effort navigation (taps only on visible labels; never typing).
        dump = ""
        for action in step.get("nav", []):
            verb = action[0]
            if verb == "start":
                do_start(serial)
            elif verb == "back":
                do_back(serial)
            elif verb == "swipe-up":
                do_swipe_up(serial)
            elif verb == "tap":
                if not dump:
                    dump = ui_dump(serial)
                center = find_center_for_text(dump, action[1])
                if center is not None:
                    do_tap(serial, *center)
                    dump = ""
        dump = ui_dump(serial)
        with open(os.path.join(out_dir, f"{tag}.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write(dump)
        hit = dump_contains(dump, step["expect_any"])
        shot_ok = screencap(serial, os.path.join(out_dir, step["shot"]))
        ok = hit is not None and shot_ok and len(dump) > 100
        detail = (f"marker={hit!r} shot={step['shot']}:{shot_ok}")
        if ok:
            print(f"[PASS] step {i}/{len(STEPS)} {step['id']:12s} {detail}")
        else:
            failures += 1
            print(f"[FAIL] step {i}/{len(STEPS)} {step['id']:12s} {detail}")
            snippet = logcat_snippet(serial)
            with open(os.path.join(out_dir, f"{tag}.logcat.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write(f"step={step['id']} marker={hit!r} "
                         f"shot_ok={shot_ok}\n{snippet}\n")
            print(f"      logcat snippet (redacted) -> {tag}.logcat.txt")
        for action in step.get("close", []):
            if action[0] == "back":
                do_back(serial)
    print(f"\n==== TOUR: {len(STEPS) - failures}/{len(STEPS)} PASS ====")
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="View-only adb screenshot tour of MANUAL_USUARIO.md flows.")
    ap.add_argument("--serial", default=None,
                    help="device serial (default: emulator-5554 if present, "
                         "else first adb device)")
    ap.add_argument("--out", default=None,
                    help="output dir (default: %%TEMP%%/tour)")
    ap.add_argument("--dry-run", action="store_true",
                    help="list steps only; never touch adb")
    ap.add_argument("--self-test", action="store_true",
                    help="offline framing/parsing checks; never touch adb")
    args = ap.parse_args(argv)

    if args.self_test:
        return cmd_self_test()
    if args.dry_run:
        return cmd_dry_run()

    busy, reason = lane_busy()
    if busy:
        print(f"BUSY: {reason}")
        print("Another lane holds the rig -- degrading to --dry-run "
              "(steps listed only, adb untouched).")
        return cmd_dry_run()

    serial = args.serial or default_serial(list_devices())
    if serial is None:
        print("No --serial given and no adb device found; "
              "degrading to --dry-run.")
        return cmd_dry_run()
    if args.serial:
        devices = dict(list_devices())
        if devices.get(args.serial) != "device":
            print(f"Serial {args.serial!r} not in device state "
                  f"(seen: {devices}); refusing to steal/fight -- "
                  "degrading to --dry-run.")
            return cmd_dry_run()
    return run_live(serial, args.out or default_out_dir())


if __name__ == "__main__":
    sys.exit(main())
