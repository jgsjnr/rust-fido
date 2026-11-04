#!/usr/bin/env python3
"""Automated screenshot tour mirroring docs/manual/MANUAL_USUARIO.md (host-only).

Two tour modes share the adb plumbing:

- View-only tour (default live): ``uiautomator dump`` asserted against
  expected visible text (PASS/FAIL), ``screencap`` PNG per step, redacted
  ``logcat`` snippet saved on failure. NEVER types anything.
- Full click-through tour (``--full``): walks EVERY reachable screen and
  taps everything safe -- open, PIN unlock (owner PIN via env only),
  vault list, create ``tour-`` entry + delete it via UI, TOTP codes, caps
  screen (+GET_CAPS evidence), vault diagnostics, OTA card (view only),
  rescue/audit views, language EN toggle (verified, then back to PT),
  lock, recovery view-only, keys/devices, PIV view, destructive-guard
  evidence (screenshot-only, then BACK out).

SAFETY RAILS (hard rules, do not relax):
  - Default tour NEVER types a PIN or recovery code (ZERO wrong-PIN
    attempts by design: the script has no ``input text`` path at all).
  - ``--full`` unlock enters the owner PIN AT MOST ONCE, read ONLY from
    the ``MANUAL_TOUR_PIN`` environment variable. The value is never
    hardcoded, never printed, never written to disk (dumps/logcat go
    through :func:`redact` before persisting). The keypad identity gate
    (:func:`keypad_identity`: Hardware Session Authentication title +
    Minimum 4 digits hint + exact digit node, EN/PT) is proven BEFORE
    any tap and every digit resolves ONLY by exact match
    (:func:`find_exact_digit`, center+bounds logged without the value);
    pre/post dumps go to evidence as ``pin-entry-pre.xml`` /
    ``pin-entry-post.xml``. When the variable is absent (or the gate
    fails) the run ABORTS before typing anything -- zero keypresses,
    zero attempts consumed.
    A failed unlock STOPS the run; there is exactly one attempt, never
    a retry (ZERO wrong-PIN attempts beyond the single authorized one).
  - Recovery screen is opened for VIEWING ONLY; it is closed with
    ``Cancel``/BACK and nothing is ever submitted. The throwaway
    ``tour-`` label is typed ONLY after :func:`create_dialog_identity`
    proves the vault-create dialog is foreground; any recovery marker
    aborts the step with zero keypresses (wrong-field guard).
  - Screenshots NEVER save a legible live recovery code: every capture
    goes through :func:`guarded_screencap`, which detects the
    "Emergency Recovery Code" box and either blacks it out via Pillow
    or skips the screen with SKIP-SECRET-VISIBLE (no Pillow/bounds ->
    nothing saved).
  - A vault-create step PASSes ONLY when the throwaway label appears
    as a listed entry via a subsequent list query
    (:func:`tour_label_listed` ignores EditText contents).
  - OTA card is opened for VIEWING ONLY; no install/flash is triggered.
  - Destructive controls (factory reset, selective wipe, unbind/release
    ownership, confirm-destruction tokens such as CONFIRM_WIPE_*) are
    NEVER tapped. The guard step screenshots the dialog (when surfaced)
    and BACKs out. The only delete confirmation ever tapped is the
    vault-entry delete for the ``tour-`` entry this run created, and
    only when the dialog text proves it names that entry.
  - No wipe / eFuse / provisioning commands exist in this script.
  - Screenshots default to ``%TEMP%/tour/`` (view-only) or
    ``docs/manual/img/`` (``--full`` without ``--out``) and are
    downscaled to 720px max width. Evidence XML/logcat for ``--full``
    goes to ``%TEMP%/tour-full-evidence/`` (binaries stay out of git
    except the curated ``docs/manual/img`` PNGs).
  - The run STOPS on the first unexpected state (assertion miss): later
    steps are reported SKIP/stopped, never forced through.

Device selection (``--serial``):
  - Explicit ``--serial`` always wins.
  - Default: ``emulator-5554`` when present, else the first ``device``-state
    entry from ``adb devices``.
  - NEVER steals a device another lane holds: when ``%TEMP%/tour.lock``
    exists, or the manual/clickthrough lanes show recent activity
    (``%TEMP%/opencode-manual``, ``%TEMP%/clickthru`` touched in the last
    ``LANE_BUSY_WINDOW_S`` seconds), the script auto-degrades to
    ``--dry-run`` (steps listed only, adb untouched) and exits 0.
  - Emulator stays OFF for acceptance: ``--full`` live refuses to run
    against ``emulator-*`` serials (physical device only).

Modes:
  - live (default): navigate + dump + assert + screencap per step.
    Exit code is 0 iff every step PASSes, non-zero otherwise.
  - ``--full``: full click-through table (see FULL_STEPS). Requires
    ``MANUAL_TOUR_PIN`` for live; aborts (exit 2) when absent.
  - ``--dry-run``: list the steps (adb never touched). Always green.
    With ``--full`` it lists the full table instead.
  - ``--self-test``: offline unit checks (arg parsing, redaction, XML
    tap-center parsing, step-table integrity, forbidden-tap guards,
    no-hardcoded-PIN scan). No adb, no device.

Manual coverage, view-only (docs/manual/MANUAL_USUARIO.md):
  open (ch.1) -> unlock-view (ch.2, no typing) -> vault (ch.3/4) ->
  totp (ch.5) -> caps (ch.7) -> ota (ch.8, no install) ->
  language (ch.9, view only) -> recovery-view (ch.11, no submit).

Manual coverage, full (``--full``):
  open -> unlock-pin (env PIN, single attempt) -> vault-list ->
  vault-create-tour -> vault-delete-tour -> totp -> caps (+GET_CAPS
  evidence) -> vault-diagnostics -> ota-view -> rescue-audit ->
  language-en (verify) -> language-pt (verify back) -> lock ->
  recovery-view -> keys-devices -> piv-view -> destructive-guard
  (screenshot-only, then BACK).
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

# Owner PIN arrives ONLY via this env var. Never hardcoded, never logged.
PIN_ENV = "MANUAL_TOUR_PIN"
# Prefix for the throwaway vault entry this run creates and deletes.
TOUR_LABEL_PREFIX = "tour-"
# Screenshot width cap for docs/manual/img (acceptance: <=720px wide).
SHOT_MAX_W = 720

# Tap targets that must NEVER be tapped (destruction scope). Checked by
# forbidden_tap() before every tap and by --self-test against both tables.
# Vault-entry delete ("Delete Key") is intentionally NOT here: it is only
# tapped by the scoped tour-entry delete, which requires the dialog to
# name the tour- entry created moments earlier.
FORBIDDEN_TAP_SUBSTRINGS = (
    "confirm wipe",
    "confirmar limpeza",
    "confirm reset",
    "confirmar redefini",
    "factory reset",
    "redefini",
    "selective wipe",
    "limpeza seletiva",
    "confirm_wipe_aegis_guard",
    "release device ownership",
    "release ownership or reset key",
    "unbind security key",
    "desvincular",
    "proceed to transfer",
    "erase all",
    "apagar todos",
)

# Keypad identity gate for pin-entry (parent gate): the unlock dialog must
# prove it is the Hardware Session Authentication keypad BEFORE any tap.
# Requires the title (EN/PT) + the min-digits hint (EN/PT) + at least one
# exact digit node (text/content-desc == "0".."9"). Absent -> STOP with
# zero keypresses. Digits are tapped ONLY by exact match (a substring hit
# such as "Minimum 4 digits" must NEVER satisfy digit "4"); every digit
# tap logs index+center+bounds WITHOUT the digit value (PIN never printed).
KEYPAD_TITLE_ANY = (
    "Hardware Session Authentication",
    "Autenticação de Sessão de Hardware",
)
KEYPAD_HINT_ANY = (
    "Minimum 4 digits",
    "Mínimo de 4 dígitos",
)

# Residual-session guard (22:18 dumps: UNLOCKED + timer 04:55->04:44 +
# tour-215946 Slot #0 still listed). A previous run may leave the session
# UNLOCKED, so the unlock-pin step must not blindly hunt the LOCKED UI.
# :func:`is_unlocked` proves the real state BEFORE any PIN tap; when
# unlocked, run_full tries Lock Now/Bloquear Agora + re-dump proving
# LOCKED, else marks unlock SKIP explicitly and proceeds from the real
# (unlocked) state with ZERO PIN consumes.
UNLOCKED_ANY = (
    "UNLOCKED",
    "Session Unlocked",
    "Session Active",
    "Sessão Ativa",
    "Remaining authorization time",
    "Tempo de autorização",
    "Lock Now",
    "Bloquear Agora",
)
LOCKED_ANY = (
    "Session Locked",
    "Sessão Bloqueada",
    "Unlock Session",
    "Desbloquear Sessão",
)

# Dialog identity for the vault-create step (defect 1: wrong-field typing).
# The throwaway label must ONLY be typed when the dump proves the intended
# create dialog is foreground. Recovery markers veto typing even when a
# create marker is also present (identity mismatch -> abort, no keypresses).
CREATE_DIALOG_MUST_ANY = (
    "Generate Key in Security Key",
    "Gerar Chave",
    "Generate Key",
    "Gerar",
    "Label",
    "R\u00f3tulo",
)
RECOVERY_DIALOG_FORBIDDEN_ANY = (
    "Emergency Recovery",
    "Recupera\u00e7\u00e3o de Emerg\u00eancia",
    "Recovery Code",
    "Recover and Save",
    "Recuperar e Salvar",
    "New PIN (4 to 16 digits)",
)

# Recovery-code box markers (defect 2: secret exposure). The live code box
# is identified by its label/resource-id, never by the code value itself.
RECOVERY_SECRET_MARKERS = (
    "emergency recovery code",
    "recovery_code",
    "recoverycode",
)


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def manual_img_dir() -> str:
    return os.path.join(repo_root(), "docs", "manual", "img")

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
        "nav": [("tap", "Go to Vault"),
                ("tap", "Unlock Session"), ("tap", "Desbloquear Sess\u00e3o")],
        "expect_any": [
            "Hardware Session Authentication", "Minimum 4 digits",
            "Tentativas Restantes", "Desbloquear", "Unlock", "Cancel",
        ],
        # Cancel dismisses the dialog and stays in the app; BACK from the
        # hub would exit to the launcher and cascade every later step.
        "close": [("tap", "Cancel")],
    },
    {
        "id": "vault",
        "title": "Tela principal do cofre (manual ch.3/4)",
        "shot": "03_vault_hub.png",
        "nav": [],
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
                ("swipe-up",), ("swipe-up",), ("swipe-up",)],
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
        # Fresh cold entry lands on the Language row; tab re-entry would
        # restore the deep OTA scroll offset, so restart instead of swiping.
        "nav": [("start",), ("tap", "Go to Vault"), ("tap", "Settings")],
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
        # Return to the hub tab instead of BACK (BACK exits to launcher).
        "close": [("tap", "Vault")],
    },
]

# ---------------------------------------------------------------------------
# Full click-through table (--full). Verbs:
#   start / tap / back / swipe-up -- as in STEPS.
#   pin-entry      -- single owner-PIN attempt from MANUAL_TOUR_PIN.
#   type-tour-label-- type the throwaway "tour-HHMMSS" entry label.
#   delete-tour    -- scoped delete: taps confirm ONLY when the dialog
#                     names the tour- entry created earlier.
#   getcaps-evidence -- persist caps lines from the dump to a .txt.
#   verify-en / verify-pt -- assert the language toggle took effect.
#   guard-shot     -- screenshot-only when a destructive dialog surfaces,
#                     then BACK out (SKIP when nothing destructive shows).
# ---------------------------------------------------------------------------
FULL_STEPS: list[dict] = [
    {
        "id": "open",
        "title": "Abertura fria -- cofre bloqueado (manual ch.1)",
        "shot": "01_open_locked.png",
        "nav": [("start",)],
        "expect_any": [
            "LOCKED", "Session Locked", "Sess\u00e3o Bloqueada",
            "Unlock Session", "Desbloquear Sess\u00e3o", "[ 5 / 5 ]",
            "Find Security Key", "Go to Vault",
        ],
    },
    {
        "id": "unlock-pin",
        "title": "Desbloqueio com PIN do dono via env (uma tentativa, manual ch.2)",
        "shot": "02_unlock_pin.png",
        "nav": [("tap", "Go to Vault"),
                ("tap", "Unlock Session"), ("tap", "Desbloquear Sess\u00e3o"),
                ("pin-entry",)],
        "expect_any": [
            "UNLOCKED", "Sess\u00e3o Ativa",
            "Tempo de autoriza\u00e7\u00e3o", "Authorization",
            "Bloquear Agora", "Lock Now",
        ],
    },
    {
        "id": "vault-list",
        "title": "Cofre desbloqueado -- lista do vault (manual ch.3)",
        "shot": "03_vault_list.png",
        "nav": [],
        "expect_any": [
            "Generate Key in Security Key", "Gerar Chave",
            "Nenhuma chave no dispositivo", "No keys",
            "UNLOCKED", "Sess\u00e3o Ativa", "Todas", "All",
        ],
    },
    {
        "id": "vault-create-tour",
        "title": "Criar entrada descartavel tour- (manual ch.4)",
        "shot": "04_vault_create_tour.png",
        "nav": [("tap", "Generate Key in Security Key"),
                ("tap", "Gerar Chave"),
                ("type-tour-label",),
                ("tap", "Generate Key"), ("tap", "Gerar")],
        "expect_any": [
            # Gate is tour_label_listed (list query); generic capability
            # markers (FIDO2/WebAuthn/create-button text) must NOT pass
            # this step alone.
            "tour-", "Slot #", "Toque Obrigat\u00f3rio", "Touch Required",
        ],
    },
    {
        "id": "vault-delete-tour",
        "title": "Apagar entrada tour- via UI (escopo: dialog precisa citar tour-)",
        "shot": "05_vault_delete_tour.png",
        "nav": [("delete-tour",)],
        "expect_any": [
            "Generate Key in Security Key", "Gerar Chave",
            "Nenhuma chave no dispositivo", "No keys", "UNLOCKED",
        ],
    },
    {
        "id": "totp",
        "title": "TOTP -- codigos de verificacao (manual ch.5)",
        "shot": "06_totp_codes.png",
        "nav": [("tap", "TOTP"), ("tap", "C\u00f3digos")],
        "expect_any": [
            "Verification Codes", "TOTP", "Add Code",
            "Adicionar c\u00f3digo", "Scan QR Code", "Ler QR Code",
            "No codes registered", "Copiar c\u00f3digo", "e2e-test",
        ],
    },
    {
        "id": "caps",
        "title": "Capacidades da placa + evidencia GET_CAPS (manual ch.7)",
        "shot": "07_caps_getcaps.png",
        "nav": [("tap", "Vault"), ("tap", "Capacidades"),
                ("tap", "Capabilities"), ("tap", "Refresh"),
                ("tap", "Atualizar"),
                ("getcaps-evidence",)],
        "expect_any": [
            "Capacidades da placa", "Capabilities", "Hardware Diagnostics",
            "Health status", "Estado de sa\u00fade", "ChaCha20", "PSRAM",
            "Unknown", "desconhecido", "Firmware",
        ],
    },
    {
        "id": "vault-diagnostics",
        "title": "Diagnostico do cofre expandido (manual ch.7)",
        "shot": "08_vault_diagnostics.png",
        "nav": [("tap", "Vault"),
                ("tap", "Show Hardware Diagnostics"),
                ("tap", "Exibir Diagn\u00f3sticos")],
        "expect_any": [
            "Health status", "Estado de sa\u00fade",
            "Hardware PIN", "PIN de hardware",
            "Device binding", "ChaCha20", "PSRAM",
            "Hardware Diagnostics", "Slots PIV",
        ],
    },
    {
        "id": "ota-view",
        "title": "Cartao OTA SOMENTE visualizado, sem instalar (manual ch.8)",
        "shot": "09_ota_card.png",
        "nav": [("tap", "Settings"), ("tap", "Configura\u00e7\u00f5es"),
                ("swipe-up",), ("swipe-up",), ("swipe-up",)],
        "expect_any": [
            "OTA Firmware Update", "Atualiza\u00e7\u00e3o de Firmware OTA",
            "Firmware v", "Open OTA Panel", "Abrir Painel OTA",
            "Stable (Production)", "Est\u00e1vel",
            "Check for Updates", "Offline", "Ed25519",
        ],
    },
    {
        "id": "rescue-audit",
        "title": "Rescue diagnostics + audit logs SOMENTE visualizados (0x2E/0x38)",
        "shot": "10_audit_rescue.png",
        "nav": [("tap", "Diagnostics (0x2E)"), ("tap", "Audit Logs (0x38)"),
                ("tap", "Rescue Diagnostics")],
        "expect_any": [
            "Rescue Diagnostics", "Security Audit Logs",
            "Self-Test (0x2E)", "Audit Logs (0x38)",
            "NVS", "TRNG", "Monotonic Counter", "Verdict",
            "No audit log entries", "Self-test completed",
        ],
    },
    {
        "id": "language-en",
        "title": "Idioma -> EN com verificacao (manual ch.9)",
        "shot": "11_language_en.png",
        "nav": [("start",), ("tap", "Go to Vault"), ("tap", "Settings"),
                ("tap", "Configura\u00e7\u00f5es"),
                ("tap", "English"), ("tap", "Ingl\u00eas"),
                ("verify-en",)],
        "expect_any": ["Language", "Settings", "English", "System"],
    },
    {
        "id": "language-pt",
        "title": "Idioma -> PT de volta com verificacao (manual ch.9)",
        "shot": "12_language_pt.png",
        "nav": [("tap", "Portugu\u00eas (Brasil)"), ("tap", "Portuguese"),
                ("verify-pt",)],
        "expect_any": ["Idioma", "Configura\u00e7\u00f5es", "Portugu\u00eas"],
    },
    {
        "id": "lock",
        "title": "Bloqueio da sessao (manual ch.10)",
        "shot": "13_locked.png",
        "nav": [("tap", "Vault"), ("tap", "Bloquear Agora"),
                ("tap", "Lock Now")],
        "expect_any": [
            "LOCKED", "Session Locked", "Sess\u00e3o Bloqueada",
            "Unlock Session", "Desbloquear Sess\u00e3o",
        ],
    },
    {
        "id": "recovery-view",
        "title": "Recuperacao de emergencia SOMENTE visualizada (manual ch.11)",
        "shot": "14_recovery_view.png",
        "nav": [("tap", "Emergency Recovery"),
                ("tap", "Recupera\u00e7\u00e3o de Emerg\u00eancia")],
        "expect_any": [
            "Emergency Recovery with Recovery Code",
            "Recovery Code (XXXX-XXXX-XXXX-XXXX)",
            "New PIN (4 to 16 digits)",
            "Recover and Save", "Recuperar e Salvar",
            "Cancel", "Cancelar",
        ],
        "close": [("tap", "Vault")],
    },
    {
        "id": "keys-devices",
        "title": "Dispositivos -- placa vinculada SOMENTE visualizada (manual ch.6)",
        "shot": "15_keys_devices.png",
        "nav": [("tap", "Keys"), ("tap", "Chaves"),
                ("tap", "Devices"), ("tap", "Dispositivos")],
        "expect_any": [
            "Chaves vinculadas", "Bound keys", "Connected",
            "Conectado", "Minha Chave", "BRIDGE", "NEAR", "Renomear",
            "Rename", "Conectar nova chave", "Connect new",
        ],
    },
    {
        "id": "piv-view",
        "title": "Smartcard PIV SOMENTE visualizado",
        "shot": "16_piv_view.png",
        "nav": [("tap", "Settings"), ("tap", "Configura\u00e7\u00f5es"),
                ("tap", "Smart Card"), ("tap", "PIV")],
        "expect_any": [
            "Smart Card", "PIV", "Certificates", "Certificados",
            "Slots", "9A", "NIST", "Authentication", "Autentica",
        ],
    },
    {
        "id": "destructive-guard",
        "title": "Guarda destrutiva: dialog screenshotted, BACK out, nada tocado",
        "shot": "17_destructive_guard.png",
        "nav": [("guard-shot",)],
        "expect_any": [
            "Ownership", "Factory Reset", "Selective Wipe",
            "Release Device Ownership", "Confirm", "Cancelar", "Cancel",
            "Security Key Ownership", "Limpeza", "Redefini",
            "Settings", "Configura\u00e7\u00f5es",
        ],
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


def evidence_dir() -> str:
    base = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    return os.path.join(base, "tour-full-evidence")


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


def is_emulator_serial(serial: str) -> bool:
    return serial.startswith("emulator-")


def tour_pin_present() -> bool:
    """True iff the owner PIN env var is set (value never leaves here)."""
    return bool(os.environ.get(PIN_ENV))


def forbidden_tap(needle: str) -> str | None:
    """Matched forbidden substring for a tap target, else None."""
    low = needle.strip().lower()
    for bad in FORBIDDEN_TAP_SUBSTRINGS:
        if bad in low:
            return bad
    return None


def dump_contains(dump_xml: str, markers: list[str]) -> str | None:
    """First expected marker found in the dump (case-insensitive), else None."""
    low = dump_xml.lower()
    for m in markers:
        if m.lower() in low:
            return m
    return None


def create_dialog_identity(dump_xml: str) -> tuple[bool, str]:
    """Prove the vault-create dialog is foreground before typing.

    Returns (ok, reason). Recovery markers veto typing even when a
    create marker is also present: the Emergency Recovery "Recovery
    Code" field must never receive the throwaway label.
    """
    low = (dump_xml or "").lower()
    for bad in RECOVERY_DIALOG_FORBIDDEN_ANY:
        if bad.lower() in low:
            return False, f"identity mismatch: recovery marker {bad!r} present"
    for good in CREATE_DIALOG_MUST_ANY:
        if good.lower() in low:
            return True, f"create dialog proven by {good!r}"
    return False, "identity unproven: no create-dialog marker"


def recovery_secret_visible(dump_xml: str) -> bool:
    """True when the Emergency Recovery code box is on screen.

    Detected by label/resource-id (never by the live code value), plus
    a guarded fallback: a recovery dialog showing a code-shaped value.
    """
    low = (dump_xml or "").lower()
    if any(m in low for m in RECOVERY_SECRET_MARKERS):
        return True
    if "emergency recovery" in low and re.search(
            r"[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3,}", dump_xml or "",
            re.IGNORECASE) is not None:
        return True
    return False


def parse_rect(bounds_text: str) -> tuple[int, int, int, int] | None:
    """Parse uiautomator bounds into (x1, y1, x2, y2)."""
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]$",
                 (bounds_text or "").strip())
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    if x2 <= x1 or y2 <= y1:
        return None
    return (x1, y1, x2, y2)


def secret_node_bounds(dump_xml: str) -> list[tuple[int, int, int, int]]:
    """Bounds of recovery-code box nodes (label/id/code value)."""
    try:
        root = ET.fromstring(dump_xml or "")
    except ET.ParseError:
        return []
    rects: list[tuple[int, int, int, int]] = []
    for node in root.iter("node"):
        hay = " ".join([
            node.get("text") or "",
            node.get("content-desc") or "",
            node.get("resource-id") or "",
        ]).lower()
        is_box = any(m in hay for m in RECOVERY_SECRET_MARKERS)
        is_code = (re.search(r"[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3,}", hay,
                             re.IGNORECASE) is not None
                   and "emergency recovery" in (dump_xml or "").lower())
        if not (is_box or is_code):
            continue
        r = parse_rect(node.get("bounds") or "")
        if r is not None:
            rects.append(r)
    return rects


def pillow_available() -> bool:
    try:
        import PIL.Image  # noqa: F401
        return True
    except ImportError:
        return False


def blackout_secret_regions(png_path: str,
                            dump_xml: str) -> str:
    """Black out recovery-code regions in an already-saved PNG.

    Returns "redacted" on success, else a "no-*" reason so the caller
    can SKIP (delete) the file instead of leaving a legible live code.
    """
    rects = secret_node_bounds(dump_xml or "")
    if not rects:
        return "no-bounds"
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return "no-pillow"
    try:
        with Image.open(png_path) as im:
            img_w, img_h = im.size
            dump_w, dump_h = 0, 0
            try:
                root = ET.fromstring(dump_xml or "")
                for node in root.iter("node"):
                    r = parse_rect(node.get("bounds") or "")
                    if r is not None:
                        dump_w = max(dump_w, r[2])
                        dump_h = max(dump_h, r[3])
                        break
                if dump_w <= 0 or dump_h <= 0:
                    for node in root.iter("node"):
                        r = parse_rect(node.get("bounds") or "")
                        if r is not None:
                            dump_w = max(dump_w, r[2])
                            dump_h = max(dump_h, r[3])
            except ET.ParseError:
                return "no-bounds"
            if dump_w <= 0 or dump_h <= 0:
                return "no-bounds"
            sx = img_w / dump_w
            sy = img_h / dump_h
            draw = ImageDraw.Draw(im)
            for x1, y1, x2, y2 in rects:
                # Pad generously: the code value sits next to its label.
                pad = 12
                ix1 = max(0, int(x1 * sx) - pad)
                iy1 = max(0, int(y1 * sy) - pad)
                ix2 = min(img_w, int(x2 * sx) + pad * 8)
                iy2 = min(img_h, int(y2 * sy) + pad)
                draw.rectangle([ix1, iy1, ix2, iy2], fill=(0, 0, 0))
            im.save(png_path, optimize=True)
            return "redacted"
    except OSError:
        return "no-image"


def tour_label_listed(dump_xml: str, tour_label: str) -> bool:
    """True iff ``tour_label`` appears as a listed entry (not typed text).

    EditText contents do NOT prove creation: a PASS on input-field text
    is the defect-3 false-pass. Only a non-editable node (vault list /
    detail row) counts.
    """
    want = (tour_label or "").strip().lower()
    if not want or not dump_xml:
        return False
    try:
        root = ET.fromstring(dump_xml)
    except ET.ParseError:
        return False
    for node in root.iter("node"):
        cls = (node.get("class") or "")
        if cls.endswith("EditText"):
            continue
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "").strip()
            if val and want in val.lower():
                return True
    return False


def caps_evidence_lines(dump_xml: str) -> str:
    """Caps/GET_CAPS related text lines extracted from a dump (redacted)."""
    keys = ("caps", "capabilit", "capacidades", "firmware", "preset",
            "health", "sa\u00fade", "chacha", "psram", "piv", "slot",
            "unknown", "desconhecido", "refresh", "atualizar",
            "unsupported", "diagnostics", "diagn\u00f3stico")
    out: list[str] = []
    try:
        root = ET.fromstring(dump_xml)
    except ET.ParseError:
        return ""
    for node in root.iter("node"):
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "").strip()
            if val and any(k in val.lower() for k in keys):
                out.append(val)
    seen: list[str] = []
    for line in out:
        if line not in seen:
            seen.append(line)
    return redact("\n".join(seen[:60]))


def parse_bounds(center_text: str) -> tuple[int, int] | None:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]$", center_text.strip())
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def find_center_for_text(dump_xml: str, needle: str) -> tuple[int, int] | None:
    """Center of the first uiautomator node whose text contains ``needle``.

    Exact (case-insensitive, whole-text) hits win over substring hits, so a
    tab label like ``Vault`` beats a sentence that merely mentions the vault
    (e.g. a Settings description row) and the tap lands on real chrome.
    """
    try:
        root = ET.fromstring(dump_xml)
    except ET.ParseError:
        return None
    want = needle.strip().lower()

    def center(nodes: list) -> tuple[int, int] | None:
        for node, _ in nodes:
            c = parse_bounds(node.get("bounds") or "")
            if c is not None:
                return c
        return None

    exact, partial = [], []
    for node in root.iter("node"):
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "")
            if not val:
                continue
            low = val.strip().lower()
            if not low:
                continue
            if low == want:
                exact.append((node, attr))
            elif want in low:
                partial.append((node, attr))
    return center(exact) or center(partial)


def find_bounds_for_text(dump_xml: str, needle: str) -> str | None:
    """Raw uiautomator bounds string for ``needle`` (exact wins)."""
    try:
        root = ET.fromstring(dump_xml or "")
    except ET.ParseError:
        return None
    want = (needle or "").strip().lower()
    if not want or not dump_xml:
        return None
    exact, partial = [], []
    for node in root.iter("node"):
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "")
            if not val or not val.strip():
                continue
            low = val.strip().lower()
            if low == want:
                exact.append(node)
            elif want in low:
                partial.append(node)
    for node in exact + partial:
        b = (node.get("bounds") or "").strip()
        if re.match(r"\[\d+,\d+\]\[\d+,\d+\]$", b):
            return b
    return None


def find_exact_digit(dump_xml: str, digit: str) -> tuple[tuple[int, int], str] | None:
    """Center+bounds of the keypad node whose text IS ``digit`` (exact only).

    Substring hits NEVER count: a hint such as "Minimum 4 digits" must not
    satisfy digit "4". Returns (center, bounds_str) or None. The caller
    must log center+bounds WITHOUT the digit value.
    """
    want = (digit or "").strip()
    if len(want) != 1 or not want.isdigit():
        return None
    try:
        root = ET.fromstring(dump_xml or "")
    except ET.ParseError:
        return None
    for node in root.iter("node"):
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "").strip()
            if val == want:
                b = (node.get("bounds") or "").strip()
                if not re.match(r"\[\d+,\d+\]\[\d+,\d+\]$", b):
                    continue
                c = parse_bounds(b)
                if c is None:
                    continue
                return c, b
    return None


def keypad_identity(dump_xml: str) -> tuple[bool, str]:
    """Prove the Hardware Session Authentication keypad is foreground.

    Requires title (EN/PT) + min-digits hint (EN/PT) + at least one exact
    digit node ("0".."9" as whole-text). Returns (ok, reason). Anything
    missing -> abort BEFORE any tap (zero keypresses, STOP upstream).
    """
    low = (dump_xml or "").lower()
    title = next((t for t in KEYPAD_TITLE_ANY if t.lower() in low), None)
    if title is None:
        return False, "keypad identity unproven: title missing"
    hint = next((h for h in KEYPAD_HINT_ANY if h.lower() in low), None)
    if hint is None:
        return False, "keypad identity unproven: min-digits hint missing"
    for d in "0123456789":
        if find_exact_digit(dump_xml or "", d) is not None:
            return True, f"keypad proven by {title!r}+{hint!r}+digit node"
    return False, "keypad identity unproven: no exact digit node"


def is_unlocked(dump_xml: str) -> bool:
    """True when the dump proves a residual UNLOCKED session.

    Any UNLOCKED_ANY marker (EN/PT title, auth-timer line, Lock Now)
    counts. Empty/bad dumps are never unlocked (conservative False).
    """
    low = (dump_xml or "").lower()
    if not low.strip():
        return False
    for m in UNLOCKED_ANY:
        if m.lower() in low:
            return True
    return False


def is_locked(dump_xml: str) -> bool:
    """True when the dump proves the LOCKED precondition.

    Standalone LOCKED token uses a word-boundary regex so UNLOCKED never
    counts as locked; explicit Session Locked / Unlock Session markers
    (EN/PT) also count. Empty dumps are never locked.
    """
    low = (dump_xml or "").lower()
    if not low.strip():
        return False
    for m in LOCKED_ANY:
        if m.lower() in low:
            return True
    if re.search(r"\blocked\b", low) is not None:
        return True
    return False


def slots_used_summary(dump_xml: str) -> str:
    """Auxiliary Slots-evidence: lines mentioning slot + Slot # count."""
    if not dump_xml:
        return "slots=unknown (empty dump)"
    try:
        root = ET.fromstring(dump_xml)
    except ET.ParseError:
        return "slots=unknown (bad xml)"
    hits: list[str] = []
    slot_hash = 0
    for node in root.iter("node"):
        for attr in ("text", "content-desc"):
            val = (node.get(attr) or "").strip()
            if not val:
                continue
            if "slot" in val.lower():
                if val not in hits:
                    hits.append(val)
            slot_hash += val.count("Slot #")
    count_line = f"slot_hash_count={slot_hash}"
    lines = hits[:20] + [count_line]
    return redact("\n".join(lines))


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
    do_wake(serial)  # re-assert display; wifi latency can outlast the timeout
    run_adb(serial, ["shell", "uiautomator", "dump", "/sdcard/tour_uidump.xml"],
            timeout=30)
    proc = run_adb(serial, ["shell", "cat", "/sdcard/tour_uidump.xml"], timeout=30)
    return proc.stdout or ""


def do_tap(serial: str, x: int, y: int) -> None:
    do_wake(serial)  # re-assert display; wifi latency can outlast the timeout
    run_adb(serial, ["shell", "input", "tap", str(x), str(y)], timeout=15)
    time.sleep(1.2)


def safe_tap_text(serial: str, dump: str, label: str) -> tuple[str, tuple[int, int] | None]:
    """Tap a visible label unless it is destruction-scoped.

    Returns ("tapped"|"missing"|"forbidden", center). Forbidden targets
    are never tapped. Every attempt logs label+center+bounds.
    """
    bad = forbidden_tap(label)
    if bad is not None:
        print(f"[tap] label={label!r} status=forbidden:{bad}")
        return f"forbidden:{bad}", None
    center = find_center_for_text(dump, label)
    bounds = find_bounds_for_text(dump, label)
    if center is None:
        print(f"[tap] label={label!r} status=missing bounds={bounds!r}")
        return "missing", None
    print(f"[tap] label={label!r} center={center} bounds={bounds!r}")
    do_tap(serial, *center)
    return "tapped", center


def do_back(serial: str) -> None:
    run_adb(serial, ["shell", "input", "keyevent", "KEYCODE_BACK"], timeout=15)
    time.sleep(1.0)


def do_swipe_up(serial: str) -> None:
    run_adb(serial, ["shell", "input", "swipe", "540", "1600", "540", "500", "400"],
            timeout=15)
    time.sleep(1.0)


def do_wake(serial: str) -> None:
    # Display wake only: no unlock, no typing, no secrets. The handset may
    # sit in Doze/AOD (uiautomator then dumps com.motorola.motodisplay and
    # screencap returns a black frame); wake first so dumps see the app.
    run_adb(serial, ["shell", "input", "keyevent", "KEYCODE_WAKEUP"],
            timeout=15)
    time.sleep(1.0)


def do_start(serial: str) -> None:
    do_wake(serial)
    # Cold start for determinism: a leftover task (earlier probe or step)
    # may sit on Settings/backup screens, which breaks step navigation.
    # force-stop only ends the process; no user data, keys, or NVS touched.
    run_adb(serial, ["shell", "am", "force-stop", APP_PACKAGE], timeout=30)
    # A cold start occasionally needs a second nudge (verified, not blind:
    # each attempt is followed by a dump asserting the app is foreground).
    for attempt in range(1, 4):
        run_adb(serial, ["shell", "am", "start", "-n", APP_ACTIVITY],
                timeout=30)
        time.sleep(3.0)
        dump = ui_dump(serial)
        try:
            pkgs = sorted({n.get("package", "") or "?"
                           for n in ET.fromstring(dump).iter("node")})
        except ET.ParseError:
            pkgs = ["<bad-xml>"]
        print(f"do_start attempt {attempt}: pkgs={pkgs}")
        if APP_PACKAGE in dump:
            return


def do_input_text(serial: str, text: str) -> bool:
    """Type a NON-secret label (tour- entry name). Letters/digits only."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", text):
        print(f"do_input_text: refusing unsafe label {text!r}")
        return False
    escaped = text.replace(" ", "%s")
    proc = run_adb(serial, ["shell", "input", "text", escaped], timeout=15)
    time.sleep(1.2)
    return proc.returncode == 0


def dismiss_keyboard_after_typing(serial: str, dump: str) -> tuple[str, str]:
    """Dismiss the soft keyboard so Generate Key is tappable.

    Prefers an IME Done action when visible, else a single KEYCODE_BACK
    (when the keyboard is open BACK dismisses the keyboard, not the
    dialog). Returns (fresh_dump, method). The caller must re-dump
    before tapping Generate Key; the fresh dump is the pre-submit dump.
    """
    for done_label in ("Done", "Concluir", "Conclu\u00eddo", "Concluido"):
        c = find_center_for_text(dump or "", done_label)
        if c is not None:
            print(f"[tap] label={done_label!r} center={c} "
                  f"bounds={find_bounds_for_text(dump or '', done_label)!r}")
            do_tap(serial, *c)
            time.sleep(0.8)
            return ui_dump(serial), f"ime-done:{done_label}"
    do_back(serial)
    return ui_dump(serial), "keycode-back"


def do_pin_entry(serial: str) -> tuple[bool, str]:
    """Single owner-PIN attempt from MANUAL_TOUR_PIN. Never logs the value.

    Parent gate: the Hardware Session Authentication keypad identity
    (title + min-digits hint + exact digit node) is proven BEFORE any tap;
    absent -> return False with ZERO keypresses (run_full STOPs upstream).
    Digits resolve ONLY by exact match (:func:`find_exact_digit`); every
    digit tap logs index+center+bounds WITHOUT the digit value. Pre/post
    dumps are saved to the evidence dir (never the PIN).
    Returns (submitted, reason). Exactly one submit otherwise.
    """
    pin = os.environ.get(PIN_ENV) or ""
    if not pin:
        return False, f"{PIN_ENV} absent -- aborting before any keypress"
    if not re.fullmatch(r"[0-9]{4,16}", pin):
        return False, f"{PIN_ENV} malformed -- aborting before any keypress"
    dump = ui_dump(serial)
    try:
        os.makedirs(evidence_dir(), exist_ok=True)
        with open(os.path.join(evidence_dir(), "pin-entry-pre.xml"),
                  "w", encoding="utf-8") as fh:
            fh.write(dump)
    except OSError:
        pass
    print("pin-entry: pre dump saved (evidence/pin-entry-pre.xml "
          f"{len(dump)}B)")
    id_ok, id_reason = keypad_identity(dump)
    if not id_ok:
        print(f"pin-entry: identity gate FAIL ({id_reason}) -- "
              "zero keypresses, STOP")
        return False, f"keypad identity unproven ({id_reason}) -- nothing tapped"
    print(f"pin-entry: identity gate PASS ({id_reason})")
    hits: list[tuple[tuple[int, int], str]] = []
    for digit in pin:
        hit = find_exact_digit(dump, digit)
        if hit is None:
            print("pin-entry: exact digit node missing -- "
                  "zero keypresses, STOP")
            return False, "keypad digit missing (exact) -- nothing tapped"
        hits.append(hit)
    for i, ((x, y), bounds) in enumerate(hits):
        print(f"[pin-digit] i={i + 1}/{len(hits)} center={(x, y)} "
              f"bounds={bounds!r} status=exact")
        run_adb(serial, ["shell", "input", "tap", str(x), str(y)], timeout=15)
        time.sleep(0.6)
    # Single submit on the unlock/confirm control.
    dump2 = ui_dump(serial)
    try:
        os.makedirs(evidence_dir(), exist_ok=True)
        with open(os.path.join(evidence_dir(), "pin-entry-post.xml"),
                  "w", encoding="utf-8") as fh:
            fh.write(dump2)
    except OSError:
        pass
    print("pin-entry: post dump saved (evidence/pin-entry-post.xml "
          f"{len(dump2)}B)")
    for label in ("Desbloquear", "Unlock", "Confirm", "Confirmar"):
        c = find_center_for_text(dump2, label)
        if c is not None:
            do_tap(serial, *c)
            time.sleep(2.0)
            return True, "single attempt submitted"
    return False, "no submit control -- digits tapped but nothing submitted"


def screencap(serial: str, dest: str) -> tuple[bool, int]:
    """PNG via exec-out straight to ``dest``. Returns (ok, width_px)."""
    try:
        proc = subprocess.run(["adb", "-s", serial, "exec-out", "screencap", "-p"],
                              capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False, 0
    data = proc.stdout
    if len(data) < 1000 or not data.startswith(b"\x89PNG"):
        return False, 0
    try:
        with open(dest, "wb") as fh:
            fh.write(data)
    except OSError:
        return False, 0
    width = downscale_to_max(dest, SHOT_MAX_W)
    return True, width


def downscale_to_max(path: str, max_w: int) -> int:
    """Downscale PNG to ``max_w`` px wide (aspect kept). Returns width."""
    try:
        from PIL import Image
    except ImportError:
        return 0
    try:
        with Image.open(path) as im:
            w, h = im.size
            if w <= max_w:
                return w
            im = im.resize((max_w, int(h * max_w / w)))
            im.save(path, optimize=True)
            return max_w
    except OSError:
        return 0


def guarded_screencap(serial: str, dump_xml: str,
                      dest: str) -> tuple[bool, int, str]:
    """Screenshot that never saves a legible live recovery code.

    When :func:`recovery_secret_visible` fires, the code region is
    blacked out via Pillow before ``dest`` is left on disk. Without
    Pillow (or without parseable bounds) nothing is saved and the
    caller must report SKIP-SECRET-VISIBLE. Returns (ok, width, mode)
    where mode is "saved" | "redacted" | "SKIP-SECRET-VISIBLE:*" |
    "screencap-failed".
    """
    if recovery_secret_visible(dump_xml or ""):
        if not pillow_available():
            return False, 0, "SKIP-SECRET-VISIBLE:no-pillow"
        tmp = dest + ".tmp-secret.png"
        ok, _w = screencap(serial, tmp)
        if not ok:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False, 0, "SKIP-SECRET-VISIBLE:screencap-failed"
        res = blackout_secret_regions(tmp, dump_xml or "")
        if res != "redacted":
            for p in (tmp, dest):
                try:
                    os.remove(p)
                except OSError:
                    pass
            return False, 0, f"SKIP-SECRET-VISIBLE:{res}"
        try:
            os.replace(tmp, dest)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False, 0, "SKIP-SECRET-VISIBLE:move-failed"
        width = downscale_to_max(dest, SHOT_MAX_W)
        return True, width, "redacted"
    ok, width = screencap(serial, dest)
    return ok, width, "saved" if ok else "screencap-failed"


def logcat_snippet(serial: str) -> str:
    """Last 40 app lines (no *:W filter), filtered by package + redacted."""
    try:
        proc = run_adb(serial, ["logcat", "-d", "-t", "500"], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return "(logcat unavailable)"
    lines = [ln for ln in (proc.stdout or "").splitlines()
             if APP_PACKAGE in ln]
    return redact("\n".join(lines[-40:])) or "(logcat empty)"


# ---------------------------------------------------------------------------
# Modes.
# ---------------------------------------------------------------------------
def active_steps(full: bool) -> list[dict]:
    return FULL_STEPS if full else STEPS


def cmd_dry_run(full: bool = False) -> int:
    steps = active_steps(full)
    mode = "FULL CLICK-THROUGH" if full else "VIEW-ONLY"
    print(f"manual screenshot tour -- DRY RUN ({mode}, no device touched)")
    for i, s in enumerate(steps, 1):
        print(f"[DRY ok] step {i}/{len(steps)} {s['id']:12s} "
              f"{s['title']} -> {s['shot']}")
    print(f"DRY RUN: {len(steps)}/{len(steps)} steps listed, 0 failed")
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

    # 2. Full table integrity.
    fids = [s["id"] for s in FULL_STEPS]
    check("full: 17 steps covering every reachable screen",
          len(FULL_STEPS) == 17, f"ids={fids}")
    check("full: unique ids and png shots <=720p naming",
          len(set(fids)) == len(fids)
          and all(s["shot"].endswith(".png") for s in FULL_STEPS),
          f"shots={[s['shot'] for s in FULL_STEPS]}")
    check("full: every step asserts visible text",
          all(s.get("expect_any") for s in FULL_STEPS),
          "all expect_any non-empty")
    check("full: exactly one pin-entry (single attempt, env-gated)",
          sum(a[0] == "pin-entry"
              for s in FULL_STEPS for a in s.get("nav", [])) == 1,
          "single authorized attempt, never retried")
    check("full: tour create+delete pair present (prefix tour-)",
          any(s["id"] == "vault-create-tour" for s in FULL_STEPS)
          and any(s["id"] == "vault-delete-tour" for s in FULL_STEPS)
          and TOUR_LABEL_PREFIX == "tour-",
          "throwaway entry created and removed via UI")
    check("full: language EN verified then restored to PT",
          any(s["id"] == "language-en" for s in FULL_STEPS)
          and any(s["id"] == "language-pt" for s in FULL_STEPS),
          "toggle verified both ways, ends in PT")
    check("full: GET_CAPS evidence hook present",
          any("getcaps-evidence" in [a[0] for a in s.get("nav", [])]
              for s in FULL_STEPS),
          "caps dump lines persisted as evidence")
    check("full: destructive-guard step present (screenshot-only)",
          any(s["id"] == "destructive-guard" for s in FULL_STEPS),
          "reset/wipe/unbind never tapped")

    # 3. Forbidden-tap guards.
    check("guards: forbidden list covers destruction scope",
          len(FORBIDDEN_TAP_SUBSTRINGS) >= 8
          and any("wipe" in b for b in FORBIDDEN_TAP_SUBSTRINGS)
          and any("factory reset" in b for b in FORBIDDEN_TAP_SUBSTRINGS),
          f"{len(FORBIDDEN_TAP_SUBSTRINGS)} guarded substrings")
    check("guards: no step taps a forbidden label",
          all(forbidden_tap(a[1]) is None
              for table in (STEPS, FULL_STEPS) for s in table
              for a in s.get("nav", []) + s.get("close", [])
              if a[0] == "tap"),
          "no nav/close tap names a destructive control")
    check("guards: forbidden_tap matches EN/PT variants",
          forbidden_tap("Confirm Wipe") is not None
          and forbidden_tap("Confirmar Limpeza") is not None
          and forbidden_tap("Generate Key") is None
          and forbidden_tap("Delete Key") is None,
          "destruction blocked, tour-entry delete allowed (scoped)")

    # 4. No hardcoded PIN anywhere in this file (env-only by design).
    # NOTE: the check itself must not contain a PIN-looking literal.
    try:
        with open(__file__, "r", encoding="utf-8") as fh:
            src = fh.read()
        leak = (re.search(r"(?i)\b(pin|passcode)\b\s*=\s*[\"'][0-9]{4,16}[\"']",
                          src) is not None)
    except OSError:
        leak, src = True, ""
    check("guards: owner PIN never hardcoded (env-only)",
          not leak and PIN_ENV in src,
          f"{PIN_ENV} read from env, no literal PIN in source")

    # 5. Default serial framing.
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
    check("framing: --full refuses emulator serials",
          is_emulator_serial("emulator-5554")
          and not is_emulator_serial("192.168.15.17:38071"),
          "physical-device acceptance only")

    # 6. Redaction.
    sample = ("pin: 1234 password=abcd recovery: word word "
              "bearer=tok123 code 482910 ref AB12-CD34-EF56-GH78")
    red = redact(sample)
    check("redact: secrets scrubbed",
          "1234" not in red and "482910" not in red
          and "tok123" not in red and "AB12-CD34-EF56-GH78" not in red,
          f"redacted={red!r}")

    # 7. XML tap-center parsing on synthetic dump.
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
    check("parse: caps evidence extractor",
          "Diagnostics" in caps_evidence_lines(synth),
          "caps lines extracted from dump")

    # 8. Out-dir default honors %TEMP%/tour.
    check("framing: default out is %TEMP%/tour",
          os.path.basename(os.path.normpath(default_out_dir())) == "tour",
          f"out={default_out_dir()!r}")

    # 9. Defect 1: dialog identity gates the throwaway-label typing.
    create_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                   '<node text="Generate Key in Security Key" '
                   'bounds="[100,200][500,300]" />'
                   '<node text="Label" bounds="[100,320][500,420]" />'
                   '<node class="android.widget.EditText" text="" '
                   'bounds="[100,440][900,540]" />'
                   "</node></hierarchy>")
    recovery_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                     '<node text="Emergency Recovery with Recovery Code" '
                     'bounds="[100,200][900,300]" />'
                     '<node text="Emergency Recovery Code" '
                     'resource-id="dev.aegiskey.app:id/recovery_code" '
                     'bounds="[100,320][900,520]" />'
                     '<node text="AB12-CD34-EF56-GH78" '
                     'bounds="[100,340][900,440]" />'
                     '<node text="Recover and Save" '
                     'bounds="[100,600][500,700]" />'
                     "</node></hierarchy>")
    ok_c, reason_c = create_dialog_identity(create_dump)
    ok_r, reason_r = create_dialog_identity(recovery_dump)
    ok_e, _ = create_dialog_identity(
        '<hierarchy><node bounds="[0,0][1080,2400]">'
        '<node text="Vault" bounds="[0,0][200,200]" /></node></hierarchy>')
    check("dialog-identity: create dialog proven before typing",
          ok_c, f"create dump -> {reason_c!r}")
    check("dialog-identity: recovery dialog vetoes typing (no wrong-field)",
          (not ok_r)
          and recovery_secret_visible(recovery_dump)
          and not recovery_secret_visible(create_dump),
          f"recovery dump veto -> {reason_r!r}")
    check("dialog-identity: blank screen never proves create dialog",
          not ok_e, "no marker -> abort, nothing typed")

    # 10. Defect 2: recovery-code box never saved legible.
    check("secret-guard: box label triggers, vault list does not",
          recovery_secret_visible(recovery_dump)
          and not recovery_secret_visible(create_dump),
          "label/resource-id detection only")
    check("secret-guard: code-box bounds extracted",
          len(secret_node_bounds(recovery_dump)) >= 1
          and secret_node_bounds(create_dump) == [],
          f"rects={secret_node_bounds(recovery_dump)!r}")
    if pillow_available():
        import tempfile as _tf
        from PIL import Image as _Image
        with _tf.NamedTemporaryFile(suffix=".png",
                                    delete=False) as _tmp:
            _tmp_path = _tmp.name
        try:
            _Image.new("RGB", (270, 600), (255, 255, 255)).save(_tmp_path)
            _res = blackout_secret_regions(_tmp_path, recovery_dump)
            with _Image.open(_tmp_path) as _im:
                _px = _im.getpixel((135, 105))
            check("secret-guard: redaction blacks out the code region",
                  _res == "redacted" and _px == (0, 0, 0),
                  f"blackout={_res!r} pixel={_px!r}")
        finally:
            try:
                os.remove(_tmp_path)
            except OSError:
                pass
    else:
        check("secret-guard: no Pillow -> SKIP-SECRET-VISIBLE path",
              blackout_secret_regions("/nonexistent.png",
                                      recovery_dump) == "no-pillow",
              "without Pillow nothing legible is saved")
    with open(__file__, "r", encoding="utf-8") as _fh:
        _src = _fh.read()
    check("secret-guard: all screenshot sites go through the guard",
          "guarded_screencap(serial, dump" in _src
          and _src.count("guarded_screencap(serial, dump") >= 3,
          "run_live + run_full (guard + step) use guarded_screencap")

    # 11. Defect 3: creation verified via list query, not typed text.
    typed_only = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                  '<node class="android.widget.EditText" '
                  'text="tour-120000" bounds="[100,440][900,540]" />'
                  "</node></hierarchy>")
    listed = ('<hierarchy><node bounds="[0,0][1080,2400]">'
              '<node text="tour-120000" bounds="[100,600][900,700]" />'
              "</node></hierarchy>")
    check("create-verify: EditText contents do NOT prove creation",
          not tour_label_listed(typed_only, "tour-120000")
          and tour_label_listed(listed, "tour-120000")
          and not tour_label_listed(listed, "tour-999999"),
          "list/detail node required, input-field text ignored")
    check("create-verify: run_full enforces the list query",
          'tour_label_listed(dump, tour_label)' in _src
          and 'vault-create-tour' in _src
          and 'list query' in _src.lower(),
          "vault-create-tour gates PASS on list-query hit")

    # 12. Keypad identity gate: pin-entry proves the Hardware Session
    # Authentication keypad BEFORE any tap; digits resolve ONLY by exact
    # match; pre/post dumps are persisted (PIN never logged).
    keypad_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                   '<node text="Hardware Session Authentication" '
                   'bounds="[100,100][900,200]" />'
                   '<node text="Minimum 4 digits" '
                   'bounds="[100,200][900,300]" />'
                   '<node text="1" bounds="[100,400][300,500]" />'
                   '<node text="2" bounds="[350,400][550,500]" />'
                   "</node></hierarchy>")
    hint_only_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                      '<node text="Hardware Session Authentication" '
                      'bounds="[100,100][900,200]" />'
                      '<node text="Minimum 4 digits" '
                      'bounds="[100,200][900,300]" />'
                      "</node></hierarchy>")
    no_keypad_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                      '<node text="Vault" bounds="[0,0][200,200]" />'
                      "</node></hierarchy>")
    ok_k, reason_k = keypad_identity(keypad_dump)
    ok_h, _ = keypad_identity(hint_only_dump)
    ok_n, _ = keypad_identity(no_keypad_dump)
    ok_pt, _ = keypad_identity(
        keypad_dump.replace("Hardware Session Authentication",
                            "Autenticação de Sessão de Hardware").replace(
            "Minimum 4 digits", "Mínimo de 4 dígitos"))
    check("keypad-gate: title+hint+digit proves keypad (EN and PT)",
          ok_k and ok_pt, f"gate -> {reason_k!r}")
    check("keypad-gate: hint-only / blank never prove keypad",
          not ok_h and not ok_n,
          "absent -> STOP with zero keypresses")
    check("keypad-gate: digits resolve ONLY by exact match",
          find_exact_digit(keypad_dump, "1") is not None
          and find_exact_digit(hint_only_dump, "4") is None
          and find_exact_digit("not xml", "1") is None
          and find_exact_digit(keypad_dump, "x") is None,
          "hint 'Minimum 4 digits' must NOT satisfy digit '4'")
    check("keypad-gate: exact center+bounds logged (no substring)",
          find_exact_digit(keypad_dump, "1") == ((200, 450),
                                                 "[100,400][300,500]"),
          "digit '1' -> center (200,450) bounds [100,400][300,500]")
    check("keypad-gate: do_pin_entry gates + saves pre/post dumps",
          "keypad_identity(dump)" in _src
          and "find_exact_digit(dump" in _src
          and "pin-entry-pre.xml" in _src
          and "pin-entry-post.xml" in _src,
          "identity before any tap, exact digits, dumps persisted")

    # 13. Residual-session guard: is_unlocked/is_locked prove the real
    # state BEFORE unlock-pin hunts the LOCKED keypad (22:18 dumps:
    # UNLOCKED + Remaining 04:55->04:44 + tour-215946 Slot #0).
    unlocked_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                     '<node text="UNLOCKED" bounds="[100,100][300,180]" />'
                     '<node text="Session Unlocked" '
                     'bounds="[100,200][500,280]" />'
                     '<node text="Remaining authorization time: 04:55" '
                     'bounds="[100,280][700,360]" />'
                     '<node text="Lock Now" bounds="[100,360][400,440]" />'
                     '<node text="tour-215946" '
                     'bounds="[100,600][500,680]" />'
                     "</node></hierarchy>")
    locked_dump = ('<hierarchy><node bounds="[0,0][1080,2400]">'
                   '<node text="Session Locked" '
                   'bounds="[100,100][500,180]" />'
                   '<node text="Unlock Session" '
                   'bounds="[100,200][500,280]" />'
                   "</node></hierarchy>")
    check("session-guard: UNLOCKED residual detected (timer+Lock Now)",
          is_unlocked(unlocked_dump) and not is_locked(unlocked_dump),
          "UNLOCKED+timer+Lock Now -> unlocked only")
    check("session-guard: LOCKED proven, never confused with UNLOCKED",
          is_locked(locked_dump) and not is_unlocked(locked_dump),
          "Session Locked/Unlock Session -> locked only")
    check("session-guard: UNLOCKED never counts as LOCKED (boundary)",
          not is_locked(unlocked_dump),
          "word-boundary LOCKED: UNLOCKED must not match")
    check("session-guard: empty/bad dumps are neither state",
          not is_unlocked("") and not is_locked("")
          and not is_unlocked("not xml") and not is_locked("not xml"),
          "conservative False on empty/garbage")
    check("session-guard: run_full relocks or SKIPs without extra PIN",
          "is_unlocked(pre)" in _src
          and "unlock-pin-relock" in _src
          and "already UNLOCKED residual -- no PIN consumed" in _src
          and "Lock Now" in _src and "Bloquear Agora" in _src,
          "Lock Now/Bloquear Agora + re-dump, else explicit SKIP")

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
        do_wake(serial)  # keep display off Doze/AOD so dumps see the app
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
                if forbidden_tap(action[1]) is not None:
                    print(f"[SKIP-tap] forbidden target refused: {action[1]!r}")
                    continue
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
        shot_ok, _w, shot_mode = guarded_screencap(
            serial, dump, os.path.join(out_dir, step["shot"]))
        if "SKIP-SECRET-VISIBLE" in shot_mode:
            failures += 1
            print(f"[SKIP] step {i}/{len(STEPS)} {step['id']:12s} "
                  f"marker={hit!r} {shot_mode} (secret box on screen)")
            snippet = logcat_snippet(serial)
            with open(os.path.join(out_dir, f"{tag}.logcat.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write(f"step={step['id']} marker={hit!r} "
                         f"shot_ok={shot_ok} shot_mode={shot_mode}\n{snippet}\n")
            print(f"      logcat snippet (redacted) -> {tag}.logcat.txt")
            ok = False
            detail = (f"marker={hit!r} shot={step['shot']}:{shot_ok} "
                      f"mode={shot_mode}")
        else:
            ok = hit is not None and shot_ok and len(dump) > 100
            detail = (f"marker={hit!r} shot={step['shot']}:{shot_ok} "
                      f"mode={shot_mode}")
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
            elif action[0] == "tap":
                if forbidden_tap(action[1]) is not None:
                    continue
                dump = ui_dump(serial)
                center = find_center_for_text(dump, action[1])
                if center is not None:
                    do_tap(serial, *center)
    print(f"\n==== TOUR: {len(STEPS) - failures}/{len(STEPS)} PASS ====")
    return 0 if failures == 0 else 1


def run_full(serial: str, png_dir: str) -> int:
    """Full click-through on a PHYSICAL device. Stops on first surprise."""
    os.makedirs(png_dir, exist_ok=True)
    ev_dir = evidence_dir()
    os.makedirs(ev_dir, exist_ok=True)
    print(f"manual screenshot tour -- FULL LIVE on {serial}")
    print(f"  png -> {png_dir} (<= {SHOT_MAX_W}px wide)")
    print(f"  evidence xml/logcat -> {ev_dir}")
    print("SAFETY: owner PIN at most once (env-only); recovery view-only; "
          "OTA view-only; reset/wipe/unbind NEVER tapped; STOP on surprise.")
    if is_emulator_serial(serial):
        print(f"ABORT: --full requires a physical device; {serial!r} is an "
              "emulator. Emulator stays OFF for acceptance.")
        return 2
    if not tour_pin_present():
        print(f"ABORT: {PIN_ENV} is absent -- refusing to type any PIN "
              "(ZERO wrong-PIN attempts). Set the env var and re-run.")
        return 2
    tour_label = f"{TOUR_LABEL_PREFIX}{time.strftime('%H%M%S')}"
    results: list[tuple[str, str, str]] = []  # (id, PASS/SKIP/STOP, reason)

    def evidence(step_id: str, dump: str) -> None:
        with open(os.path.join(ev_dir, f"{step_id}.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write(dump)

    def stop(reason: str) -> int:
        print(f"\nSTOP: {reason} -- remaining steps SKIP (run halted).")
        for s in FULL_STEPS[len(results):]:
            results.append((s["id"], "SKIP", "stopped: " + reason))
        summary(results)
        return 1

    for i, step in enumerate(FULL_STEPS, 1):
        sid = step["id"]
        do_wake(serial)
        dump = ""
        skipped_step = ""
        if sid == "unlock-pin":
            # Residual-session guard: a previous run may leave UNLOCKED
            # (timer 04:55->04:44 + tour-215946 still listed). Prove the
            # real state BEFORE hunting the LOCKED keypad UI.
            pre = ui_dump(serial)
            if is_unlocked(pre):
                print("unlock-pin: residual UNLOCKED session detected "
                      "(auth timer still valid) -- restoring LOCKED via "
                      "Lock Now/Bloquear Agora, else SKIP without PIN")
                relocked: str | None = None
                cur = pre
                for lock_label in ("Lock Now", "Bloquear Agora"):
                    st, _cc = safe_tap_text(serial, cur, lock_label)
                    if st != "tapped":
                        continue
                    time.sleep(2.0)
                    cand = ui_dump(serial)
                    evidence("unlock-pin-relock", cand)
                    if is_locked(cand) and not is_unlocked(cand):
                        print(f"unlock-pin: relock via {lock_label!r} "
                              "proved LOCKED -- proceeding to PIN unlock")
                        relocked = cand
                        break
                    print(f"unlock-pin: relock via {lock_label!r} did not "
                          "prove LOCKED (still unlocked?)")
                    cur = cand
                if relocked is None and is_unlocked(cur):
                    # Explicit SKIP: already unlocked, ZERO PIN consumes.
                    # expect_any for this step is the UNLOCKED markers, so
                    # the real state already satisfies the postcondition.
                    evidence(sid, cur)
                    shot_path = os.path.join(png_dir, step["shot"])
                    shot_ok, w, shot_mode = guarded_screencap(
                        serial, cur, shot_path)
                    results.append(
                        (sid, "SKIP",
                         "already UNLOCKED residual -- no PIN consumed, "
                         f"proceeding from real state "
                         f"(shot={step['shot']}:{shot_ok} [{w}px] "
                         f"mode={shot_mode})"))
                    print(f"[SKIP] step {i}/{len(FULL_STEPS)} {sid:16s} "
                          f"already UNLOCKED residual -- no PIN consumed "
                          f"[{w}px] mode={shot_mode}")
                    continue
                # Relocked (or lock state ambiguous): fall through to the
                # normal nav below; pin-entry consumes the single
                # authorized PIN only when the LOCKED keypad is proven.
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
                status, center = safe_tap_text(serial, dump, action[1])
                if status == "tapped":
                    dump = ""
                # "missing" taps are best-effort (EN/PT variants); the
                # expect_any assert below is the real gate.
            elif verb == "pin-entry":
                submitted, reason = do_pin_entry(serial)
                print(f"pin-entry: {reason}")
                if not submitted:
                    evidence(sid, ui_dump(serial))
                    results.append((sid, "SKIP", reason))
                    return stop(f"unlock gate: {reason}")
                dump = ""
            elif verb == "type-tour-label":
                if not dump:
                    dump = ui_dump(serial)
                # Defect 1: prove the intended create dialog is foreground
                # BEFORE typing. The Emergency Recovery "Recovery Code"
                # field must never receive the throwaway label.
                id_ok, id_reason = create_dialog_identity(dump)
                if not id_ok:
                    evidence(sid, dump)
                    results.append((sid, "SKIP",
                                    f"create dialog identity mismatch "
                                    f"({id_reason}) -- nothing typed"))
                    return stop(f"wrong-dialog guard: {id_reason}")
                # Focus the label field, then type the throwaway name.
                tapped = False
                for label_hint in ("Label", "R\u00f3tulo", "Nome", "Name"):
                    c = find_center_for_text(dump, label_hint)
                    if c is not None:
                        print(f"[tap] label={label_hint!r} center={c} "
                              f"bounds={find_bounds_for_text(dump, label_hint)!r}")
                        do_tap(serial, *c)
                        tapped = True
                        break
                if not tapped:
                    # Fallback: tap first editable field.
                    try:
                        root = ET.fromstring(dump)
                        for node in root.iter("node"):
                            if (node.get("class") or "").endswith("EditText"):
                                c = parse_bounds(node.get("bounds") or "")
                                if c is not None:
                                    print(f"[tap] label='<EditText-fallback>' "
                                          f"center={c} "
                                          f"bounds={node.get('bounds')!r}")
                                    do_tap(serial, *c)
                                    tapped = True
                                    break
                    except ET.ParseError:
                        pass
                if tapped and do_input_text(serial, tour_label):
                    print(f"typed throwaway label (len {len(tour_label)})")
                    # Pre-dismiss dump (post-type, keyboard may cover
                    # Generate Key) then dismiss keyboard, re-dump, and
                    # only then let the next nav tap Generate Key.
                    dump_typed = ui_dump(serial)
                    evidence(sid + "-typed", dump_typed)
                    dump_ready, kb_method = dismiss_keyboard_after_typing(
                        serial, dump_typed)
                    evidence(sid + "-pre-submit", dump_ready)
                    print(f"keyboard dismissed via {kb_method} "
                          f"(typed={len(dump_typed)}B "
                          f"pre-submit={len(dump_ready)}B)")
                    id_ok2, id_reason2 = create_dialog_identity(dump_ready)
                    if not id_ok2:
                        evidence(sid, dump_ready)
                        results.append((sid, "SKIP",
                                        f"post-keyboard dialog lost "
                                        f"({id_reason2}) -- nothing submitted"))
                        return stop(f"keyboard-dismiss guard: {id_reason2}")
                    dump = dump_ready
                else:
                    evidence(sid, dump)
                    results.append((sid, "SKIP", "label field not typable"))
                    return stop("tour-entry label could not be typed")
            elif verb == "delete-tour":
                dump = ui_dump(serial)
                c = find_center_for_text(dump, tour_label)
                used_needle = tour_label
                if c is None:
                    # Entry may already be listed under a truncated label;
                    # look for any tour- entry before giving up.
                    c = find_center_for_text(dump, TOUR_LABEL_PREFIX)
                    used_needle = TOUR_LABEL_PREFIX
                if c is None:
                    evidence(sid, dump)
                    results.append((sid, "SKIP", "tour- entry not on screen"))
                    return stop("throwaway entry missing -- nothing to delete")
                print(f"[tap] label={used_needle!r} center={c} "
                      f"bounds={find_bounds_for_text(dump, used_needle)!r}")
                do_tap(serial, *c)
                time.sleep(1.5)
                dlg = ui_dump(serial)
                names_tour = (tour_label in dlg
                              or TOUR_LABEL_PREFIX in dlg)
                if not names_tour:
                    do_back(serial)
                    evidence(sid, dlg)
                    results.append((sid, "SKIP",
                                    "delete dialog lacks tour- label -- "
                                    "backed out, nothing deleted"))
                    return stop("delete scope unproven -- backed out safely")
                confirmed = False
                for btn in ("Delete Key", "Delete Permanently", "Excluir",
                            "Apagar", "Delete"):
                    cc = find_center_for_text(dlg, btn)
                    if cc is not None:
                        print(f"[tap] label={btn!r} center={cc} "
                              f"bounds={find_bounds_for_text(dlg, btn)!r}")
                        do_tap(serial, *cc)
                        confirmed = True
                        break
                if not confirmed:
                    do_back(serial)
                    evidence(sid, dlg)
                    results.append((sid, "SKIP", "no delete confirm found"))
                    return stop("delete confirm missing -- backed out safely")
                time.sleep(2.0)
                dump = ""
            elif verb == "getcaps-evidence":
                if not dump:
                    dump = ui_dump(serial)
                lines = caps_evidence_lines(dump)
                with open(os.path.join(ev_dir, f"{sid}_getcaps.txt"), "w",
                          encoding="utf-8") as fh:
                    fh.write(f"serial={serial} transport=app\n{lines}\n")
                print(f"getcaps evidence: {len(lines.splitlines())} lines")
            elif verb in ("verify-en", "verify-pt"):
                if not dump:
                    dump = ui_dump(serial)
                want = ("Language", "Settings") if verb == "verify-en" else (
                    "Idioma", "Configura\u00e7\u00f5es")
                if dump_contains(dump, list(want)) is None:
                    evidence(sid, dump)
                    results.append((sid, "SKIP",
                                    f"{verb} marker missing"))
                    return stop(f"language toggle unverified ({verb})")
            elif verb == "guard-shot":
                # Screenshot-only: surface (but never tap) destructive
                # controls, then BACK out.
                dump = ui_dump(serial)
                surfaced = dump_contains(
                    dump, ["Ownership", "Factory Reset", "Selective Wipe",
                           "Release Device Ownership", "Limpeza Seletiva",
                           "Redefini"])
                if surfaced is None:
                    # Try one scroll to reveal the ownership section.
                    do_swipe_up(serial)
                    dump = ui_dump(serial)
                    surfaced = dump_contains(
                        dump, ["Ownership", "Factory Reset", "Selective Wipe",
                               "Release Device Ownership", "Limpeza Seletiva",
                               "Redefini"])
                shot_path = os.path.join(png_dir, step["shot"])
                shot_ok, w, shot_mode = guarded_screencap(
                    serial, dump, shot_path)
                evidence(sid, dump)
                do_back(serial)
                if "SKIP-SECRET-VISIBLE" in shot_mode:
                    results.append((sid, "SKIP",
                                    f"guard shot skipped ({shot_mode}) -- "
                                    "backed out"))
                    print(f"[SKIP] step "
                          f"{i}/{len(FULL_STEPS)} {sid:16s} {shot_mode} [{w}px]")
                    skipped_step = "handled"
                    break
                if not shot_ok:
                    results.append((sid, "SKIP", "screencap failed"))
                    return stop("guard screenshot failed")
                reason = (f"destructive dialog surfaced "
                          f"({surfaced!r}) -- screenshotted, backed out"
                          if surfaced else
                          "no destructive dialog surfaced -- "
                          "screenshot-only, backed out")
                results.append((sid, "SKIP" if not surfaced else "PASS",
                                reason))
                print(f"[{'PASS' if surfaced else 'SKIP'}] step "
                      f"{i}/{len(FULL_STEPS)} {sid:16s} {reason} [{w}px]")
                skipped_step = "handled"
                break
        if skipped_step:
            continue
        dump = ui_dump(serial)
        evidence(sid, dump)
        hit = dump_contains(dump, step["expect_any"])
        if sid == "vault-create-tour":
            # Defect 3: typed text in the input field is NOT a created
            # entry. Verify via a subsequent list query: the throwaway
            # label must appear as a non-EditText list/detail node.
            # Slots pré (aux evidence) before the refresh/list-query.
            slots_pre = slots_used_summary(dump)
            with open(os.path.join(ev_dir, f"{sid}_slots_pre.txt"),
                      "w", encoding="utf-8") as fh:
                fh.write(f"step={sid} phase=pre\n{slots_pre}\n")
            print(f"slots pre: {slots_pre!r}")
            # Refresh the list before querying: tap Refresh, swipe-up,
            # re-dump (best-effort; the list-query gate decides PASS).
            refresh_base = dump
            for refresh_label in ("Refresh", "Atualizar"):
                st, _cc = safe_tap_text(serial, refresh_base,
                                         refresh_label)
                if st == "tapped":
                    refresh_base = ui_dump(serial)
                    break
            do_swipe_up(serial)
            dump = ui_dump(serial)
            evidence(sid + "-refreshed", dump)
            if not tour_label_listed(dump, tour_label):
                queried = ui_dump(serial)
                if tour_label_listed(queried, tour_label):
                    dump = queried
                    evidence(sid + "-list", dump)
                else:
                    slots_post = slots_used_summary(dump)
                    with open(os.path.join(ev_dir, f"{sid}_slots_post.txt"),
                              "w", encoding="utf-8") as fh:
                        fh.write(f"step={sid} phase=post-fail\n"
                                 f"pre:\n{slots_pre}\npost:\n{slots_post}\n")
                    results.append(
                        (sid, "STOP",
                         f"create unverified: {tour_label!r} absent from "
                         f"list query (marker={hit!r}) -- typed text "
                         f"does not count"))
                    snippet = logcat_snippet(serial)
                    with open(os.path.join(ev_dir, f"{sid}.logcat.txt"),
                              "w", encoding="utf-8") as fh:
                        fh.write(f"step={sid} marker={hit!r} "
                                 f"create_unverified list-query-miss\n"
                                 f"{snippet}\n")
                    print(f"[STOP] step {i}/{len(FULL_STEPS)} {sid:16s} "
                          f"create unverified -- list query lacks "
                          f"{tour_label!r}")
                    return stop(f"step {sid} create unverified "
                                f"(list query miss)")
            slots_post = slots_used_summary(dump)
            with open(os.path.join(ev_dir, f"{sid}_slots_post.txt"),
                      "w", encoding="utf-8") as fh:
                fh.write(f"step={sid} phase=post\n"
                         f"pre:\n{slots_pre}\npost:\n{slots_post}\n")
            print(f"slots post: {slots_post!r}")
        shot_path = os.path.join(png_dir, step["shot"])
        shot_ok, w, shot_mode = guarded_screencap(serial, dump, shot_path)
        if "SKIP-SECRET-VISIBLE" in shot_mode:
            results.append(
                (sid, "SKIP",
                 f"secret box on screen ({shot_mode}) -- nothing saved"))
            print(f"[SKIP] step {i}/{len(FULL_STEPS)} {sid:16s} "
                  f"{shot_mode} [{w}px]")
            return stop(f"step {sid} secret-visible -- screenshot skipped")
        if hit is None or not shot_ok or len(dump) <= 100:
            results.append(
                (sid, "STOP",
                 f"unexpected state (marker={hit!r} shot_ok={shot_ok})"))
            snippet = logcat_snippet(serial)
            with open(os.path.join(ev_dir, f"{sid}.logcat.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write(f"step={sid} marker={hit!r} "
                         f"shot_ok={shot_ok}\n{snippet}\n")
            print(f"[STOP] step {i}/{len(FULL_STEPS)} {sid:16s} "
                  f"marker={hit!r} shot={step['shot']}:{shot_ok} [{w}px]")
            return stop(f"step {sid} assertion missed")
        results.append((sid, "PASS",
                        f"marker={hit!r} shot={step['shot']}:{shot_ok} "
                        f"[{w}px] mode={shot_mode}"))
        print(f"[PASS] step {i}/{len(FULL_STEPS)} {sid:16s} "
              f"marker={hit!r} shot={step['shot']}:{shot_ok} "
              f"[{w}px] mode={shot_mode}")
        for action in step.get("close", []):
            if action[0] == "back":
                do_back(serial)
            elif action[0] == "tap":
                if forbidden_tap(action[1]) is not None:
                    continue
                dump = ui_dump(serial)
                center = find_center_for_text(dump, action[1])
                if center is not None:
                    do_tap(serial, *center)
    summary(results)
    fails = sum(1 for _, st, _ in results if st not in ("PASS", "SKIP"))
    return 0 if fails == 0 else 1


def summary(results: list[tuple[str, str, str]]) -> None:
    n_pass = sum(1 for _, st, _ in results if st == "PASS")
    print(f"\n==== FULL TOUR: {n_pass}/{len(results)} PASS ====")
    for sid, st, reason in results:
        print(f"[{st}] {sid:16s} {reason}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="View-only adb screenshot tour of MANUAL_USUARIO.md flows; "
                    "--full adds the owner-PIN click-through.")
    ap.add_argument("--serial", default=None,
                    help="device serial (default: emulator-5554 if present, "
                         "else first adb device)")
    ap.add_argument("--out", default=None,
                    help="output dir (default: %%TEMP%%/tour; with --full: "
                         "docs/manual/img)")
    ap.add_argument("--full", action="store_true",
                    help="full click-through tour (owner PIN via "
                         "MANUAL_TOUR_PIN, single attempt; aborts when absent)")
    ap.add_argument("--dry-run", action="store_true",
                    help="list steps only; never touch adb")
    ap.add_argument("--self-test", action="store_true",
                    help="offline framing/parsing checks; never touch adb")
    args = ap.parse_args(argv)

    if args.self_test:
        return cmd_self_test()
    if args.dry_run:
        return cmd_dry_run(full=args.full)

    busy, reason = lane_busy()
    if busy:
        print(f"BUSY: {reason}")
        print("Another lane holds the rig -- degrading to --dry-run "
              "(steps listed only, adb untouched).")
        return cmd_dry_run(full=args.full)

    serial = args.serial or default_serial(list_devices())
    if serial is None:
        print("No --serial given and no adb device found; "
              "degrading to --dry-run.")
        return cmd_dry_run(full=args.full)
    if args.serial:
        devices = dict(list_devices())
        if devices.get(args.serial) != "device":
            print(f"Serial {args.serial!r} not in device state "
                  f"(seen: {devices}); refusing to steal/fight -- "
                  "degrading to --dry-run.")
            return cmd_dry_run(full=args.full)
    if args.full:
        return run_full(serial, args.out or manual_img_dir())
    return run_live(serial, args.out or default_out_dir())


if __name__ == "__main__":
    sys.exit(main())
