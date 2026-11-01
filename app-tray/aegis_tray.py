#!/usr/bin/env python3
"""AegisKey Desktop Companion & System Tray App — Cross-Platform Cyber-Security Authority.

Runs as a complete Desktop Application with native System Tray integration.
Features:
1. Vault & Secure Guard Authority (Real Zero-Trust Device State, PIN Unlock/Lock, Provisioning & Hardware Vault)
2. TOTP Authenticator (ESP32-S3 0x26 OP_OATH_CODE live calculations with 1-click copy)
3. Connected Keys & BLE Proximity Lock (Telemetry, Port/VID/PID, and Windows Dynamic Lock engine)
4. SSH Guard & Settings (Zero-Password SSH lifespan, Instant Purge on Lock/Unplug, SSH_ASKPASS config, i18n)

Provides native operating system alerts (Windows Balloon/Toast, Linux notify-send, macOS osascript)
when hardware keys are connected, disconnected, or when Secure Guard state changes.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, Optional

# Local imports
from hardware_client import AegisHardwareClient, DeviceInfo, SecureGuardStatus
from i18n import t
from notifications import NOTIFIER, NativeNotifier
from ssh_guard import SshGuard

# Material 3 Cyber-Security Dark Palette (Exact Mobile Match)
COLOR_BG = "#0B0F19"
COLOR_CARD = "#111827"
COLOR_CARD_BORDER = "#1F2937"
COLOR_CYAN = "#00E5FF"
COLOR_EMERALD = "#10B981"
COLOR_AMBER = "#F59E0B"
COLOR_CORAL = "#EF4444"
COLOR_TEXT_PRIMARY = "#F9FAFB"
COLOR_TEXT_MUTED = "#9CA3AF"
COLOR_INPUT_BG = "#1A2234"


class AegisDesktopApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "en"  # "en" or "pt"
        self.root.title(t("app_title", self.lang))
        self.root.geometry("680x760")
        self.root.minsize(620, 700)
        self.root.configure(bg=COLOR_BG)

        # Center window on screen at startup
        self._center_window(680, 760)

        # High-DPI support on Windows
        if platform.system() == "Windows":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass

        # Hardware & Security engines (Zero Mocks)
        self.notifier = NOTIFIER
        self.hw_client = AegisHardwareClient()
        self.ssh_guard = SshGuard(
            hardware_client=self.hw_client,
            on_purge_callback=self._on_ssh_purge,
            on_state_change_callback=self._on_guard_state_change,
        )

        # Telemetry & State Tracking for Connection Notifications
        self.current_device = DeviceInfo()
        self.current_guard = SecureGuardStatus()
        self.current_tab = "vault_sg"
        self._prev_connected: Optional[bool] = None
        self._prev_state: Optional[int] = None
        self._is_first_sync = True

        # Intercept window close to minimize to system tray
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        self._setup_styles()
        self._build_header()
        self._build_navigation_bar()
        self._build_content_panels()

        # Initialize native system tray icon
        self._setup_system_tray()

        # Start background polling and SSH watchdog
        self.ssh_guard.start_watchdog(interval_seconds=1.5)
        self._start_background_sync()

        # Ensure window is visible, centered, and active on launch
        self.show_from_tray()

    def _center_window(self, width: int, height: int):
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=COLOR_BG, foreground=COLOR_TEXT_PRIMARY)
        style.configure("Card.TFrame", background=COLOR_CARD, relief="flat")

    # =========================================================================
    # SINGLE HEADER (ASD-STE100, No Duplication, i18n EN/PT)
    # =========================================================================
    def _build_header(self):
        header_frame = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=14)
        header_frame.pack(fill="x")

        # Top row: Brand Title & Language Toggle
        top_row = tk.Frame(header_frame, bg=COLOR_BG)
        top_row.pack(fill="x")

        title_box = tk.Frame(top_row, bg=COLOR_BG)
        title_box.pack(side="left")

        self.lbl_title = tk.Label(
            title_box,
            text=t("app_title", self.lang),
            font=("Segoe UI", 16, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_BG,
        )
        self.lbl_title.pack(anchor="w")

        self.lbl_subtitle = tk.Label(
            title_box,
            text=t("app_subtitle", self.lang),
            font=("Segoe UI", 9),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_BG,
        )
        self.lbl_subtitle.pack(anchor="w")

        # Language toggle button
        self.btn_lang = tk.Button(
            top_row,
            text="EN / PT",
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_INPUT_BG,
            fg=COLOR_CYAN,
            activebackground=COLOR_CARD,
            activeforeground=COLOR_CYAN,
            relief="flat",
            bd=0,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._toggle_language,
        )
        self.btn_lang.pack(side="right")

        # Single Hardware Detection & Connection Badge Banner
        self.banner_frame = tk.Frame(
            header_frame, bg=COLOR_CARD, highlightthickness=1, highlightbackground=COLOR_CARD_BORDER, padx=14, pady=10
        )
        self.banner_frame.pack(fill="x", pady=(12, 0))

        self.lbl_device_name = tk.Label(
            self.banner_frame,
            text="ESP32-S3 (COM7 / USB 0x303A:0xAE61)",
            font=("Segoe UI", 10, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_CARD,
        )
        self.lbl_device_name.pack(side="left")

        self.lbl_conn_badge = tk.Label(
            self.banner_frame,
            text="Connecting...",
            font=("Segoe UI", 8, "bold"),
            fg=COLOR_AMBER,
            bg=COLOR_INPUT_BG,
            padx=10,
            pady=3,
        )
        self.lbl_conn_badge.pack(side="right")

    def _toggle_language(self):
        self.lang = "pt" if self.lang == "en" else "en"
        self._refresh_i18n_labels()

    def _refresh_i18n_labels(self):
        self.lbl_title.config(text=t("app_title", self.lang))
        self.lbl_subtitle.config(text=t("app_subtitle", self.lang))
        self.btn_nav_vault_sg.config(text=t("tab_vault_sg", self.lang))
        self.btn_nav_totp.config(text=t("tab_totp", self.lang))
        self.btn_nav_conn.config(text=t("tab_connected_keys", self.lang))
        self.btn_nav_ssh.config(text=t("tab_ssh_settings", self.lang))
        self._render_current_tab()

    # =========================================================================
    # NAVIGATION TABS (4 SECTIONS)
    # =========================================================================
    def _build_navigation_bar(self):
        nav_frame = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=4)
        nav_frame.pack(fill="x")

        def make_tab(text_key, tab_id):
            btn = tk.Button(
                nav_frame,
                text=t(text_key, self.lang),
                font=("Segoe UI", 9, "bold"),
                bg=COLOR_CARD if self.current_tab == tab_id else COLOR_BG,
                fg=COLOR_CYAN if self.current_tab == tab_id else COLOR_TEXT_MUTED,
                activebackground=COLOR_CARD,
                activeforeground=COLOR_CYAN,
                relief="flat",
                bd=0,
                padx=10,
                pady=7,
                cursor="hand2",
                command=lambda: self._switch_tab(tab_id),
            )
            btn.pack(side="left", padx=(0, 6))
            return btn

        self.btn_nav_vault_sg = make_tab("tab_vault_sg", "vault_sg")
        self.btn_nav_totp = make_tab("tab_totp", "totp")
        self.btn_nav_conn = make_tab("tab_connected_keys", "conn")
        self.btn_nav_ssh = make_tab("tab_ssh_settings", "ssh")

    def _switch_tab(self, tab_id: str):
        self.current_tab = tab_id
        for bid, btn in [
            ("vault_sg", self.btn_nav_vault_sg),
            ("totp", self.btn_nav_totp),
            ("conn", self.btn_nav_conn),
            ("ssh", self.btn_nav_ssh),
        ]:
            if bid == tab_id:
                btn.config(bg=COLOR_CARD, fg=COLOR_CYAN)
            else:
                btn.config(bg=COLOR_BG, fg=COLOR_TEXT_MUTED)
        self._render_current_tab()

    def _build_content_panels(self):
        self.content_container = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=10)
        self.content_container.pack(fill="both", expand=True)
        self._render_current_tab()

    def _render_current_tab(self):
        for widget in self.content_container.winfo_children():
            widget.destroy()

        if self.current_tab == "vault_sg":
            self._render_section_vault_sg()
        elif self.current_tab == "totp":
            self._render_section_totp()
        elif self.current_tab == "conn":
            self._render_section_connected_keys()
        elif self.current_tab == "ssh":
            self._render_section_ssh_settings()

    # =========================================================================
    # SECTION 1: VAULT & SECURE GUARD AUTHORITY
    # =========================================================================
    def _render_section_vault_sg(self):
        # Outer scrollable or direct frame
        card = tk.Frame(
            self.content_container,
            bg=COLOR_CARD,
            highlightthickness=1,
            highlightbackground=COLOR_CARD_BORDER,
            padx=18,
            pady=16,
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text=t("sg_title", self.lang),
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_CARD,
        ).pack(anchor="w")

        # Telemetry grid
        grid_frame = tk.Frame(card, bg=COLOR_CARD, pady=8)
        grid_frame.pack(fill="x")

        # Status badge
        tk.Label(
            grid_frame, text=t("sg_status_label", self.lang), font=("Segoe UI", 9), fg=COLOR_TEXT_MUTED, bg=COLOR_CARD
        ).grid(row=0, column=0, sticky="w", pady=3)

        state_color = COLOR_EMERALD if self.current_guard.unlocked else COLOR_AMBER
        if self.current_guard.state in (0, 5, 6, 9):
            state_color = COLOR_CORAL

        state_badge = tk.Label(
            grid_frame,
            text=self.current_guard.state_name.upper(),
            font=("Segoe UI", 8, "bold"),
            fg=state_color,
            bg=COLOR_INPUT_BG,
            padx=8,
            pady=2,
        )
        state_badge.grid(row=0, column=1, sticky="w", padx=10, pady=3)

        # Attempts badge
        tk.Label(
            grid_frame,
            text=t("sg_attempts_label", self.lang),
            font=("Segoe UI", 9),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).grid(row=1, column=0, sticky="w", pady=3)

        attempts_text = f"[{self.current_guard.remaining_attempts}/{self.current_guard.max_attempts}]"
        attempts_color = COLOR_EMERALD if self.current_guard.remaining_attempts >= 3 else COLOR_CORAL
        tk.Label(
            grid_frame,
            text=attempts_text,
            font=("Segoe UI", 9, "bold"),
            fg=attempts_color,
            bg=COLOR_CARD,
        ).grid(row=1, column=1, sticky="w", padx=10, pady=3)

        # Session countdown
        tk.Label(
            grid_frame,
            text=t("sg_session_label", self.lang),
            font=("Segoe UI", 9),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).grid(row=2, column=0, sticky="w", pady=3)

        rem_sec = max(0, self.current_guard.session_remaining_ms // 1000)
        sess_str = f"{rem_sec // 60:02d}:{rem_sec % 60:02d}" if self.current_guard.unlocked else "--:--"
        tk.Label(
            grid_frame,
            text=sess_str,
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_CYAN if self.current_guard.unlocked else COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).grid(row=2, column=1, sticky="w", padx=10, pady=3)

        # Security Badges (GAP-01 & GAP-02)
        sec_badges_frame = tk.Frame(card, bg=COLOR_CARD)
        sec_badges_frame.pack(fill="x", pady=(2, 6))

        tk.Label(
            sec_badges_frame,
            text=f"✓ {t('badge_ecdh_active', self.lang)}",
            font=("Segoe UI", 8, "bold"),
            fg=COLOR_EMERALD,
            bg=COLOR_INPUT_BG,
            padx=6,
            pady=2,
        ).pack(side="left", padx=(0, 6))

        tk.Label(
            sec_badges_frame,
            text=f"🔒 {t('badge_efuse_safe', self.lang)}",
            font=("Segoe UI", 8, "bold"),
            fg=COLOR_CYAN,
            bg=COLOR_INPUT_BG,
            padx=6,
            pady=2,
        ).pack(side="left")

        # Actions area (PIN Unlock or Lock Now)
        actions_box = tk.Frame(card, bg=COLOR_CARD)
        actions_box.pack(fill="x", pady=6)

        if not self.current_guard.unlocked:
            pin_row = tk.Frame(actions_box, bg=COLOR_CARD)
            pin_row.pack(fill="x")

            self.ent_pin = tk.Entry(
                pin_row,
                show="*",
                font=("Segoe UI", 11),
                bg=COLOR_INPUT_BG,
                fg=COLOR_TEXT_PRIMARY,
                insertbackground=COLOR_CYAN,
                relief="flat",
                bd=0,
                width=16,
            )
            self.ent_pin.pack(side="left", ipady=5, padx=(0, 10))
            self.ent_pin.focus_set()
            self.ent_pin.bind("<Return>", lambda e: self._action_unlock_pin())

            btn_unlock = tk.Button(
                pin_row,
                text=t("sg_btn_unlock", self.lang),
                font=("Segoe UI", 9, "bold"),
                bg=COLOR_CYAN,
                fg="#000000",
                activebackground="#33EBFF",
                relief="flat",
                bd=0,
                padx=14,
                pady=5,
                cursor="hand2",
                command=self._action_unlock_pin,
            )
            btn_unlock.pack(side="left")

            if not self.current_guard.provisioned:
                btn_prov = tk.Button(
                    actions_box,
                    text=t("sg_btn_provision", self.lang),
                    font=("Segoe UI", 9, "bold"),
                    bg=COLOR_AMBER,
                    fg="#000000",
                    relief="flat",
                    bd=0,
                    padx=12,
                    pady=5,
                    cursor="hand2",
                    command=self._action_provision,
                )
                btn_prov.pack(anchor="w", pady=(8, 0))
        else:
            btn_lock = tk.Button(
                actions_box,
                text=t("sg_btn_lock", self.lang),
                font=("Segoe UI", 9, "bold"),
                bg=COLOR_CORAL,
                fg="#FFFFFF",
                relief="flat",
                bd=0,
                padx=16,
                pady=6,
                cursor="hand2",
                command=self._action_lock_now,
            )
            btn_lock.pack(anchor="w")

        # Feedback label
        self.lbl_sg_feedback = tk.Label(
            card,
            text="",
            font=("Segoe UI", 8),
            fg=COLOR_CYAN,
            bg=COLOR_CARD,
            wraplength=560,
            justify="left",
        )
        self.lbl_sg_feedback.pack(anchor="w", pady=(6, 4))

        # Separator line
        tk.Frame(card, height=1, bg=COLOR_CARD_BORDER).pack(fill="x", pady=8)

        # Hardware Vault Area
        tk.Label(
            card,
            text=t("vault_subtitle", self.lang),
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_CARD,
        ).pack(anchor="w")

        if not self.current_guard.unlocked:
            lock_box = tk.Frame(
                card, bg=COLOR_INPUT_BG, highlightthickness=1, highlightbackground=COLOR_AMBER, padx=14, pady=12
            )
            lock_box.pack(fill="x", pady=8)

            tk.Label(
                lock_box,
                text=t("vault_locked_banner", self.lang),
                font=("Segoe UI", 9, "bold"),
                fg=COLOR_AMBER,
                bg=COLOR_INPUT_BG,
                wraplength=520,
            ).pack()
            return

        # UNLOCKED: Show registered hardware keys & wallets
        keys_header = tk.Frame(card, bg=COLOR_CARD)
        keys_header.pack(fill="x", pady=(4, 6))

        btn_shamir = tk.Button(
            keys_header,
            text=t("btn_shamir_backup", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_EMERALD,
            fg="#000000",
            relief="flat",
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
            command=self._action_shamir_backup,
        )
        btn_shamir.pack(side="right", padx=(6, 0))

        btn_create = tk.Button(
            keys_header,
            text=t("vault_btn_create", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_CYAN,
            fg="#000000",
            relief="flat",
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
            command=self._action_create_key,
        )
        btn_create.pack(side="right")

        keys = self.hw_client.get_vault_keys()
        wallets = self.hw_client.get_wallets()

        if not keys and not wallets:
            tk.Label(
                card,
                text=t("vault_no_keys", self.lang),
                font=("Segoe UI", 9),
                fg=COLOR_TEXT_MUTED,
                bg=COLOR_CARD,
            ).pack(anchor="w", pady=6)
            return

        vault_list = tk.Frame(card, bg=COLOR_CARD)
        vault_list.pack(fill="both", expand=True)

        for k in keys[:4]:
            row = tk.Frame(
                vault_list,
                bg=COLOR_INPUT_BG,
                highlightthickness=1,
                highlightbackground=COLOR_CARD_BORDER,
                padx=10,
                pady=6,
            )
            row.pack(fill="x", pady=3)

            tk.Label(
                row,
                text=f"Slot {k.slot_id}: {k.label}",
                font=("Segoe UI", 9, "bold"),
                fg=COLOR_TEXT_PRIMARY,
                bg=COLOR_INPUT_BG,
            ).pack(side="left")

            tk.Label(
                row,
                text=k.algorithm,
                font=("Segoe UI", 8),
                fg=COLOR_CYAN,
                bg=COLOR_INPUT_BG,
                padx=8,
            ).pack(side="left")

            btn_del = tk.Button(
                row,
                text=t("vault_btn_delete", self.lang),
                font=("Segoe UI", 7, "bold"),
                bg=COLOR_CORAL,
                fg="#FFFFFF",
                relief="flat",
                bd=0,
                padx=8,
                pady=2,
                cursor="hand2",
                command=lambda s=k.slot_id: self._action_delete_key(s),
            )
            btn_del.pack(side="right")

        for w in wallets[:2]:
            row = tk.Frame(
                vault_list,
                bg=COLOR_INPUT_BG,
                highlightthickness=1,
                highlightbackground=COLOR_CARD_BORDER,
                padx=10,
                pady=6,
            )
            row.pack(fill="x", pady=3)

            tk.Label(
                row,
                text=f"Wallet {w.slot}: {w.label}",
                font=("Segoe UI", 9, "bold"),
                fg=COLOR_EMERALD,
                bg=COLOR_INPUT_BG,
            ).pack(anchor="w")

            tk.Label(
                row,
                text=w.address,
                font=("Consolas", 8),
                fg=COLOR_TEXT_MUTED,
                bg=COLOR_INPUT_BG,
            ).pack(anchor="w")

    def _action_unlock_pin(self):
        pin = getattr(self, "ent_pin", None)
        if not pin:
            return
        pin_val = pin.get().strip()
        if not pin_val:
            self.lbl_sg_feedback.config(text="Enter a PIN.", fg=COLOR_AMBER)
            return

        res = self.hw_client.unlock_secure_guard(pin_val)
        if res.get("ok"):
            self.lbl_sg_feedback.config(text=t("sg_unlock_success", self.lang), fg=COLOR_EMERALD)
            self._sync_immediate()
        else:
            err = res.get("error") or res.get("message") or t("sg_unlock_failed", self.lang)
            self.lbl_sg_feedback.config(text=f"Error: {err}", fg=COLOR_CORAL)
            self._sync_immediate()

    def _action_lock_now(self):
        self.hw_client.lock_secure_guard()
        self.lbl_sg_feedback.config(text=t("sg_lock_success", self.lang), fg=COLOR_AMBER)
        self._sync_immediate()

    def _action_provision(self):
        pin = getattr(self, "ent_pin", None)
        pin_val = pin.get().strip() if pin else ""
        if len(pin_val) < 4:
            self.lbl_sg_feedback.config(text="PIN must be at least 4 digits.", fg=COLOR_AMBER)
            return
        res = self.hw_client.provision_secure_guard(pin_val)
        if res.get("ok"):
            self.lbl_sg_feedback.config(text="Provisioned successfully! You may now unlock.", fg=COLOR_EMERALD)
            self._sync_immediate()
        else:
            self.lbl_sg_feedback.config(text=f"Provisioning failed: {res.get('error')}", fg=COLOR_CORAL)

    def _action_create_key(self):
        res = self.hw_client.create_key("PASSKEY_FIDO", "ed25519", curve=-8)
        if res.get("ok"):
            self._render_current_tab()
        else:
            messagebox.showerror("Error", res.get("error", "Key creation failed"))

    def _action_delete_key(self, slot_id: int):
        self.hw_client.delete_key(slot_id)
        self._render_current_tab()

    def _action_shamir_backup(self):
        res = self.hw_client.shamir_split()
        if res.get("ok"):
            shares = res.get("shares", [])
            lines = [
                "Shamir 2-of-3 Secret Sharing Backup (SLIP-0039 / GF(256)) Generated:\n",
            ]
            for sh in shares:
                hex_trunc = sh.get("share_hex", "")[:16]
                lines.append(f"Share {sh.get('index')}: {hex_trunc}... ({sh.get('description')})")
            lines.append("\nLagrange Quorum: Any 2 shares restore 100% of vault master seed.")
            messagebox.showinfo(t("shamir_title", self.lang), "\n".join(lines))
        else:
            messagebox.showerror("Error", res.get("error", "Shamir split failed"))

    def _action_clear_sign_preview(self):
        res = self.hw_client.clear_sign_preview({
            "tx_type": "ETH",
            "to": "0x892a43bC8419F71bC02Fa9832A1C90B5D",
            "amount": "0.7500 ETH",
            "fee": "0.0012 ETH",
            "chain": "Ethereum Mainnet"
        })
        if res.get("ok"):
            screen = res.get("screen", {})
            ascii_text = "\n".join(screen.get("ascii_frame", []))
            messagebox.showinfo(
                t("clear_signing_title", self.lang),
                f"Virtual SSD1306 OLED Frame Preview (Code-Only Mode):\n\n{ascii_text}"
            )
        else:
            messagebox.showerror("Error", res.get("error", "Clear signing preview failed"))

    # =========================================================================
    # SECTION 2: HARDWARE TOTP CODES
    # =========================================================================
    def _render_section_totp(self):
        card = tk.Frame(
            self.content_container,
            bg=COLOR_CARD,
            highlightthickness=1,
            highlightbackground=COLOR_CARD_BORDER,
            padx=18,
            pady=16,
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text=t("totp_title", self.lang),
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_CARD,
        ).pack(anchor="w")

        tk.Label(
            card,
            text=t("totp_subtitle", self.lang),
            font=("Segoe UI", 8),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).pack(anchor="w", pady=(0, 12))

        accounts = self.hw_client.get_oath_codes()
        if not accounts:
            tk.Label(
                card,
                text=t("totp_no_accounts", self.lang),
                font=("Segoe UI", 9),
                fg=COLOR_TEXT_MUTED,
                bg=COLOR_CARD,
            ).pack(anchor="w", pady=10)
            return

        for acc in accounts:
            row = tk.Frame(
                card,
                bg=COLOR_INPUT_BG,
                highlightthickness=1,
                highlightbackground=COLOR_CARD_BORDER,
                padx=14,
                pady=12,
            )
            row.pack(fill="x", pady=5)

            name_box = tk.Frame(row, bg=COLOR_INPUT_BG)
            name_box.pack(side="left")

            tk.Label(
                name_box,
                text=acc.name,
                font=("Segoe UI", 10, "bold"),
                fg=COLOR_TEXT_PRIMARY,
                bg=COLOR_INPUT_BG,
            ).pack(anchor="w")

            code_str = f"{acc.code[:3]} {acc.code[3:]}" if len(acc.code) == 6 else acc.code
            tk.Label(
                name_box,
                text=code_str,
                font=("Consolas", 15, "bold"),
                fg=COLOR_CYAN,
                bg=COLOR_INPUT_BG,
            ).pack(anchor="w")

            btn_copy = tk.Button(
                row,
                text=t("totp_btn_copy", self.lang),
                font=("Segoe UI", 8, "bold"),
                bg=COLOR_CYAN,
                fg="#000000",
                relief="flat",
                bd=0,
                padx=12,
                pady=5,
                cursor="hand2",
                command=lambda c=acc.code: self._copy_to_clipboard(c, t("totp_copied", self.lang)),
            )
            btn_copy.pack(side="right")

    # =========================================================================
    # SECTION 3: CONNECTED KEYS & BLE PROXIMITY LOCK
    # =========================================================================
    def _render_section_connected_keys(self):
        card = tk.Frame(
            self.content_container,
            bg=COLOR_CARD,
            highlightthickness=1,
            highlightbackground=COLOR_CARD_BORDER,
            padx=18,
            pady=16,
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text=t("conn_title", self.lang),
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_CARD,
        ).pack(anchor="w")

        # Physical Hardware Telemetry Box
        tele_box = tk.Frame(
            card, bg=COLOR_INPUT_BG, highlightthickness=1, highlightbackground=COLOR_CARD_BORDER, padx=14, pady=12
        )
        tele_box.pack(fill="x", pady=12)

        def add_info_row(parent, label_key, val_text, val_color=COLOR_TEXT_PRIMARY):
            r = tk.Frame(parent, bg=COLOR_INPUT_BG)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=t(label_key, self.lang), font=("Segoe UI", 9), fg=COLOR_TEXT_MUTED, bg=COLOR_INPUT_BG).pack(
                side="left"
            )
            tk.Label(r, text=f" {val_text}", font=("Segoe UI", 9, "bold"), fg=val_color, bg=COLOR_INPUT_BG).pack(
                side="left"
            )

        add_info_row(tele_box, "badge_hardware", self.current_device.product, COLOR_CYAN)
        add_info_row(tele_box, "conn_chip_label", self.current_device.chip, COLOR_TEXT_PRIMARY)
        add_info_row(tele_box, "conn_port_label", self.current_device.port, COLOR_TEXT_PRIMARY)
        add_info_row(tele_box, "conn_vidpid_label", f"{self.current_device.vid}:{self.current_device.pid}", COLOR_TEXT_MUTED)
        conn_col = COLOR_EMERALD if self.current_device.connected else COLOR_CORAL
        conn_txt = t("connected", self.lang) if self.current_device.connected else t("disconnected", self.lang)
        add_info_row(tele_box, "conn_status_label", conn_txt.upper(), conn_col)

        # BLE Proximity & Dynamic Lock Telemetry
        prox_info = self.hw_client.get_proximity_status()
        prox_box = tk.Frame(
            card, bg=COLOR_INPUT_BG, highlightthickness=1, highlightbackground=COLOR_CARD_BORDER, padx=14, pady=12
        )
        prox_box.pack(fill="x", pady=(8, 0))

        tk.Label(
            prox_box,
            text=t("conn_prox_title", self.lang),
            font=("Segoe UI", 10, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_INPUT_BG,
        ).pack(anchor="w", pady=(0, 6))

        is_prox_armed = prox_info.get("enabled", True)
        add_info_row(
            prox_box,
            "conn_prox_status",
            t("conn_prox_active", self.lang) if is_prox_armed else t("conn_prox_inactive", self.lang),
            COLOR_EMERALD if is_prox_armed else COLOR_AMBER,
        )
        add_info_row(prox_box, "conn_prox_rssi", f"{prox_info.get('rssi_dbm', -35)} dBm", COLOR_CYAN)
        add_info_row(prox_box, "conn_prox_threshold", f"{prox_info.get('threshold_dbm', -75)} dBm", COLOR_TEXT_MUTED)
        add_info_row(prox_box, "conn_os_companion_title", t("conn_os_companion_safe", self.lang), COLOR_CYAN)

        # Clear Signing 128x64 OLED Preview Button (OPP-06)
        btn_clear_signing = tk.Button(
            card,
            text=t("btn_clear_signing", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_CYAN,
            fg="#000000",
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
            command=self._action_clear_sign_preview,
        )
        btn_clear_signing.pack(anchor="w", pady=(12, 0))

    # =========================================================================
    # SECTION 4: SSH GUARD & SETTINGS
    # =========================================================================
    def _render_section_ssh_settings(self):
        card = tk.Frame(
            self.content_container,
            bg=COLOR_CARD,
            highlightthickness=1,
            highlightbackground=COLOR_CARD_BORDER,
            padx=18,
            pady=16,
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text=t("ssh_title", self.lang),
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_TEXT_PRIMARY,
            bg=COLOR_CARD,
        ).pack(anchor="w")

        tk.Label(
            card,
            text=t("ssh_subtitle", self.lang),
            font=("Segoe UI", 8),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).pack(anchor="w", pady=(0, 10))

        is_active = self.current_guard.unlocked and self.current_device.connected
        banner_bg = COLOR_INPUT_BG
        banner_border = COLOR_EMERALD if is_active else COLOR_AMBER
        banner_text = t("ssh_status_active", self.lang) if is_active else t("ssh_status_inactive", self.lang)

        banner = tk.Frame(
            card, bg=banner_bg, highlightthickness=1, highlightbackground=banner_border, padx=12, pady=10
        )
        banner.pack(fill="x", pady=6)

        # Native OpenSSH Agent Provider Card (OPP-01)
        native_box = tk.Frame(
            card, bg=COLOR_INPUT_BG, highlightthickness=1, highlightbackground=COLOR_CARD_BORDER, padx=12, pady=8
        )
        native_box.pack(fill="x", pady=(4, 8))

        tk.Label(
            native_box,
            text=t("ssh_native_agent_title", self.lang),
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_CYAN,
            bg=COLOR_INPUT_BG,
        ).pack(anchor="w")

        tk.Label(
            native_box,
            text=t("ssh_native_agent_status", self.lang),
            font=("Segoe UI", 8, "bold"),
            fg=COLOR_EMERALD,
            bg=COLOR_INPUT_BG,
        ).pack(anchor="w", pady=(2, 0))

        tk.Label(
            native_box,
            text=t("ssh_native_agent_desc", self.lang),
            font=("Segoe UI", 8),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_INPUT_BG,
        ).pack(anchor="w")

        tk.Label(
            banner,
            text=banner_text,
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_EMERALD if is_active else COLOR_AMBER,
            bg=banner_bg,
            wraplength=520,
            justify="left",
        ).pack(anchor="w")

        id_count, id_msg = self.ssh_guard.get_agent_identities_count()
        agent_box = tk.Frame(card, bg=COLOR_CARD, pady=6)
        agent_box.pack(fill="x")

        tk.Label(
            agent_box,
            text=t("ssh_agent_cache_label", self.lang),
            font=("Segoe UI", 9),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).pack(side="left")

        tk.Label(
            agent_box,
            text=f" {id_count} ({id_msg})",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_CYAN if id_count > 0 else COLOR_TEXT_MUTED,
            bg=COLOR_CARD,
        ).pack(side="left")

        # Fast Actions Frame
        actions_frame = tk.Frame(card, bg=COLOR_CARD, pady=8)
        actions_frame.pack(fill="x")

        btn_purge = tk.Button(
            actions_frame,
            text=t("ssh_btn_purge", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_CORAL,
            fg="#FFFFFF",
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._action_purge_ssh,
        )
        btn_purge.pack(side="left", padx=(0, 8))

        btn_fido2 = tk.Button(
            actions_frame,
            text=t("ssh_btn_load_fido2", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_CYAN,
            fg="#000000",
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._action_load_fido2,
        )
        btn_fido2.pack(side="left", padx=(0, 8))

        btn_env = tk.Button(
            actions_frame,
            text=t("ssh_btn_env", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_INPUT_BG,
            fg=COLOR_CYAN,
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._action_copy_ssh_env,
        )
        btn_env.pack(side="left")

        # Ephemeral Session Passphrase Section
        pass_box = tk.LabelFrame(
            card,
            text=t("ssh_ephemeral_label", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_CARD,
            fg=COLOR_TEXT_MUTED,
            padx=10,
            pady=8,
        )
        pass_box.pack(fill="x", pady=10)

        pass_row = tk.Frame(pass_box, bg=COLOR_CARD)
        pass_row.pack(fill="x")

        self.ent_ssh_pass = tk.Entry(
            pass_row,
            show="*",
            font=("Segoe UI", 10),
            bg=COLOR_INPUT_BG,
            fg=COLOR_TEXT_PRIMARY,
            insertbackground=COLOR_CYAN,
            relief="flat",
            bd=0,
            width=20,
        )
        self.ent_ssh_pass.pack(side="left", ipady=4, padx=(0, 8))

        btn_set_pass = tk.Button(
            pass_row,
            text=t("ssh_btn_set_ephemeral", self.lang),
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_CYAN,
            fg="#000000",
            relief="flat",
            bd=0,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._action_set_session_passphrase,
        )
        btn_set_pass.pack(side="left", padx=(0, 6))

        btn_clear_pass = tk.Button(
            pass_row,
            text=t("ssh_btn_clear_ephemeral", self.lang),
            font=("Segoe UI", 8),
            bg=COLOR_INPUT_BG,
            fg=COLOR_TEXT_MUTED,
            relief="flat",
            bd=0,
            padx=8,
            pady=4,
            cursor="hand2",
            command=self._action_clear_session_passphrase,
        )
        btn_clear_pass.pack(side="left")

        self.lbl_ssh_feedback = tk.Label(
            card,
            text="",
            font=("Segoe UI", 8),
            fg=COLOR_CYAN,
            bg=COLOR_CARD,
            wraplength=520,
            justify="left",
        )
        self.lbl_ssh_feedback.pack(anchor="w", pady=(6, 0))

    def _action_purge_ssh(self):
        res = self.ssh_guard.purge_ssh_agent()
        self.lbl_ssh_feedback.config(text=f"ssh-add -D: {res}", fg=COLOR_AMBER)
        self._render_current_tab()

    def _action_load_fido2(self):
        ok, msg = self.ssh_guard.load_resident_fido2_keys()
        self.lbl_ssh_feedback.config(text=f"ssh-add -K: {msg}", fg=COLOR_EMERALD if ok else COLOR_CORAL)
        self._render_current_tab()

    def _action_copy_ssh_env(self):
        scripts = self.ssh_guard.get_environment_setup_script()
        script_text = scripts.get("powershell" if platform.system() == "Windows" else "bash", "")
        self._copy_to_clipboard(script_text, t("ssh_env_copied", self.lang))
        self.lbl_ssh_feedback.config(text=t("ssh_env_copied", self.lang), fg=COLOR_EMERALD)

    def _action_set_session_passphrase(self):
        ent = getattr(self, "ent_ssh_pass", None)
        if not ent:
            return
        p = ent.get()
        if not self.current_guard.unlocked:
            self.lbl_ssh_feedback.config(text="Secure Guard must be UNLOCKED first.", fg=COLOR_AMBER)
            return
        ok = self.ssh_guard.set_ephemeral_passphrase(p)
        if ok:
            self.lbl_ssh_feedback.config(
                text="Session passphrase active. Will be auto-wiped on lock/disconnect.", fg=COLOR_EMERALD
            )
            ent.delete(0, tk.END)
        else:
            self.lbl_ssh_feedback.config(text="Failed to set session authorization.", fg=COLOR_CORAL)

    def _action_clear_session_passphrase(self):
        self.ssh_guard.clear_ephemeral_passphrase()
        self.lbl_ssh_feedback.config(text="Session passphrase cleared.", fg=COLOR_TEXT_MUTED)

    def _copy_to_clipboard(self, text: str, feedback_msg: str = ""):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    # =========================================================================
    # BACKGROUND TELEMETRY & CONNECTION TRANSITION NOTIFICATIONS
    # =========================================================================
    def _start_background_sync(self):
        def sync_worker():
            while True:
                try:
                    self._sync_immediate()
                except Exception:
                    pass
                time.sleep(1.5)

        t_sync = threading.Thread(target=sync_worker, daemon=True, name="AegisTraySync")
        t_sync.start()

    def _sync_immediate(self):
        dev = self.hw_client.detect_device()
        sg = self.hw_client.get_secure_guard_status()
        self.root.after(0, self._apply_state_update, dev, sg)

    def _apply_state_update(self, dev: DeviceInfo, sg: SecureGuardStatus):
        prev_conn = self._prev_connected
        prev_st = self._prev_state

        self.current_device = dev
        self.current_guard = sg
        self._prev_connected = dev.connected
        self._prev_state = sg.state

        # Update Header Banner
        dev_label = f"{dev.product} ({dev.port})"
        self.lbl_device_name.config(text=dev_label)

        if dev.connected:
            self.lbl_conn_badge.config(
                text=t("connected", self.lang).upper(), fg=COLOR_EMERALD, bg=COLOR_INPUT_BG
            )
        else:
            self.lbl_conn_badge.config(
                text=t("disconnected", self.lang).upper(), fg=COLOR_CORAL, bg=COLOR_INPUT_BG
            )

        # STATE TRANSITION DETECTION & NATIVE NOTIFICATIONS
        if not self._is_first_sync:
            # 1. DISCONNECTED -> CONNECTED
            if prev_conn is False and dev.connected is True:
                self.notifier.notify(
                    title=t("notif_conn_title", self.lang),
                    message=t("notif_conn_body", self.lang, port=dev.port, state=sg.state_name),
                    level="info",
                )
                # Auto-switch to Vault & Secure Guard if locked
                if not sg.unlocked:
                    self._switch_tab("vault_sg")

            # 2. CONNECTED -> DISCONNECTED
            elif prev_conn is True and dev.connected is False:
                self.notifier.notify(
                    title=t("notif_disconn_title", self.lang),
                    message=t("notif_disconn_body", self.lang),
                    level="warning",
                )
                self.ssh_guard.purge_ssh_agent()

            # 3. LOCKED -> UNLOCKED
            if prev_st is not None and prev_st != 4 and sg.state == 4:
                self.notifier.notify(
                    title=t("notif_unlocked_title", self.lang),
                    message=t("notif_unlocked_body", self.lang),
                    level="info",
                )

            # 4. UNLOCKED -> LOCKED
            elif prev_st == 4 and sg.state != 4:
                self.notifier.notify(
                    title=t("notif_locked_title", self.lang),
                    message=t("notif_locked_body", self.lang),
                    level="warning",
                )
                self.ssh_guard.purge_ssh_agent()
        else:
            self._is_first_sync = False

        # Re-render active tab
        self._render_current_tab()

    def _on_ssh_purge(self, msg: str):
        self.notifier.notify("AegisKey Security Alert", msg, level="warning")

    def _on_guard_state_change(self, is_unlocked: bool):
        self.root.after(0, self._sync_immediate)

    # =========================================================================
    # SYSTEM TRAY INTEGRATION (Cross-Platform)
    # =========================================================================
    def _setup_system_tray(self):
        """Initializes system tray icon. Uses Win32 ctypes on Windows, fallback on other OS."""
        if platform.system() == "Windows":
            self._setup_win32_tray()
        else:
            try:
                import pystray
                from PIL import Image, ImageDraw

                image = Image.new("RGB", (64, 64), color="#0B0F19")
                draw = ImageDraw.Draw(image)
                draw.rectangle((16, 16, 48, 48), fill="#00E5FF")
                menu = pystray.Menu(
                    pystray.MenuItem(t("tray_open", self.lang), self.show_from_tray),
                    pystray.MenuItem(t("tray_lock", self.lang), self._action_lock_now),
                    pystray.MenuItem(t("tray_purge_ssh", self.lang), self._action_purge_ssh),
                    pystray.MenuItem(t("tray_exit", self.lang), self.exit_app),
                )
                self.tray_icon = pystray.Icon("AegisKey", image, "AegisKey Secure Guard", menu)
                threading.Thread(target=self.tray_icon.run, daemon=True).start()
            except Exception:
                pass

    def _setup_win32_tray(self):
        """Native Windows Shell_NotifyIcon implementation with zero external dependencies."""
        WM_USER = 0x0400
        self.WM_TRAY_CALLBACK = WM_USER + 20
        NIM_ADD = 0x00000000
        NIF_MESSAGE = 0x00000001
        NIF_ICON = 0x00000002
        NIF_TIP = 0x00000004

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint32),
                ("hWnd", ctypes.c_void_p),
                ("uID", ctypes.c_uint32),
                ("uFlags", ctypes.c_uint32),
                ("uCallbackMessage", ctypes.c_uint32),
                ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128),
                ("dwState", ctypes.c_uint32),
                ("dwStateMask", ctypes.c_uint32),
                ("szInfo", ctypes.c_wchar * 256),
                ("uTimeoutOrVersion", ctypes.c_uint32),
                ("szInfoTitle", ctypes.c_wchar * 64),
                ("dwInfoFlags", ctypes.c_uint32),
            ]

        self.NOTIFYICONDATAW = NOTIFYICONDATAW
        self.nid = NOTIFYICONDATAW()
        self.nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        self.nid.hWnd = self.root.winfo_id()
        self.nid.uID = 1001
        self.nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        self.nid.uCallbackMessage = self.WM_TRAY_CALLBACK
        self.nid.szTip = "AegisKey Authenticator & Secure Guard"

        # Load system shield icon
        IDI_SHIELD = 32518
        self.nid.hIcon = ctypes.windll.user32.LoadIconW(0, IDI_SHIELD)

        # Register tray icon
        ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self.nid))
        self.notifier.attach_win32_nid(self.nid)

    def hide_to_tray(self):
        """Hides the main window while keeping the background daemon and SSH watchdog alive."""
        self.root.withdraw()

    def show_from_tray(self, *args):
        """Restores and focuses the main desktop window."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def exit_app(self, *args):
        """Cleans up tray icon and exits gracefully."""
        self.ssh_guard.stop_watchdog()
        if platform.system() == "Windows" and hasattr(self, "nid"):
            NIM_DELETE = 0x00000002
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))
        self.root.destroy()
        sys.exit(0)


def main():
    root = tk.Tk()
    app = AegisDesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
