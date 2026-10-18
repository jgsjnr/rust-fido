#!/usr/bin/env python3
"""
================================================================================
  🛡️ AEGISKEY S3 - SIMULADOR GRÁFICO INTERATIVO DE HARDWARE & DISPLAY (170x320) 🛡️
================================================================================
  Emulador visual em Python / Tkinter que replica com fidelidade absoluta:
  1. Tela LCD IPS ST7789 (320x170 pixels) do firmware Rust (crates/aegis-fido-firmware)
  2. Paleta Cyberpunk RGB565 (Deep Slate, Cyan Neon, Emerald, Glowing Amber, Red)
  3. Placa LilyGO T-Display-S3 com 2 Botões Físicos:
     - Botão 1: BOOT (GPIO 0) -> Confirmar UP / Autorizar / Segurar 2s para TOTP
     - Botão 2: KEY  (GPIO 14)-> Cancelar / Recusar transação / Alternar contas TOTP
  4. Modo ESP32-S3 DevKitC-1 com 1 Botão (GPIO 0) + LED RGB WS2812 Dinâmico
================================================================================
"""

import sys
import time
import math
import tkinter as tk
from tkinter import ttk

# Configurações de display nativo da placa
NATIVE_W = 320
NATIVE_H = 170
SCALE = 2.5  # Escala de renderização (800 x 425 pixels)
CANVAS_W = int(NATIVE_W * SCALE)
CANVAS_H = int(NATIVE_H * SCALE)

# Paleta Cyberpunk RGB565 do AegisKey S3 (crates/aegis-fido-firmware/src/display/ui.rs)
COLOR_BG_DARK = "#0B0F19"       # Deep Cyber Slate
COLOR_HEADER_BG = "#081820"     # Fundo do cabeçalho
COLOR_CYAN = "#00F0FF"          # Ciano Neon Elétrico
COLOR_GREEN = "#10B981"         # Verde Esmeralda
COLOR_AMBER = "#F59E0B"         # Âmbar Brilhante
COLOR_RED = "#EF4444"           # Vermelho Carmesim
COLOR_WHITE = "#FFFFFF"         # Branco Puro
COLOR_MUTED = "#94A3B8"         # Cinza Dim
COLOR_BOX_BORDER = "#143038"    # Borda de cartões
COLOR_BOX_BG = "#0D1E28"        # Fundo interno de caixas

# Estados de Tela (UiScreen em ui.rs)
SCREEN_BOOT = "BOOT_SPLASH"
SCREEN_IDLE = "IDLE_STANDBY"
SCREEN_PROMPT = "USER_PRESENCE_PROMPT"
SCREEN_SUCCESS = "SUCCESS"
SCREEN_ERROR = "ERROR"
SCREEN_TOTP = "TOTP_CODE"

# Modos de Hardware
MODE_T_DISPLAY = "LilyGO T-Display-S3 (2 Botões: GPIO 0 + GPIO 14)"
MODE_DEVKITC = "ESP32-S3 DevKitC-1 (1 Botão: GPIO 0 + WS2812 RGB LED)"

# Contas TOTP de exemplo
TOTP_ACCOUNTS = [
    {"label": "GitHub: aegis-admin", "secret": "JBSWY3DPEHPK3PXP"},
    {"label": "Google: junior@aegiskey.dev", "secret": "HXDMVJECJJWSRB3H"},
    {"label": "AWS: root-production", "secret": "MFRGGZDFMYYTOMJS"},
]


class AegisSimulatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AegisKey S3 - Simulador de Hardware & Interface Gráfica (LilyGO T-Display-S3 & DevKitC-1)")
        self.root.configure(bg="#060911")
        self.root.geometry("1100x820")
        self.root.resizable(False, False)

        # Estado do Sistema
        self.current_screen = SCREEN_BOOT
        self.board_mode = MODE_T_DISPLAY
        self.boot_start_time = time.time()
        self.prompt_start_time = 0
        self.prompt_timeout_s = 25.0
        self.prompt_rp_id = "passkey2.com"
        self.prompt_user = "junior@aegiskey.dev"
        self.prompt_operation = "Registro de Passkey"
        self.success_title = "ACESSO AUTORIZADO"
        self.success_subtitle = "Passkey gerada com sucesso"
        self.error_message = "Toque cancelado pelo usuário"
        
        # TOTP State
        self.totp_account_index = 0
        self.totp_display_until = 0

        # Botões físicos simulados
        self.boot_pressed = False
        self.key_pressed = False
        self.boot_press_start = 0

        # LED WS2812 (para modo DevKitC-1)
        self.led_color = "#000000"
        self.led_brightness = 1.0

        # Construção da Interface Tkinter
        self._build_ui()

        # Atalhos de Teclado globais
        self.root.bind("<space>", lambda e: self._on_boot_click())
        self.root.bind("<b>", lambda e: self._on_boot_click())
        self.root.bind("B", lambda e: self._on_boot_click())
        self.root.bind("<Escape>", lambda e: self._on_key_click())
        self.root.bind("<k>", lambda e: self._on_key_click())
        self.root.bind("K", lambda e: self._on_key_click())

        # Loop de Animação a ~30 FPS
        self._tick()

    def _build_ui(self):
        # 1. Cabeçalho Superior
        header_frame = tk.Frame(self.root, bg="#0D111D", padx=16, pady=10)
        header_frame.pack(fill=tk.X)

        title_lbl = tk.Label(
            header_frame,
            text="🛡️ AEGISKEY S3 AUTHENTICATOR • EMULADOR DE TELA LCD & HARDWARE",
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_CYAN,
            bg="#0D111D"
        )
        title_lbl.pack(side=tk.LEFT)

        self.mode_var = tk.StringVar(value=self.board_mode)
        mode_cb = ttk.Combobox(
            header_frame,
            textvariable=self.mode_var,
            values=[MODE_T_DISPLAY, MODE_DEVKITC],
            state="readonly",
            width=48,
            font=("Segoe UI", 9)
        )
        mode_cb.pack(side=tk.RIGHT, padx=5)
        mode_cb.bind("<<ComboboxSelected>>", self._on_mode_change)

        mode_lbl = tk.Label(header_frame, text="Placa Selecionada:", font=("Segoe UI", 9), fg=COLOR_MUTED, bg="#0D111D")
        mode_lbl.pack(side=tk.RIGHT, padx=4)

        # 2. Painel Central (Representação da Placa Física + Tela LCD)
        center_frame = tk.Frame(self.root, bg="#060911", pady=10)
        center_frame.pack(fill=tk.BOTH, expand=False)

        # Moldura simulando o corpo físico da PCB da LilyGO / DevKit
        self.pcb_frame = tk.Frame(center_frame, bg="#161B26", bd=2, relief=tk.RIDGE, padx=24, pady=16)
        self.pcb_frame.pack(anchor=tk.CENTER)

        # Informações de serigrafia na PCB
        pcb_top_bar = tk.Frame(self.pcb_frame, bg="#161B26")
        pcb_top_bar.pack(fill=tk.X, pady=(0, 8))

        self.pcb_label = tk.Label(
            pcb_top_bar,
            text="LILYGO® T-Display-S3 | ST7789 IPS LCD (320x170) | Dual Buttons (IO0 + IO14)",
            font=("Consolas", 9, "bold"),
            fg="#94A3B8",
            bg="#161B26"
        )
        self.pcb_label.pack(side=tk.LEFT)

        usb_status = tk.Label(
            pcb_top_bar,
            text="[USB-C OTG: FIDO2 HID CONECTADO]",
            font=("Consolas", 9, "bold"),
            fg=COLOR_GREEN,
            bg="#161B26"
        )
        usb_status.pack(side=tk.RIGHT)

        # Área da Tela + Botões Laterais Físicos
        display_container = tk.Frame(self.pcb_frame, bg="#161B26")
        display_container.pack()

        # Canvas da Tela LCD 320x170 (escalado para 800x425)
        self.canvas = tk.Canvas(
            display_container,
            width=CANVAS_W,
            height=CANVAS_H,
            bg=COLOR_BG_DARK,
            highlightthickness=3,
            highlightbackground="#222B3D"
        )
        self.canvas.pack(side=tk.LEFT)

        # Painel Lateral dos Botões da Placa
        self.button_panel = tk.Frame(display_container, bg="#161B26", padx=16)
        self.button_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(12, 0))

        # Indicador LED WS2812 (visível no modo DevKitC-1)
        self.led_frame = tk.Frame(self.button_panel, bg="#161B26")
        self.led_canvas = tk.Canvas(self.led_frame, width=50, height=50, bg="#161B26", highlightthickness=0)
        self.led_canvas.pack(pady=4)
        self.led_caption = tk.Label(self.led_frame, text="WS2812 (IO48)", font=("Segoe UI", 7), fg=COLOR_MUTED, bg="#161B26")
        self.led_caption.pack()

        # Botão 1: BOOT (GPIO 0)
        btn1_title = tk.Label(self.button_panel, text="BOTÃO 1 (IO0)", font=("Segoe UI", 8, "bold"), fg=COLOR_GREEN, bg="#161B26")
        btn1_title.pack(pady=(10, 2))

        self.btn_boot_gui = tk.Button(
            self.button_panel,
            text="🔘 BOOT\n(GPIO 0)\n[Espaço / B]",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_WHITE,
            bg="#064E3B",
            activebackground=COLOR_GREEN,
            activeforeground="#000000",
            relief=tk.RAISED,
            bd=3,
            width=12,
            height=3,
            command=self._on_boot_click
        )
        self.btn_boot_gui.pack(pady=4)

        btn1_desc = tk.Label(
            self.button_panel,
            text="• Confirmar UP\n• Segurar 2s: TOTP",
            font=("Segoe UI", 7),
            fg=COLOR_MUTED,
            bg="#161B26",
            justify=tk.CENTER
        )
        btn1_desc.pack(pady=(0, 16))

        # Botão 2: KEY (GPIO 14) - Exclusivo LilyGO T-Display-S3
        self.btn2_container = tk.Frame(self.button_panel, bg="#161B26")
        self.btn2_container.pack()

        btn2_title = tk.Label(self.btn2_container, text="BOTÃO 2 (IO14)", font=("Segoe UI", 8, "bold"), fg=COLOR_RED, bg="#161B26")
        btn2_title.pack(pady=(4, 2))

        self.btn_key_gui = tk.Button(
            self.btn2_container,
            text="🔴 KEY\n(GPIO 14)\n[Esc / K]",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_WHITE,
            bg="#7F1D1D",
            activebackground=COLOR_RED,
            activeforeground="#000000",
            relief=tk.RAISED,
            bd=3,
            width=12,
            height=3,
            command=self._on_key_click
        )
        self.btn_key_gui.pack(pady=4)

        btn2_desc = tk.Label(
            self.btn2_container,
            text="• Recusar/Cancelar\n• Próximo TOTP",
            font=("Segoe UI", 7),
            fg=COLOR_MUTED,
            bg="#161B26",
            justify=tk.CENTER
        )
        btn2_desc.pack(pady=(0, 8))

        # 3. Painel de Controle de Simulação (Ações Rápidas)
        ctrl_frame = tk.LabelFrame(
            self.root,
            text=" ⚙️ Painel de Eventos de Simulação (Disparar Chamadas FIDO2 / CTAP2) ",
            bg="#0D111D",
            fg=COLOR_CYAN,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=8
        )
        ctrl_frame.pack(fill=tk.X, padx=16, pady=4)

        action_row = tk.Frame(ctrl_frame, bg="#0D111D")
        action_row.pack(fill=tk.X)

        tk.Button(
            action_row,
            text="🚀 1. Boot Splash",
            font=("Segoe UI", 9),
            bg="#1E293B",
            fg=COLOR_WHITE,
            command=self.sim_boot
        ).pack(side=tk.LEFT, padx=3)

        tk.Button(
            action_row,
            text="🛡️ 2. Reg. Passkey (passkey2.com)",
            font=("Segoe UI", 9, "bold"),
            bg="#0284C7",
            fg=COLOR_WHITE,
            command=lambda: self.sim_prompt("passkey2.com", "junior@aegiskey.dev", "Registro de Passkey")
        ).pack(side=tk.LEFT, padx=3)

        tk.Button(
            action_row,
            text="🔑 3. Login Google (accounts.google.com)",
            font=("Segoe UI", 9, "bold"),
            bg="#2563EB",
            fg=COLOR_WHITE,
            command=lambda: self.sim_prompt("accounts.google.com", "junior.dev@gmail.com", "Autenticação FIDO2")
        ).pack(side=tk.LEFT, padx=3)

        tk.Button(
            action_row,
            text="🐙 4. Login GitHub (github.com)",
            font=("Segoe UI", 9, "bold"),
            bg="#475569",
            fg=COLOR_WHITE,
            command=lambda: self.sim_prompt("github.com", "junior", "Autenticação FIDO2")
        ).pack(side=tk.LEFT, padx=3)

        tk.Button(
            action_row,
            text="⏱️ 5. Visualizar TOTP 2FA",
            font=("Segoe UI", 9),
            bg="#059669",
            fg=COLOR_WHITE,
            command=self.sim_totp
        ).pack(side=tk.LEFT, padx=3)

        tk.Button(
            action_row,
            text="⏳ Simular Long-Press BOOT (2s)",
            font=("Segoe UI", 9),
            bg="#D97706",
            fg=COLOR_WHITE,
            command=self.sim_long_press
        ).pack(side=tk.LEFT, padx=3)

        # 4. Caixa de Log do Terminal / Serial Monitor
        log_frame = tk.LabelFrame(
            self.root,
            text=" 📟 Console Serial UART / CTAPHID Debug Log ",
            bg="#0D111D",
            fg=COLOR_MUTED,
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4
        )
        log_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 10))

        self.log_text = tk.Text(
            log_frame,
            height=6,
            bg="#060911",
            fg="#A7F3D0",
            font=("Consolas", 8),
            bd=0,
            highlightthickness=0
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

        self.log("[SISTEMA] AegisKey S3 GUI Simulator carregado com sucesso!")
        self.log("[HARDWARE] Target: LilyGO T-Display-S3 (ST7789 320x170) | USB VID: 0x303A PID: 0xAE61")
        self.log("[FIRMWARE] AegisKey S3 v1.0.0 (100% Rust) Inicializado.")

    def log(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {text}\n")
        self.log_text.see(tk.END)

    def _on_mode_change(self, event=None):
        self.board_mode = self.mode_var.get()
        if self.board_mode == MODE_T_DISPLAY:
            self.pcb_label.config(text="LILYGO® T-Display-S3 | ST7789 IPS LCD (320x170) | Dual Buttons (IO0 + IO14)")
            self.btn2_container.pack(pady=4)
            self.led_frame.pack_forget()
            self.log("[HARDWARE SWITCH] Modo LILYGO T-DISPLAY-S3 ativado (Botões BOOT GPIO 0 + KEY GPIO 14 habilitados).")
        else:
            self.pcb_label.config(text="ESP32-S3 DevKitC-1 | Display ST7789 Externo | Botão Único (GPIO 0) + WS2812 (GPIO 48)")
            self.btn2_container.pack_forget()
            self.led_frame.pack(before=self.btn_boot_gui, pady=4)
            self.log("[HARDWARE SWITCH] Modo DEVKITC-1 ativado (Apenas GPIO 0 ativo; LED WS2812 RGB sincronizado).")

    # --------------------------------------------------------------------------
    # Tratamento de Botões Físicos
    # --------------------------------------------------------------------------
    def _on_boot_click(self):
        """Ação do Botão 1: BOOT (GPIO 0)."""
        self.log("[BOTÃO 1 / BOOT (GPIO 0)] Pressionado!")
        if self.current_screen == SCREEN_PROMPT:
            self.log(f"[UP] Presença confirmada fisicamente via BOOT (GPIO 0) para '{self.prompt_rp_id}'!")
            self.current_screen = SCREEN_SUCCESS
            self.success_title = "ACESSO AUTORIZADO"
            self.success_subtitle = f"Dominio: {self.prompt_rp_id}"
            self.root.after(2200, self.sim_idle)
        elif self.current_screen in [SCREEN_BOOT, SCREEN_ERROR, SCREEN_SUCCESS]:
            self.current_screen = SCREEN_IDLE

    def _on_key_click(self):
        """Ação do Botão 2: KEY (GPIO 14)."""
        if self.board_mode == MODE_DEVKITC:
            self.log("[AVISO] Botão KEY (GPIO 14) não existe na placa DevKitC-1. Apenas GPIO 0 está conectado.")
            return

        self.log("[BOTÃO 2 / KEY (GPIO 14)] Pressionado!")
        if self.current_screen == SCREEN_PROMPT:
            self.log(f"[RECUSADO] Usuário rejeitou ativamente a autenticação para '{self.prompt_rp_id}' via KEY (GPIO 14)!")
            self.current_screen = SCREEN_ERROR
            self.error_message = "Transação cancelada pelo usuário (Botão KEY)"
            self.root.after(2200, self.sim_idle)
        elif self.current_screen in [SCREEN_IDLE, SCREEN_TOTP]:
            # Alterna conta TOTP
            self.totp_account_index = (self.totp_account_index + 1) % len(TOTP_ACCOUNTS)
            acc = TOTP_ACCOUNTS[self.totp_account_index]
            self.log(f"[YKOATH] Conta TOTP alternada via GPIO 14 -> {acc['label']}")
            self.sim_totp()

    def sim_long_press(self):
        """Simula manter o botão BOOT pressionado por 2 segundos."""
        self.log("[LONG PRESS] Botão BOOT (GPIO 0) segurado por 2.0s -> Ativando Auto-Digitação USB!")
        acc = TOTP_ACCOUNTS[self.totp_account_index]
        code = self._get_totp_code(acc["secret"])
        self.log(f"[USB HID KEYBOARD] Auto-digitando código para {acc['label']}: {code} + <ENTER>")
        self.sim_totp()

    # --------------------------------------------------------------------------
    # Ações de Simulação
    # --------------------------------------------------------------------------
    def sim_boot(self):
        self.boot_start_time = time.time()
        self.current_screen = SCREEN_BOOT
        self.log("[SIM] Reiniciando firmware AegisKey S3 (Boot Splash)...")

    def sim_idle(self):
        self.current_screen = SCREEN_IDLE
        self.log("[SIM] Retornando ao modo Idle Standby (Pronto).")

    def sim_prompt(self, rp_id, user, op):
        self.prompt_rp_id = rp_id
        self.prompt_user = user
        self.prompt_operation = op
        self.prompt_start_time = time.time()
        self.current_screen = SCREEN_PROMPT
        self.log(f"[CTAPHID] Solicitação recebida! RP ID: '{rp_id}', Conta: '{user}', Operação: '{op}'")
        self.log(f"[UP] Aguardando confirmação física do usuário (Limite: {int(self.prompt_timeout_s)}s)...")

    def sim_totp(self):
        self.totp_display_until = time.time() + 6.0
        self.current_screen = SCREEN_TOTP
        acc = TOTP_ACCOUNTS[self.totp_account_index]
        self.log(f"[OATH] Exibindo código TOTP na tela: {acc['label']}")

    # --------------------------------------------------------------------------
    # Renderizador da Tela LCD (Espelha fielmente `display/ui.rs`)
    # --------------------------------------------------------------------------
    def _tick(self):
        now = time.time()

        # Transição automática da tela de Boot Splash (após 2.8s)
        if self.current_screen == SCREEN_BOOT and (now - self.boot_start_time) > 2.8:
            self.current_screen = SCREEN_IDLE
            self.log("[BOOT] Inicialização concluída. Dispositivo online em Standby.")

        # Timeout da tela de User Presence Prompt (após 25s)
        if self.current_screen == SCREEN_PROMPT:
            elapsed = now - self.prompt_start_time
            if elapsed >= self.prompt_timeout_s:
                self.log(f"[TIMEOUT] Tempo de autorização esgotado (25s) para '{self.prompt_rp_id}'!")
                self.current_screen = SCREEN_ERROR
                self.error_message = "Tempo limite esgotado (Timeout 25s)"
                self.root.after(2200, self.sim_idle)

        # Timeout do display TOTP (retorna ao Standby após 6s)
        if self.current_screen == SCREEN_TOTP and now >= self.totp_display_until:
            self.current_screen = SCREEN_IDLE

        # Renderizar Framebuffer
        self._render_screen(now)

        # Atualizar LED WS2812 (Modo DevKitC-1)
        self._render_led(now)

        # Agenda o próximo frame (~30ms = 33 FPS)
        self.root.after(30, self._tick)

    def _render_screen(self, now):
        self.canvas.delete("all")
        s = SCALE

        if self.current_screen == SCREEN_BOOT:
            self._draw_boot_splash(now, s)
        elif self.current_screen == SCREEN_IDLE:
            self._draw_idle_standby(now, s)
        elif self.current_screen == SCREEN_PROMPT:
            self._draw_user_presence_prompt(now, s)
        elif self.current_screen == SCREEN_SUCCESS:
            self._draw_success(now, s)
        elif self.current_screen == SCREEN_ERROR:
            self._draw_error(now, s)
        elif self.current_screen == SCREEN_TOTP:
            self._draw_totp(now, s)

    def _draw_header(self, title, accent_color, s):
        # Cabeçalho 24px de altura nativa
        self.canvas.create_rectangle(0, 0, 320 * s, 24 * s, fill=COLOR_HEADER_BG, width=0)
        self.canvas.create_line(0, 24 * s, 320 * s, 24 * s, fill=accent_color, width=max(2, int(2 * s / 2)))

        # Título
        self.canvas.create_text(
            12 * s, 12 * s,
            text=title,
            font=("Consolas", int(9 * s / 2), "bold"),
            fill=COLOR_WHITE,
            anchor=tk.W
        )

        # Badge "AEGIS-S3"
        self.canvas.create_text(
            290 * s, 12 * s,
            text="AEGIS-S3",
            font=("Consolas", int(8 * s / 2), "bold"),
            fill=accent_color,
            anchor=tk.E
        )

    # 1. Tela Boot Splash (Espelha draw_boot_screen em ui.rs)
    def _draw_boot_splash(self, now, s):
        cx = 160 * s

        # Escudo Geométrico
        p1 = (cx, 30 * s)
        p2 = (cx + 30 * s, 45 * s)
        p3 = (cx + 30 * s, 75 * s)
        p4 = (cx, 100 * s)
        p5 = (cx - 30 * s, 75 * s)
        p6 = (cx - 30 * s, 45 * s)

        shield_points = [p1[0], p1[1], p2[0], p2[1], p3[0], p3[1], p4[0], p4[1], p5[0], p5[1], p6[0], p6[1]]
        self.canvas.create_polygon(shield_points, outline=COLOR_CYAN, fill="#07202B", width=int(2 * s / 2))

        # Fechadura no centro do escudo
        self.canvas.create_oval(cx - 7 * s, 50 * s, cx + 7 * s, 64 * s, fill=COLOR_CYAN, width=0)
        self.canvas.create_rectangle(cx - 3 * s, 60 * s, cx + 3 * s, 75 * s, fill=COLOR_CYAN, width=0)

        # Título principal
        self.canvas.create_text(cx, 120 * s, text="AEGISKEY S3", font=("Consolas", int(14 * s / 2), "bold"), fill=COLOR_WHITE)
        self.canvas.create_text(cx, 136 * s, text="FIDO2 / CTAP 2.1 Passkeys", font=("Consolas", int(8 * s / 2)), fill=COLOR_CYAN)
        self.canvas.create_text(cx, 150 * s, text="ESP32-S3 Dual-Core @ 240MHz", font=("Consolas", int(8 * s / 2)), fill=COLOR_MUTED)
        self.canvas.create_text(cx, 162 * s, text="v1.0.0 (100% Rust Native)", font=("Consolas", int(8 * s / 2), "bold"), fill=COLOR_AMBER)

    # 2. Tela Idle Standby (Espelha draw_idle_screen em ui.rs)
    def _draw_idle_standby(self, now, s):
        self._draw_header("AEGISKEY S3 • PRONTO", COLOR_CYAN, s)

        cx = 160 * s
        cy = 85 * s

        # Círculo de segurança pulsante
        pulse = 0.5 + 0.5 * math.sin(now * 3.0)
        radius = (26 + pulse * 2.5) * s

        # Aura
        self.canvas.create_oval(cx - radius - 4, cy - radius - 4, cx + radius + 4, cy + radius + 4, outline="#073B4C", width=1)
        self.canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, outline=COLOR_CYAN, width=int(2 * s / 2))

        # Ícone de Cadeado central
        self.canvas.create_rectangle(cx - 10 * s, cy - 4 * s, cx + 10 * s, cy + 12 * s, fill=COLOR_CYAN, width=0)
        self.canvas.create_arc(cx - 7 * s, cy - 16 * s, cx + 7 * s, cy, start=0, extent=180, outline=COLOR_CYAN, width=int(3 * s / 2), style=tk.ARC)

        # Textos de status
        self.canvas.create_text(cx, 118 * s, text="DISPOSITIVO ATIVO", font=("Consolas", int(12 * s / 2), "bold"), fill=COLOR_WHITE)
        self.canvas.create_text(cx, 135 * s, text="Aguardando solicitação FIDO2 / WebAuthn...", font=("Consolas", int(8 * s / 2)), fill=COLOR_MUTED)

        # Rodapé com indicador verde de conexão
        self.canvas.create_rectangle(0, 152 * s, 320 * s, 170 * s, fill=COLOR_HEADER_BG, width=0)
        self.canvas.create_oval(14 * s, 157 * s, 22 * s, 165 * s, fill=COLOR_GREEN, width=0)
        self.canvas.create_text(28 * s, 161 * s, text="USB CTAPHID / WebAuthn Online", font=("Consolas", int(7 * s / 2)), fill=COLOR_GREEN, anchor=tk.W)

    # 3. Tela User Presence Prompt (Espelha draw_prompt_screen em ui.rs)
    def _draw_user_presence_prompt(self, now, s):
        self._draw_header("SOLICITAÇÃO DE AUTENTICAÇÃO", COLOR_AMBER, s)

        # Tipo de Operação
        self.canvas.create_text(
            15 * s, 36 * s,
            text=f"Ação: {self.prompt_operation}",
            font=("Consolas", int(8 * s / 2), "bold"),
            fill=COLOR_AMBER,
            anchor=tk.W
        )

        # Cartão de Destaque Anti-Phishing para o Domínio (RP ID)
        box_x1 = 12 * s
        box_y1 = 44 * s
        box_x2 = 308 * s
        box_y2 = 76 * s

        self.canvas.create_rectangle(box_x1, box_y1, box_x2, box_y2, fill=COLOR_BOX_BG, outline=COLOR_AMBER, width=2)
        
        # Ícone de globo / domínio
        self.canvas.create_text(
            22 * s, 60 * s,
            text="🌐",
            font=("Segoe UI Emoji", int(10 * s / 2)),
            anchor=tk.W
        )

        # Nome do domínio em negrito de alta visibilidade
        self.canvas.create_text(
            42 * s, 60 * s,
            text=self.prompt_rp_id,
            font=("Consolas", int(12 * s / 2), "bold"),
            fill=COLOR_WHITE,
            anchor=tk.W
        )

        # Linha de Identificação da Conta
        self.canvas.create_text(
            15 * s, 90 * s,
            text="Conta:",
            font=("Consolas", int(8 * s / 2)),
            fill=COLOR_MUTED,
            anchor=tk.W
        )
        self.canvas.create_text(
            58 * s, 90 * s,
            text=self.prompt_user,
            font=("Consolas", int(8 * s / 2), "bold"),
            fill=COLOR_CYAN,
            anchor=tk.W
        )

        # Instruções de Toque dos Botões (Diferenciadas por Placa)
        if self.board_mode == MODE_T_DISPLAY:
            # Modo LilyGO T-Display: Exibe claramente os 2 botões!
            self.canvas.create_text(
                20 * s, 115 * s,
                text="👉 [BOOT / IO0]: Confirmar",
                font=("Consolas", int(9 * s / 2), "bold"),
                fill=COLOR_GREEN,
                anchor=tk.W
            )
            self.canvas.create_text(
                170 * s, 115 * s,
                text="✕ [KEY / IO14]: Cancelar",
                font=("Consolas", int(9 * s / 2), "bold"),
                fill=COLOR_RED,
                anchor=tk.W
            )
        else:
            # Modo DevKitC-1: Apenas botão único GPIO 0
            self.canvas.create_text(
                30 * s, 115 * s,
                text="👉 Pressione o Botão BOOT (GPIO 0)",
                font=("Consolas", int(10 * s / 2), "bold"),
                fill=COLOR_GREEN,
                anchor=tk.W
            )

        # Barra de Contagem Regressiva de 25s
        elapsed = now - self.prompt_start_time
        remaining = max(0.0, self.prompt_timeout_s - elapsed)
        progress = max(0.0, min(1.0, remaining / self.prompt_timeout_s))

        bar_x1 = 20 * s
        bar_y1 = 130 * s
        bar_w = 280 * s
        bar_h = 10 * s

        # Fundo da barra
        self.canvas.create_rectangle(bar_x1, bar_y1, bar_x1 + bar_w, bar_y1 + bar_h, fill=COLOR_HEADER_BG, width=0)

        # Preenchimento dinâmico com cor baseada no tempo restante
        if remaining > 10.0:
            bar_color = COLOR_CYAN
        elif remaining > 5.0:
            bar_color = COLOR_AMBER
        else:
            bar_color = COLOR_RED

        fill_w = bar_w * progress
        if fill_w > 0:
            self.canvas.create_rectangle(bar_x1, bar_y1, bar_x1 + fill_w, bar_y1 + bar_h, fill=bar_color, width=0)

        # Contador de Segundos
        self.canvas.create_text(
            160 * s, 154 * s,
            text=f"Expira em {int(math.ceil(remaining))}s",
            font=("Consolas", int(8 * s / 2)),
            fill=COLOR_MUTED
        )

    # 4. Tela de Sucesso (Espelha draw_success_screen em ui.rs)
    def _draw_success(self, now, s):
        self._draw_header("AUTORIZAÇÃO CONFIRMADA", COLOR_GREEN, s)

        cx = 160 * s
        cy = 72 * s

        # Círculo verde com Checkmark
        radius = 28 * s
        self.canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, fill=COLOR_GREEN, width=0)

        # Checkmark linhas brancas
        p_start = (cx - 14 * s, cy)
        p_mid = (cx - 4 * s, cy + 10 * s)
        p_end = (cx + 16 * s, cy - 10 * s)

        self.canvas.create_line(p_start[0], p_start[1], p_mid[0], p_mid[1], fill=COLOR_BG_DARK, width=int(4 * s / 2))
        self.canvas.create_line(p_mid[0], p_mid[1], p_end[0], p_end[1], fill=COLOR_BG_DARK, width=int(4 * s / 2))

        self.canvas.create_text(cx, 120 * s, text=self.success_title, font=("Consolas", int(12 * s / 2), "bold"), fill=COLOR_WHITE)
        self.canvas.create_text(cx, 140 * s, text=self.success_subtitle, font=("Consolas", int(8 * s / 2), "bold"), fill=COLOR_GREEN)

    # 5. Tela de Erro / Recusa (Espelha draw_error_screen em ui.rs)
    def _draw_error(self, now, s):
        self._draw_header("FALHA / CANCELADO", COLOR_RED, s)

        cx = 160 * s
        cy = 72 * s

        # Círculo vermelho com X
        radius = 28 * s
        self.canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, fill=COLOR_RED, width=0)

        self.canvas.create_line(cx - 12 * s, cy - 12 * s, cx + 12 * s, cy + 12 * s, fill=COLOR_BG_DARK, width=int(4 * s / 2))
        self.canvas.create_line(cx + 12 * s, cy - 12 * s, cx - 12 * s, cy + 12 * s, fill=COLOR_BG_DARK, width=int(4 * s / 2))

        self.canvas.create_text(cx, 120 * s, text="OPERAÇÃO RECUSADA", font=("Consolas", int(12 * s / 2), "bold"), fill=COLOR_WHITE)
        self.canvas.create_text(cx, 140 * s, text=self.error_message, font=("Consolas", int(8 * s / 2)), fill=COLOR_RED)

    # 6. Tela TOTP 2FA (Espelha draw_totp_screen em ui.rs)
    def _draw_totp(self, now, s):
        self._draw_header("YKOATH / TOTP 2FA", COLOR_CYAN, s)

        cx = 160 * s
        acc = TOTP_ACCOUNTS[self.totp_account_index]
        code = self._get_totp_code(acc["secret"])

        # Label da conta
        self.canvas.create_text(cx, 44 * s, text=acc["label"], font=("Consolas", int(9 * s / 2), "bold"), fill=COLOR_MUTED)

        # Caixa do Código
        box_w = 240 * s
        box_h = 42 * s
        self.canvas.create_rectangle(cx - box_w / 2, 56 * s, cx + box_w / 2, 56 * s + box_h, fill=COLOR_BOX_BG, outline=COLOR_CYAN, width=2)

        # Código de 6 dígitos formatado "XXX XXX"
        formatted_code = f"{code[:3]} {code[3:]}"
        self.canvas.create_text(cx, 77 * s, text=formatted_code, font=("Consolas", int(20 * s / 2), "bold"), fill=COLOR_CYAN)

        # Barra regressiva de 30s da janela TOTP
        sec_in_step = int(now) % 30
        remaining_totp = 30 - sec_in_step
        progress_totp = remaining_totp / 30.0

        bar_x1 = cx - 120 * s
        bar_y1 = 110 * s
        bar_w_totp = 240 * s
        bar_h_totp = 8 * s

        self.canvas.create_rectangle(bar_x1, bar_y1, bar_x1 + bar_w_totp, bar_y1 + bar_h_totp, fill=COLOR_HEADER_BG, width=0)
        self.canvas.create_rectangle(bar_x1, bar_y1, bar_x1 + (bar_w_totp * progress_totp), bar_y1 + bar_h_totp, fill=COLOR_CYAN, width=0)

        # Dica de Operação
        if self.board_mode == MODE_T_DISPLAY:
            hint = "Segure BOOT (2s): Digitar | KEY: Próxima Conta"
        else:
            hint = "Segure BOOT (2s): Auto-Digitar Token"

        self.canvas.create_text(cx, 134 * s, text=hint, font=("Consolas", int(8 * s / 2), "bold"), fill=COLOR_WHITE)
        self.canvas.create_text(cx, 152 * s, text=f"Expira em {remaining_totp}s", font=("Consolas", int(7 * s / 2)), fill=COLOR_MUTED)

    # --------------------------------------------------------------------------
    # Renderizador do LED WS2812 (Para modo DevKitC-1)
    # --------------------------------------------------------------------------
    def _render_led(self, now):
        if self.board_mode != MODE_DEVKITC:
            return

        self.led_canvas.delete("all")
        cx = 25
        cy = 25

        # Determina a cor baseada no estado da tela
        if self.current_screen == SCREEN_BOOT:
            # Rainbow cycle
            hue = (now * 2.0) % 6.0
            r, g, b = self._hsv_to_rgb(hue / 6.0, 1.0, 1.0)
            color_hex = f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}"
        elif self.current_screen == SCREEN_IDLE:
            # Breathing cyan
            breath = 0.3 + 0.7 * (0.5 + 0.5 * math.sin(now * 3.14))
            color_hex = f"#{int(0*breath):02x}{int(240*breath):02x}{int(255*breath):02x}"
        elif self.current_screen == SCREEN_PROMPT:
            # Rapid amber flash
            flash = (int(now * 8) % 2) == 0
            color_hex = COLOR_AMBER if flash else "#332000"
        elif self.current_screen == SCREEN_SUCCESS:
            color_hex = COLOR_GREEN
        elif self.current_screen == SCREEN_ERROR:
            color_hex = COLOR_RED
        elif self.current_screen == SCREEN_TOTP:
            color_hex = "#2563EB"
        else:
            color_hex = "#000000"

        # Desenhar halo brilhante e corpo do LED
        self.led_canvas.create_oval(cx - 20, cy - 20, cx + 20, cy + 20, fill="#1E293B", outline="#334155")
        self.led_canvas.create_oval(cx - 12, cy - 12, cx + 12, cy + 12, fill=color_hex, outline="#FFFFFF", width=1)

    def _get_totp_code(self, secret):
        """Gera código TOTP de 6 dígitos baseado no timestamp atual."""
        import hashlib, hmac, struct
        try:
            # Base32 decode simplificado ou fallback
            import base64
            key = base64.b32decode(secret, True)
            counter = int(time.time() // 30)
            msg = struct.pack(">Q", counter)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
            return f"{code:06d}"
        except Exception:
            return "482915"

    def _hsv_to_rgb(self, h, s, v):
        if s == 0.0:
            return v, v, v
        i = int(h * 6.0)
        f = (h * 6.0) - i
        p = v * (1.0 - s)
        q = v * (1.0 - s * f)
        t = v * (1.0 - s * (1.0 - f))
        i = i % 6
        if i == 0: return v, t, p
        if i == 1: return q, v, p
        if i == 2: return p, v, t
        if i == 3: return p, q, v
        if i == 4: return t, p, v
        if i == 5: return v, p, q
        return v, v, v


def main():
    root = tk.Tk()
    app = AegisSimulatorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
