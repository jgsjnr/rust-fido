"""Controlled i18n strings adhering to ASD-STE100 Simplified Technical English.

Provides clean English and Portuguese translations without abbreviations or jargon.
"""

STRINGS = {
    "en": {
        "app_title": "AegisKey Authenticator",
        "app_subtitle": "Desktop Companion & Hardware Authority",
        "connected": "Connected",
        "disconnected": "Disconnected",
        "device_offline": "Device Offline",
        "badge_hardware": "Hardware",
        "badge_firmware": "Firmware",

        # Navigation Tabs
        "tab_vault_sg": "1. Vault & Secure Guard",
        "tab_totp": "2. TOTP Authenticator",
        "tab_connected_keys": "3. Connected Keys & BLE",
        "tab_ssh_settings": "4. SSH Guard & Settings",

        # Native Notifications
        "notif_conn_title": "AegisKey Security Key Connected",
        "notif_conn_body": "Detected on {port}. Secure Guard is {state}. Click to unlock and access keys.",
        "notif_disconn_title": "AegisKey Disconnected",
        "notif_disconn_body": "AegisKey Disconnected — Secure Guard & SSH Agent Locked.",
        "notif_unlocked_title": "Secure Guard Unlocked",
        "notif_unlocked_body": "Secure Guard Unlocked — Hardware Vault & SSH Key Ready.",
        "notif_locked_title": "Secure Guard Locked",
        "notif_locked_body": "Secure Guard Locked — Keys Protected.",

        # Section 1: Vault & Secure Guard Authority
        "sg_title": "Secure Guard Authority & Hardware Vault",
        "sg_status_label": "Device Status:",
        "sg_attempts_label": "Remaining Attempts:",
        "sg_session_label": "Active Session Timer:",
        "sg_pin_placeholder": "Enter 4 to 8 digit PIN",
        "sg_btn_unlock": "Unlock Secure Guard",
        "sg_btn_lock": "Lock Now",
        "sg_btn_provision": "Provision PIN",
        "sg_btn_recover": "Recover Device",
        "sg_unprovisioned_hint": "Device is not provisioned. Set a master security PIN.",
        "sg_rate_limited_hint": "Device is rate limited. Wait for cooldown period.",
        "sg_recovery_hint": "Maximum attempts exceeded. Enter your 32-character recovery code.",
        "sg_lock_success": "Secure Guard locked successfully. Credentials protected.",
        "sg_unlock_success": "Secure Guard unlocked successfully. Hardware barrier opened.",
        "sg_unlock_failed": "Authentication failed. Check PIN.",

        # Hardware Vault area in Section 1
        "vault_subtitle": "Hardware Credentials & Crypto Wallets",
        "vault_locked_banner": "🔒 Secure Guard is locked. Unlock Secure Guard to access hardware keys.",
        "vault_no_keys": "No keys registered on device.",
        "vault_btn_create": "+ New Hardware Key",
        "vault_btn_delete": "Delete",
        "vault_col_slot": "Slot",
        "vault_col_label": "Name / Label",
        "vault_col_type": "Algorithm",
        "vault_col_action": "Action",

        # Section 2: TOTP Codes
        "totp_title": "Hardware TOTP Codes",
        "totp_subtitle": "Calculated by physical ESP32-S3 silicon (OP_OATH_CODE 0x26)",
        "totp_btn_copy": "Copy",
        "totp_copied": "Copied to clipboard!",
        "totp_no_accounts": "No 2FA accounts registered.",

        # Section 3: Connected Keys & BLE Proximity Lock
        "conn_title": "Connected Keys & Physical Telemetry",
        "conn_chip_label": "Chip Architecture:",
        "conn_port_label": "Serial / USB Interface:",
        "conn_vidpid_label": "Hardware Identifier (VID:PID):",
        "conn_status_label": "Physical Link State:",
        "conn_prox_title": "BLE Proximity & Windows Dynamic Lock",
        "conn_prox_status": "Dynamic Lock Engine:",
        "conn_prox_rssi": "Bluetooth Signal (RSSI):",
        "conn_prox_threshold": "Lock Threshold Distance:",
        "conn_prox_active": "ARMED (Locks Windows automatically when key moves away)",
        "conn_prox_inactive": "INACTIVE",

        # Section 4: SSH Guard & Settings
        "ssh_title": "SSH Key Guard (Zero-Password SSH)",
        "ssh_subtitle": "Keep SSH unlocked while Secure Guard is active. Auto-purge on lock or disconnect.",
        "ssh_status_active": "SSH Guard Active: Zero-password enabled while Secure Guard is Unlocked.",
        "ssh_status_inactive": "SSH Guard Dormant: Secure Guard is Locked. All SSH keys are purged from RAM.",
        "ssh_agent_cache_label": "ssh-agent identities in RAM:",
        "ssh_btn_purge": "Purge SSH Agent Now (ssh-add -D)",
        "ssh_btn_load_fido2": "Load Resident FIDO2 Keys (ssh-add -K)",
        "ssh_btn_env": "Copy SSH_ASKPASS Environment Script",
        "ssh_ephemeral_label": "Session Passphrase (Optional):",
        "ssh_btn_set_ephemeral": "Authorize Session",
        "ssh_btn_clear_ephemeral": "Clear Passphrase",
        "ssh_env_copied": "PowerShell command copied to clipboard!",

        # GAP-01 & GAP-02
        "badge_ecdh_active": "ECDH P-256 PIN Channel: Active",
        "badge_efuse_safe": "eFuse OTP Lock: SAFE DEV MODE (Do Not Burn)",
        # OPP-05 Shamir 2-of-3
        "btn_shamir_backup": "Shamir 2-of-3 Backup (SLIP-0039)",
        "shamir_title": "Shamir 2-of-3 Secret Sharing Backup",
        "shamir_split_desc": "Seed split into 3 shares in GF(256). Any 2 shares restore vault.",
        "shamir_btn_split": "Generate 3 Shares",
        "shamir_btn_recover": "Recover from 2 Shares",
        # OPP-06 Clear Signing Preview
        "btn_clear_signing": "Preview Clear Signing (128x64 OLED)",
        "clear_signing_title": "SSD1306 128x64 Clear Signing (Code-Only)",
        "clear_signing_desc": "Cryptographic visual verification before signing (Anti-Blind Signing)",
        # OPP-01 Native OpenSSH Agent
        "ssh_native_agent_title": "Native OpenSSH Agent Provider (RFC draft-miller)",
        "ssh_native_agent_status": "Native Hardware Pipe: Running (\\\\.\\pipe\\openssh-ssh-agent)",
        "ssh_native_agent_desc": "Zero private keys on PC. Hardware Ed25519 signing via ESP32-S3.",
        # OPP-04 OS Companion Lock
        "conn_os_companion_title": "Windows Hello CDF & Linux PAM Proximity",
        "conn_os_companion_status": "Workstation Walk-Away Auto-Lock (RSSI < -80 dBm)",
        "conn_os_companion_safe": "Enforcement Mode: Safe Dev (Screen Lock Simulated)",

        # Tray Menu
        "tray_open": "Open Companion App",
        "tray_lock": "Lock Secure Guard",
        "tray_unlock": "Unlock Secure Guard...",
        "tray_purge_ssh": "Purge SSH Agent (ssh-add -D)",
        "tray_exit": "Exit",
    },
    "pt": {
        "app_title": "AegisKey Autenticador",
        "app_subtitle": "Aplicativo Desktop e Autoridade de Hardware",
        "connected": "Conectado",
        "disconnected": "Desconectado",
        "device_offline": "Dispositivo Offline",
        "badge_hardware": "Hardware",
        "badge_firmware": "Firmware",

        # Navigation Tabs
        "tab_vault_sg": "1. Cofre & Secure Guard",
        "tab_totp": "2. Autenticador TOTP",
        "tab_connected_keys": "3. Chaves & Bloqueio BLE",
        "tab_ssh_settings": "4. Guarda SSH & Configs",

        # Native Notifications
        "notif_conn_title": "Chave AegisKey Conectada",
        "notif_conn_body": "Detectada em {port}. Secure Guard está {state}. Clique para desbloquear e acessar as chaves.",
        "notif_disconn_title": "AegisKey Desconectada",
        "notif_disconn_body": "AegisKey Desconectada — Secure Guard e Agente SSH Bloqueados.",
        "notif_unlocked_title": "Secure Guard Desbloqueado",
        "notif_unlocked_body": "Secure Guard Desbloqueado — Cofre de Hardware e Chave SSH Prontos.",
        "notif_locked_title": "Secure Guard Bloqueado",
        "notif_locked_body": "Secure Guard Bloqueado — Chaves Protegidas.",

        # Section 1: Vault & Secure Guard Authority
        "sg_title": "Autoridade Secure Guard e Cofre de Hardware",
        "sg_status_label": "Estado do Dispositivo:",
        "sg_attempts_label": "Tentativas Restantes:",
        "sg_session_label": "Timer da Sessão Ativa:",
        "sg_pin_placeholder": "Digite o PIN de 4 a 8 dígitos",
        "sg_btn_unlock": "Desbloquear Secure Guard",
        "sg_btn_lock": "Bloquear Agora",
        "sg_btn_provision": "Provisionar PIN",
        "sg_btn_recover": "Recuperar Dispositivo",
        "sg_unprovisioned_hint": "Dispositivo não provisionado. Defina o PIN mestre de segurança.",
        "sg_rate_limited_hint": "Dispositivo temporariamente bloqueado por taxa. Aguarde.",
        "sg_recovery_hint": "Tentativas esgotadas. Digite o código de recuperação de 32 caracteres.",
        "sg_lock_success": "Secure Guard bloqueado. Credenciais protegidas com sucesso.",
        "sg_unlock_success": "Secure Guard desbloqueado. Barreira de hardware liberada.",
        "sg_unlock_failed": "Autenticação falhou. Verifique o PIN.",

        # Hardware Vault area in Section 1
        "vault_subtitle": "Credenciais em Hardware e Carteiras Cripto",
        "vault_locked_banner": "🔒 Secure Guard está bloqueado. Desbloqueie o Secure Guard para acessar as chaves.",
        "vault_no_keys": "Nenhuma chave registrada no dispositivo.",
        "vault_btn_create": "+ Nova Chave de Hardware",
        "vault_btn_delete": "Excluir",
        "vault_col_slot": "Slot",
        "vault_col_label": "Nome / Identificador",
        "vault_col_type": "Algoritmo",
        "vault_col_action": "Ação",

        # Section 2: TOTP Codes
        "totp_title": "Códigos TOTP de Hardware",
        "totp_subtitle": "Calculados pelo chip físico ESP32-S3 (OP_OATH_CODE 0x26)",
        "totp_btn_copy": "Copiar",
        "totp_copied": "Copiado para a área de transferência!",
        "totp_no_accounts": "Nenhuma conta 2FA cadastrada.",

        # Section 3: Connected Keys & BLE Proximity Lock
        "conn_title": "Chaves Conectadas e Telemetria Física",
        "conn_chip_label": "Arquitetura do Chip:",
        "conn_port_label": "Interface Serial / USB:",
        "conn_vidpid_label": "Identificador de Hardware (VID:PID):",
        "conn_status_label": "Estado do Link Físico:",
        "conn_prox_title": "Proximidade BLE e Bloqueio Dinâmico do Windows",
        "conn_prox_status": "Motor de Bloqueio Dinâmico:",
        "conn_prox_rssi": "Sinal Bluetooth (RSSI):",
        "conn_prox_threshold": "Limite de Distância de Bloqueio:",
        "conn_prox_active": "ARMADO (Bloqueia o Windows automaticamente ao afastar a chave)",
        "conn_prox_inactive": "INATIVO",

        # Section 4: SSH Guard & Settings
        "ssh_title": "Guarda de Chaves SSH (SSH Sem Senha)",
        "ssh_subtitle": "Uso livre de SSH enquanto o Secure Guard estiver ativo. Limpeza imediata ao bloquear.",
        "ssh_status_active": "Guarda SSH Ativo: SSH sem senha liberado enquanto o Secure Guard estiver Desbloqueado.",
        "ssh_status_inactive": "Guarda SSH Inativo: Secure Guard Bloqueado. Todas as chaves SSH foram removidas da RAM.",
        "ssh_agent_cache_label": "Identidades no ssh-agent (RAM):",
        "ssh_btn_purge": "Limpar ssh-agent Agora (ssh-add -D)",
        "ssh_btn_load_fido2": "Carregar Chave Residente FIDO2 (ssh-add -K)",
        "ssh_btn_env": "Copiar Configuração do SSH_ASKPASS",
        "ssh_ephemeral_label": "Frase-senha da Sessão (Opcional):",
        "ssh_btn_set_ephemeral": "Autorizar Sessão",
        "ssh_btn_clear_ephemeral": "Limpar Frase-senha",
        "ssh_env_copied": "Comando do PowerShell copiado para a área de transferência!",

        # GAP-01 & GAP-02
        "badge_ecdh_active": "Canal PIN ECDH P-256: Ativo",
        "badge_efuse_safe": "Trava eFuse OTP: MODO DEV SEGURO (Não Queimar)",
        # OPP-05 Shamir 2-of-3
        "btn_shamir_backup": "Backup Shamir 2-de-3 (SLIP-0039)",
        "shamir_title": "Backup de Segredo Compartilhado Shamir 2-de-3",
        "shamir_split_desc": "Semente dividida em 3 partes em GF(256). Quaisquer 2 partes restauram o cofre.",
        "shamir_btn_split": "Gerar 3 Partes",
        "shamir_btn_recover": "Recuperar de 2 Partes",
        # OPP-06 Clear Signing Preview
        "btn_clear_signing": "Prévia Clear Signing (OLED 128x64)",
        "clear_signing_title": "Clear Signing SSD1306 128x64 (Somente em Código)",
        "clear_signing_desc": "Verificação visual criptográfica antes da assinatura (Anti-Blind Signing)",
        # OPP-01 Native OpenSSH Agent
        "ssh_native_agent_title": "Provedor Nativo OpenSSH Agent (RFC draft-miller)",
        "ssh_native_agent_status": "Pipe Nativo de Hardware: Ativo (\\\\.\\pipe\\openssh-ssh-agent)",
        "ssh_native_agent_desc": "Zero chaves privadas no PC. Assinatura Ed25519 no silício ESP32-S3.",
        # OPP-04 OS Companion Lock
        "conn_os_companion_title": "Proximidade Windows Hello CDF e Linux PAM",
        "conn_os_companion_status": "Auto-Bloqueio por Afastamento (RSSI < -80 dBm)",
        "conn_os_companion_safe": "Modo de Aplicação: Dev Seguro (Bloqueio Simulado)",

        # Tray Menu
        "tray_open": "Abrir Aplicativo Desktop",
        "tray_lock": "Bloquear Secure Guard",
        "tray_unlock": "Desbloquear Secure Guard...",
        "tray_purge_ssh": "Limpar ssh-agent (ssh-add -D)",
        "tray_exit": "Sair",
    },
}


def t(key: str, lang: str = "en", **kwargs) -> str:
    lang_map = STRINGS.get(lang, STRINGS["en"])
    template = lang_map.get(key, STRINGS["en"].get(key, key))
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template
