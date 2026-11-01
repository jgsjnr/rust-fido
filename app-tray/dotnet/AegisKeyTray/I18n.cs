namespace AegisKeyTray;

public static class I18n
{
    public static string CurrentLanguage = "en";

    private static readonly Dictionary<string, Dictionary<string, string>> Strings = new()
    {
        ["en"] = new()
        {
            ["app_title"] = "AegisKey Authenticator",
            ["app_subtitle"] = "Desktop Companion & Hardware Authority",
            ["connected"] = "CONNECTED",
            ["disconnected"] = "DISCONNECTED",

            // Tabs
            ["tab_vault_sg"] = "1. Vault & Secure Guard",
            ["tab_totp"] = "2. TOTP Authenticator",
            ["tab_connected_keys"] = "3. Connected Keys & BLE",
            ["tab_ssh_settings"] = "4. SSH Guard & Settings",

            // Notifications
            ["notif_conn_title"] = "AegisKey Security Key Connected",
            ["notif_conn_body"] = "Detected on {0}. Secure Guard is {1}. Click to unlock and access keys.",
            ["notif_disconn_title"] = "AegisKey Disconnected",
            ["notif_disconn_body"] = "AegisKey Disconnected — Secure Guard & SSH Agent Locked.",
            ["notif_unlocked_title"] = "Secure Guard Unlocked",
            ["notif_unlocked_body"] = "Secure Guard Unlocked — Hardware Vault & SSH Key Ready.",
            ["notif_locked_title"] = "Secure Guard Locked",
            ["notif_locked_body"] = "Secure Guard Locked — Keys Protected.",

            // Section 1
            ["sg_title"] = "Secure Guard Authority & Hardware Vault",
            ["sg_status_label"] = "Device Status:",
            ["sg_attempts_label"] = "Remaining Attempts:",
            ["sg_session_label"] = "Active Session Timer:",
            ["sg_btn_unlock"] = "Unlock Secure Guard",
            ["sg_btn_lock"] = "Lock Now",
            ["vault_locked_banner"] = "🔒 Secure Guard is locked. Unlock Secure Guard to access hardware keys.",

            // Section 2
            ["totp_title"] = "Hardware TOTP Codes",
            ["totp_subtitle"] = "Calculated by physical ESP32-S3 silicon (OP_OATH_CODE 0x26)",
            ["totp_btn_copy"] = "Copy Code",

            // Section 3
            ["conn_title"] = "Connected Keys & Physical Telemetry",
            ["conn_prox_title"] = "BLE Proximity & Windows Dynamic Lock",

            // Section 4
            ["ssh_title"] = "SSH Key Guard (Zero-Password SSH)",
            ["ssh_subtitle"] = "Keep SSH unlocked while Secure Guard is active. Auto-purge on lock or disconnect.",
            ["ssh_status_active"] = "SSH Guard Active: Zero-password enabled while Secure Guard is Unlocked.",
            ["ssh_status_inactive"] = "SSH Guard Dormant: Secure Guard is Locked. All SSH keys are purged from RAM.",
            ["ssh_btn_purge"] = "Purge SSH Agent (ssh-add -D)",
            ["ssh_btn_load_fido2"] = "Load Resident FIDO2 Keys (ssh-add -K)",
            ["ssh_btn_env"] = "Copy SSH_ASKPASS Script",

            // Tray
            ["tray_open"] = "Open Companion App",
            ["tray_lock"] = "Lock Secure Guard",
            ["tray_purge_ssh"] = "Purge SSH Agent",
            ["tray_exit"] = "Exit",
        },
        ["pt"] = new()
        {
            ["app_title"] = "AegisKey Autenticador",
            ["app_subtitle"] = "Aplicativo Desktop e Autoridade de Hardware",
            ["connected"] = "CONECTADO",
            ["disconnected"] = "DESCONECTADO",

            // Tabs
            ["tab_vault_sg"] = "1. Cofre & Secure Guard",
            ["tab_totp"] = "2. Autenticador TOTP",
            ["tab_connected_keys"] = "3. Chaves & Bloqueio BLE",
            ["tab_ssh_settings"] = "4. Guarda SSH & Configs",

            // Notifications
            ["notif_conn_title"] = "Chave AegisKey Conectada",
            ["notif_conn_body"] = "Detectada em {0}. Secure Guard está {1}. Clique para desbloquear e acessar as chaves.",
            ["notif_disconn_title"] = "AegisKey Desconectada",
            ["notif_disconn_body"] = "AegisKey Desconectada — Secure Guard e Agente SSH Bloqueados.",
            ["notif_unlocked_title"] = "Secure Guard Desbloqueado",
            ["notif_unlocked_body"] = "Secure Guard Desbloqueado — Cofre de Hardware e Chave SSH Prontos.",
            ["notif_locked_title"] = "Secure Guard Bloqueado",
            ["notif_locked_body"] = "Secure Guard Bloqueado — Chaves Protegidas.",

            // Section 1
            ["sg_title"] = "Autoridade Secure Guard e Cofre de Hardware",
            ["sg_status_label"] = "Estado do Dispositivo:",
            ["sg_attempts_label"] = "Tentativas Restantes:",
            ["sg_session_label"] = "Timer da Sessão Ativa:",
            ["sg_btn_unlock"] = "Desbloquear Secure Guard",
            ["sg_btn_lock"] = "Bloquear Agora",
            ["vault_locked_banner"] = "🔒 Secure Guard está bloqueado. Desbloqueie o Secure Guard para acessar as chaves.",

            // Section 2
            ["totp_title"] = "Códigos TOTP de Hardware",
            ["totp_subtitle"] = "Calculados pelo chip físico ESP32-S3 (OP_OATH_CODE 0x26)",
            ["totp_btn_copy"] = "Copiar Código",

            // Section 3
            ["conn_title"] = "Chaves Conectadas e Telemetria Física",
            ["conn_prox_title"] = "Proximidade BLE e Bloqueio Dinâmico do Windows",

            // Section 4
            ["ssh_title"] = "Guarda de Chaves SSH (SSH Sem Senha)",
            ["ssh_subtitle"] = "Uso livre de SSH enquanto o Secure Guard estiver ativo. Limpeza imediata ao bloquear.",
            ["ssh_status_active"] = "Guarda SSH Ativo: SSH sem senha liberado enquanto o Secure Guard estiver Desbloqueado.",
            ["ssh_status_inactive"] = "Guarda SSH Inativo: Secure Guard Bloqueado. Todas as chaves SSH foram removidas da RAM.",
            ["ssh_btn_purge"] = "Limpar ssh-agent (ssh-add -D)",
            ["ssh_btn_load_fido2"] = "Carregar Chave Residente FIDO2 (ssh-add -K)",
            ["ssh_btn_env"] = "Copiar Configuração SSH_ASKPASS",

            // Tray
            ["tray_open"] = "Abrir Aplicativo Desktop",
            ["tray_lock"] = "Bloquear Secure Guard",
            ["tray_purge_ssh"] = "Limpar ssh-agent",
            ["tray_exit"] = "Sair",
        }
    };

    public static string T(string key, params object[] args)
    {
        string val = key;
        if (Strings.TryGetValue(CurrentLanguage, out var map) && map.TryGetValue(key, out var localized))
            val = localized;
        else if (Strings["en"].TryGetValue(key, out var defVal))
            val = defVal;

        if (args != null && args.Length > 0)
        {
            try { return string.Format(val, args); }
            catch { return val; }
        }
        return val;
    }
}
