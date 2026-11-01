namespace AegisKeyTray;

public static class I18n
{
    public static string CurrentLanguage = "en";

    private static readonly Dictionary<string, Dictionary<string, string>> Strings = new()
    {
        ["en"] = new()
        {
            ["app_title"] = "AegisKey Authenticator",
            ["app_subtitle"] = "Hardware Security Authority & Vault",
            ["connected"] = "CONNECTED",
            ["disconnected"] = "DISCONNECTED",
            ["sg_title"] = "Secure Guard Authority",
            ["sg_status_label"] = "Device Status:",
            ["sg_attempts_label"] = "Remaining Attempts:",
            ["sg_session_label"] = "Active Session Timer:",
            ["sg_btn_unlock"] = "Unlock Secure Guard",
            ["sg_btn_lock"] = "Lock Now",
            ["vault_title"] = "Hardware Vault & Crypto Wallets",
            ["vault_locked_banner"] = "🔒 Secure Guard is locked. Unlock Secure Guard to access hardware keys.",
            ["totp_title"] = "Hardware TOTP Codes",
            ["totp_subtitle"] = "Calculated by physical ESP32-S3 silicon (OP_OATH_CODE 0x26)",
            ["ssh_title"] = "SSH Key Guard (Zero-Password SSH)",
            ["ssh_subtitle"] = "Keep SSH unlocked while Secure Guard is active. Auto-purge on lock or disconnect.",
            ["ssh_status_active"] = "SSH Guard Active: Zero-password enabled while Secure Guard is Unlocked.",
            ["ssh_status_inactive"] = "SSH Guard Dormant: Secure Guard is Locked. All SSH keys are purged from RAM.",
            ["ssh_btn_purge"] = "Purge SSH Agent (ssh-add -D)",
            ["ssh_btn_load_fido2"] = "Load Resident FIDO2 Keys (ssh-add -K)",
            ["ssh_btn_env"] = "Copy SSH_ASKPASS Script",
            ["tray_open"] = "Open Dashboard",
            ["tray_lock"] = "Lock Secure Guard",
            ["tray_purge_ssh"] = "Purge SSH Agent",
            ["tray_exit"] = "Exit",
        },
        ["pt"] = new()
        {
            ["app_title"] = "AegisKey Autenticador",
            ["app_subtitle"] = "Autoridade de Segurança e Cofre em Hardware",
            ["connected"] = "CONECTADO",
            ["disconnected"] = "DESCONECTADO",
            ["sg_title"] = "Autoridade Secure Guard",
            ["sg_status_label"] = "Estado do Dispositivo:",
            ["sg_attempts_label"] = "Tentativas Restantes:",
            ["sg_session_label"] = "Timer da Sessão Ativa:",
            ["sg_btn_unlock"] = "Desbloquear Secure Guard",
            ["sg_btn_lock"] = "Bloquear Agora",
            ["vault_title"] = "Cofre de Hardware e Carteiras Cripto",
            ["vault_locked_banner"] = "🔒 Secure Guard está bloqueado. Desbloqueie o Secure Guard para acessar as chaves.",
            ["totp_title"] = "Códigos TOTP de Hardware",
            ["totp_subtitle"] = "Calculados pelo chip físico ESP32-S3 (OP_OATH_CODE 0x26)",
            ["ssh_title"] = "Guarda de Chaves SSH (SSH Sem Senha)",
            ["ssh_subtitle"] = "Uso livre de SSH enquanto o Secure Guard estiver ativo. Limpeza imediata ao bloquear.",
            ["ssh_status_active"] = "Guarda SSH Ativo: SSH sem senha liberado enquanto o Secure Guard estiver Desbloqueado.",
            ["ssh_status_inactive"] = "Guarda SSH Inativo: Secure Guard Bloqueado. Todas as chaves SSH foram removidas da RAM.",
            ["ssh_btn_purge"] = "Limpar ssh-agent (ssh-add -D)",
            ["ssh_btn_load_fido2"] = "Carregar Chave Residente FIDO2 (ssh-add -K)",
            ["ssh_btn_env"] = "Copiar Configuração SSH_ASKPASS",
            ["tray_open"] = "Abrir Painel",
            ["tray_lock"] = "Bloquear Secure Guard",
            ["tray_purge_ssh"] = "Limpar ssh-agent",
            ["tray_exit"] = "Sair",
        }
    };

    public static string T(string key)
    {
        if (Strings.TryGetValue(CurrentLanguage, out var map) && map.TryGetValue(key, out var val))
            return val;
        if (Strings["en"].TryGetValue(key, out var defVal))
            return defVal;
        return key;
    }
}
