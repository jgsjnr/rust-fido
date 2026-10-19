//! Wave4 — maquina de telas Boot/Home/PairingBLE/PairingAP/Vault/Locked/Busy.
//!
//! - LCD usa `UiScreen`; headless usa a mesma maquina com renderer LED.
//! - Menu NUNCA decide auth: so chama `UpPolicy`/`CtapEngine` (ver `policy.rs`).
//! - Vault (OATH apos UP) auto-limpa em 15s (`VAULT_AUTO_CLEAR_SECS`).
//! - WAVE8: Boot->Home->Pairing->Vault->Locked->Busy com timeouts; erros claros
//!   (sem UP / sem PIN / timeout / sem contas); espelho LCD<->LED.

extern crate alloc;

use alloc::string::String;
use crate::config::{PAIRING_WINDOW_MS, VAULT_AUTO_CLEAR_SECS};
use crate::display::UiScreen;
use crate::led::{Color, LedEffect};
use crate::totp_view::NO_ACCOUNTS_MSG;
use alloc::format;

/// WAVE8 — timeouts da jornada (ms, mesma base monotonica do `tick`).
/// Pareamento expira como o AP/BLE (60s); `Busy` (CTAP) expira em 30s.
pub const JOURNEY_PAIRING_TIMEOUT_MS: u64 = PAIRING_WINDOW_MS;
/// WAVE8 — `Busy` volta para `Home` apos 30s sem resposta do host.
pub const JOURNEY_BUSY_TIMEOUT_MS: u64 = 30_000;
/// WAVE8 — countdown TOTP exibido no Vault (janela 30s, RFC 6238).
pub const JOURNEY_TOTP_PERIOD_SECS: u32 = 30;

/// Telas da jornada (espelho LCD <-> LED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JourneyScreen {
    /// Splash de boot.
    Boot,
    /// Repouso (aguardando FIDO2).
    Home,
    /// Pareamento BLE (mostra codigo 6 digitos).
    PairingBle {
        /// Codigo de pareamento (6 digitos ASCII).
        code: String,
    },
    /// Pareamento AP (mostra SSID).
    PairingAp {
        /// SSID `AegisKey-XXXX`.
        ssid: String,
    },
    /// Cofre OATH apos UP (auto-limpa em 15s).
    Vault {
        /// Rotulo da conta.
        account: String,
        /// Codigo TOTP (6-8 digitos, nunca secret).
        code: String,
        /// Expiracao em ms monotonicos.
        expires_ms: u64,
    },
    /// Bloqueado (timeout/erro).
    Locked,
    /// Ocupado (operacao CTAP em curso).
    Busy,
}

/// Maquina de telas (sem auth interna).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiJourney {
    screen: JourneyScreen,
}

impl UiJourney {
    /// Cria em `Boot`.
    pub fn new() -> Self {
        Self {
            screen: JourneyScreen::Boot,
        }
    }

    /// Tela atual.
    pub fn screen(&self) -> &JourneyScreen {
        &self.screen
    }

    /// Vai para `Home`.
    pub fn show_home(&mut self) {
        self.screen = JourneyScreen::Home;
    }

    /// Mostra pareamento BLE com codigo 6 digitos (chamador gera via TRNG).
    pub fn show_pairing_ble(&mut self, code_6: &str) {
        self.screen = JourneyScreen::PairingBle {
            code: String::from(code_6),
        };
    }

    /// Mostra pareamento AP com SSID.
    pub fn show_pairing_ap(&mut self, ssid: &str) {
        self.screen = JourneyScreen::PairingAp {
            ssid: String::from(ssid),
        };
    }

    /// Mostra cofre OATH apos UP (chamador ja validou `UpPolicy`).
    /// Codigo expira em 15s; secret nunca entra aqui.
    pub fn show_vault(&mut self, account: &str, code: &str, now_ms: u64) {
        self.screen = JourneyScreen::Vault {
            account: String::from(account),
            code: String::from(code),
            expires_ms: now_ms.saturating_add(VAULT_AUTO_CLEAR_SECS * 1000),
        };
    }

    /// Trava (timeout/erro).
    pub fn show_locked(&mut self) {
        self.screen = JourneyScreen::Locked;
    }

    /// Ocupado (CTAP em curso).
    pub fn show_busy(&mut self) {
        self.screen = JourneyScreen::Busy;
    }

    /// WAVE8 — trava apos timeout/expiracao (pareamento 60s, UP 25s, CTAP 30s).
    /// Equivale a `show_locked`; existe para deixar a transicao explicita no call-site.
    pub fn show_locked_timeout(&mut self) {
        self.screen = JourneyScreen::Locked;
    }

    /// WAVE8 — espelha a jornada na tela LilyGO (ST7789 135x240).
    /// Textos curtos cabem em 135px; Vault repassa o codigo do device sem tocar.
    pub fn to_ui_screen_at(&self, now_ms: u64) -> UiScreen {
        match &self.screen {
            JourneyScreen::Boot => UiScreen::BootSplash {
                version: String::from("v1.0.0 (Rust)"),
                chip: String::from("ESP32-S3 Dual-Core"),
            },
            JourneyScreen::Home => UiScreen::IdleStandby {
                status_text: String::from("Aguardando solicitacao FIDO2..."),
            },
            JourneyScreen::PairingBle { code } => UiScreen::IdleStandby {
                status_text: format!("BLE parear: {} confirme no app", code),
            },
            JourneyScreen::PairingAp { ssid } => UiScreen::IdleStandby {
                status_text: format!("AP: {} conecte e configure", ssid),
            },
            JourneyScreen::Vault {
                account,
                code,
                expires_ms,
            } => {
                let remaining = expires_ms
                    .saturating_sub(now_ms)
                    .div_ceil(1000)
                    .min(JOURNEY_TOTP_PERIOD_SECS as u64)
                    as u32;
                UiScreen::TotpCode {
                    label: account.clone(),
                    code: code.clone(),
                    remaining_seconds: remaining,
                }
            }
            JourneyScreen::Locked => UiScreen::Error {
                message: String::from("BLOQUEADO - novo hold 5s"),
            },
            JourneyScreen::Busy => UiScreen::IdleStandby {
                status_text: String::from("processando..."),
            },
        }
    }

    /// Avanca timers; Vault expirado volta para `Home` (auto-limpa).
    pub fn tick(&mut self, now_ms: u64) {
        if let JourneyScreen::Vault { expires_ms, .. } = &self.screen {
            if now_ms >= *expires_ms {
                self.screen = JourneyScreen::Home;
            }
        }
    }

    /// `true` quando o Vault esta visivel e nao expirado.
    pub fn is_vault_visible(&self, now_ms: u64) -> bool {
        match &self.screen {
            JourneyScreen::Vault { expires_ms, .. } => now_ms < *expires_ms,
            _ => false,
        }
    }
}

impl Default for UiJourney {
    fn default() -> Self {
        Self::new()
    }
}

/// WAVE8 — telas de erro claras (LCD via `DisplayManager::set_screen`,
/// LED via `led_for_journey(Locked)` = `ErrorFlash`).
/// Nenhuma delas exibe segredo: so mensagem curta.
pub fn error_screen_no_up() -> UiScreen {
    UiScreen::Error {
        message: String::from("Sem toque UP - pressione BOOT"),
    }
}

/// WAVE8 — PIN exigido (ex.: troca de senha AP, DELETE OATH).
pub fn error_screen_no_pin() -> UiScreen {
    UiScreen::Error {
        message: String::from("PIN exigido - desbloqueie no app"),
    }
}

/// WAVE8 — timeout (pareamento 60s, UP 25s, CTAP 30s).
pub fn error_screen_timeout() -> UiScreen {
    UiScreen::Error {
        message: String::from("Tempo esgotado - tente de novo"),
    }
}

/// WAVE8 — long-press sem contas no NVS (nunca codigo falso).
pub fn error_screen_no_accounts() -> UiScreen {
    UiScreen::Error {
        message: String::from(NO_ACCOUNTS_MSG),
    }
}

/// Renderer LED headless para a mesma maquina (sem LCD).
pub fn led_for_journey(screen: &JourneyScreen) -> LedEffect {
    match screen {
        JourneyScreen::Boot => LedEffect::RainbowCycle { speed_ms: 1000 },
        JourneyScreen::Home => LedEffect::Breathing {
            color: Color::CYAN,
            period_ms: 2000,
        },
        JourneyScreen::PairingBle { .. } | JourneyScreen::PairingAp { .. } => {
            LedEffect::Breathing {
                color: Color::BLUE,
                period_ms: 1600,
            }
        }
        JourneyScreen::Vault { .. } => LedEffect::Solid(Color::BLUE),
        JourneyScreen::Locked => LedEffect::ErrorFlash,
        JourneyScreen::Busy => LedEffect::PromptTouch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journey_boot_home_vault_autoclear() {
        let mut j = UiJourney::new();
        assert_eq!(*j.screen(), JourneyScreen::Boot);
        j.show_home();
        assert_eq!(*j.screen(), JourneyScreen::Home);
        j.show_vault("GitHub:alice", "287082", 1000);
        assert!(j.is_vault_visible(1000));
        assert!(j.is_vault_visible(1000 + 14_000));
        j.tick(1000 + VAULT_AUTO_CLEAR_SECS * 1000);
        assert_eq!(*j.screen(), JourneyScreen::Home);
        assert!(!j.is_vault_visible(1000 + VAULT_AUTO_CLEAR_SECS * 1000));
    }

    #[test]
    fn pairing_screens_hold_code_and_ssid() {
        let mut j = UiJourney::new();
        j.show_pairing_ble("483920");
        assert_eq!(
            *j.screen(),
            JourneyScreen::PairingBle {
                code: String::from("483920")
            }
        );
        j.show_pairing_ap("AegisKey-00AF");
        assert_eq!(
            *j.screen(),
            JourneyScreen::PairingAp {
                ssid: String::from("AegisKey-00AF")
            }
        );
        j.show_locked();
        assert_eq!(*j.screen(), JourneyScreen::Locked);
        j.show_busy();
        assert_eq!(*j.screen(), JourneyScreen::Busy);
    }

    #[test]
    fn led_covers_every_screen() {
        assert!(matches!(
            led_for_journey(&JourneyScreen::Boot),
            LedEffect::RainbowCycle { .. }
        ));
        assert!(matches!(
            led_for_journey(&JourneyScreen::Home),
            LedEffect::Breathing { .. }
        ));
        assert_eq!(
            led_for_journey(&JourneyScreen::Vault {
                account: String::from("a"),
                code: String::from("123456"),
                expires_ms: 9
            }),
            LedEffect::Solid(Color::BLUE)
        );
        assert_eq!(
            led_for_journey(&JourneyScreen::Locked),
            LedEffect::ErrorFlash
        );
    }

    #[test]
    fn wave8_timeouts_match_config() {
        assert_eq!(JOURNEY_PAIRING_TIMEOUT_MS, 60_000);
        assert_eq!(
            JOURNEY_PAIRING_TIMEOUT_MS,
            crate::config::PAIRING_WINDOW_MS
        );
        assert_eq!(JOURNEY_BUSY_TIMEOUT_MS, 30_000);
        assert_eq!(VAULT_AUTO_CLEAR_SECS, 15);
        assert_eq!(JOURNEY_TOTP_PERIOD_SECS, 30);
    }

    #[test]
    fn wave8_error_screens_are_distinct_and_clear() {
        let no_up = error_screen_no_up();
        let no_pin = error_screen_no_pin();
        let timeout = error_screen_timeout();
        let no_acct = error_screen_no_accounts();
        assert_ne!(no_up, no_pin);
        assert_ne!(no_up, timeout);
        assert_ne!(no_up, no_acct);
        assert_ne!(no_pin, timeout);
        assert_ne!(no_pin, no_acct);
        assert_ne!(timeout, no_acct);
        // Sem contas usa a mesma mensagem do totp_view (fonte unica).
        assert_eq!(
            no_acct,
            UiScreen::Error {
                message: String::from(crate::totp_view::NO_ACCOUNTS_MSG)
            }
        );
        for s in [no_up, no_pin, timeout, no_acct] {
            assert!(
                matches!(s, UiScreen::Error { .. }),
                "erro deve ser UiScreen::Error"
            );
        }
        // LED headless espelha erro em vermelho.
        assert_eq!(
            led_for_journey(&JourneyScreen::Locked),
            LedEffect::ErrorFlash
        );
    }

    #[test]
    fn wave8_to_ui_screen_covers_every_state() {
        let mut j = UiJourney::new();
        assert!(matches!(j.to_ui_screen_at(0), UiScreen::BootSplash { .. }));
        j.show_home();
        assert!(matches!(j.to_ui_screen_at(0), UiScreen::IdleStandby { .. }));
        j.show_pairing_ble("483920");
        assert!(matches!(j.to_ui_screen_at(0), UiScreen::IdleStandby { .. }));
        j.show_pairing_ap("AegisKey-00AF");
        assert!(matches!(j.to_ui_screen_at(0), UiScreen::IdleStandby { .. }));
        j.show_locked();
        assert!(matches!(j.to_ui_screen_at(0), UiScreen::Error { .. }));
        j.show_locked_timeout();
        assert_eq!(*j.screen(), JourneyScreen::Locked);
        j.show_busy();
        assert!(matches!(j.to_ui_screen_at(0), UiScreen::IdleStandby { .. }));
    }

    #[test]
    fn wave8_vault_repasses_device_code_untouched() {
        let mut j = UiJourney::new();
        // Codigo real do device (vetor RFC 4226, T=1) atravessa sem copia falsa.
        j.show_vault("TestService:alice", "287082", 60_000);
        match j.to_ui_screen_at(60_000) {
            UiScreen::TotpCode {
                label,
                code,
                remaining_seconds,
            } => {
                assert_eq!(label, "TestService:alice");
                assert_eq!(code, "287082");
                assert_eq!(remaining_seconds, 15);
            }
            other => panic!("Vault deve espelhar TotpCode, veio {:?}", other),
        }
        // Expirado -> Home (auto-limpa 15s preservado).
        j.tick(60_000 + VAULT_AUTO_CLEAR_SECS * 1000);
        assert_eq!(*j.screen(), JourneyScreen::Home);
    }
}
