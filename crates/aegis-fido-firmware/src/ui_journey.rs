//! Wave4 — maquina de telas Boot/Home/PairingBLE/PairingAP/Vault/Locked/Busy.
//!
//! - LCD usa `UiScreen`; headless usa a mesma maquina com renderer LED.
//! - Menu NUNCA decide auth: so chama `UpPolicy`/`CtapEngine` (ver `policy.rs`).
//! - Vault (OATH apos UP) auto-limpa em 15s (`VAULT_AUTO_CLEAR_SECS`).

extern crate alloc;

use alloc::string::String;
use crate::config::VAULT_AUTO_CLEAR_SECS;
use crate::led::{Color, LedEffect};

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
}
