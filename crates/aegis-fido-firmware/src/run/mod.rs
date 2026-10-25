//! Authenticator run loops (moved from `main.rs`; single-owner audit slice).
//!
//! - `run_authenticator`: legacy poll loop (USB + serial + BLE + CCID).
//! - `run_authenticator_freertos`: FreeRTOS variant (usb + button + housekeeping).
//! - Helpers moved with the loops: FFI shims, `kprintln!`,
//!   OTA version/key helpers, `freertos_test_mode` and thin serial shims.
//!   BLE complete-message dispatcher lives in `ble_dispatch`
//!   (thin composition, no logic fork).
//!
//! Contract (R15/R16, MATRIZ-TODO sec. 9): wire behavior preserved byte for
//! byte; time arrives via `now_ms`/`now_secs` args, never from a host clock;
//! no secrets in logs; hardware only via declared FFI + lib stores/radios.
//! `main.rs` keeps only thin `app_main` wiring over `run::*`.

#[cfg(target_os = "espidf")]
use crate::led::LedEffect;
#[cfg(all(feature = "debug-terminal", target_os = "espidf"))]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::{
    button::{DualButtonManager, EspBootButtonInput, EspKeyButtonInput},
    display::{DisplayManager, UiScreen},
    efuse::{EfuseManager, RamEfuseStorage},
    led::{EspWs2812Output, Ws2812Controller},
    persistence::{PlatformFlashBackend, SecureStorage},
    provision::load_device_keys,
    totp_view::{collect_totp_codes, NO_ACCOUNTS_MSG, TOTP_SHOW_TICKS},
    usb_descriptors,
    watchdog::Watchdog,
};
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
use crate::{
    ota::{OtaState, OP_OTA_COMMIT},
    ota_store::{
        dispatch_ota_request, is_ota_op, FlashOtaSink, OtaRequestCtx, OTA_STATUS_FAIL,
        OTA_STATUS_OK,
    },
};
use aegis_fido_core::ctap::CtapEngine;
#[cfg(target_os = "espidf")]
use aegis_fido_core::ctap::CTAP_CMD_RESET;
#[cfg(target_os = "espidf")]
use aegis_fido_core::ctap::{CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL};
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::wallet::WalletStore;
use aegis_fido_usb::ctaphid::CtapHidManager;
#[cfg(target_os = "espidf")]
use aegis_fido_usb::ctaphid::{
    CtapHidFramer, RawPacket, CAPABILITY_CBOR, CAPABILITY_WINK, CMD_CANCEL, CMD_CBOR, CMD_INIT,
    CMD_MSG, CMD_PING, CMD_WINK, PACKET_SIZE, STATUS_UPNEEDED,
};
use core::time::Duration;

#[cfg(target_os = "espidf")]
extern "C" {
    // USB-OTG (TinyUSB) ATIVO no dispatcher FreeRTOS: dono único do PHY
    // interno (GPIO19/20); console primário no UART0 (sdkconfig).
    #[allow(dead_code)]
    fn aegis_usb_init() -> esp_idf_sys::esp_err_t;
    fn aegis_usb_is_mounted() -> bool;
    fn aegis_usb_send_report(packet: *const u8, len: u16) -> bool;
    fn aegis_usb_pop_packet(out_buf: *mut u8, max_len: u16) -> u16;
    // F4: CCID bulk (driver C `ccid_device.c`; frames completos remontados).
    // `pop` devolve 0 sem frame; `send` fragmenta em 64B no bulk-IN.
    fn aegis_ccid_pop_frame(out_buf: *mut u8, max_len: u16) -> u16;
    fn aegis_ccid_send(data: *const u8, len: u16) -> bool;
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Reboot p/ download ROM via RTC_CNTL (sem BOOT/DTR/RTS).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    fn aegis_reboot_to_download();
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Drop + re-enumera o USB nativo (dispensa replug físico).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    fn aegis_usb_reconnect() -> bool;
    // Serial CTAPHID (UART 115200, framing identical to USB). Classic reuses
    // the UART-backed aegis_usb_* symbols; S3/S2 use aegis_serial_* (UART0
    // diagnostic channel alongside native USB-OTG).
    #[cfg(all(feature = "board-ttgo-classic", feature = "test-mode"))]
    fn aegis_usb_read_chunk(out_buf: *mut u8, max_len: u16) -> u16;
    #[cfg(not(feature = "board-ttgo-classic"))]
    fn aegis_serial_init() -> esp_idf_sys::esp_err_t;
    #[cfg(not(feature = "board-ttgo-classic"))]
    fn aegis_serial_send_report(packet: *const u8, len: u16) -> bool;
    #[cfg(not(feature = "board-ttgo-classic"))]
    fn aegis_serial_pop_packet(out_buf: *mut u8, max_len: u16) -> u16;
    #[cfg(all(not(feature = "board-ttgo-classic"), feature = "test-mode"))]
    fn aegis_serial_read_chunk(out_buf: *mut u8, max_len: u16) -> u16;
}

macro_rules! kprintln {
    () => {
        kprintln!("");
    };
    ($($arg:tt)*) => {{
        let mut raw: [u8; 256] = [0u8; 256];
        let mut w = crate::watchdog::StaticBuf::new(&mut raw);
        let _ = core::fmt::Write::write_fmt(&mut w, format_args!($($arg)*));
        let s = w.as_str();
        #[cfg(target_os = "espidf")]
        #[allow(unused_unsafe)]
        unsafe {
            for b in s.as_bytes() {
                esp_idf_sys::esp_rom_printf(b"%c\0".as_ptr() as *const _, *b as core::ffi::c_int);
            }
            esp_idf_sys::esp_rom_printf(b"\r\n\0".as_ptr() as *const _);
        }
        #[cfg(not(target_os = "espidf"))]
        println!("{}", s);
    }};
}

pub(crate) mod ble_dispatch;
#[cfg(target_os = "espidf")]
pub(crate) mod serial_io;
#[cfg(all(target_os = "espidf", feature = "test-mode"))]
use self::serial_io::serial_read_chunk;
#[cfg(feature = "freertos")]
pub(crate) mod run_loop_freertos;
pub(crate) mod run_loop_legacy;
#[cfg(target_os = "espidf")]
use self::serial_io::{serial_pop_packet, serial_send_bytes};

/// Running firmware version (monotonic u32; OTA manifests must exceed it).
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
const FIRMWARE_VERSION: u32 = 1;

/// Offline OTA pubkey via injected provider (T6/A4).
///
/// The OTA pubkeys moved out of the dispatcher into ota OtaKeyProvider.
/// Release is zeros fail-closed until the factory programs the real release
/// key. Lab key compiled only under feature = "test-mode" gate.
/// CI-GREP TEST-HOOK marker TEST-OTA-KEY.
/// scripts check-release-clean proves absence in the release artifact.
/// R12 no hard coded key in main, R13 stub only, R14 eFuse BLOCK7 plus
/// BLOCK8 salt path via ota_provisioned below.
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
fn ota_active_pubkey() -> [u8; 32] {
    crate::ota::OtaKeyProvider::active_pubkey_for_build()
}

/// Provisionado p/ OTA: eFuse válido, ou lab em test-mode (CI-GREP: TEST-HOOK).
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
fn ota_provisioned(efuse_mgr: &crate::efuse::EfuseManager<crate::efuse::RamEfuseStorage>) -> bool {
    crate::provision::load_device_keys(efuse_mgr).is_ok() || cfg!(feature = "test-mode")
}

/// Diagnóstico TEST_* no caminho FreeRTOS (device + test-mode; host inalterado).
///
/// Drena linhas de texto da serial (`aegis_serial_*` fora da classic, igual
/// ao poll USB binário) e roteia via `SerialRouter`/dispatch existentes:
/// - `TEST_UP` arma 1 latch de presença (consumo único, mesma semântica do
///   legado: vale no próximo Tick, 1,5 s via `prox.note_presence`).
/// - `TEST_PAIRING_OPEN[_300]` delega a `dispatch_serial_pairing_line`
///   (usa o ponto de pareamento `PairingManager::open_test_window[_secs]`;
///   UP/bonding seguem exigidos, sem auto-parear).
/// - `TEST_PAIRING_CLOSE` fecha a janela em `freertos_test` (via
///   `close_test_window`, test-only) e o chamador FreeRTOS fecha a janela
///   host em `pairing_mgr` (mesmo `close_test_window`); ack
///   `pairing_closed source=software`.
/// - `TEST_DOWNLOAD` responde ack e reboota p/ download ROM (`RTC_CNTL`).
/// - Demais `TEST_*` respondem status textual sem segredos ou são ignorados
///   (documentado): `TEST_LED_*` não tem pipeline LED/display no FreeRTOS
///   (o latch `led_test_hold` vive no loop legado), então é ack compatível
///   sem latch; `TEST_LIFETIME_DUMP` delega ao dump canónico (só metadados);
///   `TEST_*` desconhecido ou não-TESTE não responde (sem janela/latch).
/// - Fio continua `k=v` texto; domínio interno é tipado (`FreertosTestLine`,
///   `TestLineOutcome`); sem JSON fora de FFI.
///
/// Todo o ramo só compila com `test-mode` (release nem vê este `mod`).
#[cfg(feature = "test-mode")]
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
mod freertos_test_mode {
    use crate::pairing::{PairingManager, PairingState};

    /// Linha TEST_* tipada (domínio interno; fio segue texto `k=v`, sem JSON).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FreertosTestLine {
        /// `TEST_UP`: 1 toque BOOT via software.
        UpLatch,
        /// `TEST_PAIRING_OPEN`: janela 60 s.
        PairingOpen,
        /// `TEST_PAIRING_OPEN_300`: janela 300 s.
        PairingOpen300,
        /// `TEST_PAIRING_CLOSE`: fecha qualquer janela aberta (determinismo).
        PairingClose,
        /// `TEST_DOWNLOAD`: reboot p/ download ROM.
        Download,
        /// `TEST_USB_RECONNECT`: re-enumera o USB nativo.
        UsbReconnect,
        /// `TEST_LED_STATE`: estado textual (sem segredos).
        LedState,
        /// `TEST_LED_{RED,GREEN,BLUE,OFF,ON}`: ack compatível (`led_set <CMD>`),
        /// sem latch/cor no FreeRTOS. `TEST_LED_ON` é compat HIL: ack sem
        /// travar cor em nenhum loop (sem residual entre sessões).
        LedSet,
        /// `TEST_LED_RELEASE`: ack compatível, sem latch no FreeRTOS.
        LedRelease,
        /// `TEST_LIFETIME_DUMP`: dump canónico (só metadados).
        LifetimeDump,
        /// `TEST_*` desconhecido: ignorado (sem resposta).
        UnknownTest,
        /// Não é `TEST_*`: ignorado.
        NotTest,
    }

    /// Classifica a linha já aparada (sem alocar; sem segredos).
    pub fn classify_freertos_test_line(trimmed: &str) -> FreertosTestLine {
        match trimmed {
            "TEST_UP" => FreertosTestLine::UpLatch,
            "TEST_PAIRING_OPEN" => FreertosTestLine::PairingOpen,
            "TEST_PAIRING_OPEN_300" => FreertosTestLine::PairingOpen300,
            "TEST_PAIRING_CLOSE" => FreertosTestLine::PairingClose,
            "TEST_DOWNLOAD" => FreertosTestLine::Download,
            "TEST_USB_RECONNECT" => FreertosTestLine::UsbReconnect,
            "TEST_LED_STATE" => FreertosTestLine::LedState,
            "TEST_LED_RED" | "TEST_LED_GREEN" | "TEST_LED_BLUE" | "TEST_LED_OFF"
            | "TEST_LED_ON" => FreertosTestLine::LedSet,
            "TEST_LED_RELEASE" => FreertosTestLine::LedRelease,
            "TEST_LIFETIME_DUMP" => FreertosTestLine::LifetimeDump,
            s if s.starts_with("TEST_") => FreertosTestLine::UnknownTest,
            _ => FreertosTestLine::NotTest,
        }
    }

    /// Resultado tipado de uma linha (resposta textual + efeitos FFI a cargo do device).
    pub struct TestLineOutcome {
        /// Linha de status a enviar na serial (sem segredos) ou `None` (ignorado).
        pub response: Option<String>,
        /// Sinaliza reboot p/ download ROM (FFI só no device).
        pub reboot_to_download: bool,
        /// Sinaliza re-enumeração USB (FFI só no device).
        pub usb_reconnect: bool,
    }

    /// Estado test-mode do dispatcher FreeRTOS (latch UP 1x + janela de pareamento).
    pub struct FreertosTestState {
        up_pending: bool,
        pairing: PairingManager,
    }

    impl FreertosTestState {
        /// Estado inicial: sem latch, sem janela (fail-closed).
        pub fn new() -> Self {
            Self {
                up_pending: false,
                pairing: PairingManager::new(),
            }
        }

        /// Arma 1 UP software (consumo único via [`Self::take_up`]).
        pub fn arm_up(&mut self) {
            self.up_pending = true;
        }

        /// Consome o latch 1x (semântica legado: 1 UP, uso único).
        pub fn take_up(&mut self) -> bool {
            core::mem::replace(&mut self.up_pending, false)
        }

        /// Latch armado? (só metadado p/ `extra_states` do dump).
        pub fn up_pending(&self) -> bool {
            self.up_pending
        }

        /// Janela de pareamento atual (p/ `prox.tick`; `Idle` sem `TEST_PAIRING_OPEN`).
        pub fn pairing_state(&self) -> PairingState {
            self.pairing.state()
        }

        /// `true` SOMENTE com a janela de 60 s aberta (não basta `!= Idle`:
        /// `Locked` pós-timeout NÃO é janela aberta; sem isto, a primeira
        /// janela expirada deixava `test_open` preso em `true` e os gates
        /// de pairing do dispatcher viam janela aberta para sempre).
        pub fn is_pairing_window_open(&self, now_ms: u64) -> bool {
            self.pairing.is_pairing_window_open(now_ms)
        }

        /// Fecha a janela de teste (test-only; determinismo entre sessões).
        ///
        /// Espelha `TEST_PAIRING_OPEN` (que abre via
        /// `dispatch_serial_pairing_line`): vira `Locked`, mesmo estado do
        /// timeout natural. Não toca em `bonded`.
        pub fn close_test_window(&mut self) {
            self.pairing.close_test_window();
        }

        /// Acesso ao pareamento (só via `dispatch_serial_pairing_line`).
        pub fn pairing_mut(&mut self) -> &mut PairingManager {
            &mut self.pairing
        }

        /// Avança timeouts da janela (chamar a cada `Tick10ms`).
        pub fn tick(&mut self, now_ms: u64) {
            self.pairing.tick(now_ms);
        }
    }

    impl Default for FreertosTestState {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Roteia uma linha de texto (já sem `\n`) para resposta/efeitos, sem FFI.
    ///
    /// `extra_states` carrega só metadados (uptime/latch; nunca segredos).
    /// O dreno TEST de `run_authenticator_freertos` monta `extra_states`
    /// como `uptime_s=<s> up_latched=<0|1> touch=<0|1>`, onde `touch` é o
    /// flag do dispatcher (`touch_latched`) — visível só via este texto.
    /// `TEST_LED_STATE` ignora o resto de `extra_states` e só reflete
    /// `touch=` (metadado, sem efeito no latch).
    pub fn dispatcher_touch_from_extra(extra_states: &str) -> u8 {
        for token in extra_states.split([' ', '\t', '\r', '\n', ',']) {
            if let Some(v) = token.strip_prefix("touch=") {
                return u8::from(v.starts_with('1'));
            }
        }
        0
    }

    pub fn handle_freertos_test_line(
        state: &mut FreertosTestState,
        line: &str,
        now_ms: u64,
        extra_states: &str,
    ) -> TestLineOutcome {
        let trimmed = line.trim();
        match classify_freertos_test_line(trimmed) {
            FreertosTestLine::UpLatch => {
                state.arm_up();
                TestLineOutcome {
                    response: Some(String::from("up_latched source=software\n")),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::PairingOpen | FreertosTestLine::PairingOpen300 => {
                let resp = crate::serial_ctaphid::dispatch_serial_pairing_line(
                    line,
                    state.pairing_mut(),
                    now_ms,
                );
                TestLineOutcome {
                    response: resp,
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::PairingClose => {
                state.close_test_window();
                TestLineOutcome {
                    response: Some(String::from("pairing_closed source=software\n")),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::Download => TestLineOutcome {
                response: Some(String::from("download_mode source=software\n")),
                reboot_to_download: true,
                usb_reconnect: false,
            },
            FreertosTestLine::UsbReconnect => TestLineOutcome {
                response: Some(String::from("usb_reconnect source=software\n")),
                reboot_to_download: false,
                usb_reconnect: true,
            },
            FreertosTestLine::LedState => {
                // Sem pipeline LED/display no FreeRTOS (o latch `led_test_hold`
                // + `display_mgr` vivem no loop legado): responde só metadados.
                // `touch=` vem do dreno TEST via `extra_states` (flag do
                // dispatcher `touch_latched`); só texto, sem efeito no latch.
                let resp = format!(
                    "led_state screen=freertos pairing={:?} up_pending={} touch={} uptime_s={}\n",
                    state.pairing_state(),
                    state.up_pending() as u8,
                    dispatcher_touch_from_extra(extra_states),
                    now_ms / 1000
                );
                TestLineOutcome {
                    response: Some(resp),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::LedSet => {
                // Ack compatível com o legado (`led_set <CMD>`); sem latch/cor
                // no FreeRTOS (documentado: E2E não trava esperando o ack).
                let resp = format!("led_set {trimmed}\n");
                TestLineOutcome {
                    response: Some(resp),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::LedRelease => TestLineOutcome {
                response: Some(String::from("led_set released\n")),
                reboot_to_download: false,
                usb_reconnect: false,
            },
            FreertosTestLine::LifetimeDump => {
                let resp = crate::serial_ctaphid::dispatch_serial_text_line(line, extra_states);
                TestLineOutcome {
                    response: resp,
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::UnknownTest | FreertosTestLine::NotTest => TestLineOutcome {
                response: None,
                reboot_to_download: false,
                usb_reconnect: false,
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classifica_todas_do_manifesto_sem_json() {
            assert_eq!(
                classify_freertos_test_line("TEST_UP"),
                FreertosTestLine::UpLatch
            );
            assert_eq!(
                classify_freertos_test_line("TEST_DOWNLOAD"),
                FreertosTestLine::Download
            );
            assert_eq!(
                classify_freertos_test_line("TEST_USB_RECONNECT"),
                FreertosTestLine::UsbReconnect
            );
            assert_eq!(
                classify_freertos_test_line("TEST_PAIRING_OPEN"),
                FreertosTestLine::PairingOpen
            );
            assert_eq!(
                classify_freertos_test_line("TEST_PAIRING_OPEN_300"),
                FreertosTestLine::PairingOpen300
            );
            assert_eq!(
                classify_freertos_test_line("TEST_PAIRING_CLOSE"),
                FreertosTestLine::PairingClose
            );
            assert_eq!(
                classify_freertos_test_line("TEST_LIFETIME_DUMP"),
                FreertosTestLine::LifetimeDump
            );
            assert_eq!(
                classify_freertos_test_line("TEST_LED_STATE"),
                FreertosTestLine::LedState
            );
            for cmd in [
                "TEST_LED_RED",
                "TEST_LED_GREEN",
                "TEST_LED_BLUE",
                "TEST_LED_OFF",
                "TEST_LED_ON",
            ] {
                assert_eq!(classify_freertos_test_line(cmd), FreertosTestLine::LedSet);
            }
            assert_eq!(
                classify_freertos_test_line("TEST_LED_RELEASE"),
                FreertosTestLine::LedRelease
            );
            assert_eq!(
                classify_freertos_test_line("TEST_FUTURO"),
                FreertosTestLine::UnknownTest
            );
            assert_eq!(
                classify_freertos_test_line("[HEARTBEAT] oi"),
                FreertosTestLine::NotTest
            );
        }

        #[test]
        fn up_tem_consumo_unico() {
            let mut s = FreertosTestState::new();
            assert!(!s.up_pending());
            let out = handle_freertos_test_line(&mut s, "TEST_UP", 1000, "uptime_s=1 up_latched=0");
            assert_eq!(
                out.response.as_deref(),
                Some("up_latched source=software\n")
            );
            assert!(!out.reboot_to_download && !out.usb_reconnect);
            assert!(s.up_pending());
            assert!(s.take_up());
            assert!(!s.take_up());
        }

        #[test]
        fn pairing_abre_janela_60_e_300_sem_bond() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_PAIRING_OPEN", 5000, "");
            let resp = out.response.expect("ack 60s");
            assert!(resp.contains("pairing_open") && resp.contains("window_s=60"));
            assert!(s.pairing_state() != PairingState::Idle);
            assert!(!s.pairing_mut().is_bonded());

            let mut t = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut t, "TEST_PAIRING_OPEN_300", 7000, "");
            let resp = out.response.expect("ack 300s");
            assert!(resp.contains("window_s=300"));
            // Expira: tick além da janela volta a `Locked`/fechada.
            t.tick(7000 + 300 * 1000);
            assert!(!t.pairing_mut().is_pairing_window_open(7000 + 300 * 1000));
        }

        #[test]
        fn download_e_reconnect_sinalizam_ffi_sem_executar() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_DOWNLOAD", 0, "");
            assert!(out.reboot_to_download && !out.usb_reconnect);
            assert!(out.response.unwrap().contains("download_mode"));
            let out = handle_freertos_test_line(&mut s, "TEST_USB_RECONNECT", 0, "");
            assert!(out.usb_reconnect && !out.reboot_to_download);
            assert!(out.response.unwrap().contains("usb_reconnect"));
        }

        #[test]
        fn led_responde_status_sem_segredo_e_sem_latch() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_LED_STATE", 42_000, "");
            let resp = out.response.expect("led_state");
            assert!(resp.starts_with("led_state "));
            assert!(resp.contains("screen=freertos"));
            assert!(resp.contains("up_pending=0"));
            assert!(resp.contains("touch=0"));
            assert!(resp.contains("uptime_s=42"));
            assert!(!resp.contains("SECRET"));
            let out = handle_freertos_test_line(&mut s, "TEST_LED_RED", 0, "");
            assert_eq!(out.response.as_deref(), Some("led_set TEST_LED_RED\n"));
            // `TEST_LED_ON` (compat HIL): ack sem latch — estado intacto.
            let out = handle_freertos_test_line(&mut s, "TEST_LED_ON", 0, "");
            assert_eq!(out.response.as_deref(), Some("led_set TEST_LED_ON\n"));
            assert!(!s.up_pending());
            assert_eq!(s.pairing_state(), PairingState::Idle);
            let out = handle_freertos_test_line(&mut s, "TEST_LED_RELEASE", 0, "");
            assert_eq!(out.response.as_deref(), Some("led_set released\n"));
        }

        #[test]
        fn led_state_expoe_touch_do_dreno() {
            // Formato do dreno TEST (`extra="uptime_s=<s> up_latched=<0|1>
            // touch=<0|1>"`): `up_pending` vem do `FreertosTestState`,
            // `touch` é o flag do dispatcher (`touch_latched`) repassado via
            // `extra_states` (só metadado textual, sem efeito no latch).
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(
                &mut s,
                "TEST_LED_STATE",
                42_000,
                "uptime_s=42 up_latched=1 touch=1",
            );
            let resp = out.response.expect("led_state com touch");
            assert!(resp.contains("up_pending=0"));
            assert!(resp.contains("touch=1"));
            assert_eq!(
                dispatcher_touch_from_extra("uptime_s=1 up_latched=0 touch=1"),
                1
            );
            assert_eq!(
                dispatcher_touch_from_extra("uptime_s=1 up_latched=0 touch=0"),
                0
            );
            assert_eq!(dispatcher_touch_from_extra("uptime_s=1 up_latched=0"), 0);
            assert_eq!(dispatcher_touch_from_extra(""), 0);
        }

        #[test]
        fn dump_delega_e_desconhecido_ignora() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_LIFETIME_DUMP", 0, "uptime_s=42");
            let dump = out.response.expect("dump");
            assert!(dump.starts_with("lt_dump v=1\n"));
            assert!(dump.contains("lt.state uptime_s=42"));
            assert!(dump.ends_with("lt_end\n"));
            let out = handle_freertos_test_line(&mut s, "TEST_FUTURO_X", 0, "");
            assert!(out.response.is_none());
            assert!(!out.reboot_to_download && !out.usb_reconnect);
            // Linha não-TESTE também ignorada.
            let out = handle_freertos_test_line(&mut s, "[HEARTBEAT] oi", 0, "");
            assert!(out.response.is_none());
        }

        #[test]
        fn pairing_close_fecha_ambas_e_reabre_sem_regressao() {
            use crate::serial_ctaphid::dispatch_serial_pairing_line;
            // Abre as duas janelas: host (`pairing_mgr`) + teste (`freertos_test`).
            let mut host = PairingManager::new();
            let mut test = FreertosTestState::new();
            host.open_test_window(5000);
            let out = handle_freertos_test_line(&mut test, "TEST_PAIRING_OPEN", 5000, "");
            assert!(out.response.expect("ack open").contains("pairing_open"));
            assert!(host.is_pairing_window_open(5000));
            assert!(test.is_pairing_window_open(5000));
            // Fecha via mesmos calls do inbox TEST.
            let ack_host = dispatch_serial_pairing_line("TEST_PAIRING_CLOSE", &mut host, 6000)
                .expect("ack close host");
            assert_eq!(ack_host, "pairing_closed source=software\n");
            let out = handle_freertos_test_line(&mut test, "TEST_PAIRING_CLOSE", 6000, "");
            assert_eq!(
                out.response.as_deref(),
                Some("pairing_closed source=software\n")
            );
            assert!(!host.is_pairing_window_open(6000));
            assert!(!test.is_pairing_window_open(6000));
            // Reaberta depois continua funcionando (sem regressão).
            host.open_test_window(7000);
            let out = handle_freertos_test_line(&mut test, "TEST_PAIRING_OPEN", 7000, "");
            assert!(out.response.expect("ack reopen").contains("pairing_open"));
            assert!(host.is_pairing_window_open(7000));
            assert!(test.is_pairing_window_open(7000));
        }
    }
}

/// Entrada da variante FreeRTOS (corpo em `run_loop_freertos`).
#[cfg(feature = "freertos")]
pub fn run_authenticator_freertos() {
    run_loop_freertos::run_authenticator_freertos();
}

#[cfg_attr(feature = "freertos", allow(dead_code))]
pub fn run_authenticator() {
    run_loop_legacy::run_authenticator();
}
