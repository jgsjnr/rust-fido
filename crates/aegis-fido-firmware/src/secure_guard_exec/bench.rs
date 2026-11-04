//! MODO BANCADA (test-mode only): sessao estendida sem relock por ociosidade.
//!
//! Procedimento de bancada (firmware `test-mode`, default OFF):
//! 1. `TEST_BENCH_ON` (op explicita de bancada, serial/UART) antes do unlock;
//! 2. unlock normal (UP + PIN seguem exigidos; gates inalterados);
//! 3. a sessao passa a valer 24 h sem relock por ociosidade;
//! 4. `TEST_BENCH_OFF` restaura a policy salva e o idle padrao volta.
//!
//! Garantias (cobertas em `mod tests`):
//! - NUNCA em producao: comportamento so atras de `#[cfg(feature =
//!   "test-mode")]`; release expoe no-ops (`false`/`None`, linha ignorada).
//!   `prod-strict` + `test-mode` nem compila (`prod_strict_guard.rs`).
//! - Default off: flag global comeca desligado; so a op explicita liga.
//! - Disconnect lock continua valendo: `transport_lock` e
//!   `on_transport_disconnect` nao sao tocados (travam com bancada ativa).
//! - NVS/keys intactos, sem wipe/eFuse: so policy em RAM, sem
//!   `save_secure_guard_record`; o desligar restaura os valores salvos.
//! - Auditoria: liga/desliga gravam `EV_BENCH` no `FwLog` (arg `0x01` ON /
//!   `0x00` OFF) e `log::info!` com a marca `BENCH`.
//!
//! Portabilidade Xtensa LX7: estado global em `std::sync::Mutex` (sem
//! atomicas de 64 bits nesse core), mesmo padrao de `unlock.rs`.
//!
//! CI-GREP: TEST-HOOK (test-mode only; absent in release).

use aegis_fido_core::secure_guard::SecureGuardEngine;

use crate::fw_log::FwLog;
#[cfg(feature = "test-mode")]
use crate::fw_log::EV_BENCH;
use std::string::String;

/// Janela longa de bancada p/ ociosidade: 24 h em ms.
///
/// Timeout longo (nao "sem expiracao"): o relock por ociosidade deixa de
/// ocorrer na pratica de bancada, mas a sessao continua finita e auditavel.
pub const BENCH_INACTIVITY_TIMEOUT_MS: u64 = 86_400_000;

/// Duracao absoluta da sessao de bancada: 24 h em ms (carimbada no unlock).
pub const BENCH_SESSION_DURATION_MS: u64 = 86_400_000;

/// Op explicita que LIGA a bancada (so existe com `test-mode`).
///
/// Sem a feature a linha e desconhecida: nenhum dispatch a reconhece.
#[cfg(feature = "test-mode")]
pub const TEST_BENCH_ON_CMD: &str = "TEST_BENCH_ON";

/// Op explicita que DESLIGA a bancada e restaura a policy (so `test-mode`).
#[cfg(feature = "test-mode")]
pub const TEST_BENCH_OFF_CMD: &str = "TEST_BENCH_OFF";

/// Arg do `EV_BENCH` no `FwLog` p/ bancada ON (so on/off, sem PII/segredo).
pub const BENCH_FWLOG_ARG_ON: u8 = 0x01;
/// Arg do `EV_BENCH` no `FwLog` p/ bancada OFF (so on/off, sem PII/segredo).
pub const BENCH_FWLOG_ARG_OFF: u8 = 0x00;

/// Estado global da bancada (RAM; default off; nunca persistido).
///
/// Guarda a policy vigente ao ligar p/ restaurar ao desligar.
#[cfg(feature = "test-mode")]
struct BenchSlot {
    active: bool,
    saved_session_ms: u64,
    saved_inactivity_ms: u64,
    have_saved: bool,
}

#[cfg(feature = "test-mode")]
impl BenchSlot {
    const fn new() -> Self {
        Self {
            active: false,
            saved_session_ms: 0,
            saved_inactivity_ms: 0,
            have_saved: false,
        }
    }
}

#[cfg(feature = "test-mode")]
static BENCH: std::sync::Mutex<BenchSlot> = std::sync::Mutex::new(BenchSlot::new());

/// `true` quando a bancada esta ativa (sempre `false` sem `test-mode`).
pub fn is_bench_active() -> bool {
    #[cfg(feature = "test-mode")]
    {
        BENCH.lock().map(|slot| slot.active).unwrap_or(false)
    }
    #[cfg(not(feature = "test-mode"))]
    {
        false
    }
}

/// Liga a bancada: salva a policy e estende idle + absoluta p/ 24 h em RAM.
///
/// Deve ser chamado ANTES do unlock: o `session_expires_at` e carimbado no
/// unlock com a policy vigente. NVS intacta (nenhum `save` aqui). Idempotente
/// (repetir nao duplica auditoria). Retorna `true` com a bancada ativa;
/// release sempre `false`.
pub fn bench_enable(engine: &mut SecureGuardEngine, fw_log: &mut FwLog, now_ms: u64) -> bool {
    #[cfg(feature = "test-mode")]
    {
        let mut slot = BENCH.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !slot.active {
            slot.saved_session_ms = engine.policy().session_duration_ms;
            slot.saved_inactivity_ms = engine.policy().inactivity_timeout_ms;
            slot.have_saved = true;
            engine.policy_mut().session_duration_ms = BENCH_SESSION_DURATION_MS;
            engine.policy_mut().inactivity_timeout_ms = BENCH_INACTIVITY_TIMEOUT_MS;
            slot.active = true;
            fw_log.record(EV_BENCH, BENCH_FWLOG_ARG_ON, now_ms);
            log::info!("[BENCH] bancada ON: sessao estendida 24h em RAM (NVS intacta)");
        }
        true
    }
    #[cfg(not(feature = "test-mode"))]
    {
        let _ = (engine, fw_log, now_ms);
        false
    }
}

/// Desliga a bancada: restaura a policy salva (idle padrao volta).
///
/// NVS intacta (nenhum `save` aqui). Retorna `true` se desligou agora
/// (transicao); `false` se ja estava off ou sem `test-mode`.
pub fn bench_disable(engine: &mut SecureGuardEngine, fw_log: &mut FwLog, now_ms: u64) -> bool {
    #[cfg(feature = "test-mode")]
    {
        let mut slot = BENCH.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.active {
            if slot.have_saved {
                engine.policy_mut().session_duration_ms = slot.saved_session_ms;
                engine.policy_mut().inactivity_timeout_ms = slot.saved_inactivity_ms;
            }
            slot.active = false;
            slot.have_saved = false;
            fw_log.record(EV_BENCH, BENCH_FWLOG_ARG_OFF, now_ms);
            log::info!("[BENCH] bancada OFF: policy restaurada (idle padrao)");
            true
        } else {
            false
        }
    }
    #[cfg(not(feature = "test-mode"))]
    {
        let _ = (engine, fw_log, now_ms);
        false
    }
}

/// Roteia `TEST_BENCH_ON` / `TEST_BENCH_OFF` (op explicita de bancada).
///
/// Retorna o ack na batida exata (`BENCH` marcado, `source=software`);
/// `None` caso contrario. Sem `test-mode` sempre `None` (linha ignorada).
#[cfg(feature = "test-mode")]
pub fn dispatch_serial_bench_line(
    line: &str,
    engine: &mut SecureGuardEngine,
    fw_log: &mut FwLog,
    now_ms: u64,
) -> Option<String> {
    let trimmed = line.trim();
    if trimmed == TEST_BENCH_ON_CMD {
        let _ = bench_enable(engine, fw_log, now_ms);
        Some(String::from("bench_on BENCH idle=extended source=software\n"))
    } else if trimmed == TEST_BENCH_OFF_CMD {
        if bench_disable(engine, fw_log, now_ms) {
            Some(String::from("bench_off BENCH source=software\n"))
        } else {
            Some(String::from("bench_off BENCH already_off source=software\n"))
        }
    } else {
        None
    }
}

/// Release: `TEST_BENCH_*` nao existem (linhas desconhecidas, sem bancada).
#[cfg(not(feature = "test-mode"))]
pub fn dispatch_serial_bench_line(
    _line: &str,
    _engine: &mut SecureGuardEngine,
    _fw_log: &mut FwLog,
    _now_ms: u64,
) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializa os testes de bancada (estado global compartilhado).
    static BENCH_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Engine rapido p/ testes (PBKDF2 minimo; mesma policy padrao).
    #[cfg(feature = "test-mode")]
    fn fast_engine() -> SecureGuardEngine {
        use aegis_fido_core::secure_guard::SecureGuardPolicy;
        SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..SecureGuardPolicy::default()
        })
    }

    /// Garante a bancada desligada (idempotente; o engine e descartavel).
    #[cfg(feature = "test-mode")]
    fn bench_test_reset(engine: &mut SecureGuardEngine) {
        let mut fw_log = FwLog::new();
        let _ = bench_disable(engine, &mut fw_log, 0);
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn bancada_estende_sessao_sem_relock_idle() {
        use aegis_fido_core::secure_guard::SecureGuardState;
        let _guard = BENCH_TEST_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut engine = fast_engine();
        let mut fw_log = FwLog::new();
        bench_test_reset(&mut engine);
        assert!(bench_enable(&mut engine, &mut fw_log, 1_000));
        assert!(is_bench_active());
        assert_eq!(engine.policy().session_duration_ms, BENCH_SESSION_DURATION_MS);
        assert_eq!(engine.policy().inactivity_timeout_ms, BENCH_INACTIVITY_TIMEOUT_MS);
        engine
            .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 1_000)
            .expect("provision ok");
        engine.unlock_with_pin(b"7391", 2_000).expect("unlock ok");
        assert!(engine.is_unlocked());
        // Passado o idle padrao (300 s): sem bancada travaria aqui.
        let _ = engine.check_and_touch_session(2_000 + 300_001);
        assert!(engine.is_unlocked(), "bancada: sem relock por ociosidade");
        // Absoluta continua finita (24 h): expira no prazo estendido.
        let _ = engine.check_and_touch_session(2_000 + BENCH_SESSION_DURATION_MS);
        assert!(!engine.is_unlocked());
        assert_eq!(engine.state(), SecureGuardState::Locked);
        bench_test_reset(&mut engine);
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn bancada_off_restaura_policy_e_idle_volta() {
        use aegis_fido_core::secure_guard::{SecureGuardAuditEventType, SessionExpiryReason};
        let _guard = BENCH_TEST_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut engine = fast_engine();
        let mut fw_log = FwLog::new();
        bench_test_reset(&mut engine);
        assert!(bench_enable(&mut engine, &mut fw_log, 1_000));
        assert!(bench_disable(&mut engine, &mut fw_log, 2_000));
        assert!(!bench_disable(&mut engine, &mut fw_log, 3_000));
        assert!(!is_bench_active());
        assert_eq!(engine.policy().session_duration_ms, 300_000);
        assert_eq!(engine.policy().inactivity_timeout_ms, 300_000);
        engine
            .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 4_000)
            .expect("provision ok");
        engine.unlock_with_pin(b"7391", 5_000).expect("unlock ok");
        let _ = engine.check_and_touch_session(5_000 + 300_001);
        assert!(!engine.is_unlocked());
        // Policy padrao tem absoluta == inatividade (300 s); no empate a
        // absoluta vence (`check_and_touch_session` checa absoluta primeiro).
        // O ponto do teste e que a sessao volta a expirar apos o OFF.
        assert!(matches!(
            engine.audit_log().last().map(|event| &event.event_type),
            Some(SecureGuardAuditEventType::SessionExpired {
                reason: SessionExpiryReason::AbsoluteTimeout
            })
        ));
        bench_test_reset(&mut engine);
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn disconnect_lock_vale_com_bancada_ativa() {
        use aegis_fido_core::ctap::client_pin::{ClientPinState, PinUvTokenSession};
        use aegis_fido_core::otp::rescue::RescueEngine;
        use crate::transport_lock::{lock_on_transport_loss, TransportKind};
        let _guard = BENCH_TEST_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut engine = fast_engine();
        let mut fw_log = FwLog::new();
        bench_test_reset(&mut engine);
        assert!(bench_enable(&mut engine, &mut fw_log, 1_000));
        engine
            .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 1_000)
            .expect("provision ok");
        engine.unlock_with_pin(b"7391", 2_000).expect("unlock ok");
        let mut pin = ClientPinState {
            pin_hash: Some([0x5A; 16]),
            active_session: Some(PinUvTokenSession {
                token: [0xAA; 32],
                protocol: 2,
                permissions: 0xFFFF_FFFF,
                rp_id: None,
            }),
            ..Default::default()
        };
        let mut rescue = RescueEngine::new();
        rescue.set_user_presence(true);
        rescue.set_pin_uv_authenticated(true);
        let mut scratch = [0xAAu8; 24];
        let report = lock_on_transport_loss(
            &mut engine,
            &mut pin,
            &mut rescue,
            &mut [&mut scratch[..]],
            &mut fw_log,
            TransportKind::UsbHid,
            5_000,
        );
        assert!(report.session_was_live);
        assert!(!engine.is_unlocked());
        assert!(report.secure_guard_locked_now);
        // PIN/verificador intactos (so RAM de sessao cai); bancada segue armada.
        assert_eq!(pin.pin_hash, Some([0x5A; 16]));
        assert!(engine.is_provisioned());
        assert!(is_bench_active());
        bench_test_reset(&mut engine);
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn bancada_nao_persiste_nvs_nem_toca_keys() {
        use crate::persistence::{MockFlashBackend, SecureStorage};
        use crate::secure_guard_storage::{load_secure_guard_record, save_secure_guard_record};
        let _guard = BENCH_TEST_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x42; 32], &[0x99; 32]);
        let mut engine = fast_engine();
        let mut fw_log = FwLog::new();
        bench_test_reset(&mut engine);
        engine
            .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 1_000)
            .expect("provision ok");
        save_secure_guard_record(&mut storage, &engine).expect("save ok");
        assert!(bench_enable(&mut engine, &mut fw_log, 2_000));
        assert_eq!(engine.policy().inactivity_timeout_ms, BENCH_INACTIVITY_TIMEOUT_MS);
        assert!(bench_disable(&mut engine, &mut fw_log, 3_000));
        // RAM restaurada e a NVS jamais recebeu a policy de bancada.
        assert_eq!(engine.policy().session_duration_ms, 300_000);
        assert_eq!(engine.policy().inactivity_timeout_ms, 300_000);
        let reloaded = load_secure_guard_record(&storage, 4_000);
        assert_eq!(reloaded.policy().session_duration_ms, 300_000);
        assert_eq!(reloaded.policy().inactivity_timeout_ms, 300_000);
        assert!(reloaded.is_provisioned());
        bench_test_reset(&mut engine);
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn dispatch_ack_marca_bench_e_fwlog() {
        let _guard = BENCH_TEST_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut engine = fast_engine();
        let mut fw_log = FwLog::new();
        bench_test_reset(&mut engine);
        assert_eq!(dispatch_serial_bench_line("ruido", &mut engine, &mut fw_log, 0), None);
        assert!(fw_log.is_empty());
        let ack_on = dispatch_serial_bench_line("TEST_BENCH_ON\n", &mut engine, &mut fw_log, 1_000)
            .expect("ack on");
        assert!(ack_on.contains("BENCH"), "log marcando BENCH");
        assert!(is_bench_active());
        let ack_off = dispatch_serial_bench_line("TEST_BENCH_OFF", &mut engine, &mut fw_log, 2_000)
            .expect("ack off");
        assert!(ack_off.contains("BENCH"));
        assert!(!is_bench_active());
        assert_eq!(fw_log.len(), 2);
        let rendered = fw_log.render_ascii(512);
        let text = std::string::String::from_utf8(rendered).expect("fwlog ascii");
        assert!(text.contains("EV=19 ARG=1"), "EV_BENCH on");
        assert!(text.contains("EV=19 ARG=0"), "EV_BENCH off");
        bench_test_reset(&mut engine);
    }

    #[test]
    #[cfg(not(feature = "test-mode"))]
    fn release_nunca_ativa_bancada() {
        use aegis_fido_core::secure_guard::SecureGuardPolicy;
        let _guard = BENCH_TEST_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
        let mut fw_log = FwLog::new();
        assert!(!bench_enable(&mut engine, &mut fw_log, 0));
        assert!(!bench_disable(&mut engine, &mut fw_log, 0));
        assert!(!is_bench_active());
        assert_eq!(
            dispatch_serial_bench_line("TEST_BENCH_ON", &mut engine, &mut fw_log, 0),
            None
        );
    }
}
