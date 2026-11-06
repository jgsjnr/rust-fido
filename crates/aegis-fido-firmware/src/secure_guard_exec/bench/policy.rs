//! Policy da bancada (test-mode only): estado em RAM + enable/disable.
//!
//! Guarda a policy vigente ao ligar p/ restaurar ao desligar. NVS intacta
//! (nenhum `save` aqui). Portabilidade Xtensa LX7: estado global em
//! `std::sync::Mutex` (sem atomicas de 64 bits nesse core).

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

/// Reaplica a policy de bancada no engine passado quando a bancada esta
/// ativa (test-mode only; release = no-op).
///
/// Cobre o caso de dois engines (ex.: linha de texto vs. rota CTAPHID
/// serial): `bench_enable` estende o engine que recebeu o `TEST_BENCH_ON`,
/// mas um engine criado/recarregado depois (policy padrao 300 s, ou NVS
/// recarregada) carimbaria a sessao com 300 s no unlock. Chamar isto antes
/// do unlock/check garante que qualquer engine serial veja os 24 h em RAM.
/// Sem auditoria e sem NVS (so RAM); idempotente. Producao intacta: sem
/// `test-mode` sempre no-op.
pub fn apply_bench_policy_if_active(engine: &mut aegis_fido_core::secure_guard::SecureGuardEngine) {
    #[cfg(feature = "test-mode")]
    {
        if is_bench_active() {
            engine.policy_mut().session_duration_ms = BENCH_SESSION_DURATION_MS;
            engine.policy_mut().inactivity_timeout_ms = BENCH_INACTIVITY_TIMEOUT_MS;
        }
    }
    #[cfg(not(feature = "test-mode"))]
    {
        let _ = engine;
    }
}

/// Liga a bancada: salva a policy e estende idle + absoluta p/ 24 h em RAM.
///
/// Deve ser chamado ANTES do unlock: o `session_expires_at` e carimbado no
/// unlock com a policy vigente. NVS intacta (nenhum `save` aqui). Idempotente
/// na auditoria (repetir nao duplica `EV_BENCH`), mas sempre reaplica a
/// policy no engine passado - inclusive quando a bancada ja estava ativa
/// (cobre o segundo engine da rota CTAPHID serial, que carimbaria 300 s
/// sem isto). Retorna `true` com a bancada ativa; release sempre `false`.
pub fn bench_enable(
    engine: &mut aegis_fido_core::secure_guard::SecureGuardEngine,
    fw_log: &mut crate::fw_log::FwLog,
    now_ms: u64,
) -> bool {
    #[cfg(feature = "test-mode")]
    {
        let mut slot = BENCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !slot.active {
            slot.saved_session_ms = engine.policy().session_duration_ms;
            slot.saved_inactivity_ms = engine.policy().inactivity_timeout_ms;
            slot.have_saved = true;
            slot.active = true;
            fw_log.record(crate::fw_log::EV_BENCH, BENCH_FWLOG_ARG_ON, now_ms);
            log::info!("[BENCH] bancada ON: sessao estendida 24h em RAM (NVS intacta)");
        }
        // Sempre estende o engine passado (primeiro ou seguintes): o segundo
        // engine (rota serial) via `TEST_BENCH_ON` tardio ou pos-reload NVS
        // senao manteria 300 s e carimbaria a sessao curta.
        engine.policy_mut().session_duration_ms = BENCH_SESSION_DURATION_MS;
        engine.policy_mut().inactivity_timeout_ms = BENCH_INACTIVITY_TIMEOUT_MS;
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
pub fn bench_disable(
    engine: &mut aegis_fido_core::secure_guard::SecureGuardEngine,
    fw_log: &mut crate::fw_log::FwLog,
    now_ms: u64,
) -> bool {
    #[cfg(feature = "test-mode")]
    {
        let mut slot = BENCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.active {
            if slot.have_saved {
                engine.policy_mut().session_duration_ms = slot.saved_session_ms;
                engine.policy_mut().inactivity_timeout_ms = slot.saved_inactivity_ms;
            }
            slot.active = false;
            slot.have_saved = false;
            fw_log.record(crate::fw_log::EV_BENCH, BENCH_FWLOG_ARG_OFF, now_ms);
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
