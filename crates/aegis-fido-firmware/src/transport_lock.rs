//! Trava automatica na perda do transporte ativo (GEN-DEVICE).
//!
//! Motivo: sessao destravada sobrevivendo a remocao do canal (USB desplugado,
//! BLE desconectado/desligado, WiFi caido/quiescente) deixa chaves/PIN vivos
//! em RAM sem o portador por perto (fail-closed + sem segredo em log).
//!
//! Gatilhos: borda ativo-para-inativo por transporte (TransportMonitor), mais
//! quiescencia do WiFi (WIFI_QUIESCENCE_TIMEOUT_MS sem trafego apos a
//! ativacao). Borda nunca dispara sem o transporte ter estado ativo antes
//! (primeira observacao so arma a linha de base; sem trava espuria no boot).
//!
//! Efeito (lock_on_transport_loss): estado Locked via
//! SecureGuardEngine::on_transport_disconnect (audita TransportDisconnect
//! no anel do engine SOMENTE quando havia sessao viva), sessao pinUvAuth
//! do CTAP derrubada com scrub do token, chaves ECDH efemeras descartadas,
//! presenca/PIN do RescueEngine zeradas, flag RAM do compat
//! (set_secure_guard_unlocked(false)) e evento EV_TRANSPORT_LOCK no
//! FwLog (so transporte + tempo, sem PII/segredo).
//!
//! Proibicoes: SEM wipe, SEM erase/apagamento de NVS, SEM eFuse, SEM mudar
//! o PIN (verificador, retries e provisionamento intactos: so RAM de
//! sessao e tocada). Persistencia NVS NAO e escrita aqui: a trava e de RAM;
//! o proximo boot recarrega o registro integro.
//!
//! no_std compativel: so core (+ zeroize para o scrub); Debug nunca
//! expoe token, PIN ou chave (so contadores/flags).
//!
//! Fiacao (run loops, run::common): USB observa aegis_usb_is_mounted por
//! tick; BLE arma em BLE_EVT_CONNECTED e derruba em BLE_EVT_DISCONNECTED;
//! WiFi observa ap_ativo/station_up por tick (+ poll p/ quiescencia; o
//! note_wifi_traffic e o gancho p/ o futuro hook do HTTP: sem trafego
//! anotado, so a borda ativo-para-inativo (que ja inclui o timeout da
//! station) trava, sem falso-positivo).

use aegis_fido_core::ctap::client_pin::ClientPinState;
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::secure_guard::SecureGuardEngine;
use zeroize::Zeroize;

use crate::fw_log::{FwLog, EV_TRANSPORT_LOCK};

/// Transporte que carregava a sessao no momento da perda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// USB HID nativo (TinyUSB) desplugado/suspenso.
    UsbHid,
    /// BLE desconectado ou radio desligado com enlace antes ativo.
    Ble,
    /// WiFi caido (AP parado / station down por timeout) ou quiescente.
    Wifi,
}

impl TransportKind {
    /// Argumento opaco do EV_TRANSPORT_LOCK no FwLog (so o canal, sem PII).
    pub fn fw_log_arg(self) -> u8 {
        match self {
            Self::UsbHid => 0x01,
            Self::Ble => 0x02,
            Self::Wifi => 0x03,
        }
    }

    /// Rotulo estavel p/ log textual (sem segredo, so o canal).
    pub fn name(self) -> &'static str {
        match self {
            Self::UsbHid => "usb_hid",
            Self::Ble => "ble",
            Self::Wifi => "wifi",
        }
    }
}

/// WiFi ativo sem trafego anotado por este tempo = perda (quiescencia).
///
/// So vale apos ativacao + ao menos um note_wifi_traffic: sem trafego jamais
/// anotado, poll nunca dispara (sem trava espuria; a borda ativo-para-inativo,
/// que ja inclui o timeout da station, segue travando sozinha).
pub const WIFI_QUIESCENCE_TIMEOUT_MS: u64 = 30_000;

/// Borda ativo-para-inativo por transporte (RAM do loop; sem NVS, sem relogio).
///
/// Estado inicial tudo-inativo: a primeira observacao so arma a linha de base
/// (nunca trava no boot). Cada transporte trava no MAXIMO uma vez por
/// ativacao (re-arme exige voltar a ativo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportMonitor {
    usb_mounted: bool,
    ble_connected: bool,
    wifi_active: bool,
    last_wifi_activity_ms: Option<u64>,
}

impl TransportMonitor {
    /// Monitor zerado (nada ativo; primeira observacao arma, nao trava).
    pub fn new() -> Self {
        Self {
            usb_mounted: false,
            ble_connected: false,
            wifi_active: false,
            last_wifi_activity_ms: None,
        }
    }

    /// Observa o USB montado; Some(UsbHid) SO na borda ativo-para-inativo.
    pub fn observe_usb(&mut self, mounted: bool) -> Option<TransportKind> {
        let was = self.usb_mounted;
        self.usb_mounted = mounted;
        if was && !mounted {
            Some(TransportKind::UsbHid)
        } else {
            None
        }
    }

    /// Observa o enlace BLE; Some(Ble) SO na borda conectado-para-desconectado.
    ///
    /// Chamar com true em BLE_EVT_CONNECTED e false em BLE_EVT_DISCONNECTED
    /// (radio desligado apos enlace ativo chega aqui como desconexao do
    /// stack; sem enlace previo nunca dispara).
    pub fn observe_ble(&mut self, connected: bool) -> Option<TransportKind> {
        let was = self.ble_connected;
        self.ble_connected = connected;
        if was && !connected {
            Some(TransportKind::Ble)
        } else {
            None
        }
    }

    /// Observa o WiFi ativo (ap_ativo ou station_up); borda ativo-para-inativo
    /// trava (inclui queda por timeout da station). Subida re-arma a
    /// quiescencia com now_ms como atividade inicial.
    ///
    /// Bancada (bench-aware): delega para `observe_wifi_with_bench` com a
    /// flag global de bancada (`test-mode`); em release a flag e sempre
    /// `false`. Com bancada ativa a borda WiFi e suprimida (retorna None,
    /// sem trava): o WiFi da placa cai sozinho a cada ~100 s e a bancada
    /// usa USB/UART. USB (`observe_usb`) e BLE (`observe_ble`) seguem
    /// travando com ou sem bancada.
    pub fn observe_wifi(&mut self, active: bool, now_ms: u64) -> Option<TransportKind> {
        #[cfg(feature = "test-mode")]
        let bench = crate::secure_guard_exec::bench::policy::is_bench_active();
        #[cfg(not(feature = "test-mode"))]
        let bench = false;
        self.observe_wifi_with_bench(active, now_ms, bench)
    }

    /// Nucleo testavel da borda WiFi com a flag de bancada explicita.
    ///
    /// Com `bench_active = true` a borda ativo-para-inativo atualiza o
    /// estado (cai p/ inativo, limpa a atividade) mas retorna None: sem
    /// trava, sem EV_TRANSPORT_LOCK. Com `false` vale o comportamento
    /// legado (borda trava). USB/BLE nao passam por aqui e travam com ou
    /// sem bancada; producao (release) sempre usa `false`.
    pub fn observe_wifi_with_bench(
        &mut self,
        active: bool,
        now_ms: u64,
        bench_active: bool,
    ) -> Option<TransportKind> {
        let was = self.wifi_active;
        self.wifi_active = active;
        if active {
            if !was {
                // Subida: re-arme; sem isto um poll imediato usaria lixo.
                self.last_wifi_activity_ms = Some(now_ms);
            }
            None
        } else {
            self.last_wifi_activity_ms = None;
            if was && !bench_active {
                Some(TransportKind::Wifi)
            } else {
                None
            }
        }
    }

    /// Anota trafego WiFi legitimo (gancho p/ o futuro hook do HTTP/front).
    pub fn note_wifi_traffic(&mut self, now_ms: u64) {
        if self.wifi_active {
            self.last_wifi_activity_ms = Some(now_ms);
        }
    }

    /// Quiescencia: WiFi ativo + silencio >= timeout = perda (dispara uma vez;
    /// o transporte cai p/ inativo ate a proxima subida/atividade).
    ///
    /// Bancada (bench-aware): delega para `poll_with_bench` com a flag global
    /// de bancada (`test-mode`); em release a flag e sempre `false`.
    pub fn poll(&mut self, now_ms: u64) -> Option<TransportKind> {
        #[cfg(feature = "test-mode")]
        let bench = crate::secure_guard_exec::bench::policy::is_bench_active();
        #[cfg(not(feature = "test-mode"))]
        let bench = false;
        self.poll_with_bench(now_ms, bench)
    }

    /// Nucleo testavel da quiescencia com a flag de bancada explicita.
    ///
    /// Com `bench_active = true` o silencio tolerado estende para
    /// `BENCH_INACTIVITY_TIMEOUT_MS` (24 h, mesma janela da sessao de
    /// bancada); com `false` vale `WIFI_QUIESCENCE_TIMEOUT_MS`. Bordas
    /// duro USB/BLE (`observe_usb`/`observe_ble`) travam com ou sem
    /// bancada; a borda WiFi com bancada e suprimida em
    /// `observe_wifi_with_bench` (placa cai sozinha; bancada usa USB/UART).
    pub fn poll_with_bench(&mut self, now_ms: u64, bench_active: bool) -> Option<TransportKind> {
        if !self.wifi_active {
            return None;
        }
        let timeout_ms = if bench_active {
            crate::secure_guard_exec::bench::policy::BENCH_INACTIVITY_TIMEOUT_MS
        } else {
            WIFI_QUIESCENCE_TIMEOUT_MS
        };
        match self.last_wifi_activity_ms {
            Some(last) if now_ms.saturating_sub(last) >= timeout_ms => {
                self.wifi_active = false;
                self.last_wifi_activity_ms = None;
                Some(TransportKind::Wifi)
            }
            _ => None,
        }
    }
}

impl Default for TransportMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Resultado auditavel da trava (so flags; nenhum segredo viaja aqui).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLockReport {
    /// Transporte cuja perda causou a trava.
    pub kind: TransportKind,
    /// true quando havia sessao viva (SecureGuard desbloqueado OU sessao
    /// pinUvAuth presente OU presenca/PIN do rescue ativos).
    pub session_was_live: bool,
    /// Estado do SecureGuard apos a chamada (true = Locked agora).
    pub secure_guard_locked_now: bool,
    /// true quando havia sessao pinUvAuth/chave efemera p/ limpar.
    pub pin_session_cleared: bool,
}

/// Trava a sessao na perda do transporte ativo.
///
/// Efeito total em RAM (sem NVS, sem wipe, sem eFuse, sem mudar o PIN):
/// 1. engine.on_transport_disconnect (audita TransportDisconnect no anel
///    do engine SOMENTE se estava desbloqueado; ja-Locked e no-op);
/// 2. sessao pinUvAuth do CTAP: token com scrub + None, ECDH efemero e
///    acordo descartados (verificador/retries do PIN intactos);
/// 3. RescueEngine: presenca e pin_uv zerados;
/// 4. cada fatia de scratch com scrub (buffers transitorios do chamador);
/// 5. flag RAM do compat (set_secure_guard_unlocked(false));
/// 6. FwLog::EV_TRANSPORT_LOCK com o canal (sem PII/segredo).
///
/// O chamador persiste NVS se/quando quiser: aqui NADA e escrito no flash.
pub fn lock_on_transport_loss(
    engine: &mut SecureGuardEngine,
    pin_state: &mut ClientPinState,
    rescue: &mut RescueEngine,
    scratch: &mut [&mut [u8]],
    fw_log: &mut FwLog,
    kind: TransportKind,
    now_ms: u64,
) -> TransportLockReport {
    let session_was_live = engine.is_unlocked()
        || pin_state.has_valid_pin_uv_session()
        || rescue.pin_uv_authenticated
        || rescue.user_presence_confirmed;
    let had_pin_session = pin_state.active_session.is_some() || pin_state.ephemeral_key.is_some();

    // 1. Engine: transicao p/ Locked + auditoria (no-op se ja Locked).
    let _ = engine.on_transport_disconnect(now_ms);

    // 2. CTAP pinUvAuth em RAM: scrub do token e descarte (PIN preservado:
    //    pin_hash, retries e politica NAO sao tocados).
    if let Some(mut session) = pin_state.active_session.take() {
        session.token.zeroize();
    }
    pin_state.ephemeral_key = None;
    pin_state.key_agreement = None;

    // 3. Rescue: presenca e PIN espelhados caem junto com o transporte.
    rescue.set_user_presence(false);
    rescue.set_pin_uv_authenticated(false);

    // 4. Buffers transitorios do chamador.
    for buf in scratch.iter_mut() {
        buf.zeroize();
    }

    // 5. Flag RAM do compat HMAC (sessao SecureGuard p/ o Challenge-Response).
    crate::hmac_cr_compat_layer::set_secure_guard_unlocked(false);

    // 6. Auditoria do device (so canal + tempo).
    fw_log.record(EV_TRANSPORT_LOCK, kind.fw_log_arg(), now_ms);

    TransportLockReport {
        kind,
        session_was_live,
        secure_guard_locked_now: !engine.is_unlocked(),
        pin_session_cleared: had_pin_session,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use aegis_fido_core::ctap::client_pin::PinUvTokenSession;
    use aegis_fido_core::secure_guard::{
        SecureGuardAuditEventType, SecureGuardPolicy, SecureGuardState, SessionExpiryReason,
    };

    fn provisioned_unlocked_engine() -> SecureGuardEngine {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        engine
            .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 0)
            .expect("provision ok");
        engine.unlock_with_pin(b"7391", 100).expect("unlock ok");
        assert!(engine.is_unlocked());
        engine
    }

    fn live_pin_state() -> ClientPinState {
        ClientPinState {
            pin_hash: Some([0x5A; 16]),
            active_session: Some(PinUvTokenSession {
                token: [0xAA; 32],
                protocol: 2,
                permissions: 0xFFFF_FFFF,
                rp_id: None,
            }),
            ..Default::default()
        }
    }

    fn live_rescue() -> RescueEngine {
        let mut rescue = RescueEngine::new();
        rescue.set_user_presence(true);
        rescue.set_pin_uv_authenticated(true);
        rescue
    }

    #[test]
    fn usb_loss_locks_clears_ram_and_audits() {
        let mut engine = provisioned_unlocked_engine();
        let mut pin = live_pin_state();
        let mut rescue = live_rescue();
        let mut fw_log = FwLog::new();
        let mut scratch = [0xAAu8; 24];
        let audit_before = engine.audit_log().len();

        let report = lock_on_transport_loss(
            &mut engine,
            &mut pin,
            &mut rescue,
            &mut [&mut scratch[..]],
            &mut fw_log,
            TransportKind::UsbHid,
            1_000,
        );

        assert_eq!(report.kind, TransportKind::UsbHid);
        assert!(report.session_was_live);
        assert!(report.pin_session_cleared);
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert!(report.secure_guard_locked_now);
        // Sessao CTAP derrubada (sem token residual p/ reler).
        assert!(!pin.has_valid_pin_uv_session());
        assert!(pin.ephemeral_key.is_none());
        assert!(pin.key_agreement.is_none());
        // Rescue zerado.
        assert!(!rescue.user_presence_confirmed);
        assert!(!rescue.pin_uv_authenticated);
        // Scratch com scrub.
        assert!(scratch.iter().all(|&b| b == 0));
        // Compat flag derrubada.
        assert!(!crate::hmac_cr_compat_layer::is_secure_guard_unlocked());
        // Auditoria: engine registra TransportDisconnect; fw-log o evento.
        assert!(engine.audit_log().len() > audit_before);
        assert!(
            matches!(
                engine.audit_log().last().map(|e| &e.event_type),
                Some(SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::TransportDisconnect
                })
            ),
            "ultimo evento do engine deve ser TransportDisconnect"
        );
        assert_eq!(fw_log.len(), 1);
    }

    #[test]
    fn pin_verifier_retries_and_provision_survive_lock() {
        let mut engine = provisioned_unlocked_engine();
        let mut pin = live_pin_state();
        pin.pin_retries = 5;
        let mut rescue = live_rescue();
        let mut fw_log = FwLog::new();
        let mut empty: [&mut [u8]; 0] = [];

        lock_on_transport_loss(
            &mut engine,
            &mut pin,
            &mut rescue,
            &mut empty,
            &mut fw_log,
            TransportKind::Ble,
            2_000,
        );

        // SEM wipe / SEM NVS-erase / SEM troca de PIN: tudo preservado.
        assert!(engine.is_provisioned());
        assert_eq!(engine.failed_attempts(), 0);
        assert_eq!(pin.pin_hash, Some([0x5A; 16]));
        assert_eq!(pin.pin_retries, 5);
        assert_eq!(engine.state(), SecureGuardState::Locked);
    }

    #[test]
    fn already_locked_is_idempotent_no_engine_audit_spam() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        engine
            .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 0)
            .expect("provision ok");
        assert!(!engine.is_unlocked());
        let mut pin = ClientPinState::default();
        let mut rescue = RescueEngine::new();
        let mut fw_log = FwLog::new();
        let mut empty: [&mut [u8]; 0] = [];
        let audit_before = engine.audit_log().len();

        let report = lock_on_transport_loss(
            &mut engine,
            &mut pin,
            &mut rescue,
            &mut empty,
            &mut fw_log,
            TransportKind::Wifi,
            3_000,
        );

        assert!(!report.session_was_live);
        assert!(!report.pin_session_cleared);
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert!(report.secure_guard_locked_now);
        // Engine ja Locked: sem evento novo la; o fw-log registra a perda.
        assert_eq!(engine.audit_log().len(), audit_before);
        assert_eq!(fw_log.len(), 1);
    }

    #[test]
    fn monitor_usb_edge_only_from_active() {
        let mut mon = TransportMonitor::new();
        // Linha de base: nunca trava sem estar ativo (boot seguro).
        assert_eq!(mon.observe_usb(false), None);
        assert_eq!(mon.observe_usb(true), None);
        assert_eq!(mon.observe_usb(true), None);
        assert_eq!(mon.observe_usb(false), Some(TransportKind::UsbHid));
        // Dispara uma vez por ativacao.
        assert_eq!(mon.observe_usb(false), None);
    }

    #[test]
    fn monitor_ble_needs_prior_connection() {
        let mut mon = TransportMonitor::new();
        assert_eq!(mon.observe_ble(false), None);
        assert_eq!(mon.observe_ble(true), None);
        assert_eq!(mon.observe_ble(false), Some(TransportKind::Ble));
        assert_eq!(mon.observe_ble(false), None);
    }

    #[test]
    fn monitor_wifi_edge_and_quiescence() {
        // Flag de bancada explicita `false` (= producao): deterministico
        // mesmo sob `test-mode` com outro teste de bancada em paralelo.
        let mut mon = TransportMonitor::new();
        assert_eq!(mon.observe_wifi_with_bench(false, 0, false), None);
        assert_eq!(mon.observe_wifi_with_bench(true, 1_000, false), None);
        mon.note_wifi_traffic(2_000);
        // Antes do timeout: nada.
        assert_eq!(
            mon.poll_with_bench(2_000 + WIFI_QUIESCENCE_TIMEOUT_MS - 1, false),
            None
        );
        // Quiescencia: trava uma vez.
        assert_eq!(
            mon.poll_with_bench(2_000 + WIFI_QUIESCENCE_TIMEOUT_MS, false),
            Some(TransportKind::Wifi)
        );
        assert_eq!(
            mon.poll_with_bench(2_000 + WIFI_QUIESCENCE_TIMEOUT_MS + 1, false),
            None
        );
        // Sem trafego jamais anotado apos ativacao: a subida ancora o relogio.
        let mut mon2 = TransportMonitor::new();
        assert_eq!(mon2.observe_wifi_with_bench(true, 5_000, false), None);
        assert_eq!(
            mon2.poll_with_bench(5_000 + WIFI_QUIESCENCE_TIMEOUT_MS - 1, false),
            None
        );
        assert_eq!(
            mon2.poll_with_bench(5_000 + WIFI_QUIESCENCE_TIMEOUT_MS, false),
            Some(TransportKind::Wifi)
        );
        // Borda ativo-para-inativo (timeout da station) trava direto.
        let mut mon3 = TransportMonitor::new();
        assert_eq!(mon3.observe_wifi_with_bench(true, 0, false), None);
        assert_eq!(
            mon3.observe_wifi_with_bench(false, 500, false),
            Some(TransportKind::Wifi)
        );
        assert_eq!(mon3.observe_wifi_with_bench(false, 600, false), None);
    }

    #[test]
    fn poll_with_bench_estende_quiescencia_para_24h() {
        let mut mon = TransportMonitor::new();
        assert_eq!(mon.observe_wifi(true, 1_000), None);
        mon.note_wifi_traffic(2_000);
        // Timeout normal (30 s) com bancada ativa: nada (janela estendida).
        assert_eq!(
            mon.poll_with_bench(2_000 + WIFI_QUIESCENCE_TIMEOUT_MS, true),
            None
        );
        let bench_timeout_ms = crate::secure_guard_exec::bench::policy::BENCH_INACTIVITY_TIMEOUT_MS;
        assert_eq!(
            mon.poll_with_bench(2_000 + bench_timeout_ms - 1, true),
            None
        );
        // Quiescencia de bancada: trava uma vez na janela de 24 h.
        assert_eq!(
            mon.poll_with_bench(2_000 + bench_timeout_ms, true),
            Some(TransportKind::Wifi)
        );
        assert_eq!(
            mon.poll_with_bench(2_000 + bench_timeout_ms + 1, true),
            None
        );
    }

    #[test]
    fn wifi_edge_suprimida_com_bancada_usb_ble_intactos() {
        // Com bancada ativa a borda dura WiFi NAO trava (o WiFi da placa
        // cai sozinho a cada ~100 s; bancada usa USB/UART): o estado cai
        // p/ inativo mas retorna None, sem EV_TRANSPORT_LOCK. Sem bancada
        // (producao) a borda trava como antes; USB/BLE travam com ou sem
        // bancada (so o WiFi e suprimido).
        let mut mon = TransportMonitor::new();
        assert_eq!(mon.observe_wifi_with_bench(true, 0, true), None);
        mon.note_wifi_traffic(100);
        assert_eq!(
            mon.poll_with_bench(100 + WIFI_QUIESCENCE_TIMEOUT_MS, true),
            None
        );
        // Borda com bancada: suprimida, e o estado cai p/ inativo.
        assert_eq!(mon.observe_wifi_with_bench(false, 500, true), None);
        assert_eq!(mon.observe_wifi_with_bench(false, 600, true), None);
        // Sem bancada: borda trava (producao intacta).
        let mut mon2 = TransportMonitor::new();
        assert_eq!(mon2.observe_wifi_with_bench(true, 0, false), None);
        assert_eq!(
            mon2.observe_wifi_with_bench(false, 500, false),
            Some(TransportKind::Wifi)
        );
        assert_eq!(mon2.observe_wifi_with_bench(false, 600, false), None);
        // USB/BLE com bancada: seguem travando (fora do caminho WiFi).
        let mut mon3 = TransportMonitor::new();
        assert_eq!(mon3.observe_usb(true), None);
        assert_eq!(mon3.observe_usb(false), Some(TransportKind::UsbHid));
        assert_eq!(mon3.observe_ble(true), None);
        assert_eq!(mon3.observe_ble(false), Some(TransportKind::Ble));
        // Quiescencia com flag off == comportamento legado do `poll`.
        let mut mon4 = TransportMonitor::new();
        assert_eq!(mon4.observe_wifi_with_bench(true, 1_000, false), None);
        mon4.note_wifi_traffic(2_000);
        assert_eq!(
            mon4.poll_with_bench(2_000 + WIFI_QUIESCENCE_TIMEOUT_MS - 1, false),
            None
        );
        assert_eq!(
            mon4.poll_with_bench(2_000 + WIFI_QUIESCENCE_TIMEOUT_MS, false),
            Some(TransportKind::Wifi)
        );
    }

    #[test]
    fn full_loss_sequence_usb_then_ble_then_wifi() {
        // Cada perda com sessao viva trava de novo sem erro (idempotente e
        // sempre Locked ao fim, sem tocar no PIN).
        for kind in [
            TransportKind::UsbHid,
            TransportKind::Ble,
            TransportKind::Wifi,
        ] {
            let mut engine = provisioned_unlocked_engine();
            let mut pin = live_pin_state();
            let mut rescue = live_rescue();
            let mut fw_log = FwLog::new();
            let mut empty: [&mut [u8]; 0] = [];
            let report = lock_on_transport_loss(
                &mut engine,
                &mut pin,
                &mut rescue,
                &mut empty,
                &mut fw_log,
                kind,
                9_000,
            );
            assert_eq!(report.kind, kind);
            assert!(report.session_was_live);
            assert_eq!(engine.state(), SecureGuardState::Locked);
            assert!(!pin.has_valid_pin_uv_session());
            assert_eq!(pin.pin_hash, Some([0x5A; 16]));
            assert!(engine.is_provisioned());
        }
    }

    #[test]
    fn kind_codes_and_names_are_stable_no_secrets() {
        assert_eq!(TransportKind::UsbHid.fw_log_arg(), 0x01);
        assert_eq!(TransportKind::Ble.fw_log_arg(), 0x02);
        assert_eq!(TransportKind::Wifi.fw_log_arg(), 0x03);
        assert_eq!(TransportKind::UsbHid.name(), "usb_hid");
        assert_eq!(TransportKind::Ble.name(), "ble");
        assert_eq!(TransportKind::Wifi.name(), "wifi");
        let dbg = format!(
            "{:?}",
            TransportLockReport {
                kind: TransportKind::UsbHid,
                session_was_live: true,
                secure_guard_locked_now: true,
                pin_session_cleared: true,
            }
        );
        assert!(dbg.contains("UsbHid"));
        assert!(!dbg.contains("aa"));
    }

    #[test]
    fn debug_never_carries_session_bytes() {
        // O monitor e o report so carregam flags/transporte.
        let mon = TransportMonitor::new();
        let dbg = format!("{mon:?}");
        assert!(dbg.contains("TransportMonitor"));
        let report = TransportLockReport {
            kind: TransportKind::Ble,
            session_was_live: false,
            secure_guard_locked_now: true,
            pin_session_cleared: false,
        };
        let dbg = format!("{report:?}");
        assert!(!dbg.contains("token"));
    }
}
