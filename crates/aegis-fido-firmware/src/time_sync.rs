//! TOTP sem bateria: fonte de tempo via SNTP + ancora NVS (fail-closed).
//!
//! Sem RTC com bateria, o device nao tem relogio de parede no boot. Este
//! modulo resolve `TotpClock` (ver `totp.rs`) a partir de duas fontes, sem
//! inventar tempo e sem deps novas (so `core`, NVS via `SecureStorage` e, no
//! device, `std::net` UDP para SNTP):
//!
//! 1. SNTP quando a rede esta up (station conectada, ver `poll_time_sync`):
//!    pacote de 48 B (RFC 5905) com `build_ntp_request`, resposta validada
//!    por `parse_ntp_response` (modo servidor, VN>=3, stratum 1..=15,
//!    transmit != 0, faixa sania). Erro de rede/DNS/resposta = `Failed`,
//!    nunca tempo fabricado; no host, `Unsupported` sem tocar em socket.
//! 2. Ancora NVS (`totp_time`, envelope AES-GCM): par
//!    `(unix_secs, mono_ms)` salvo em TODO sync valido e recarregado no boot.
//!   
//! `resolve_clock(mono_ms) = max(ancora.unix + (mono - ancora.mono)/1000,
//! ancora.unix)`: o `max()` trava regressao do monotonico no ultimo valor
//! bem conhecido. `rtc_trusted = true` SOMENTE com ancora sania (piso
//! 2024-01-01, teto = fim da era NTP 2036); sem SNTP fresco nem ancora
//! confiavel, `rtc_trusted = false` e o TOTP nega (fail-closed, ver
//! `totp_code`).
//!
//! Sobrevive ao reboot sem bateria: a ancora persiste; o relogio retoma do
//! ultimo valor conhecido + tempo ligado. LIMITACAO RESIDUAL documentada:
//! o relogio PARA durante o power-off (downtime desconhecido) e o cristal
//! deriva entre syncs (~20 ppm tipico); codigos podem divergir do servidor
//! ate o proximo SNTP valido. A ancora nunca anda para tras.
//!
//! Contrato p/ consumidores: chamar `resolve_clock()` e respeitar
//! `rtc_trusted` (negar em vez de emitir codigo de janela errada). Fiar a
//! ancora nos handlers OATH/HTTP existentes (que hoje recebem `unix_secs`
//! explicito) eh follow-up; este modulo + `poll_time_sync` ja proveem
//! sync + persistencia + resolucao.
//!
//! Cadencia: primeira sync na primeira janela com rede (retry 60 s reaproveita
//! `sta_retry_due`, sem segunda politica); depois, refresh a cada 1 h.
//! `no_std` compativel (`core` apenas; `std::net` so no sync do device).

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
use crate::totp::TotpClock;
use crate::wifi_station::sta_retry_due;

/// `kprintln!` local: mesmo caminho de log que `run::kprintln` usa
/// (`StaticBuf` sem alloc -> `esp_rom_printf` no device, `println!` no host).
///
/// `run::kprintln` e um `macro_rules!` textual escopado ao modulo `run` (os
/// filhos o enxergam, mas `crate::kprintln!` nao resolve fora dele); este
/// espelho local mantem o texto das mensagens e os gates `cfg` identicos.
///
/// So existe onde e usada (device): os 3 pontos de chamada vivem num bloco
/// `cfg(target_os = "espidf")`, entao o gate identico evita macro morta no host.
#[cfg(target_os = "espidf")]
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

/// Tamanho do pacote NTP (RFC 5905, cabecalho 48 B).
pub const NTP_PACKET_LEN: usize = 48;
/// Porta UDP do SNTP.
pub const NTP_PORT: u16 = 123;
/// Segundos entre 1900-01-01 (era NTP) e 1970-01-01 (era Unix).
pub const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;
/// Fim da era NTP de 32 bits (2036-02-07): teto sanio p/ amostra SNTP.
pub const TIME_MAX_SANE_UNIX_SECS: u64 = 2_085_978_495;
/// Piso sanio (2024-01-01T00:00:00Z): abaixo disso a amostra e lixo.
pub const TIME_MIN_SANE_UNIX_SECS: u64 = 1_704_067_200;
/// Chave NVS da ancora (envelope AES-GCM; par unix u64BE + mono u64BE).
pub const TIME_ANCHOR_NVS_KEY: &str = "totp_time";
/// Servidor SNTP padrao (DNS da station; erro = retry, nunca chute).
pub const DEFAULT_SNTP_SERVER: &str = "pool.ntp.org";
/// Refresh periodico com rede up (deriva do cristal << janela de 30 s).
pub const TIME_SYNC_REFRESH_MS: u64 = 3_600_000;

/// Erro tipado do sync (sem panics; sem tempo fabricado).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SntpError {
    /// DNS/apelido sem resposta.
    Resolve,
    /// Socket UDP indisponivel.
    Net,
    /// Resposta fora do formato/validacao.
    BadResponse,
    /// Host/sem hardware: sync indisponivel (fail-closed, nunca finge).
    Unsupported,
}

impl core::fmt::Display for SntpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resolve => write!(f, "sntp dns resolve failed"),
            Self::Net => write!(f, "sntp socket unavailable"),
            Self::BadResponse => write!(f, "sntp bad response"),
            Self::Unsupported => write!(f, "sntp unsupported (no radio)"),
        }
    }
}

/// Requisicao SNTP: LI=0, VN=4, Mode=3 (cliente), resto zero.
pub fn build_ntp_request() -> [u8; NTP_PACKET_LEN] {
    let mut pkt = [0u8; NTP_PACKET_LEN];
    pkt[0] = 0x23;
    pkt
}

/// Valida resposta SNTP e extrai Unix secs (`None` = rejeita).
///
/// Checa: >= 48 B, modo servidor (4), VN >= 3, stratum 1..=15 (0 =
/// kiss/unsynced, 16 = unsynced), transmit != 0 e conversivel (>= 1970).
pub fn parse_ntp_response(pkt: &[u8]) -> Option<u64> {
    if pkt.len() < NTP_PACKET_LEN {
        return None;
    }
    if pkt[0] & 0x07 != 4 {
        return None;
    }
    if (pkt[0] >> 3) & 0x07 < 3 {
        return None;
    }
    if pkt[1] == 0 || pkt[1] > 15 {
        return None;
    }
    let tx = u32::from_be_bytes([pkt[40], pkt[41], pkt[42], pkt[43]]);
    if tx == 0 {
        return None;
    }
    (tx as u64).checked_sub(NTP_UNIX_EPOCH_OFFSET_SECS)
}

/// Estado da fonte de tempo (RAM; a ancora persiste em NVS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncState {
    anchor_unix_secs: u64,
    anchor_mono_ms: u64,
    has_anchor: bool,
    last_sync_mono_ms: Option<u64>,
}

impl TimeSyncState {
    /// Sem ancora (boot sem NVS ou NVS corrompida: fail-closed).
    pub fn new() -> Self {
        Self {
            anchor_unix_secs: 0,
            anchor_mono_ms: 0,
            has_anchor: false,
            last_sync_mono_ms: None,
        }
    }

    /// Carrega a ancora da NVS; ausente/corrompida/fora da faixa = sem
    /// confianca (nunca confia em lixo).
    pub fn load<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> Self {
        let mut st = Self::new();
        if let Ok(blob) = storage.load(TIME_ANCHOR_NVS_KEY) {
            if let Some((unix, mono)) = decode_anchor(&blob) {
                if (TIME_MIN_SANE_UNIX_SECS..=TIME_MAX_SANE_UNIX_SECS).contains(&unix) {
                    st.anchor_unix_secs = unix;
                    st.anchor_mono_ms = mono;
                    st.has_anchor = true;
                }
            }
        }
        st
    }

    /// Registra sync valido (faixa sania); fora da faixa = rejeita (`false`).
    pub fn note_sync(&mut self, unix_secs: u64, mono_ms: u64) -> bool {
        if !(TIME_MIN_SANE_UNIX_SECS..=TIME_MAX_SANE_UNIX_SECS).contains(&unix_secs) {
            return false;
        }
        self.anchor_unix_secs = unix_secs;
        self.anchor_mono_ms = mono_ms;
        self.has_anchor = true;
        self.last_sync_mono_ms = Some(mono_ms);
        true
    }

    /// Persiste a ancora (todo sync valido; sem ancora = no-op).
    pub fn save<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
    ) -> Result<(), StorageError> {
        if !self.has_anchor {
            return Ok(());
        }
        let blob = encode_anchor(self.anchor_unix_secs, self.anchor_mono_ms);
        storage.store(TIME_ANCHOR_NVS_KEY, &blob, &[0u8; 12])
    }

    /// `true` com ancora sania (SNTP fresco ou persistida valida).
    pub fn is_trusted(&self) -> bool {
        self.has_anchor
    }

    /// Resolve `TotpClock`: `max(ancora + decorrido, ancora)`; sem ancora,
    /// `rtc_trusted = false` (o TOTP nega em vez de chutar janela).
    pub fn resolve_clock(&self, mono_ms: u64) -> TotpClock {
        if !self.has_anchor {
            return TotpClock {
                now_unix_secs: 0,
                rtc_trusted: false,
            };
        }
        let elapsed_secs = mono_ms.saturating_sub(self.anchor_mono_ms) / 1000;
        let derived = self.anchor_unix_secs.saturating_add(elapsed_secs);
        TotpClock {
            now_unix_secs: derived.max(self.anchor_unix_secs),
            rtc_trusted: true,
        }
    }
}

impl Default for TimeSyncState {
    fn default() -> Self {
        Self::new()
    }
}

/// Codifica a ancora (unix u64BE + mono u64BE).
fn encode_anchor(unix_secs: u64, mono_ms: u64) -> [u8; 16] {
    let mut blob = [0u8; 16];
    blob[..8].copy_from_slice(&unix_secs.to_be_bytes());
    blob[8..].copy_from_slice(&mono_ms.to_be_bytes());
    blob
}

/// Decodifica a ancora (`None` = tamanho invalido).
fn decode_anchor(blob: &[u8]) -> Option<(u64, u64)> {
    if blob.len() != 16 {
        return None;
    }
    let mut unix_b = [0u8; 8];
    let mut mono_b = [0u8; 8];
    unix_b.copy_from_slice(&blob[..8]);
    mono_b.copy_from_slice(&blob[8..]);
    Some((u64::from_be_bytes(unix_b), u64::from_be_bytes(mono_b)))
}

/// Sync SNTP real (device, UDP; DNS da station). Sem rede/DNS/resposta,
/// `Err` (nunca tempo fabricado).
#[cfg(target_os = "espidf")]
pub fn sntp_sync_once(server: &str) -> Result<u64, SntpError> {
    use std::net::{ToSocketAddrs, UdpSocket};
    use std::time::Duration;
    let req = build_ntp_request();
    let addr = (server, NTP_PORT)
        .to_socket_addrs()
        .map_err(|_| SntpError::Resolve)?
        .next()
        .ok_or(SntpError::Resolve)?;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|_| SntpError::Net)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| SntpError::Net)?;
    sock.send_to(&req, addr).map_err(|_| SntpError::Net)?;
    let mut buf = [0u8; 64];
    let (n, _) = sock.recv_from(&mut buf).map_err(|_| SntpError::Net)?;
    parse_ntp_response(&buf[..n]).ok_or(SntpError::BadResponse)
}

/// Host/sem radio: sync indisponivel (fail-closed, sem socket).
#[cfg(not(target_os = "espidf"))]
pub fn sntp_sync_once(_server: &str) -> Result<u64, SntpError> {
    Err(SntpError::Unsupported)
}

/// Resultado do poll periodico (chamado pelos run loops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSyncPoll {
    /// Sem rede, sem refresh devido ou sem retry devido.
    NotDue,
    /// Host/sem radio: tentativa pulada sem tocar em socket.
    SkippedUnsupported,
    /// Sync valido, ancorado e persistido (valor = unix_secs).
    Synced(u64),
    /// Tentativa feita sem resposta valida (retry em 60 s).
    Failed,
}

/// Poll da fonte de tempo (run loops, apos o poll da station).
///
/// - So tenta com station up; refresh 1 h apos sync, retry 60 s apos falha
///   (reaproveita `sta_retry_due`, sem segunda politica).
/// - Sucesso: ancora + persiste NVS imediatamente.
/// - Host: nunca abre socket (`SkippedUnsupported`, estado intacto).
pub fn poll_time_sync<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    state: &mut TimeSyncState,
    sta_up: bool,
    now_ms: u64,
    last_attempt_ms: &mut Option<u64>,
) -> TimeSyncPoll {
    if !sta_up {
        return TimeSyncPoll::NotDue;
    }
    if let Some(last) = state.last_sync_mono_ms {
        if now_ms.saturating_sub(last) < TIME_SYNC_REFRESH_MS {
            return TimeSyncPoll::NotDue;
        }
    }
    if !sta_retry_due(now_ms, *last_attempt_ms) {
        return TimeSyncPoll::NotDue;
    }
    *last_attempt_ms = Some(now_ms);
    #[cfg(target_os = "espidf")]
    {
        match sntp_sync_once(DEFAULT_SNTP_SERVER) {
            Ok(unix) => {
                if state.note_sync(unix, now_ms) {
                    let _ = state.save(storage);
                    kprintln!("[TIME] SNTP sync unix={} (ancora NVS).", unix);
                    return TimeSyncPoll::Synced(unix);
                }
                kprintln!("[TIME] SNTP fora da faixa (ignorado).");
                TimeSyncPoll::Failed
            }
            Err(_) => {
                kprintln!("[TIME] SNTP falhou (retry 60s).");
                TimeSyncPoll::Failed
            }
        }
    }
    #[cfg(not(target_os = "espidf"))]
    {
        // Sem radio no host: sem socket, sem escrita; so registra a tentativa.
        let _ = &storage;
        TimeSyncPoll::SkippedUnsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn server_response(tx_unix_secs: u64) -> [u8; NTP_PACKET_LEN] {
        let mut pkt = [0u8; NTP_PACKET_LEN];
        pkt[0] = 0x24;
        pkt[1] = 1;
        let tx = (tx_unix_secs + NTP_UNIX_EPOCH_OFFSET_SECS) as u32;
        pkt[40..44].copy_from_slice(&tx.to_be_bytes());
        pkt
    }

    #[test]
    fn ntp_request_e_cliente_v4_48b_zerado() {
        let req = build_ntp_request();
        assert_eq!(req.len(), NTP_PACKET_LEN);
        assert_eq!(req[0], 0x23);
        assert!(req[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn ntp_parse_aceita_resposta_valida() {
        // Vetor RFC 6238 (TOTP usa o mesmo Unix): t=1111111109.
        let pkt = server_response(1_111_111_109);
        assert_eq!(parse_ntp_response(&pkt), Some(1_111_111_109));
    }

    #[test]
    fn ntp_parse_rejeita_malformado() {
        let good = server_response(1_111_111_109);
        assert_eq!(parse_ntp_response(&good[..47]), None);
        let mut mode_cli = good;
        mode_cli[0] = 0x23;
        assert_eq!(parse_ntp_response(&mode_cli), None);
        let mut kiss = good;
        kiss[1] = 0;
        assert_eq!(parse_ntp_response(&kiss), None);
        let mut unsync = good;
        unsync[1] = 16;
        assert_eq!(parse_ntp_response(&unsync), None);
        let mut zero_tx = good;
        zero_tx[40..44].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(parse_ntp_response(&zero_tx), None);
        let mut pre_epoch = good;
        pre_epoch[40..44].copy_from_slice(&100u32.to_be_bytes());
        assert_eq!(parse_ntp_response(&pre_epoch), None);
    }

    #[test]
    fn ancora_nvs_roundtrip_e_relogio_fake() {
        let mut st = storage();
        let mut ts = TimeSyncState::load(&st);
        assert!(!ts.is_trusted());
        let bad = ts.resolve_clock(9_999_999);
        assert!(!bad.rtc_trusted);
        assert!(ts.note_sync(1_733_000_000, 5_000));
        ts.save(&mut st).expect("save");
        // Recarrega (simula reboot): sem SNTP fresco, ancora vale.
        let ts2 = TimeSyncState::load(&st);
        assert!(ts2.is_trusted());
        // Relogio fake: mono parado => ancora; +60 s => +60 s; regressao => max.
        let c0 = ts2.resolve_clock(5_000);
        assert!((c0.rtc_trusted, c0.now_unix_secs) == (true, 1_733_000_000));
        let c1 = ts2.resolve_clock(65_000);
        assert_eq!(c1.now_unix_secs, 1_733_000_060);
        let cr = ts2.resolve_clock(1_000);
        assert_eq!(cr.now_unix_secs, 1_733_000_000);
        assert!(cr.rtc_trusted);
    }

    #[test]
    fn reboot_sem_rede_mantem_ultimo_bem_conhecido() {
        // Ancora persistida pre-reboot; apos reboot (RAM zerada) sem rede,
        // o relogio retoma do ultimo valor conhecido (max), ainda confiavel.
        let mut st = storage();
        let mut ts = TimeSyncState::load(&st);
        assert!(ts.note_sync(1_800_000_000, 5_000));
        ts.save(&mut st).expect("save");
        let rebooted = TimeSyncState::load(&st);
        assert!(rebooted.is_trusted());
        assert_eq!(rebooted.last_sync_mono_ms, None);
        let c = rebooted.resolve_clock(900);
        assert!(c.rtc_trusted);
        assert_eq!(c.now_unix_secs, 1_800_000_000);
    }

    #[test]
    fn amostra_insana_nao_envenena_ancora() {
        let mut st = storage();
        let mut ts = TimeSyncState::load(&st);
        assert!(!ts.note_sync(0, 1_000));
        assert!(!ts.note_sync(TIME_MIN_SANE_UNIX_SECS - 1, 1_000));
        assert!(!ts.note_sync(TIME_MAX_SANE_UNIX_SECS + 1, 1_000));
        assert!(!ts.is_trusted());
        // Blob curto/corrompido na NVS = sem confianca.
        st.store(TIME_ANCHOR_NVS_KEY, &[1, 2, 3], &[0u8; 12])
            .expect("store");
        let ts2 = TimeSyncState::load(&st);
        assert!(!ts2.is_trusted());
        assert!(!ts2.resolve_clock(50_000).rtc_trusted);
    }

    #[test]
    fn poll_host_nunca_toca_em_rede() {
        let mut st = storage();
        let mut ts = TimeSyncState::load(&st);
        let mut last = None;
        // Sem station: NotDue, nada registrado.
        assert_eq!(
            poll_time_sync(&mut st, &mut ts, false, 1_000, &mut last),
            TimeSyncPoll::NotDue
        );
        assert_eq!(last, None);
        // Com station no host: pula sem socket, estado intacto.
        assert_eq!(
            poll_time_sync(&mut st, &mut ts, true, 61_000, &mut last),
            TimeSyncPoll::SkippedUnsupported,
        );
        assert!(!ts.is_trusted());
        assert_eq!(last, Some(61_000));
        // Retry gate: segunda chamada imediata nao tenta de novo.
        assert_eq!(
            poll_time_sync(&mut st, &mut ts, true, 62_000, &mut last),
            TimeSyncPoll::NotDue,
        );
    }
}
