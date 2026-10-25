//! Proximity monitor + beacon gates (moved from `proximity`; unchanged).
//! Owner of `ProximityMonitor`/`ProximityBeacon`/coex gates. NVS `prox_k`
//! stays in parent `proximity` (single owner); crypto stays top-level in
//! `proximity_crypto` (re-exported here for the beacon verifier).

//! Proximidade pura por RSSI (sem BLE real, sem relogio real).
//!
//! - Trava (`Away`) apos `lock_secs` acumulados abaixo de `lock_rssi_dbm`.
//! - `Locked` somente via [`ProximityMonitor::confirm_lock`] (nunca automatico).
//! - Volta a `Near` somente acima de `lock_rssi_dbm + hysteresis_db`.
//! - `update` nunca sai de `Locked` sozinho: exige presenca+PIN via [`ProximityMonitor::unlock`].
//! - `no_std` compativel: sem alloc, sem I/O, tempo injetado (`elapsed_secs`).
//! - RSSI nunca e fator de auth: apenas sinaliza ausencia para o chamador travar.
//!
//! Limites padrao ([`ProximityConfig::default`]): trava abaixo de -75 dBm por
//! 10 s, com histerese de 5 dB (retorno somente acima de -70 dBm).

/// Maximo de segundos aceitos por chamada de `update` (anti-DoS).
const MAX_ELAPSED_SECS_PER_UPDATE: u32 = 60;

/// Configuracao da politica de proximidade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProximityConfig {
    /// Trava quando RSSI fica abaixo deste valor (dBm, ex. -75).
    pub lock_rssi_dbm: i16,
    /// Segundos acumulados abaixo do threshold para ir a `Away`.
    pub lock_secs: u32,
    /// Histerese em dB para voltar a `Near` (ex. 5 => retorna acima de -70).
    pub hysteresis_db: u8,
}

impl Default for ProximityConfig {
    /// Padrao: trava < -75 dBm por 10 s, histerese 5 dB.
    fn default() -> Self {
        Self {
            lock_rssi_dbm: -75,
            lock_secs: 10,
            hysteresis_db: 5,
        }
    }
}

/// Estado de proximidade do autenticador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProximityState {
    /// Perto: RSSI acima do threshold.
    Near,
    /// Longe: ausente por `lock_secs`; aguardando confirmacao de trava.
    Away,
    /// Travado: exige presenca+PIN para voltar a `Near`.
    Locked,
}

/// Monitor de proximidade com relogio injetado (testavel no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProximityMonitor {
    config: ProximityConfig,
    state: ProximityState,
    below_secs: u32,
}

impl ProximityMonitor {
    /// Cria em `Near`, sem tempo acumulado.
    pub fn new(config: ProximityConfig) -> Self {
        Self {
            config,
            state: ProximityState::Near,
            below_secs: 0,
        }
    }

    /// Estado atual (copia, sem borrow).
    pub fn state(&self) -> ProximityState {
        self.state
    }

    /// Configuracao atual (copia, sem borrow).
    pub fn config(&self) -> ProximityConfig {
        self.config
    }

    /// Atualiza o estado a partir de uma amostra de RSSI e do tempo decorrido.
    ///
    /// - `None` (sem leitura) conta como sinal fraco (conservador: tende a travar).
    /// - Fraco (`rssi < lock_rssi_dbm`) acumula `elapsed_secs`; ao atingir
    ///   `lock_secs`, transita para `Away`.
    /// - Bom (`rssi >= lock_rssi_dbm + hysteresis_db`) zera o acumulado e, se
    ///   em `Away`, volta a `Near`.
    /// - Banda de histerese (entre os dois limites) congela tudo: anti-flap.
    /// - Em `Locked`, nunca muda sozinho (nem com RSSI bom); use [`Self::unlock`].
    pub fn update(&mut self, rssi_dbm: Option<i16>, elapsed_secs: u32) -> ProximityState {
        if self.state == ProximityState::Locked {
            return ProximityState::Locked;
        }
        // Clamp anti-DoS: uma amostra nao pode injetar tempo arbitrario.
        let elapsed_secs = elapsed_secs.min(MAX_ELAPSED_SECS_PER_UPDATE);
        let release_dbm = self
            .config
            .lock_rssi_dbm
            .saturating_add(self.config.hysteresis_db as i16);
        match rssi_dbm {
            // Sinal bom: reseta acumulado; Away volta a Near.
            Some(rssi) if rssi >= release_dbm => {
                self.below_secs = 0;
                if self.state == ProximityState::Away {
                    self.state = ProximityState::Near;
                }
            }
            // Sinal fraco (ou sem leitura): acumula; Near vira Away no limite.
            Some(rssi) if rssi < self.config.lock_rssi_dbm => {
                self.below_secs = self.below_secs.saturating_add(elapsed_secs);
                if self.below_secs >= self.config.lock_secs {
                    self.state = ProximityState::Away;
                }
            }
            None => {
                self.below_secs = self.below_secs.saturating_add(elapsed_secs);
                if self.below_secs >= self.config.lock_secs {
                    self.state = ProximityState::Away;
                }
            }
            // Banda de histerese: mantem estado e acumulado (anti-flap).
            Some(_) => {}
        }
        self.state
    }

    /// Confirma a trava: `Away` vira `Locked`. Nos demais estados, sem efeito.
    pub fn confirm_lock(&mut self) -> ProximityState {
        if self.state == ProximityState::Away {
            self.state = ProximityState::Locked;
        }
        self.state
    }

    /// Destrava somente de `Locked` com presenca fisica E PIN valido.
    ///
    /// Retorna `true` se destravou (volta a `Near` com acumulado zerado).
    pub fn unlock(&mut self, presence: bool, pin_ok: bool) -> bool {
        if self.state == ProximityState::Locked && presence && pin_ok {
            self.state = ProximityState::Near;
            self.below_secs = 0;
            return true;
        }
        false
    }
}

/// RSSI de trava canonico (< -75 dBm).
///
/// Igual a `ProximityConfig::default` e aos agents host (`--threshold-db -75`).
/// RSSI nunca autentica: apenas sinaliza ausencia para o chamador travar.
pub const PROXIMITY_LOCK_RSSI_DBM: i16 = -75;
/// Segundos de AWAY ate `Away` (10 s).
///
/// Igual ao default e aos agents (`--lock-secs 10`).
pub const PROXIMITY_LOCK_SECS: u32 = 10;
/// Histerese canonica (5 dB, retorno acima de -70 dBm).
///
/// Igual ao default e aos agents host.
pub const PROXIMITY_HYSTERESIS_DB: u8 = 5;

/// Coexistencia mutuamente exclusiva: BLE-proximidade vs USB/CTAP.
///
/// USB ativo => proximidade BLE NAO pode consumir RSSI nem destravar
/// (o chamador mantem `Locked`/`Away` e para o scan). USB tem controlador
/// dedicado e prioridade total. Retorna `false` com USB ativo.
pub fn coex_proximity_allowed(usb_active: bool) -> bool {
    !usb_active
}

/// Bonding sempre obrigatorio para proximidade (JustWorks+bonding+UP).
///
/// RSSI so vale de fob bonded; sem bond a amostra e descartada.
pub fn bonding_required() -> bool {
    true
}

/// Gate antes de aceitar uma amostra RSSI: exige fob bonded E USB idle.
///
/// Ordem: bonding -> coex. `false` = descartar a amostra (o chamador
/// alimenta `None`/fraco no `update`: fail-closed, tende a travar).
pub fn authorize_proximity_sample(bonded: bool, usb_active: bool) -> bool {
    bonded && !usb_active
}

// ---------------------------------------------------------------------------
// Wave2: rolling-code de presenca (adv 0xFFFE, separado do GATT 0xFFFD).
//
// Adv de presenca (legado, 30 B):
//   Flags(0x06) + CompleteList16[0xFFFE] + ServiceData16[FE FF VER CTR TAG]
//   + Nome "AegisKey".
// Service-data (11 B): [UUID16 LE:2 | VER:1 | CTR u32LE:4 | TAG:4].
//   VER = 0x01. CTR++ ~1 s (tick_if_due). TAG = AES-CCM-128 trunc 4 B com
//   nonce = VER || CTR_LE || fob_short_id (6 B, endereco BLE do fob) e
//   AAD = VER || CTR_LE (mensagem vazia). Rollover: CTR satura em u32::MAX
//   e o adv mantem o ultimo valor ate rekey (nunca volta a zero sozinho).
//
// K_prox (128 b): gerada apos on_link_secured -> Paired (ver rekey_proximity),
// guardada em NVS cifrada (envelope AEGN via SecureStorage) com zeroize da
// copia em RAM. Rekey em release/recovery e apos rollover (is_rollover).
// Sem K_prox nao ha adv (gate proximity_adv_allowed).
//
// Host (agents): UUID diferente de 0xFFFE ignora; VER diferente de 0x01
// relata Unsupported; TAG invalida ou replay (ctr <= last) descarta como
// None (fail-closed, tende a travar); salto > PROXIMITY_REVERIFY_JUMP aceita
// mas marca reverify_pending (o host re-confere bonding e UP antes de
// confiar na amostra).
//
// Gates (todos exigidos): feature proximity ON em compilacao, bonded, Idle,
// trusted, usb inativo e K_prox presente (proximity_adv_allowed). Coex
// USB > WiFi > BLE: USB veta o adv; WiFi ativo so desacelera o intervalo
// (ver ble_nimble::adv_intervals); BLE nunca bloqueia o USB. Lock-only:
// aceitar um beacon nunca destrava (unlock exige presenca fisica + PIN,
// ver ProximityMonitor::unlock); beacon e RSSI so sinalizam ausencia.
// ---------------------------------------------------------------------------

pub use crate::proximity_crypto::{
    proximity_tag, verify_proximity_tag, PROXIMITY_BEACON_TAG_LEN, PROXIMITY_FOB_ID_LEN,
    PROXIMITY_KEY_LEN,
};

/// UUID16 do anuncio de presenca (adv). Separado do GATT FIDO 0xFFFD.
pub const PROXIMITY_BEACON_SVC_UUID16: u16 = 0xFFFE;
/// Versao do layout do beacon ([VER:1 | CTR u32LE:4 | TAG:4]).
pub const PROXIMITY_BEACON_VERSION: u8 = 0x01;
/// Bytes do service-data de presenca (UUID16 + VER + CTR + TAG).
pub const PROXIMITY_BEACON_SVC_DATA_LEN: usize = 11;
/// Bytes do contador (u32 LE).
pub const PROXIMITY_BEACON_CTR_LEN: usize = 4;
/// Periodo de incremento do contador em ms (~1 s; relogio injetado).
pub const PROXIMITY_BEACON_TICK_MS: u64 = 1000;
/// Salto de contador que marca re-verificacao conservadora no host.
pub const PROXIMITY_REVERIFY_JUMP: u32 = 1000;
/// Contador do beacon de presenca (relogio monotonico injetado, testavel no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProximityBeacon {
    pub(crate) ctr: u32,
}

impl ProximityBeacon {
    /// Contador zerado (primeiro adv usa ctr 0 apos rekey).
    pub fn new() -> Self {
        Self { ctr: 0 }
    }

    /// Valor atual do contador (copia).
    pub fn counter(&self) -> u32 {
        self.ctr
    }

    /// Incrementa ~1 s. Satura em u32::MAX (ver is_rollover).
    pub fn tick(&mut self) -> u32 {
        self.ctr = self.ctr.saturating_add(1);
        self.ctr
    }

    /// Verdade quando o contador travou no MAX (exige rekey, nunca wrap).
    pub fn is_rollover(&self) -> bool {
        self.ctr == u32::MAX
    }

    /// Avanca o contador se passaram >= PROXIMITY_BEACON_TICK_MS desde last_ms.
    /// Retorna true quando avancou (chamador re-anuncia o service-data).
    pub fn tick_if_due(&mut self, last_ms: u64, now_ms: u64) -> bool {
        if now_ms.saturating_sub(last_ms) >= PROXIMITY_BEACON_TICK_MS {
            self.tick();
            true
        } else {
            false
        }
    }
}

impl Default for ProximityBeacon {
    fn default() -> Self {
        Self::new()
    }
}

/// Monta o service-data de presenca (11 B: UUID16 LE + VER + CTR + TAG).
pub fn encode_proximity_svc_data(
    ctr: u32,
    tag: &[u8; PROXIMITY_BEACON_TAG_LEN],
) -> [u8; PROXIMITY_BEACON_SVC_DATA_LEN] {
    let mut out = [0u8; PROXIMITY_BEACON_SVC_DATA_LEN];
    out[0] = (PROXIMITY_BEACON_SVC_UUID16 & 0xFF) as u8;
    out[1] = ((PROXIMITY_BEACON_SVC_UUID16 >> 8) & 0xFF) as u8;
    out[2] = PROXIMITY_BEACON_VERSION;
    out[3..7].copy_from_slice(&ctr.to_le_bytes());
    out[7..11].copy_from_slice(tag);
    out
}

/// Resultado do parse do service-data recebido (semantica do host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconParse {
    /// Beacon bem formado: contador e tag para verificar.
    Ok {
        ctr: u32,
        tag: [u8; PROXIMITY_BEACON_TAG_LEN],
    },
    /// UUID diferente de 0xFFFE: nao e adv de presenca, ignorar.
    Ignore,
    /// VER diferente de 0x01: relatar Unsupported, nunca autenticar.
    Unsupported,
    /// Tamanho invalido: quadro malformado, descartar.
    Malformed,
}

/// Interpreta o service-data apos o UUID (9 B: VER + CTR + TAG).
///
/// data sao os bytes apos o UUID16 (o chamador ja separou por AD structure).
pub fn parse_proximity_svc_data(svc_uuid: u16, data: &[u8]) -> BeaconParse {
    if svc_uuid != PROXIMITY_BEACON_SVC_UUID16 {
        return BeaconParse::Ignore;
    }
    if data.len() != PROXIMITY_BEACON_SVC_DATA_LEN - 2 {
        return BeaconParse::Malformed;
    }
    if data[0] != PROXIMITY_BEACON_VERSION {
        return BeaconParse::Unsupported;
    }
    let mut ctr = [0u8; PROXIMITY_BEACON_CTR_LEN];
    ctr.copy_from_slice(&data[1..5]);
    let mut tag = [0u8; PROXIMITY_BEACON_TAG_LEN];
    tag.copy_from_slice(&data[5..9]);
    BeaconParse::Ok {
        ctr: u32::from_le_bytes(ctr),
        tag,
    }
}

/// Veredito da verificacao de um beacon (fail-closed: so Accept consome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconVerdict {
    /// TAG ok e ctr novo; reverify indica salto > PROXIMITY_REVERIFY_JUMP.
    Accept { ctr: u32, reverify: bool },
    /// UUID diferente de 0xFFFE: ignorar o quadro.
    Ignore,
    /// VER diferente de 0x01: relatar Unsupported.
    Unsupported,
    /// TAG invalida: descartar como None (fail-closed, tende a travar).
    BadTag,
    /// Replay (ctr <= last): descartar como None.
    Replay,
    /// Quadro malformado: descartar como None.
    Malformed,
}

/// Verifica beacons com anti-replay (estado: ultimo ctr aceito).
#[derive(Debug, Clone, Copy)]
pub struct ProximityVerifier {
    last_ctr: Option<u32>,
    reverify: bool,
}

impl ProximityVerifier {
    /// Verificador sem historico (primeiro beacon com TAG valida aceita).
    pub fn new() -> Self {
        Self {
            last_ctr: None,
            reverify: false,
        }
    }

    /// Ultimo contador aceito (None antes do primeiro Accept).
    pub fn last_ctr(&self) -> Option<u32> {
        self.last_ctr
    }

    /// Verdade apos salto > PROXIMITY_REVERIFY_JUMP (re-conferir bonding e UP).
    pub fn reverify_pending(&self) -> bool {
        self.reverify
    }

    /// Limpa o flag apos re-conferir bonding e UP no host.
    pub fn clear_reverify(&mut self) {
        self.reverify = false;
    }

    /// Valida um beacon: parse, TAG, anti-replay e salto conservador.
    ///
    /// data sao os 9 B apos o UUID16. TAG invalida, replay ou quadro ruim
    /// nunca avancam last_ctr (o chamador alimenta None no monitor).
    pub fn accept(
        &mut self,
        key: &[u8; PROXIMITY_KEY_LEN],
        fob_id: &[u8; PROXIMITY_FOB_ID_LEN],
        svc_uuid: u16,
        data: &[u8],
    ) -> BeaconVerdict {
        match parse_proximity_svc_data(svc_uuid, data) {
            BeaconParse::Ignore => BeaconVerdict::Ignore,
            BeaconParse::Unsupported => BeaconVerdict::Unsupported,
            BeaconParse::Malformed => BeaconVerdict::Malformed,
            BeaconParse::Ok { ctr, tag } => {
                if !verify_proximity_tag(key, PROXIMITY_BEACON_VERSION, ctr, fob_id, &tag) {
                    return BeaconVerdict::BadTag;
                }
                if let Some(last) = self.last_ctr {
                    if ctr <= last {
                        return BeaconVerdict::Replay;
                    }
                    if ctr - last > PROXIMITY_REVERIFY_JUMP {
                        self.reverify = true;
                    }
                }
                self.last_ctr = Some(ctr);
                BeaconVerdict::Accept {
                    ctr,
                    reverify: self.reverify,
                }
            }
        }
    }
}

impl Default for ProximityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// fob_short_id = MAC BLE público real via `ble_nimble::own_addr()`; `None` com stack down => sem adv (fail-closed, mesma semântica de `proximity_adv_allowed`).
pub fn beacon_fob_id() -> Option<[u8; PROXIMITY_FOB_ID_LEN]> {
    crate::ble_nimble::own_addr()
}

/// Gate do anuncio de presenca (todos exigidos; ordem: bond, estado, trust, coex, chave).
///
/// feature proximity ON em compilacao, fob bonded, Idle, trusted (bonded da
/// sessao ou claimed da NVS), USB inativo e K_prox presente. USB > WiFi > BLE:
/// USB veta; WiFi so desacelera o intervalo no backend.
pub fn proximity_adv_allowed(
    bonded: bool,
    idle: bool,
    trusted: bool,
    usb_active: bool,
    key_present: bool,
) -> bool {
    bonded && idle && trusted && !usb_active && key_present
}
