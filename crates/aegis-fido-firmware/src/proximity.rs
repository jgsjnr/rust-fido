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

use aes::cipher::{BlockEncrypt, KeyInit};
use zeroize::Zeroize;

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};

/// UUID16 do anuncio de presenca (adv). Separado do GATT FIDO 0xFFFD.
pub const PROXIMITY_BEACON_SVC_UUID16: u16 = 0xFFFE;
/// Versao do layout do beacon ([VER:1 | CTR u32LE:4 | TAG:4]).
pub const PROXIMITY_BEACON_VERSION: u8 = 0x01;
/// Bytes do service-data de presenca (UUID16 + VER + CTR + TAG).
pub const PROXIMITY_BEACON_SVC_DATA_LEN: usize = 11;
/// Bytes do contador (u32 LE).
pub const PROXIMITY_BEACON_CTR_LEN: usize = 4;
/// Bytes da tag autenticada (AES-CCM-128 truncada em 32 b).
pub const PROXIMITY_BEACON_TAG_LEN: usize = 4;
/// Periodo de incremento do contador em ms (~1 s; relogio injetado).
pub const PROXIMITY_BEACON_TICK_MS: u64 = 1000;
/// Salto de contador que marca re-verificacao conservadora no host.
pub const PROXIMITY_REVERIFY_JUMP: u32 = 1000;
/// Chave NVS do K_prox (no maximo 15 chars; envelope AEGN via SecureStorage).
pub const PROXIMITY_BOND_NVS_KEY: &str = "prox_k";
/// Tamanho do K_prox (AES-128) em bytes.
pub const PROXIMITY_KEY_LEN: usize = 16;
/// Tamanho do fob_short_id (endereco BLE de 6 B) em bytes.
pub const PROXIMITY_FOB_ID_LEN: usize = 6;

/// Contador do beacon de presenca (relogio monotonico injetado, testavel no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProximityBeacon {
    ctr: u32,
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

/// Um bloco AES-128-ECB (primitiva do AES-CCM abaixo).
///
/// allow(deprecated): arvore presa no generic-array 0.14 via aes 0.8 (no_std,
/// sem novas deps); a API de bloco e a unica peca usada aqui.
#[allow(deprecated)]
fn aes128_encrypt_block(key: &[u8; PROXIMITY_KEY_LEN], block: &mut [u8; 16]) {
    use aes::cipher::generic_array::GenericArray;
    let cipher = aes::Aes128::new_from_slice(key).expect("K_prox tem 16 bytes");
    let mut b = GenericArray::clone_from_slice(block as &[u8]);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(b.as_slice());
}

/// CBC-MAC do AES-CCM (T = 4, L = 4, mensagem vazia, AAD autenticado).
///
/// B0 = [0x4B] || nonce(11) || qlen (4 zeros); depois AAD com prefixo de
/// comprimento BE u16 e pad de zeros ate multiplo de 16.
fn ccm_cbc_mac(key: &[u8; PROXIMITY_KEY_LEN], nonce: &[u8; 11], aad: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x[0] = 0x4B;
    x[1..12].copy_from_slice(nonce);
    aes128_encrypt_block(key, &mut x);
    let aad_len = aad.len().min(0xFF00);
    let mut block = [0u8; 16];
    block[0] = ((aad_len >> 8) & 0xFF) as u8;
    block[1] = (aad_len & 0xFF) as u8;
    let head = aad_len.min(14);
    block[2..2 + head].copy_from_slice(&aad[..head]);
    for (a, b) in x.iter_mut().zip(block.iter()) {
        *a ^= *b;
    }
    aes128_encrypt_block(key, &mut x);
    let mut off = head;
    while off < aad_len {
        block = [0u8; 16];
        let take = (aad_len - off).min(16);
        block[..take].copy_from_slice(&aad[off..off + take]);
        for (a, b) in x.iter_mut().zip(block.iter()) {
            *a ^= *b;
        }
        aes128_encrypt_block(key, &mut x);
        off += take;
    }
    x
}

/// TAG = AES-CCM-128(K_prox, nonce, AAD, mensagem vazia) truncada em 4 B.
///
/// nonce (11 B) = VER || CTR_LE || fob_short_id; AAD (5 B) = VER || CTR_LE.
/// O fob_short_id e o endereco BLE de 6 B do fob bonded (injetado pelo
/// chamador a partir do peer real; nunca inventado aqui).
pub fn proximity_tag(
    key: &[u8; PROXIMITY_KEY_LEN],
    ver: u8,
    ctr: u32,
    fob_id: &[u8; PROXIMITY_FOB_ID_LEN],
) -> [u8; PROXIMITY_BEACON_TAG_LEN] {
    let mut nonce = [0u8; 11];
    nonce[0] = ver;
    nonce[1..5].copy_from_slice(&ctr.to_le_bytes());
    nonce[5..11].copy_from_slice(fob_id);
    let mut aad = [0u8; 5];
    aad[0] = ver;
    aad[1..5].copy_from_slice(&ctr.to_le_bytes());
    let mut mac = ccm_cbc_mac(key, &nonce, &aad);
    let mut s0 = [0u8; 16];
    s0[0] = 0x03;
    s0[1..12].copy_from_slice(&nonce);
    aes128_encrypt_block(key, &mut s0);
    let mut tag = [0u8; PROXIMITY_BEACON_TAG_LEN];
    for ((d, m), s) in tag.iter_mut().zip(mac.iter()).zip(s0.iter()) {
        *d = m ^ s;
    }
    mac.zeroize();
    s0.zeroize();
    tag
}

/// Comparacao em tempo constante da TAG (falso nao revela posicao).
pub fn verify_proximity_tag(
    key: &[u8; PROXIMITY_KEY_LEN],
    ver: u8,
    ctr: u32,
    fob_id: &[u8; PROXIMITY_FOB_ID_LEN],
    tag: &[u8; PROXIMITY_BEACON_TAG_LEN],
) -> bool {
    let expect = proximity_tag(key, ver, ctr, fob_id);
    let diff: u8 = expect
        .iter()
        .zip(tag.iter())
        .fold(0, |acc, (a, b)| acc | (a ^ b));
    diff == 0
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
    Ok { ctr: u32, tag: [u8; PROXIMITY_BEACON_TAG_LEN] },
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

/// Gera um K_prox aleatorio de 128 b (TRNG do chamador; zeroize apos salvar).
pub fn generate_proximity_key<R: rand_core::RngCore>(rng: &mut R) -> [u8; PROXIMITY_KEY_LEN] {
    let mut key = [0u8; PROXIMITY_KEY_LEN];
    rng.fill_bytes(&mut key);
    key
}

/// Persiste o K_prox em NVS cifrada (envelope AEGN via SecureStorage).
///
/// A copia em RAM continua com o chamador: zeroize apos o uso.
pub fn save_proximity_key<B: FlashStorageBackend, R: rand_core::RngCore + rand_core::CryptoRng>(
    storage: &mut SecureStorage<B>,
    key: &[u8; PROXIMITY_KEY_LEN],
    rng: &mut R,
) -> Result<(), StorageError> {
    storage.store_with_rng(PROXIMITY_BOND_NVS_KEY, key, rng)
}

/// Carrega o K_prox da NVS cifrada (tamanho diferente de 16 B = corrompido).
pub fn load_proximity_key<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<[u8; PROXIMITY_KEY_LEN], StorageError> {
    let raw = storage.load(PROXIMITY_BOND_NVS_KEY)?;
    if raw.len() != PROXIMITY_KEY_LEN {
        return Err(StorageError::CorruptedEnvelope);
    }
    let mut key = [0u8; PROXIMITY_KEY_LEN];
    key.copy_from_slice(&raw);
    Ok(key)
}

/// Apaga o K_prox (release, recovery ou antes do rekey).
pub fn delete_proximity_key<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), StorageError> {
    storage.delete(PROXIMITY_BOND_NVS_KEY)
}

/// Rekey: gera e persiste um K_prox novo (chamar em release, recovery e
/// apos rollover; fiar apos BondOutcome::Paired no main.rs).
pub fn rekey_proximity<B: FlashStorageBackend, R: rand_core::RngCore + rand_core::CryptoRng>(
    storage: &mut SecureStorage<B>,
    rng: &mut R,
) -> Result<[u8; PROXIMITY_KEY_LEN], StorageError> {
    let key = generate_proximity_key(rng);
    save_proximity_key(storage, &key, rng)?;
    Ok(key)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Arrange
    fn monitor() -> ProximityMonitor {
        ProximityMonitor::new(ProximityConfig::default())
    }

    #[test]
    fn should_lock_away_when_weak_for_10s() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(Some(-80), 10);
        // Assert
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_not_lock_before_10s() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(Some(-80), 9);
        // Assert
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_hold_away_inside_hysteresis_band() {
        // Arrange: -75 threshold, histerese 5 => banda [-75, -70)
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        let st = m.update(Some(-72), 5);
        // Assert: anti-flap, continua Away
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_never_auto_unlock_from_locked_on_good_rssi() {
        // Arrange
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        m.confirm_lock();
        let st = m.update(Some(-50), 30);
        // Assert
        assert_eq!(st, ProximityState::Locked);
    }

    #[test]
    fn should_return_to_near_above_threshold_plus_hysteresis() {
        // Arrange: Away apos 10 s fraco
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        let st = m.update(Some(-65), 1);
        // Assert: -65 >= -75 + 5 (-70) => Near
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_need_confirm_to_reach_locked() {
        // Arrange
        let mut m = monitor();
        // Act: fraco por muito tempo nunca trava sozinho
        let st = m.update(Some(-80), 60);
        // Assert
        assert_eq!(st, ProximityState::Away);
        // Act: confirmacao leva a Locked
        let st = m.confirm_lock();
        // Assert
        assert_eq!(st, ProximityState::Locked);
    }

    #[test]
    fn should_unlock_only_with_presence_and_pin() {
        // Arrange
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        m.confirm_lock();
        // Assert: sem PIN nao destrava
        assert!(!m.unlock(true, false));
        assert_eq!(m.state(), ProximityState::Locked);
        // Assert: sem presenca nao destrava
        assert!(!m.unlock(false, true));
        assert_eq!(m.state(), ProximityState::Locked);
        // Act: presenca + PIN destrava para Near
        // Assert
        assert!(m.unlock(true, true));
        assert_eq!(m.state(), ProximityState::Near);
    }

    #[test]
    fn should_treat_missing_sample_as_weak() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(None, 10);
        // Assert
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_clamp_huge_elapsed_to_60s() {
        // Arrange: 1 s acumulado, depois amostra gigante com sinal fraco
        let mut m = monitor();
        m.update(Some(-80), 1);
        // Act: u32::MAX deve clampar para 60 s, nao estourar o acumulado
        let st = m.update(Some(-80), u32::MAX);
        // Assert: ainda trava (1 + 60 >= 10) mas sem overflow/panico
        assert_eq!(st, ProximityState::Away);
        // Act: sinal bom reseta normalmente apos o clamp
        let st = m.update(Some(-65), 1);
        // Assert
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_match_canonical_lock_policy_consts() {
        // Arrange: decisao congelada (lock < -75 dBm por 10 s, histerese 5 dB).
        // Act/Assert: consts canonicas + default em sync.
        assert_eq!(PROXIMITY_LOCK_RSSI_DBM, -75);
        assert_eq!(PROXIMITY_LOCK_SECS, 10);
        assert_eq!(PROXIMITY_HYSTERESIS_DB, 5);
        let d = ProximityConfig::default();
        assert_eq!(d.lock_rssi_dbm, PROXIMITY_LOCK_RSSI_DBM);
        assert_eq!(d.lock_secs, PROXIMITY_LOCK_SECS);
        assert_eq!(d.hysteresis_db, PROXIMITY_HYSTERESIS_DB);
    }

    #[test]
    fn should_block_proximity_when_usb_active_mutual_exclusion() {
        // Arrange: coexistencia mutuamente exclusiva (USB tem prioridade total).
        // Act/Assert
        assert!(!coex_proximity_allowed(true));
        assert!(coex_proximity_allowed(false));
    }

    #[test]
    fn should_require_bonding_for_proximity_sample() {
        // Arrange: bonding obrigatorio (JustWorks+bonding+UP).
        // Act/Assert
        assert!(bonding_required());
        assert!(authorize_proximity_sample(true, false));
        assert!(!authorize_proximity_sample(false, false));
        assert!(!authorize_proximity_sample(true, true));
        assert!(!authorize_proximity_sample(false, true));
    }

    #[test]
    fn should_treat_denied_sample_as_weak_fail_closed() {
        // Arrange: gate nega amostra sem bond.
        let mut m = monitor();
        // Act: chamador alimenta None (fraco) quando o gate nega.
        assert!(!authorize_proximity_sample(false, false));
        let st = m.update(None, 10);
        // Assert: fail-closed, trava para Away.
        assert_eq!(st, ProximityState::Away);
    }
}

#[cfg(test)]
mod rolling_tests {
    use super::*;
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use rand::SeedableRng;

    fn test_key() -> [u8; PROXIMITY_KEY_LEN] {
        [0x42u8; PROXIMITY_KEY_LEN]
    }

    fn test_fob() -> [u8; PROXIMITY_FOB_ID_LEN] {
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    }

    fn beacon_data(ctr: u32, tag: &[u8; PROXIMITY_BEACON_TAG_LEN]) -> [u8; 9] {
        let mut d = [0u8; 9];
        d[0] = PROXIMITY_BEACON_VERSION;
        d[1..5].copy_from_slice(&ctr.to_le_bytes());
        d[5..9].copy_from_slice(tag);
        d
    }

    fn storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn should_encode_svc_data_as_uuid_ver_ctr_tag() {
        let tag = [0x01, 0x02, 0x03, 0x04];
        let svc = encode_proximity_svc_data(0x01020304, &tag);
        assert_eq!(svc.len(), PROXIMITY_BEACON_SVC_DATA_LEN);
        assert_eq!(&svc[0..2], &[0xFE, 0xFF]);
        assert_eq!(svc[2], PROXIMITY_BEACON_VERSION);
        assert_eq!(&svc[3..7], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&svc[7..11], &tag);
    }

    #[test]
    fn should_bind_tag_to_key_ver_ctr_and_fob() {
        let key = test_key();
        let fob = test_fob();
        let good = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob);
        assert!(verify_proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob, &good));
        let mut other = key;
        other[0] ^= 0xFF;
        assert!(!verify_proximity_tag(&other, PROXIMITY_BEACON_VERSION, 7, &fob, &good));
        assert!(!verify_proximity_tag(&key, PROXIMITY_BEACON_VERSION, 8, &fob, &good));
        let mut fob2 = fob;
        fob2[5] ^= 0x01;
        assert!(!verify_proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob2, &good));
        let mut bad = good;
        bad[3] ^= 0x80;
        assert!(!verify_proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob, &bad));
    }

    #[test]
    fn should_derive_distinct_tags_per_counter() {
        let key = test_key();
        let fob = test_fob();
        let a = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 1, &fob);
        let b = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 1, &fob);
        let c = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 2, &fob);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn should_ignore_non_fffe_parse_unsupported_ver_and_malformed() {
        let key = test_key();
        let fob = test_fob();
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 3, &fob);
        let data = beacon_data(3, &tag);
        assert_eq!(parse_proximity_svc_data(0xFFFD, &data), BeaconParse::Ignore);
        let mut wrong_ver = data;
        wrong_ver[0] = 0x02;
        assert_eq!(
            parse_proximity_svc_data(PROXIMITY_BEACON_SVC_UUID16, &wrong_ver),
            BeaconParse::Unsupported
        );
        assert_eq!(
            parse_proximity_svc_data(PROXIMITY_BEACON_SVC_UUID16, &data[..8]),
            BeaconParse::Malformed
        );
    }

    #[test]
    fn should_accept_in_order_and_reject_replay_without_advancing() {
        let key = test_key();
        let fob = test_fob();
        let mut v = ProximityVerifier::new();
        for ctr in [1u32, 2, 3] {
            let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
            let data = beacon_data(ctr, &tag);
            assert_eq!(
                v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data),
                BeaconVerdict::Accept { ctr, reverify: false }
            );
        }
        assert_eq!(v.last_ctr(), Some(3));
        let tag3 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 3, &fob);
        let data3 = beacon_data(3, &tag3);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data3),
            BeaconVerdict::Replay
        );
        let tag2 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 2, &fob);
        let data2 = beacon_data(2, &tag2);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data2),
            BeaconVerdict::Replay
        );
        assert_eq!(v.last_ctr(), Some(3));
    }

    #[test]
    fn should_reject_bad_tag_without_advancing() {
        let key = test_key();
        let fob = test_fob();
        let mut v = ProximityVerifier::new();
        let tag1 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 1, &fob);
        let data1 = beacon_data(1, &tag1);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data1),
            BeaconVerdict::Accept { ctr: 1, reverify: false }
        );
        let mut bad = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 2, &fob);
        bad[0] ^= 0xFF;
        let data_bad = beacon_data(2, &bad);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data_bad),
            BeaconVerdict::BadTag
        );
        assert_eq!(v.last_ctr(), Some(1));
    }

    #[test]
    fn should_flag_reverify_on_jump_over_1000() {
        let key = test_key();
        let fob = test_fob();
        let mut v = ProximityVerifier::new();
        let tag1 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 10, &fob);
        let data1 = beacon_data(10, &tag1);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data1),
            BeaconVerdict::Accept { ctr: 10, reverify: false }
        );
        let jump = 10 + PROXIMITY_REVERIFY_JUMP + 1;
        let tagj = proximity_tag(&key, PROXIMITY_BEACON_VERSION, jump, &fob);
        let dataj = beacon_data(jump, &tagj);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &dataj),
            BeaconVerdict::Accept { ctr: jump, reverify: true }
        );
        assert!(v.reverify_pending());
        v.clear_reverify();
        assert!(!v.reverify_pending());
        let tag_next = proximity_tag(&key, PROXIMITY_BEACON_VERSION, jump + 1, &fob);
        let data_next = beacon_data(jump + 1, &tag_next);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data_next),
            BeaconVerdict::Accept { ctr: jump + 1, reverify: false }
        );
    }

    #[test]
    fn should_tick_about_once_per_second() {
        let mut b = ProximityBeacon::new();
        assert_eq!(b.counter(), 0);
        assert!(!b.tick_if_due(0, PROXIMITY_BEACON_TICK_MS - 1));
        assert_eq!(b.counter(), 0);
        assert!(b.tick_if_due(0, PROXIMITY_BEACON_TICK_MS));
        assert_eq!(b.counter(), 1);
        assert!(!b.tick_if_due(1000, 1500));
        assert!(b.tick_if_due(1000, 2000));
        assert_eq!(b.counter(), 2);
    }

    #[test]
    fn should_hold_max_on_rollover_until_rekey() {
        let mut b = ProximityBeacon { ctr: u32::MAX - 1 };
        assert!(!b.is_rollover());
        assert_eq!(b.tick(), u32::MAX);
        assert!(b.is_rollover());
        assert_eq!(b.tick(), u32::MAX);
        assert!(b.is_rollover());
        assert!(b.tick_if_due(0, 60_000));
        assert_eq!(b.counter(), u32::MAX);
    }

    #[test]
    fn should_roundtrip_k_prox_in_encrypted_nvs() {
        let mut s = storage();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA0E615);
        assert_eq!(
            load_proximity_key(&s),
            Err(StorageError::KeyNotFound)
        );
        let key = rekey_proximity(&mut s, &mut rng).expect("rekey salva");
        assert_eq!(load_proximity_key(&s).expect("carrega"), key);
        let key2 = rekey_proximity(&mut s, &mut rng).expect("rekey troca");
        assert_ne!(key, key2);
        assert_eq!(load_proximity_key(&s).expect("carrega nova"), key2);
        delete_proximity_key(&mut s).expect("release apaga");
        assert_eq!(
            load_proximity_key(&s),
            Err(StorageError::KeyNotFound)
        );
    }

    #[test]
    fn should_reject_tampered_or_short_k_prox() {
        let mut s = storage();
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let key = generate_proximity_key(&mut rng);
        save_proximity_key(&mut s, &key, &mut rng).expect("salva");
        s.backend_mut()
            .write_raw(PROXIMITY_BOND_NVS_KEY, &[1u8, 2, 3])
            .expect("injeta curto");
        assert_eq!(
            load_proximity_key(&s),
            Err(StorageError::CorruptedEnvelope)
        );
        save_proximity_key(&mut s, &key, &mut rng).expect("salva de novo");
        let mut raw = s.backend().read_raw(PROXIMITY_BOND_NVS_KEY).expect("envelope");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        s.backend_mut()
            .write_raw(PROXIMITY_BOND_NVS_KEY, &raw)
            .expect("injeta tamper");
        assert_eq!(
            load_proximity_key(&s),
            Err(StorageError::DecryptionFailed)
        );
    }

    #[test]
    fn should_require_every_gate_for_presence_adv() {
        assert!(proximity_adv_allowed(true, true, true, false, true));
        assert!(!proximity_adv_allowed(false, true, true, false, true));
        assert!(!proximity_adv_allowed(true, false, true, false, true));
        assert!(!proximity_adv_allowed(true, true, false, false, true));
        assert!(!proximity_adv_allowed(true, true, true, true, true));
        assert!(!proximity_adv_allowed(true, true, true, false, false));
    }

    #[test]
    fn should_never_unlock_monitor_on_beacon_accept() {
        let mut m = ProximityMonitor::new(ProximityConfig::default());
        m.update(Some(-80), 10);
        m.confirm_lock();
        assert_eq!(m.state(), ProximityState::Locked);
        let key = test_key();
        let fob = test_fob();
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 41, &fob);
        let data = beacon_data(41, &tag);
        let mut v = ProximityVerifier::new();
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data),
            BeaconVerdict::Accept { ctr: 41, reverify: false }
        );
        assert_eq!(m.state(), ProximityState::Locked);
        assert!(!m.unlock(false, false));
        assert_eq!(m.state(), ProximityState::Locked);
    }
}
