// T-PI-02 Comandos OpenPGP Card 3.4.1 (GEN-DEVICE).
//
// Motivo: a matriz exige OpenPGP 3.4.1 com vetores, mas o firmware so tinha
// transporte CCID/APDU sem applet; sem este modulo, SELECT/GET DATA/PUT
// DATA/PIN/PSO nao teriam dono nem politica (secao 9).
//
// - GEN-DEVICE: chaves nascem no device (generate) ou entram via envelope
//   (import); PSO assina/desfaz no device; privada nunca sai em log.
// - Escopo atomico: parser APDU curto reusado de piv_cmd (sem duplicar),
//   DOs de identidade, PIN/PUK(RC) com bloqueio, PSO P-256 real, ciclo
//   TERMINATE/ACTIVATE. Chaves RSA e estendido ficam de fora (fail-closed).
// - DOs: 4F AID (computado), C4 PW-status (computado), 5E/5B/5F2D/5F35/5F50
//   mutaveis (PUT exige sessao PW1), C7 fingerprint (so apos chave, PUT nega
//   ReadOnly), 6E construido (4F + C4 + 5E). PUT > 255 B nega.
// - PIN: PW1 6..=64, PW3 8..=64, RC == 8; 3 tentativas cada, retries em NVS
//   com verify-after-write; comprimento invalido nao consome tentativa;
//   sessao (pw1/pw3) e volatil: SELECT e reboot limpam (fail-closed).
// - PSO: SIGN = ECDSA-SHA256 P-256 RFC6979 (dado 1..=256 B, sai r||s 64 B);
//   DEC = ECDH P-256 + HMAC-SHA256-KDF XOR (perfil AEGIS-ECDH-v1 do device,
//   pub efemera comprimida 33 B + ct 1..=222 B). Nao afirma interop total.
// - SW: 9000 ok; 63CX tentativas; 6982 sem auth; 6983 bloqueado; 6985 nega
//   estado (read-only/terminado); 6A80 dado ruim; 6A82 tag/chat desconhecido;
//   6A88 nao provisionado; 6700 APDU/tamanho; 6D00/6E00 INS/CLA; 6F00 falha.
// - Power-loss: retries e DOs persistem (verify-after-write; torn write vira
//   Storage sem apagar o contador antigo); sessao nunca persiste.
// - Sem segredo em log: erros sem PIN/RC/chave; buffers zerados.

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::apdu::ApduError;
use crate::crypto_hrng::{HrngError, HrngSource};
use crate::crypto_p256::P256Error;
#[cfg(test)]
use crate::crypto_p256::{ecdh_p256, P256Secret};
use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage,
};

/// Prefixo do AID OpenPGP (RID + 0x01).
pub const OPGP_AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
/// Versao do cartao (OpenPGP Card 3.4.1).
pub const OPGP_VERSION: [u8; 2] = [0x03, 0x04];
/// Fabricante placeholder (2 B; HW grava o real no provisionamento).
pub const OPGP_MANUF: [u8; 2] = [0x00, 0x00];

/// CLA aceitos.
pub const CLA_ISO: u8 = 0x00;
/// INS OpenPGP.
pub const INS_SELECT: u8 = 0xA4;
/// INS GET DATA.
pub const INS_GET_DATA: u8 = 0xCA;
/// INS PUT DATA.
pub const INS_PUT_DATA: u8 = 0xDA;
/// INS VERIFY.
pub const INS_VERIFY: u8 = 0x20;
/// INS CHANGE PIN.
pub const INS_CHANGE: u8 = 0x24;
/// INS PSO.
pub const INS_PSO: u8 = 0x2A;
/// INS GET CHALLENGE.
pub const INS_CHALLENGE: u8 = 0x84;
/// INS TERMINATE DF.
pub const INS_TERMINATE: u8 = 0xE6;
/// INS ACTIVATE.
pub const INS_ACTIVATE: u8 = 0x44;

/// P1P2 do PSO SIGN (Compute Digital Signature).
pub const PSO_SIGN_P1P2: (u8, u8) = (0x9E, 0x9A);
/// P1P2 do PSO DECIPHER.
pub const PSO_DEC_P1P2: (u8, u8) = (0x80, 0x86);
/// P2 do VERIFY/CHANGE: PW1 e PW3.
pub const P2_PW1: u8 = 0x81;
/// P2 do VERIFY/CHANGE: PW3.
pub const P2_PW3: u8 = 0x83;

/// Tentativas por PIN/RC.
pub const OPGP_MAX_RETRIES: u8 = 3;
/// PIN PW1: 6..=64 B.
pub const PW1_MIN: usize = 6;
/// PIN maximo PW1/PW3.
pub const PW_MAX: usize = 64;
/// PIN PW3 minimo.
pub const PW3_MIN: usize = 8;
/// RC sempre 8 B.
pub const RC_LEN: usize = 8;
/// Sal do hash SHA-256(salt || pin).
pub const SALT_LEN: usize = 16;
/// Hash 32 B.
pub const HASH_LEN: usize = 32;
/// DO mutavel maximo (APDU curto).
pub const MAX_DO_LEN: usize = 255;
/// Entrada maxima do PSO SIGN.
pub const MAX_SIGN_INPUT: usize = 256;
/// Chave efemera comprimida do PSO DEC.
pub const EPH_LEN: usize = 33;
/// CT maximo do PSO DEC (255 - 33).
pub const MAX_DEC_CT: usize = MAX_DO_LEN - EPH_LEN;

/// SW de sucesso.
pub const SW_OK: u16 = 0x9000;

/// Slot de PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSlot {
    /// PW1 (uso diario / PSO).
    Pw1,
    /// PW3 (admin).
    Pw3,
}

/// Erros do applet. Sem PIN/RC/chave/serial nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpgpError {
    /// Applet ainda nao provisionado.
    NotProvisioned,
    /// Ja provisionado.
    AlreadyProvisioned,
    /// PIN fora do comprimento (nao consome tentativa).
    BadPin,
    /// RC fora de 8 B (nao consome tentativa).
    BadRc,
    /// PIN errado; tentativas restantes.
    InvalidPin { retries_left: u8 },
    /// RC errado; tentativas restantes.
    InvalidRc { retries_left: u8 },
    /// PIN bloqueado (exige RC ou re-provisionar).
    PinBlocked,
    /// RC bloqueado (wipe executado; exige re-provisionar).
    RcBlocked,
    /// Sem sessao (exige VERIFY antes).
    NotAuthorized,
    /// DO somente-leitura.
    ReadOnly,
    /// Tag desconhecida.
    UnknownTag,
    /// Valor acima do teto.
    TooLarge,
    /// APDU malformado (detalhe na variante interna).
    BadApdu(ApduError),
    /// CLA nao suportado.
    BadCla,
    /// INS desconhecido.
    BadIns,
    /// P1P2 invalido para o INS.
    BadP1P2,
    /// Applet terminado (so SELECT/ACTIVATE passam).
    Terminated,
    /// Sem chave provisionada no slot.
    NoKey,
    /// Chave invalida (fora da curva).
    BadKey,
    /// Ponto efemero invalido.
    BadPeer,
    /// Falha de storage / verify-after-write.
    Storage,
    /// HRNG indisponivel (salt, challenge, generate).
    Rng,
}

impl core::fmt::Display for OpgpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotProvisioned => write!(f, "openpgp not provisioned"),
            Self::AlreadyProvisioned => write!(f, "openpgp already provisioned"),
            Self::BadPin => write!(f, "bad openpgp pin length"),
            Self::BadRc => write!(f, "bad openpgp rc length"),
            Self::InvalidPin { .. } => write!(f, "wrong openpgp pin"),
            Self::InvalidRc { .. } => write!(f, "wrong openpgp rc"),
            Self::PinBlocked => write!(f, "openpgp pin blocked"),
            Self::RcBlocked => write!(f, "openpgp rc blocked"),
            Self::NotAuthorized => write!(f, "openpgp not authorized"),
            Self::ReadOnly => write!(f, "openpgp read-only object"),
            Self::UnknownTag => write!(f, "unknown openpgp tag"),
            Self::TooLarge => write!(f, "openpgp data too large"),
            Self::BadApdu(_) => write!(f, "bad openpgp apdu"),
            Self::BadCla => write!(f, "bad openpgp cla"),
            Self::BadIns => write!(f, "unknown openpgp ins"),
            Self::BadP1P2 => write!(f, "bad openpgp p1p2"),
            Self::Terminated => write!(f, "openpgp terminated"),
            Self::NoKey => write!(f, "openpgp no key"),
            Self::BadKey => write!(f, "bad openpgp key"),
            Self::BadPeer => write!(f, "bad openpgp peer"),
            Self::Storage => write!(f, "openpgp storage failure"),
            Self::Rng => write!(f, "openpgp rng failure"),
        }
    }
}

impl From<HrngError> for OpgpError {
    fn from(_: HrngError) -> Self {
        Self::Rng
    }
}

impl From<P256Error> for OpgpError {
    fn from(_: P256Error) -> Self {
        Self::BadPeer
    }
}

/// SW ISO 7816 do erro.
pub fn status_word(err: &OpgpError) -> u16 {
    match err {
        OpgpError::InvalidPin { retries_left } => 0x63C0 | u16::from(*retries_left),
        OpgpError::InvalidRc { retries_left } => 0x63C0 | u16::from(*retries_left),
        OpgpError::PinBlocked | OpgpError::RcBlocked => 0x6983,
        OpgpError::NotAuthorized => 0x6982,
        OpgpError::ReadOnly | OpgpError::Terminated => 0x6985,
        OpgpError::BadPin | OpgpError::BadRc | OpgpError::BadP1P2 => 0x6A80,
        OpgpError::UnknownTag => 0x6A82,
        OpgpError::NotProvisioned | OpgpError::NoKey => 0x6A88,
        OpgpError::BadApdu(_) | OpgpError::TooLarge => 0x6700,
        OpgpError::BadIns => 0x6D00,
        OpgpError::BadCla => 0x6E00,
        _ => 0x6F00,
    }
}

/// Sessao volatil (limpa no SELECT e no reboot; nunca persiste).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpgpSession {
    pub(crate) pw1: bool,
    pub(crate) pw3: bool,
}

impl OpgpSession {
    /// Nova sessao sem auth.
    pub fn new() -> Self {
        Self {
            pw1: false,
            pw3: false,
        }
    }

    /// PW1 verificado?
    pub fn pw1(&self) -> bool {
        self.pw1
    }

    /// PW3 verificado?
    pub fn pw3(&self) -> bool {
        self.pw3
    }
}

// Chaves NVS (namespaced opgp/).
const K_SERIAL: &str = "opgp/serial";
const K_PW1H: &str = "opgp/pw1hash";
const K_PW1S: &str = "opgp/pw1salt";
pub(crate) const K_PW1R: &str = "opgp/pw1ret";
const K_PW3H: &str = "opgp/pw3hash";
const K_PW3S: &str = "opgp/pw3salt";
pub(crate) const K_PW3R: &str = "opgp/pw3ret";
const K_RCH: &str = "opgp/rchash";
const K_RCS: &str = "opgp/rcsalt";
pub(crate) const K_RCR: &str = "opgp/rcret";
pub(crate) const K_SIGN: &str = "opgp/key/sign";
pub(crate) const K_FPSIGN: &str = "opgp/fp/sign";
const K_TERM: &str = "opgp/term";

/// Namespace `opgp/`: chaves cruas (sem teto alem do envelope
/// `MAX_PLAINTEXT_BYTES`, fail-closed no `put`), sem quota, delete
/// idempotente (paridade com o comportamento anterior a T5). Ponto unico
/// de put/get + prefixo + verify-after-write (antes manual em `store_blob`).
pub(crate) fn opgp_ns() -> NamespacedStore {
    NamespacedStore {
        prefix: "opgp/",
        max_bytes: None,
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: true,
        strict_index_reads: false,
        validate: opgp_label_ok,
    }
}

/// Gate do label: chaves fixas acima + `do/XXXX` (o applet valida o layout).
pub(crate) fn opgp_label_ok(label: &str) -> bool {
    !label.is_empty() && label.len() <= 64
}

/// Tira o prefixo `opgp/` das chaves fixas p/ o label do namespace.
pub(crate) fn opgp_label(full_key: &str) -> &str {
    full_key.strip_prefix("opgp/").unwrap_or(full_key)
}

pub(crate) fn store_blob<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    key: &str,
    value: &[u8],
) -> Result<(), OpgpError> {
    // Verify-after-write dentro do `put` (antes manual aqui).
    opgp_ns()
        .put(store, opgp_label(key), value)
        .map_err(|_| OpgpError::Storage)
}

pub(crate) fn load_blob<B: FlashStorageBackend>(
    store: &SecureStorage<B>,
    key: &str,
    expect_len: usize,
    missing: OpgpError,
) -> Result<Vec<u8>, OpgpError> {
    match opgp_ns().get(store, opgp_label(key)) {
        Ok(v) if v.len() == expect_len => Ok(v),
        Ok(_) => Err(OpgpError::Storage),
        Err(NamespacedStoreError::NotFound) => Err(missing),
        Err(_) => Err(OpgpError::Storage),
    }
}

pub(crate) fn load_retries<B: FlashStorageBackend>(
    store: &SecureStorage<B>,
    key: &str,
) -> Result<u8, OpgpError> {
    match opgp_ns().get(store, opgp_label(key)) {
        Ok(raw) => {
            if raw.len() != 1 || raw[0] > OPGP_MAX_RETRIES {
                return Err(OpgpError::Storage);
            }
            Ok(raw[0])
        }
        Err(NamespacedStoreError::NotFound) => Ok(OPGP_MAX_RETRIES),
        Err(_) => Err(OpgpError::Storage),
    }
}

pub(crate) fn store_retries<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    key: &str,
    value: u8,
) -> Result<(), OpgpError> {
    store_blob(store, key, &[value])
}

pub(crate) fn hash_pin(salt: &[u8; SALT_LEN], pin: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    h.finalize().into()
}

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn slot_keys(slot: PinSlot) -> (&'static str, &'static str, &'static str, usize, usize) {
    match slot {
        PinSlot::Pw1 => (K_PW1H, K_PW1S, K_PW1R, PW1_MIN, PW_MAX),
        PinSlot::Pw3 => (K_PW3H, K_PW3S, K_PW3R, PW3_MIN, PW_MAX),
    }
}

pub(crate) fn is_provisioned<B: FlashStorageBackend>(store: &SecureStorage<B>) -> bool {
    opgp_ns().get(store, opgp_label(K_PW1H)).is_ok()
}

pub(crate) fn check_terminated<B: FlashStorageBackend>(
    store: &SecureStorage<B>,
) -> Result<(), OpgpError> {
    match opgp_ns().get(store, opgp_label(K_TERM)) {
        Ok(v) if v == alloc::vec![0x01u8] => Err(OpgpError::Terminated),
        Ok(_) => Err(OpgpError::Storage),
        Err(NamespacedStoreError::NotFound) => Ok(()),
        Err(_) => Err(OpgpError::Storage),
    }
}

/// Provisiona o applet (serial + PW1 + PW3 + RC). So em device virgem.
pub fn provision<B, R>(
    store: &mut SecureStorage<B>,
    rng: &mut R,
    serial4: &[u8; 4],
    pw1: &[u8],
    pw3: &[u8],
    rc: &[u8],
) -> Result<(), OpgpError>
where
    B: FlashStorageBackend,
    R: HrngSource,
{
    if is_provisioned(store) {
        return Err(OpgpError::AlreadyProvisioned);
    }
    if !(PW1_MIN..=PW_MAX).contains(&pw1.len()) || !(PW3_MIN..=PW_MAX).contains(&pw3.len()) {
        return Err(OpgpError::BadPin);
    }
    if rc.len() != RC_LEN {
        return Err(OpgpError::BadRc);
    }
    let mut s1 = [0u8; SALT_LEN];
    let mut s3 = [0u8; SALT_LEN];
    let mut sr = [0u8; SALT_LEN];
    rng.fill(&mut s1)?;
    rng.fill(&mut s3)?;
    rng.fill(&mut sr)?;
    let mut h1 = hash_pin(&s1, pw1);
    let mut h3 = hash_pin(&s3, pw3);
    let mut hr = hash_pin(&sr, rc);
    let res = (|| -> Result<(), OpgpError> {
        store_blob(store, K_SERIAL, serial4)?;
        store_blob(store, K_PW1H, &h1)?;
        store_blob(store, K_PW1S, &s1)?;
        store_retries(store, K_PW1R, OPGP_MAX_RETRIES)?;
        store_blob(store, K_PW3H, &h3)?;
        store_blob(store, K_PW3S, &s3)?;
        store_retries(store, K_PW3R, OPGP_MAX_RETRIES)?;
        store_blob(store, K_RCH, &hr)?;
        store_blob(store, K_RCS, &sr)?;
        store_retries(store, K_RCR, OPGP_MAX_RETRIES)?;
        Ok(())
    })();
    s1.zeroize();
    s3.zeroize();
    sr.zeroize();
    h1.zeroize();
    h3.zeroize();
    hr.zeroize();
    res
}

/// Verifica o PIN; sucesso seta a sessao e reseta retries.
pub fn verify<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    session: &mut OpgpSession,
    slot: PinSlot,
    pin: &[u8],
) -> Result<u8, OpgpError> {
    let (kh, ks, kr, min, max) = slot_keys(slot);
    if !(min..=max).contains(&pin.len()) {
        return Err(OpgpError::BadPin);
    }
    let retries = load_retries(store, kr)?;
    if retries == 0 {
        return Err(OpgpError::PinBlocked);
    }
    let salt_raw = load_blob(store, ks, SALT_LEN, OpgpError::NotProvisioned)?;
    let expect = load_blob(store, kh, HASH_LEN, OpgpError::NotProvisioned)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_raw);
    let got = hash_pin(&salt, pin);
    salt.zeroize();
    if !ct_eq(&got, &expect) {
        let left = retries.saturating_sub(1);
        // Torn write aqui vira Storage (contador antigo preservado).
        store_retries(store, kr, left)?;
        if left == 0 {
            return Err(OpgpError::PinBlocked);
        }
        return Err(OpgpError::InvalidPin { retries_left: left });
    }
    store_retries(store, kr, OPGP_MAX_RETRIES)?;
    match slot {
        PinSlot::Pw1 => session.pw1 = true,
        PinSlot::Pw3 => session.pw3 = true,
    }
    Ok(OPGP_MAX_RETRIES)
}

/// Troca o PIN com o valor antigo (erro no antigo consome tentativa).
pub fn change_pin<B, R>(
    store: &mut SecureStorage<B>,
    rng: &mut R,
    slot: PinSlot,
    old_pin: &[u8],
    new_pin: &[u8],
) -> Result<(), OpgpError>
where
    B: FlashStorageBackend,
    R: HrngSource,
{
    let (kh, ks, kr, min, max) = slot_keys(slot);
    if !(min..=max).contains(&new_pin.len()) {
        return Err(OpgpError::BadPin);
    }
    if !(min..=max).contains(&old_pin.len()) {
        return Err(OpgpError::BadPin);
    }
    let retries = load_retries(store, kr)?;
    if retries == 0 {
        return Err(OpgpError::PinBlocked);
    }
    let salt_raw = load_blob(store, ks, SALT_LEN, OpgpError::NotProvisioned)?;
    let expect = load_blob(store, kh, HASH_LEN, OpgpError::NotProvisioned)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_raw);
    let got = hash_pin(&salt, old_pin);
    salt.zeroize();
    if !ct_eq(&got, &expect) {
        let left = retries.saturating_sub(1);
        store_retries(store, kr, left)?;
        if left == 0 {
            return Err(OpgpError::PinBlocked);
        }
        return Err(OpgpError::InvalidPin { retries_left: left });
    }
    let mut nsalt = [0u8; SALT_LEN];
    rng.fill(&mut nsalt)?;
    let mut nhash = hash_pin(&nsalt, new_pin);
    let res = (|| -> Result<(), OpgpError> {
        store_blob(store, kh, &nhash)?;
        store_blob(store, ks, &nsalt)?;
        store_retries(store, kr, OPGP_MAX_RETRIES)?;
        Ok(())
    })();
    nsalt.zeroize();
    nhash.zeroize();
    res
}

/// Reset de fabrica com o RC (apaga tudo do namespace; best-effort).
pub fn reset_factory<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    rc: &[u8],
) -> Result<(), OpgpError> {
    if rc.len() != RC_LEN {
        return Err(OpgpError::BadRc);
    }
    let retries = load_retries(store, K_RCR)?;
    if retries == 0 {
        return Err(OpgpError::RcBlocked);
    }
    let salt_raw = load_blob(store, K_RCS, SALT_LEN, OpgpError::NotProvisioned)?;
    let expect = load_blob(store, K_RCH, HASH_LEN, OpgpError::NotProvisioned)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_raw);
    let got = hash_pin(&salt, rc);
    salt.zeroize();
    if !ct_eq(&got, &expect) {
        let left = retries.saturating_sub(1);
        if store_retries(store, K_RCR, left).is_err() {
            return Err(OpgpError::Storage);
        }
        if left == 0 {
            wipe_namespace(store);
            return Err(OpgpError::RcBlocked);
        }
        return Err(OpgpError::InvalidRc { retries_left: left });
    }
    wipe_namespace(store);
    Ok(())
}

fn wipe_namespace<B: FlashStorageBackend>(store: &mut SecureStorage<B>) {
    for key in [
        K_SERIAL, K_PW1H, K_PW1S, K_PW1R, K_PW3H, K_PW3S, K_PW3R, K_RCH, K_RCS, K_RCR, K_SIGN,
        K_FPSIGN, K_TERM,
    ] {
        let _ = opgp_ns().delete(store, opgp_label(key));
    }
    for tag in [0x5Eu16, 0x5B, 0x5F2D, 0x5F35, 0x5F50] {
        let full = do_key(tag);
        let _ = opgp_ns().delete(store, opgp_label(full.as_str()));
    }
}

/// Termina o applet (exige PW3); so SELECT/ACTIVATE passam depois.
pub fn terminate<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    session: &OpgpSession,
) -> Result<(), OpgpError> {
    if !is_provisioned(store) {
        return Err(OpgpError::NotProvisioned);
    }
    if !session.pw3 {
        return Err(OpgpError::NotAuthorized);
    }
    store_blob(store, K_TERM, &[0x01])
}

/// Reativa o applet (dono unico; documentado).
pub fn activate<B: FlashStorageBackend>(store: &mut SecureStorage<B>) -> Result<(), OpgpError> {
    match opgp_ns().get(store, opgp_label(K_TERM)) {
        Ok(_) => opgp_ns()
            .delete(store, opgp_label(K_TERM))
            .map_err(|_| OpgpError::Storage),
        Err(NamespacedStoreError::NotFound) => Ok(()),
        Err(_) => Err(OpgpError::Storage),
    }
}

/// Monta o AID de 16 B: RID || 01 || ver || manuf || serial || 0000.
pub fn aid<B: FlashStorageBackend>(store: &SecureStorage<B>) -> Result<[u8; 16], OpgpError> {
    let serial = load_blob(store, K_SERIAL, 4, OpgpError::NotProvisioned)?;
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&OPGP_AID_PREFIX);
    out[6..8].copy_from_slice(&OPGP_VERSION);
    out[8..10].copy_from_slice(&OPGP_MANUF);
    out[10..14].copy_from_slice(&serial);
    out[14..16].copy_from_slice(&[0x00, 0x00]);
    Ok(out)
}

pub(crate) fn do_key(tag: u16) -> alloc::string::String {
    alloc::format!("opgp/do/{:04X}", tag)
}

pub use super::openpgp_applet::{
    dispatch, dispatch_raw, generate_sign_key, get_challenge, get_data, import_sign_key, parse_tag,
    pso_decrypt, pso_sign, put_data, pw_status,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_p256::verify_p256;
    use crate::persistence::MockFlashBackend;

    struct TestRng(u64);

    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            for b in dest.iter_mut() {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0 & 0xFF) as u8;
            }
            Ok(())
        }
    }

    fn storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
    }

    fn provisioned() -> (SecureStorage<MockFlashBackend>, TestRng) {
        let mut st = storage();
        let mut rng = TestRng(0xDEAD_BEEF_CAFE_1234);
        provision(
            &mut st,
            &mut rng,
            &[0x12, 0x34, 0x56, 0x78],
            b"123456",
            b"12345678",
            b"12345678",
        )
        .unwrap();
        (st, rng)
    }

    #[test]
    fn provision_aid_vetor() {
        let (st, _) = provisioned();
        // AID = RID || 01 || 0304 || 0000 || serial || 0000 (OpenPGP 3.4.1).
        assert_eq!(
            aid(&st).unwrap().to_vec(),
            hex::decode("D2760001240103040000123456780000").unwrap()
        );
        // SELECT com o prefixo retorna o TLV do AID e reseta a sessao.
        let mut st = st;
        let mut rng = TestRng(1);
        let mut sess = OpgpSession {
            pw1: true,
            pw3: true,
        };
        let sel = hex::decode("00A4040006D27600012401").unwrap();
        let resp = dispatch_raw(&mut st, &mut sess, &mut rng, &sel).unwrap();
        assert_eq!(
            resp,
            hex::decode("4F10D2760001240103040000123456780000").unwrap()
        );
        assert!(!sess.pw1 && !sess.pw3);
        // AID divergente nega; truncado nega.
        let bad = hex::decode("00A4040006D27600012402").unwrap();
        assert_eq!(
            dispatch_raw(&mut st, &mut sess, &mut rng, &bad),
            Err(OpgpError::UnknownTag)
        );
        assert!(matches!(
            dispatch_raw(&mut st, &mut sess, &mut rng, &[0x00, 0xA4]),
            Err(OpgpError::BadApdu(_))
        ));
        // Re-provisionar nega sem apagar.
        let mut rng2 = TestRng(2);
        assert_eq!(
            provision(
                &mut st,
                &mut rng2,
                &[0; 4],
                b"123456",
                b"12345678",
                b"12345678"
            ),
            Err(OpgpError::AlreadyProvisioned)
        );
        assert_eq!(
            aid(&st).unwrap().to_vec(),
            hex::decode("D2760001240103040000123456780000").unwrap()
        );
    }

    #[test]
    fn pw_status_vetor() {
        let (st, _) = provisioned();
        // C4 = [00, maxPW1=64, maxRC=8, maxPW3=64, e1=3, erc=3, e3=3].
        assert_eq!(pw_status(&st).unwrap(), [0x00, 64, 8, 64, 3, 3, 3]);
        let t = get_data(&st, 0xC4).unwrap();
        assert_eq!(t, alloc::vec![0xC4, 0x07, 0x00, 64, 8, 64, 3, 3, 3]);
        assert_eq!(
            status_word(&OpgpError::InvalidPin { retries_left: 2 }),
            0x63C2
        );
        assert_eq!(status_word(&OpgpError::PinBlocked), 0x6983);
        assert_eq!(status_word(&OpgpError::NotAuthorized), 0x6982);
        assert_eq!(status_word(&OpgpError::ReadOnly), 0x6985);
        assert_eq!(status_word(&OpgpError::UnknownTag), 0x6A82);
        assert_eq!(status_word(&OpgpError::NotProvisioned), 0x6A88);
        assert_eq!(status_word(&OpgpError::BadIns), 0x6D00);
        assert_eq!(status_word(&OpgpError::BadCla), 0x6E00);
    }

    #[test]
    fn pin_bloqueio_e_persistencia() {
        let (mut st, _) = provisioned();
        let mut sess = OpgpSession::new();
        assert_eq!(
            verify(&mut st, &mut sess, PinSlot::Pw1, b"000000"),
            Err(OpgpError::InvalidPin { retries_left: 2 })
        );
        assert_eq!(
            verify(&mut st, &mut sess, PinSlot::Pw1, b"000000"),
            Err(OpgpError::InvalidPin { retries_left: 1 })
        );
        assert_eq!(
            verify(&mut st, &mut sess, PinSlot::Pw1, b"000000"),
            Err(OpgpError::PinBlocked)
        );
        // Retry zerado persiste (power-loss nao ressuscita tentativa).
        assert_eq!(st.load(K_PW1R).unwrap(), alloc::vec![0u8]);
        assert_eq!(
            verify(&mut st, &mut sess, PinSlot::Pw1, b"123456"),
            Err(OpgpError::PinBlocked)
        );
        assert!(!sess.pw1);
        // Sucesso reseta e seta sessao.
        let (mut st2, _) = provisioned();
        let mut s2 = OpgpSession::new();
        assert_eq!(verify(&mut st2, &mut s2, PinSlot::Pw1, b"123456"), Ok(3));
        assert!(s2.pw1 && !s2.pw3);
        // Comprimento invalido nao consome.
        assert_eq!(
            verify(&mut st2, &mut s2, PinSlot::Pw1, b"12345"),
            Err(OpgpError::BadPin)
        );
        assert_eq!(st2.load(K_PW1R).unwrap(), alloc::vec![3u8]);
    }

    #[test]
    fn change_pin_e_reset_rc() {
        let (mut st, mut rng) = provisioned();
        // Novo invalido nao consome; velho errado consome uma.
        assert_eq!(
            change_pin(&mut st, &mut rng, PinSlot::Pw1, b"123456", b"12345"),
            Err(OpgpError::BadPin)
        );
        assert_eq!(
            change_pin(&mut st, &mut rng, PinSlot::Pw1, b"000000", b"654321"),
            Err(OpgpError::InvalidPin { retries_left: 2 })
        );
        change_pin(&mut st, &mut rng, PinSlot::Pw1, b"123456", b"654321").unwrap();
        let mut s = OpgpSession::new();
        assert_eq!(verify(&mut st, &mut s, PinSlot::Pw1, b"654321"), Ok(3));
        // RC errado decrementa; certo faz wipe total.
        assert_eq!(
            reset_factory(&mut st, b"00000000"),
            Err(OpgpError::InvalidRc { retries_left: 2 })
        );
        assert_eq!(reset_factory(&mut st, b"123"), Err(OpgpError::BadRc));
        reset_factory(&mut st, b"12345678").unwrap();
        let mut s2 = OpgpSession::new();
        assert_eq!(
            verify(&mut st, &mut s2, PinSlot::Pw1, b"654321"),
            Err(OpgpError::NotProvisioned)
        );
        assert_eq!(status_word(&OpgpError::RcBlocked), 0x6983);
    }

    #[test]
    fn put_get_login_e_leitura() {
        let (mut st, _) = provisioned();
        let mut s = OpgpSession::new();
        // Sem sessao nega.
        assert_eq!(
            put_data(&mut st, &s, 0x5E, b"alice"),
            Err(OpgpError::NotAuthorized)
        );
        verify(&mut st, &mut s, PinSlot::Pw1, b"123456").unwrap();
        put_data(&mut st, &s, 0x5E, b"alice").unwrap();
        assert_eq!(get_data(&st, 0x5E).unwrap(), b"\x5E\x05alice".to_vec());
        // 6E construido contem AID + C4 + login.
        let app = get_data(&st, 0x6E).unwrap();
        assert_eq!(app[0], 0x6E);
        assert!(app.windows(16).any(|w| w
            == hex::decode("D2760001240103040000123456780000")
                .unwrap()
                .as_slice()));
        // Somente-leitura e desconhecida.
        assert_eq!(put_data(&mut st, &s, 0xC7, b"x"), Err(OpgpError::ReadOnly));
        assert_eq!(put_data(&mut st, &s, 0x4F, b"x"), Err(OpgpError::ReadOnly));
        assert_eq!(get_data(&st, 0xFFFF), Err(OpgpError::UnknownTag));
        assert_eq!(parse_tag(0x5F, 0x2D), Ok(0x5F2D));
        assert_eq!(parse_tag(0x01, 0x00), Err(OpgpError::BadP1P2));
        // PUT gigante nega; fingerprint vazio antes da chave.
        assert_eq!(
            put_data(&mut st, &s, 0x5E, &[0u8; 256]),
            Err(OpgpError::TooLarge)
        );
        assert_eq!(get_data(&st, 0xC7).unwrap(), alloc::vec![0xC7, 0x00]);
    }

    #[test]
    fn pso_sign_verify_e_decrypt() {
        let (mut st, mut rng) = provisioned();
        let mut s = OpgpSession::new();
        // Sem auth nega; import exige PW3.
        assert_eq!(pso_sign(&st, &s, b"msg"), Err(OpgpError::NotAuthorized));
        assert_eq!(
            import_sign_key(&mut st, &s, &[0x02u8; 32]),
            Err(OpgpError::NotAuthorized)
        );
        verify(&mut st, &mut s, PinSlot::Pw3, b"12345678").unwrap();
        let public = import_sign_key(&mut st, &s, &[0x02u8; 32]).unwrap();
        assert_eq!(public.len(), 33);
        assert!(public[0] == 0x02 || public[0] == 0x03);
        // Fingerprint = SHA256(pub)[..20] (ancora cruzada independente).
        let mut h = Sha256::new();
        h.update(public);
        let d = h.finalize();
        assert_eq!(get_data(&st, 0xC7).unwrap()[2..], d[..20]);
        verify(&mut st, &mut s, PinSlot::Pw1, b"123456").unwrap();
        let sig = pso_sign(&st, &s, b"documento").unwrap();
        verify_p256(&public, b"documento", &sig).unwrap();
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(verify_p256(&public, b"documento", &bad).is_err());
        assert!(verify_p256(&public, b"outro", &sig).is_err());
        assert_eq!(pso_sign(&st, &s, b""), Err(OpgpError::TooLarge));
        // DEC roundtrip: efemera fixa [0x01; 32].
        let eph = P256Secret::from_bytes([0x01u8; 32]).unwrap();
        let eph_pub = eph.public_compressed();
        let z = ecdh_p256(&[0x01u8; 32], &public).unwrap();
        let mut hk = Sha256::new();
        hk.update(z);
        hk.update(b"aegis-openpgp-ecdh-v1");
        let ks = hk.finalize();
        let pt = b"segredo-dec";
        let ct: Vec<u8> = pt.iter().enumerate().map(|(i, b)| b ^ ks[i % 32]).collect();
        let mut input = eph_pub.to_vec();
        input.extend_from_slice(&ct);
        assert_eq!(pso_decrypt(&st, &s, &input).unwrap(), pt.to_vec());
        // Peer invalido e truncado negam.
        let mut badpeer = [0xFFu8; EPH_LEN].to_vec();
        badpeer.extend_from_slice(&ct);
        assert_eq!(pso_decrypt(&st, &s, &badpeer), Err(OpgpError::BadPeer));
        assert_eq!(pso_decrypt(&st, &s, &[0u8; 33]), Err(OpgpError::TooLarge));
        let _ = get_challenge(&mut rng, 8).unwrap();
    }

    #[test]
    fn generate_no_device() {
        let (mut st, mut rng) = provisioned();
        let mut s = OpgpSession::new();
        assert_eq!(
            generate_sign_key(&mut st, &mut rng, &s).map(|_| ()),
            Err(OpgpError::NotAuthorized)
        );
        verify(&mut st, &mut s, PinSlot::Pw3, b"12345678").unwrap();
        let public = generate_sign_key(&mut st, &mut rng, &s).unwrap();
        assert!(public[0] == 0x02 || public[0] == 0x03);
        verify(&mut st, &mut s, PinSlot::Pw1, b"123456").unwrap();
        let sig = pso_sign(&st, &s, b"teste").unwrap();
        verify_p256(&public, b"teste", &sig).unwrap();
    }

    #[test]
    fn terminate_activate() {
        let (mut st, mut rng) = provisioned();
        let mut s = OpgpSession::new();
        assert_eq!(terminate(&mut st, &s), Err(OpgpError::NotAuthorized));
        verify(&mut st, &mut s, PinSlot::Pw3, b"12345678").unwrap();
        terminate(&mut st, &s).unwrap();
        assert_eq!(get_data(&st, 0x5E), Err(OpgpError::Terminated));
        assert_eq!(
            put_data(&mut st, &s, 0x5E, b"x"),
            Err(OpgpError::Terminated)
        );
        // SELECT ainda passa (e limpa a sessao).
        let sel = hex::decode("00A4040006D27600012401").unwrap();
        assert!(dispatch_raw(&mut st, &mut s, &mut rng, &sel).is_ok());
        activate(&mut st).unwrap();
        assert!(get_data(&st, 0x5E).is_ok());
    }

    #[test]
    fn challenge_e_fios_invalidos() {
        let (mut st, mut rng) = provisioned();
        let mut s = OpgpSession::new();
        let a = get_challenge(&mut rng, 8).unwrap();
        let b = get_challenge(&mut rng, 8).unwrap();
        assert_eq!(a.len(), 8);
        assert_ne!(a, b);
        assert_eq!(get_challenge(&mut rng, 255).unwrap().len(), 255);
        assert_eq!(get_challenge(&mut rng, 7), Err(OpgpError::TooLarge));
        assert_eq!(get_challenge(&mut rng, 256), Err(OpgpError::TooLarge));
        // Fios: CLA/INS/P1P2.
        assert_eq!(
            dispatch_raw(&mut st, &mut s, &mut rng, &[0xFF, 0xA4, 0x04, 0x00]),
            Err(OpgpError::BadCla)
        );
        let ins = hex::decode("00FF0000").unwrap();
        assert_eq!(
            dispatch_raw(&mut st, &mut s, &mut rng, &ins),
            Err(OpgpError::BadIns)
        );
        let badp = hex::decode("0020008206313233343536").unwrap();
        assert_eq!(
            dispatch_raw(&mut st, &mut s, &mut rng, &badp),
            Err(OpgpError::BadP1P2)
        );
        // CHANGE com metade impar nega.
        let ch = hex::decode("0024008303313233").unwrap();
        assert_eq!(
            dispatch_raw(&mut st, &mut s, &mut rng, &ch),
            Err(OpgpError::BadPin)
        );
        assert_eq!(
            status_word(&OpgpError::BadApdu(ApduError::TooShort)),
            0x6700
        );
    }
}
