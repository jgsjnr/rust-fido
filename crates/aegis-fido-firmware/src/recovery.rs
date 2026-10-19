//! Recovery PIN — re-claim com app novo quando o celular dono foi perdido.
//!
//! - PIN 4-6 digitos ASCII, definido no claim via `RECOVERY_SET` (UP fisico).
//! - Verificado no device (`RECOVERY_UNLOCK`): hash+salt no NVS, segredo nunca sai.
//! - 8 tentativas persistidas em NVS (`rec_pin_retries`); esgotou = `Locked`
//!   (so `factory_reset` fisico recupera; `RECOVERY_UNLOCK` com PIN certo
//!   antes de esgotar faz wipe do vinculo e libera re-claim com UP).
//! - `RECOVERY_UNLOCK(pin)` + UP fisico => wipe do `BindingManager`
//!   (re-claim liberado); PIN de recovery preservado ate o novo dono
//!   definir outro via `RECOVERY_SET`.
//! - `no_std` compativel: sem alloc no hot path, sem I/O, TRNG injetavel.
//!
//! CI-GREP: MOCK-ONLY-IN-TEST — `MockFlashBackend` so em `#[cfg(test)]`.

extern crate alloc;

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::binding::BindingManager;
use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Tamanho minimo do PIN de recovery (digitos ASCII).
pub const RECOVERY_PIN_MIN_LEN: usize = 4;
/// Tamanho maximo do PIN de recovery (digitos ASCII).
pub const RECOVERY_PIN_MAX_LEN: usize = 6;
/// Tentativas de PIN persistidas (igual `DEFAULT_PIN_RETRIES`).
pub const RECOVERY_MAX_RETRIES: u8 = 8;
/// Tamanho do salt do PIN (TRNG 16B).
pub const RECOVERY_SALT_LEN: usize = 16;
/// Tamanho do hash do PIN (SHA-256 32B).
pub const RECOVERY_HASH_LEN: usize = 32;
/// Chave NVS do hash do PIN (envelope AEGN v1).
pub const RECOVERY_HASH_NVS_KEY: &str = "rec_pin_hash";
/// Chave NVS do salt do PIN (envelope AEGN v1).
pub const RECOVERY_SALT_NVS_KEY: &str = "rec_pin_salt";
/// Chave NVS das tentativas restantes (1B, envelope AEGN v1).
pub const RECOVERY_RETRIES_NVS_KEY: &str = "rec_pin_retries";
/// Nonce placeholder (ignorado, TRNG dentro de `store`).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// Erro tipado do recovery (sem panics, sem stringly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    /// PIN fora de 4-6 digitos ASCII.
    BadPin,
    /// UP ausente (mapeia NEED_UP).
    PresenceRequired,
    /// Nenhum PIN provisionado.
    NotProvisioned,
    /// Tentativas esgotadas (so reset fisico recupera).
    Locked,
    /// NVS inconsistente (parcial ou descriptografia falhou).
    Corrupted,
    /// Falha de storage.
    Storage,
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadPin => write!(f, "bad recovery pin"),
            Self::PresenceRequired => write!(f, "presence required"),
            Self::NotProvisioned => write!(f, "recovery pin not provisioned"),
            Self::Locked => write!(f, "recovery pin locked"),
            Self::Corrupted => write!(f, "recovery store corrupted"),
            Self::Storage => write!(f, "recovery storage failure"),
        }
    }
}

impl RecoveryError {
    /// Status wire §9.5: `0x01` NEED_UP, `0x02` NEED_PIN, `0x04` BAD_ENVELOPE.
    /// Recovery nunca emite `0x05` (nao e gate de dono; e resgate fisico+PIN).
    pub fn to_vendor_status(self) -> u8 {
        match self {
            Self::PresenceRequired => crate::binding::VENDOR_STATUS_NEED_UP,
            Self::BadPin | Self::Locked => crate::binding::VENDOR_STATUS_NEED_PIN,
            Self::NotProvisioned | Self::Corrupted | Self::Storage => {
                crate::binding::VENDOR_STATUS_BAD_ENVELOPE
            }
        }
    }
}

impl From<StorageError> for RecoveryError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::NotProvisioned,
            StorageError::CorruptedEnvelope | StorageError::DecryptionFailed => Self::Corrupted,
            StorageError::FlashWriteError | StorageError::BufferOverflow => Self::Storage,
        }
    }
}

/// `true` quando o PIN tem 4-6 digitos ASCII (sem alocar, sem logar o valor).
pub fn is_valid_recovery_pin(pin: &str) -> bool {
    let len = pin.len();
    if !(RECOVERY_PIN_MIN_LEN..=RECOVERY_PIN_MAX_LEN).contains(&len) {
        return false;
    }
    pin.bytes().all(|b| b.is_ascii_digit())
}

/// Hash do PIN: `SHA-256(salt || pin_ascii)` (segredo nunca sai do device).
fn hash_pin(salt: &[u8; RECOVERY_SALT_LEN], pin: &str) -> [u8; RECOVERY_HASH_LEN] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; RECOVERY_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compara 32B em tempo constante (evita oraculo de tempo no match do hash).
fn ct_eq_32(a: &[u8; RECOVERY_HASH_LEN], b: &[u8; RECOVERY_HASH_LEN]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < RECOVERY_HASH_LEN {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// `true` quando ha PIN provisionado (tripla hash+salt+retries presente).
pub fn is_provisioned<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> bool {
    storage.exists(RECOVERY_HASH_NVS_KEY)
        && storage.exists(RECOVERY_SALT_NVS_KEY)
        && storage.exists(RECOVERY_RETRIES_NVS_KEY)
}

/// Tentativas restantes (0 quando ausente/bloqueado/corrompido).
pub fn retries_remaining<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> u8 {
    match storage.load(RECOVERY_RETRIES_NVS_KEY) {
        Ok(v) if v.len() == 1 => v[0].min(RECOVERY_MAX_RETRIES),
        _ => 0,
    }
}

/// Define o PIN de recovery: exige UP fisico, valida 4-6 digitos.
///
/// Gera salt 16B via TRNG, grava hash+salt+retries(8) com verify-after-write.
/// Sobrescreve PIN anterior (novo dono deve definir outro apos re-claim).
pub fn set_recovery_pin<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    pin: &str,
    presence_confirmed: bool,
) -> Result<(), RecoveryError> {
    let mut rng = rand_core::OsRng;
    set_recovery_pin_with_rng(storage, pin, presence_confirmed, &mut rng)
}

/// Variante com TRNG injetavel (testes deterministicos).
pub fn set_recovery_pin_with_rng<B: FlashStorageBackend, R: RngCore + CryptoRng>(
    storage: &mut SecureStorage<B>,
    pin: &str,
    presence_confirmed: bool,
    rng: &mut R,
) -> Result<(), RecoveryError> {
    if !presence_confirmed {
        return Err(RecoveryError::PresenceRequired);
    }
    if !is_valid_recovery_pin(pin) {
        return Err(RecoveryError::BadPin);
    }
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut hash = hash_pin(&salt, pin);
    let retries = [RECOVERY_MAX_RETRIES];
    storage.store(RECOVERY_SALT_NVS_KEY, &salt, &IGNORED_NONCE)?;
    storage.store(RECOVERY_HASH_NVS_KEY, &hash, &IGNORED_NONCE)?;
    storage.store(RECOVERY_RETRIES_NVS_KEY, &retries, &IGNORED_NONCE)?;
    let back_hash = storage.load(RECOVERY_HASH_NVS_KEY)?;
    let back_salt = storage.load(RECOVERY_SALT_NVS_KEY)?;
    let back_ret = storage.load(RECOVERY_RETRIES_NVS_KEY)?;
    salt.zeroize();
    hash.zeroize();
    if back_hash.len() != RECOVERY_HASH_LEN
        || back_salt.len() != RECOVERY_SALT_LEN
        || back_ret.as_slice() != retries.as_slice()
    {
        let _ = storage.delete(RECOVERY_HASH_NVS_KEY);
        let _ = storage.delete(RECOVERY_SALT_NVS_KEY);
        let _ = storage.delete(RECOVERY_RETRIES_NVS_KEY);
        return Err(RecoveryError::Storage);
    }
    Ok(())
}

/// Verifica o PIN no device: exige UP, consome 1 tentativa por erro.
///
/// Sucesso reseta para 8 e retorna `Ok`; falha decrementa na NVS
/// (persistida contra queda de energia); 0 restantes => `Locked`.
/// Segredo nunca sai (so compara hash+salt); PIN nao e logado.
pub fn verify_recovery_pin<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    pin: &str,
    presence_confirmed: bool,
) -> Result<(), RecoveryError> {
    if !presence_confirmed {
        return Err(RecoveryError::PresenceRequired);
    }
    let raw_hash = storage.load(RECOVERY_HASH_NVS_KEY)?;
    let raw_salt = storage.load(RECOVERY_SALT_NVS_KEY)?;
    let raw_ret = storage.load(RECOVERY_RETRIES_NVS_KEY)?;
    if raw_hash.len() != RECOVERY_HASH_LEN
        || raw_salt.len() != RECOVERY_SALT_LEN
        || raw_ret.len() != 1
    {
        return Err(RecoveryError::Corrupted);
    }
    let remaining = raw_ret[0];
    if remaining == 0 {
        crate::ltrace!(LtCat::Pin, LtEvt::PinBlocked, 0u8);
        return Err(RecoveryError::Locked);
    }
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    let mut expected = [0u8; RECOVERY_HASH_LEN];
    salt.copy_from_slice(&raw_salt);
    expected.copy_from_slice(&raw_hash);
    let mut candidate = hash_pin(&salt, pin);
    let ok = ct_eq_32(&expected, &candidate);
    salt.zeroize();
    expected.zeroize();
    candidate.zeroize();
    if ok {
        let reset = [RECOVERY_MAX_RETRIES];
        storage
            .store(RECOVERY_RETRIES_NVS_KEY, &reset, &IGNORED_NONCE)
            .map_err(|_| RecoveryError::Storage)?;
        return Ok(());
    }
    let left = remaining.saturating_sub(1);
    let buf = [left];
    let _ = storage.store(RECOVERY_RETRIES_NVS_KEY, &buf, &IGNORED_NONCE);
    if left == 0 {
        crate::ltrace!(LtCat::Pin, LtEvt::PinBlocked, 0u8);
        return Err(RecoveryError::Locked);
    }
    crate::ltrace!(LtCat::Pin, LtEvt::PinRetry, left);
    Err(RecoveryError::BadPin)
}

/// Resgate com app novo perdido: UP fisico + PIN certo => wipe do vinculo.
///
/// Libera re-claim (`BindingManager` volta a `Unclaimed`, NVS de binding
/// limpa, RAM zerada). PIN de recovery preservado (novo dono deve
/// sobrescrever via `RECOVERY_SET`). Retries seguem as regras de `verify`.
pub fn recovery_unlock<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    binding: &mut BindingManager,
    pin: &str,
    presence_confirmed: bool,
) -> Result<(), RecoveryError> {
    verify_recovery_pin(storage, pin, presence_confirmed)?;
    binding.wipe(storage);
    Ok(())
}

/// Apaga o PIN de recovery (troca de dono com wipe completo).
pub fn wipe_recovery_pin<B: FlashStorageBackend>(storage: &mut SecureStorage<B>) {
    let _ = storage.delete(RECOVERY_HASH_NVS_KEY);
    let _ = storage.delete(RECOVERY_SALT_NVS_KEY);
    let _ = storage.delete(RECOVERY_RETRIES_NVS_KEY);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn pin_format_is_4_to_6_digits() {
        assert!(is_valid_recovery_pin("1234"));
        assert!(is_valid_recovery_pin("123456"));
        assert!(!is_valid_recovery_pin("123"));
        assert!(!is_valid_recovery_pin("1234567"));
        assert!(!is_valid_recovery_pin("12a4"));
        assert!(!is_valid_recovery_pin(""));
        assert!(!is_valid_recovery_pin("abcd"));
    }

    #[test]
    fn set_requires_up_and_valid_pin() {
        let mut st = test_storage();
        assert_eq!(
            set_recovery_pin(&mut st, "1234", false),
            Err(RecoveryError::PresenceRequired)
        );
        assert!(!is_provisioned(&st));
        assert_eq!(
            set_recovery_pin(&mut st, "12", true),
            Err(RecoveryError::BadPin)
        );
        assert!(!is_provisioned(&st));
        set_recovery_pin(&mut st, "1234", true).expect("set ok");
        assert!(is_provisioned(&st));
        assert_eq!(retries_remaining(&st), RECOVERY_MAX_RETRIES);
        let raw_hash = st.load(RECOVERY_HASH_NVS_KEY).expect("hash");
        assert_eq!(raw_hash.len(), RECOVERY_HASH_LEN);
        assert!(!raw_hash.windows(4).any(|w| w == b"1234"));
    }

    #[test]
    fn verify_ok_resets_and_wrong_decrements() {
        let mut st = test_storage();
        set_recovery_pin(&mut st, "9876", true).expect("set");
        assert_eq!(
            verify_recovery_pin(&mut st, "9876", false),
            Err(RecoveryError::PresenceRequired)
        );
        assert_eq!(retries_remaining(&st), RECOVERY_MAX_RETRIES);
        assert_eq!(
            verify_recovery_pin(&mut st, "0000", true),
            Err(RecoveryError::BadPin)
        );
        assert_eq!(retries_remaining(&st), RECOVERY_MAX_RETRIES - 1);
        verify_recovery_pin(&mut st, "9876", true).expect("ok");
        assert_eq!(retries_remaining(&st), RECOVERY_MAX_RETRIES);
    }

    #[test]
    fn exhaustion_locks_and_blocks_even_correct_pin() {
        let mut st = test_storage();
        set_recovery_pin(&mut st, "5555", true).expect("set");
        for _ in 0..RECOVERY_MAX_RETRIES - 1 {
            assert_eq!(
                verify_recovery_pin(&mut st, "0000", true),
                Err(RecoveryError::BadPin)
            );
        }
        assert_eq!(retries_remaining(&st), 1);
        assert_eq!(
            verify_recovery_pin(&mut st, "0000", true),
            Err(RecoveryError::Locked)
        );
        assert_eq!(retries_remaining(&st), 0);
        assert_eq!(
            verify_recovery_pin(&mut st, "5555", true),
            Err(RecoveryError::Locked)
        );
        assert_eq!(RecoveryError::BadPin.to_vendor_status(), 0x02);
        assert_eq!(RecoveryError::Locked.to_vendor_status(), 0x02);
        assert_eq!(RecoveryError::PresenceRequired.to_vendor_status(), 0x01);
    }

    #[test]
    fn unlock_wipes_binding_and_allows_reclaim() {
        use crate::binding::{BIND_ID_LEN, BIND_PUB_LEN};
        let mut st = test_storage();
        let sk_bytes = [0x11u8; 32];
        let sk = p256::ecdsa::SigningKey::from_slice(&sk_bytes).expect("scalar");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        let id = [0xABu8; BIND_ID_LEN];
        let mut m = BindingManager::new();
        m.claim(&sec1, &id, true, true).expect("claim");
        m.persist(&mut st).expect("persist");
        set_recovery_pin(&mut st, "4242", true).expect("set pin");
        assert!(m.is_claimed());
        assert_eq!(
            recovery_unlock(&mut st, &mut m, "0000", true),
            Err(RecoveryError::BadPin)
        );
        assert!(m.is_claimed());
        recovery_unlock(&mut st, &mut m, "4242", true).expect("unlock");
        assert!(!m.is_claimed());
        assert!(!st.exists(crate::binding::BIND_PUB_NVS_KEY));
        let sk2 = p256::ecdsa::SigningKey::from_slice(&[0x22u8; 32]).expect("scalar");
        let pt2 = sk2.verifying_key().to_encoded_point(false);
        let mut sec1_b = [0u8; BIND_PUB_LEN];
        sec1_b.copy_from_slice(pt2.as_bytes());
        m.claim(&sec1_b, &[0x09u8; BIND_ID_LEN], true, true)
            .expect("reclaim ok");
        assert!(m.is_claimed());
        let mut m2 = BindingManager::new();
        m2.claim(&sec1, &id, true, true).expect("claim2");
        assert_eq!(
            recovery_unlock(&mut st, &mut m2, "4242", false),
            Err(RecoveryError::PresenceRequired)
        );
    }
}
