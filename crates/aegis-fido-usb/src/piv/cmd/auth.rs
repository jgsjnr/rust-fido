use super::admin::PivRecordStore;
use super::parse::{
    PIV_HASH_LEN, PIV_NVS_PIN_HASH, PIV_NVS_PIN_RETRIES, PIV_NVS_PIN_SALT, PIV_NVS_PUK_HASH,
    PIV_NVS_PUK_RETRIES, PIV_NVS_PUK_SALT, PIV_PIN_MAX_LEN, PIV_PIN_MAX_RETRIES, PIV_PIN_MIN_LEN,
    PIV_PUK_LEN, PIV_PUK_MAX_RETRIES, PIV_SALT_LEN,
};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
/// Erro tipado do provisionamento PIN/PUK (sem panics, sem stringly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivPinError {
    /// PIN fora de 6-8 bytes.
    BadPin,
    /// PUK diferente de 8 bytes.
    BadPuk,
    /// Já provisionado (use CHANGE/UNBLOCK).
    AlreadyProvisioned,
    /// Falha de store.
    Storage,
    /// Verify-after-write divergiu (store não confiável; registros apagados).
    VerifyFailed,
}

/// Hash do PIN/PUK: `SHA-256(salt || pin)` (segredo nunca sai; padrão `recovery.rs`).
pub(crate) fn hash_pin(salt: &[u8; PIV_SALT_LEN], pin: &[u8]) -> [u8; PIV_HASH_LEN] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    let digest = h.finalize();
    let mut out = [0u8; PIV_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compara 32B em tempo constante (sem oráculo de tempo; padrão `recovery.rs`).
pub(crate) fn ct_eq_32(a: &[u8; PIV_HASH_LEN], b: &[u8; PIV_HASH_LEN]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < PIV_HASH_LEN {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// `true` quando o PIN tem 6-8 bytes (qualquer byte; o host conhece o formato).
pub fn is_valid_piv_pin(pin: &[u8]) -> bool {
    (PIV_PIN_MIN_LEN..=PIV_PIN_MAX_LEN).contains(&pin.len())
}

/// `true` quando o PUK tem exatamente 8 bytes.
pub fn is_valid_piv_puk(puk: &[u8]) -> bool {
    puk.len() == PIV_PUK_LEN
}

/// Grava um par salt+hash+retries com verify-after-write; zeroiza transitórios.
pub(crate) fn write_credential<S: PivRecordStore>(
    store: &mut S,
    salt_key: &str,
    hash_key: &str,
    retries_key: &str,
    secret: &[u8],
    rng: &mut impl CryptoRng,
    max_retries: u8,
) -> Result<(), PivPinError> {
    let mut salt = [0u8; PIV_SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut hash = hash_pin(&salt, secret);
    let retries = [max_retries];
    let res = (|| {
        store
            .store_record(salt_key, &salt)
            .map_err(|_| PivPinError::Storage)?;
        store
            .store_record(hash_key, &hash)
            .map_err(|_| PivPinError::Storage)?;
        store
            .store_record(retries_key, &retries)
            .map_err(|_| PivPinError::Storage)?;
        let back_hash = store
            .load_record(hash_key)
            .map_err(|_| PivPinError::Storage)?;
        let back_salt = store
            .load_record(salt_key)
            .map_err(|_| PivPinError::Storage)?;
        let back_ret = store
            .load_record(retries_key)
            .map_err(|_| PivPinError::Storage)?;
        if back_hash.as_slice() != hash.as_slice()
            || back_salt.as_slice() != salt.as_slice()
            || back_ret.as_slice() != retries.as_slice()
        {
            return Err(PivPinError::VerifyFailed);
        }
        Ok(())
    })();
    salt.zeroize();
    hash.zeroize();
    res
}

/// Provisiona PIN+PUK iniciais: exige aparelho virgem, valida, grava com
/// verify-after-write. Chamado no enrollment do firmware (gate UP); nunca via APDU.
///
/// Requer a feature `getrandom` (ligada por padrão via `std`): o salt vem do
/// RNG do SO (`getrandom::SysRng`). Alvos bare-metal/ESP32 sem RNG de SO devem
/// desligar `getrandom` (`--no-default-features`) e semear explicitamente via
/// [`provision_pin_with_rng`], ou registrar um backend `getrandom` customizado
/// e religar a feature `getrandom`.
#[cfg(feature = "getrandom")]
pub fn provision_pin<S: PivRecordStore>(
    store: &mut S,
    new_pin: &[u8],
    new_puk: &[u8],
) -> Result<(), PivPinError> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    provision_pin_with_rng(store, &mut rng, new_pin, new_puk)
}

/// Variante com RNG injetável (testes determinísticos).
pub fn provision_pin_with_rng<S: PivRecordStore, R: CryptoRng>(
    store: &mut S,
    rng: &mut R,
    new_pin: &[u8],
    new_puk: &[u8],
) -> Result<(), PivPinError> {
    if !is_valid_piv_pin(new_pin) {
        return Err(PivPinError::BadPin);
    }
    if !is_valid_piv_puk(new_puk) {
        return Err(PivPinError::BadPuk);
    }
    if store.load_record(PIV_NVS_PIN_HASH).is_ok() || store.load_record(PIV_NVS_PUK_HASH).is_ok() {
        return Err(PivPinError::AlreadyProvisioned);
    }
    if let Err(e) = write_credential(
        store,
        PIV_NVS_PIN_SALT,
        PIV_NVS_PIN_HASH,
        PIV_NVS_PIN_RETRIES,
        new_pin,
        rng,
        PIV_PIN_MAX_RETRIES,
    ) {
        wipe_pin_records(store);
        return Err(e);
    }
    if let Err(e) = write_credential(
        store,
        PIV_NVS_PUK_SALT,
        PIV_NVS_PUK_HASH,
        PIV_NVS_PUK_RETRIES,
        new_puk,
        rng,
        PIV_PUK_MAX_RETRIES,
    ) {
        wipe_pin_records(store);
        return Err(e);
    }
    Ok(())
}

/// Apaga os seis registros PIN/PUK (idempotente; base do wipe por PUK).
pub(crate) fn wipe_pin_records<S: PivRecordStore>(store: &mut S) {
    for key in [
        PIV_NVS_PIN_HASH,
        PIV_NVS_PIN_SALT,
        PIV_NVS_PIN_RETRIES,
        PIV_NVS_PUK_HASH,
        PIV_NVS_PUK_SALT,
        PIV_NVS_PUK_RETRIES,
    ] {
        let _ = store.delete_record(key);
    }
}
