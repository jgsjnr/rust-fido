//! T-PI-01 Portao PIV: parser APDU com limites + PIN/PUK com bloqueio (GEN-DEVICE).
//!
//! Motivo: o applet PIV (`aegis_fido_usb::piv`) define o fio, mas a politica
//! de tentativas/bloqueio precisa de dono no firmware com persistencia e
//! verify-after-write; sem este modulo, retry zeraria no reboot (secao 9).
//!
//! - Nao edita `piv_store.rs`: so consome `PivRecordStore` (+ `PivNvsStore`
//!   nos testes, que e o adapter real, sem mock de comportamento).
//! - Reusa chaves NVS, limites e contadores de `aegis_fido_usb::piv`
//!   (6-8 B PIN, 8 B PUK, 3 tentativas cada; hash `SHA-256(salt || pin)` no
//!   mesmo formato do applet, para interoperar com ele).
//! - APDU curto estrito: cabecalho 4 B + Lc + dados + Le opcional; Lc = 0
//!   (marcador de estendido) e negado (`UnsupportedExtended`); total > 261 B
//!   e negado (sem numero magico novo: 4 + 1 + 255 + 1).
//! - Bloqueio gruda: retries em NVS com verify-after-write; PIN zerado exige
//!   PUK; PUK zerado apaga os registros PIN/PUK (wipe) e nega tudo ate
//!   re-provisionar. Comprimento invalido nao consome tentativa.
//! - `status_word` mapeia cada erro p/ SW ISO 7816 (`63 CX`, `69 83`...).
//! - Segredo nunca em log: erros sem PIN/PUK/salt/hash; buffers zerados.

extern crate alloc;

use aegis_fido_usb::piv::{
    PivRecordStore, PivStoreError, PIV_HASH_LEN, PIV_NVS_PIN_HASH, PIV_NVS_PIN_RETRIES,
    PIV_NVS_PIN_SALT, PIV_NVS_PUK_HASH, PIV_NVS_PUK_RETRIES, PIV_NVS_PUK_SALT, PIV_PIN_MAX_LEN,
    PIV_PIN_MAX_RETRIES, PIV_PIN_MIN_LEN, PIV_PUK_LEN, PIV_PUK_MAX_RETRIES, PIV_SALT_LEN,
};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto_hrng::{HrngError, HrngSource};

pub use crate::apdu::{parse_apdu, Apdu, ApduError, APDU_MAX_TOTAL};

/// SW de sucesso.
pub const SW_OK: u16 = 0x9000;

/// Erros do portao PIN/PUK. Sem PIN, PUK, salt ou hash nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivCmdError {
    /// PIN/PUK ainda nao provisionado.
    NotProvisioned,
    /// Ja provisionado (use CHANGE/UNBLOCK).
    AlreadyProvisioned,
    /// PIN fora de 6..=8 B (nao consome tentativa).
    BadPin,
    /// PUK diferente de 8 B (nao consome tentativa).
    BadPuk,
    /// PIN errado; tentativas restantes no campo.
    InvalidPin { retries_left: u8 },
    /// PUK errado; tentativas restantes no campo.
    InvalidPuk { retries_left: u8 },
    /// PIN bloqueado (exige PUK).
    PinBlocked,
    /// PUK bloqueado (registros apagados; exige re-provisionar).
    PukBlocked,
    /// Falha de store / verify-after-write.
    Storage,
    /// HRNG indisponivel para o salt.
    Rng,
}

impl core::fmt::Display for PivCmdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotProvisioned => write!(f, "piv pin not provisioned"),
            Self::AlreadyProvisioned => write!(f, "piv pin already provisioned"),
            Self::BadPin => write!(f, "bad piv pin length"),
            Self::BadPuk => write!(f, "bad piv puk length"),
            Self::InvalidPin { .. } => write!(f, "wrong piv pin"),
            Self::InvalidPuk { .. } => write!(f, "wrong piv puk"),
            Self::PinBlocked => write!(f, "piv pin blocked"),
            Self::PukBlocked => write!(f, "piv puk blocked"),
            Self::Storage => write!(f, "piv storage failure"),
            Self::Rng => write!(f, "piv rng failure"),
        }
    }
}

impl From<HrngError> for PivCmdError {
    fn from(_: HrngError) -> Self {
        Self::Rng
    }
}

/// SW ISO 7816 para cada erro (`63 CX` carrega as tentativas restantes).
pub fn status_word(err: &PivCmdError) -> u16 {
    match err {
        PivCmdError::InvalidPin { retries_left } => 0x63C0 | u16::from(*retries_left),
        PivCmdError::InvalidPuk { retries_left } => 0x63C0 | u16::from(*retries_left),
        PivCmdError::PinBlocked | PivCmdError::PukBlocked => 0x6983,
        PivCmdError::NotProvisioned => 0x6A88,
        PivCmdError::BadPin | PivCmdError::BadPuk => 0x6A80,
        PivCmdError::AlreadyProvisioned => 0x6985,
        PivCmdError::Storage | PivCmdError::Rng => 0x6F00,
    }
}

// parse_apdu vive em crate::apdu (reexportado acima).

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `SHA-256(salt || pin)` (mesmo formato do applet USB; interoperavel).
fn hash_pin(salt: &[u8; PIV_SALT_LEN], pin: &[u8]) -> [u8; PIV_HASH_LEN] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    h.finalize().into()
}

fn validate_pin_len(pin: &[u8]) -> Result<(), PivCmdError> {
    if (PIV_PIN_MIN_LEN..=PIV_PIN_MAX_LEN).contains(&pin.len()) {
        Ok(())
    } else {
        Err(PivCmdError::BadPin)
    }
}

fn validate_puk_len(puk: &[u8]) -> Result<(), PivCmdError> {
    if puk.len() == PIV_PUK_LEN {
        Ok(())
    } else {
        Err(PivCmdError::BadPuk)
    }
}

fn store_blob<S: PivRecordStore>(
    store: &mut S,
    key: &str,
    value: &[u8],
) -> Result<(), PivCmdError> {
    store
        .store_record(key, value)
        .map_err(|_| PivCmdError::Storage)?;
    match store.load_record(key) {
        Ok(back) if back.as_slice() == value => Ok(()),
        _ => Err(PivCmdError::Storage),
    }
}

fn load_blob<S: PivRecordStore>(
    store: &S,
    key: &str,
    expect_len: usize,
    missing: PivCmdError,
) -> Result<Vec<u8>, PivCmdError> {
    match store.load_record(key) {
        Ok(v) if v.len() == expect_len => Ok(v),
        Ok(_) => Err(PivCmdError::Storage),
        Err(PivStoreError::NotFound) => Err(missing),
        Err(_) => Err(PivCmdError::Storage),
    }
}

fn load_retries<S: PivRecordStore>(store: &S, key: &str, max: u8) -> Result<u8, PivCmdError> {
    match store.load_record(key) {
        Ok(raw) => {
            if raw.len() != 1 || raw[0] > max {
                return Err(PivCmdError::Storage);
            }
            Ok(raw[0])
        }
        Err(PivStoreError::NotFound) => Ok(max),
        Err(_) => Err(PivCmdError::Storage),
    }
}

fn store_retries<S: PivRecordStore>(
    store: &mut S,
    key: &str,
    value: u8,
) -> Result<(), PivCmdError> {
    store
        .store_record(key, &[value])
        .map_err(|_| PivCmdError::Storage)?;
    match store.load_record(key) {
        Ok(back) if back.as_slice() == [value].as_slice() => Ok(()),
        _ => Err(PivCmdError::Storage),
    }
}

/// Confere o PIN sem tocar retries no sucesso (chamador decide o passo).
fn match_pin<S: PivRecordStore>(store: &S, pin: &[u8]) -> Result<(), PivCmdError> {
    let salt_raw = load_blob(
        store,
        PIV_NVS_PIN_SALT,
        PIV_SALT_LEN,
        PivCmdError::NotProvisioned,
    )?;
    let expect = load_blob(
        store,
        PIV_NVS_PIN_HASH,
        PIV_HASH_LEN,
        PivCmdError::NotProvisioned,
    )?;
    let mut salt = [0u8; PIV_SALT_LEN];
    salt.copy_from_slice(&salt_raw);
    let got = hash_pin(&salt, pin);
    salt.zeroize();
    if ct_eq(&got, &expect) {
        Ok(())
    } else {
        Err(PivCmdError::InvalidPin { retries_left: 0 })
    }
}

fn decrement_pin<S: PivRecordStore>(store: &mut S, retries: u8) -> PivCmdError {
    let left = retries.saturating_sub(1);
    // Torn write aqui vira Storage (contador antigo preservado, sem delete).
    if store_retries(store, PIV_NVS_PIN_RETRIES, left).is_err() {
        return PivCmdError::Storage;
    }
    if left == 0 {
        PivCmdError::PinBlocked
    } else {
        PivCmdError::InvalidPin { retries_left: left }
    }
}

/// Provisiona PIN+PUK (so em dispositivo virgem; enrollment com UP no transporte).
pub fn provision_piv_pin<S, R>(
    store: &mut S,
    rng: &mut R,
    pin: &[u8],
    puk: &[u8],
) -> Result<(), PivCmdError>
where
    S: PivRecordStore,
    R: HrngSource,
{
    match store.load_record(PIV_NVS_PIN_HASH) {
        Ok(_) => return Err(PivCmdError::AlreadyProvisioned),
        Err(PivStoreError::NotFound) => {}
        Err(_) => return Err(PivCmdError::Storage),
    }
    validate_pin_len(pin)?;
    validate_puk_len(puk)?;
    let mut pin_salt = [0u8; PIV_SALT_LEN];
    let mut puk_salt = [0u8; PIV_SALT_LEN];
    rng.fill(&mut pin_salt)?;
    rng.fill(&mut puk_salt)?;
    let mut pin_hash = hash_pin(&pin_salt, pin);
    let mut puk_hash = hash_pin(&puk_salt, puk);
    let res = (|| -> Result<(), PivCmdError> {
        store_blob(store, PIV_NVS_PIN_HASH, &pin_hash)?;
        store_blob(store, PIV_NVS_PIN_SALT, &pin_salt)?;
        store_retries(store, PIV_NVS_PIN_RETRIES, PIV_PIN_MAX_RETRIES)?;
        store_blob(store, PIV_NVS_PUK_HASH, &puk_hash)?;
        store_blob(store, PIV_NVS_PUK_SALT, &puk_salt)?;
        store_retries(store, PIV_NVS_PUK_RETRIES, PIV_PUK_MAX_RETRIES)?;
        Ok(())
    })();
    pin_salt.zeroize();
    puk_salt.zeroize();
    pin_hash.zeroize();
    puk_hash.zeroize();
    res
}

/// Verifica o PIN; sucesso reseta retries e retorna o maximo.
pub fn verify_piv_pin<S: PivRecordStore>(store: &mut S, pin: &[u8]) -> Result<u8, PivCmdError> {
    validate_pin_len(pin)?;
    let retries = load_retries(store, PIV_NVS_PIN_RETRIES, PIV_PIN_MAX_RETRIES)?;
    if retries == 0 {
        return Err(PivCmdError::PinBlocked);
    }
    match match_pin(store, pin) {
        Ok(()) => {
            store_retries(store, PIV_NVS_PIN_RETRIES, PIV_PIN_MAX_RETRIES)?;
            Ok(PIV_PIN_MAX_RETRIES)
        }
        Err(PivCmdError::InvalidPin { .. }) => Err(decrement_pin(store, retries)),
        Err(e) => Err(e),
    }
}

/// Desbloqueia com o PUK e troca o PIN (reseta ambos os contadores).
pub fn unblock_piv_pin<S, R>(
    store: &mut S,
    rng: &mut R,
    puk: &[u8],
    new_pin: &[u8],
) -> Result<(), PivCmdError>
where
    S: PivRecordStore,
    R: HrngSource,
{
    validate_puk_len(puk)?;
    validate_pin_len(new_pin)?;
    let retries = load_retries(store, PIV_NVS_PUK_RETRIES, PIV_PUK_MAX_RETRIES)?;
    if retries == 0 {
        return Err(PivCmdError::PukBlocked);
    }
    let salt_raw = load_blob(
        store,
        PIV_NVS_PUK_SALT,
        PIV_SALT_LEN,
        PivCmdError::NotProvisioned,
    )?;
    let expect = load_blob(
        store,
        PIV_NVS_PUK_HASH,
        PIV_HASH_LEN,
        PivCmdError::NotProvisioned,
    )?;
    let mut salt = [0u8; PIV_SALT_LEN];
    salt.copy_from_slice(&salt_raw);
    let got = hash_pin(&salt, puk);
    salt.zeroize();
    if !ct_eq(&got, &expect) {
        let left = retries.saturating_sub(1);
        if store_retries(store, PIV_NVS_PUK_RETRIES, left).is_err() {
            return Err(PivCmdError::Storage);
        }
        if left == 0 {
            wipe_piv_records(store);
            return Err(PivCmdError::PukBlocked);
        }
        return Err(PivCmdError::InvalidPuk { retries_left: left });
    }
    let mut pin_salt = [0u8; PIV_SALT_LEN];
    rng.fill(&mut pin_salt)?;
    let mut pin_hash = hash_pin(&pin_salt, new_pin);
    let res = (|| -> Result<(), PivCmdError> {
        store_blob(store, PIV_NVS_PIN_HASH, &pin_hash)?;
        store_blob(store, PIV_NVS_PIN_SALT, &pin_salt)?;
        store_retries(store, PIV_NVS_PIN_RETRIES, PIV_PIN_MAX_RETRIES)?;
        store_retries(store, PIV_NVS_PUK_RETRIES, PIV_PUK_MAX_RETRIES)?;
        Ok(())
    })();
    pin_salt.zeroize();
    pin_hash.zeroize();
    res
}

/// Troca o PIN com o valor antigo (falha no antigo consome tentativa).
pub fn change_piv_pin<S, R>(
    store: &mut S,
    rng: &mut R,
    old_pin: &[u8],
    new_pin: &[u8],
) -> Result<(), PivCmdError>
where
    S: PivRecordStore,
    R: HrngSource,
{
    validate_pin_len(old_pin)?;
    validate_pin_len(new_pin)?;
    let retries = load_retries(store, PIV_NVS_PIN_RETRIES, PIV_PIN_MAX_RETRIES)?;
    if retries == 0 {
        return Err(PivCmdError::PinBlocked);
    }
    match match_pin(store, old_pin) {
        Ok(()) => {}
        Err(PivCmdError::InvalidPin { .. }) => return Err(decrement_pin(store, retries)),
        Err(e) => return Err(e),
    }
    let mut salt = [0u8; PIV_SALT_LEN];
    rng.fill(&mut salt)?;
    let mut hash = hash_pin(&salt, new_pin);
    let res = (|| -> Result<(), PivCmdError> {
        store_blob(store, PIV_NVS_PIN_HASH, &hash)?;
        store_blob(store, PIV_NVS_PIN_SALT, &salt)?;
        store_retries(store, PIV_NVS_PIN_RETRIES, PIV_PIN_MAX_RETRIES)?;
        Ok(())
    })();
    salt.zeroize();
    hash.zeroize();
    res
}

/// Apaga os registros PIN/PUK (best-effort; chamado com PUK esgotado).
fn wipe_piv_records<S: PivRecordStore>(store: &mut S) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_hrng::HrngError;
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use crate::piv_store::PivNvsStore;

    /// HRNG deterministico de teste (xorshift; so p/ salt em teste).
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

    fn provisioned() -> (SecureStorage<MockFlashBackend>, TestRng) {
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32]);
        let mut rng = TestRng(0xDEAD_BEEF_CAFE_1234);
        {
            let mut ps = PivNvsStore::new(&mut st);
            provision_piv_pin(&mut ps, &mut rng, b"123456", b"12345678").unwrap();
        }
        (st, rng)
    }

    #[test]
    fn provision_verify_roundtrip() {
        let (mut st, _) = provisioned();
        let mut ps = PivNvsStore::new(&mut st);
        assert_eq!(verify_piv_pin(&mut ps, b"123456"), Ok(PIV_PIN_MAX_RETRIES));
        // Re-provisionar nega sem apagar.
        let mut rng = TestRng(1);
        assert_eq!(
            provision_piv_pin(&mut ps, &mut rng, b"654321", b"87654321"),
            Err(PivCmdError::AlreadyProvisioned)
        );
        assert_eq!(verify_piv_pin(&mut ps, b"123456"), Ok(PIV_PIN_MAX_RETRIES));
        // Virgem = NotProvisioned (nunca Blocked).
        let mut fresh = SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32]);
        let mut fp = PivNvsStore::new(&mut fresh);
        assert_eq!(
            verify_piv_pin(&mut fp, b"123456"),
            Err(PivCmdError::NotProvisioned)
        );
        assert_eq!(status_word(&PivCmdError::NotProvisioned), 0x6A88);
    }

    #[test]
    fn pin_errado_decrementa_e_bloqueia() {
        let (mut st, _) = provisioned();
        let mut ps = PivNvsStore::new(&mut st);
        assert_eq!(
            verify_piv_pin(&mut ps, b"000000"),
            Err(PivCmdError::InvalidPin { retries_left: 2 })
        );
        assert_eq!(
            status_word(&PivCmdError::InvalidPin { retries_left: 2 }),
            0x63C2
        );
        assert_eq!(
            verify_piv_pin(&mut ps, b"000000"),
            Err(PivCmdError::InvalidPin { retries_left: 1 })
        );
        assert_eq!(
            verify_piv_pin(&mut ps, b"000000"),
            Err(PivCmdError::PinBlocked)
        );
        assert_eq!(status_word(&PivCmdError::PinBlocked), 0x6983);
        // Bloqueado nao verifica nem com o PIN certo.
        assert_eq!(
            verify_piv_pin(&mut ps, b"123456"),
            Err(PivCmdError::PinBlocked)
        );
    }

    #[test]
    fn comprimento_invalido_nao_consome() {
        let (mut st, _) = provisioned();
        let mut ps = PivNvsStore::new(&mut st);
        assert_eq!(verify_piv_pin(&mut ps, b"12345"), Err(PivCmdError::BadPin));
        assert_eq!(
            verify_piv_pin(&mut ps, b"123456789"),
            Err(PivCmdError::BadPin)
        );
        assert_eq!(status_word(&PivCmdError::BadPin), 0x6A80);
        // Retries intactos.
        assert_eq!(verify_piv_pin(&mut ps, b"123456"), Ok(PIV_PIN_MAX_RETRIES));
    }

    #[test]
    fn unblock_reseta_e_puk_esgotado_apaga() {
        let (mut st, mut rng) = provisioned();
        {
            let mut ps = PivNvsStore::new(&mut st);
            // Esgota o PIN primeiro.
            for _ in 0..PIV_PIN_MAX_RETRIES {
                let _ = verify_piv_pin(&mut ps, b"000000");
            }
            assert_eq!(
                verify_piv_pin(&mut ps, b"123456"),
                Err(PivCmdError::PinBlocked)
            );
            // PUK errado decrementa sem apagar ainda.
            assert_eq!(
                unblock_piv_pin(&mut ps, &mut rng, b"00000000", b"654321"),
                Err(PivCmdError::InvalidPuk { retries_left: 2 })
            );
            // PUK certo troca o PIN e reseta tudo.
            unblock_piv_pin(&mut ps, &mut rng, b"12345678", b"654321").unwrap();
            assert_eq!(verify_piv_pin(&mut ps, b"654321"), Ok(PIV_PIN_MAX_RETRIES));
        }
        // Esgota o PUK: wipe total.
        {
            let mut ps = PivNvsStore::new(&mut st);
            assert_eq!(
                unblock_piv_pin(&mut ps, &mut rng, b"00000000", b"111111"),
                Err(PivCmdError::InvalidPuk { retries_left: 2 })
            );
            assert_eq!(
                unblock_piv_pin(&mut ps, &mut rng, b"00000000", b"111111"),
                Err(PivCmdError::InvalidPuk { retries_left: 1 })
            );
            assert_eq!(
                unblock_piv_pin(&mut ps, &mut rng, b"00000000", b"111111"),
                Err(PivCmdError::PukBlocked)
            );
            assert_eq!(status_word(&PivCmdError::PukBlocked), 0x6983);
            assert_eq!(
                verify_piv_pin(&mut ps, b"654321"),
                Err(PivCmdError::NotProvisioned)
            );
        }
    }

    #[test]
    fn change_exige_antigo_e_valida_novo() {
        let (mut st, mut rng) = provisioned();
        let mut ps = PivNvsStore::new(&mut st);
        // Novo com comprimento invalido nao consome.
        assert_eq!(
            change_piv_pin(&mut ps, &mut rng, b"123456", b"12345"),
            Err(PivCmdError::BadPin)
        );
        // Antigo errado consome uma tentativa.
        assert_eq!(
            change_piv_pin(&mut ps, &mut rng, b"000000", b"654321"),
            Err(PivCmdError::InvalidPin { retries_left: 2 })
        );
        change_piv_pin(&mut ps, &mut rng, b"123456", b"654321").unwrap();
        assert_eq!(verify_piv_pin(&mut ps, b"654321"), Ok(PIV_PIN_MAX_RETRIES));
        assert_eq!(
            verify_piv_pin(&mut ps, b"123456"),
            Err(PivCmdError::InvalidPin { retries_left: 2 })
        );
    }

    #[test]
    fn apdu_limites() {
        // So cabecalho.
        let a = parse_apdu(&[0x00, 0x20, 0x00, 0x80]).unwrap();
        assert!(!a.le_present && a.data.is_empty());
        // Lc + dados + Le.
        let a = parse_apdu(&[0x00, 0x20, 0x00, 0x80, 0x02, 0x31, 0x32, 0x00]).unwrap();
        assert_eq!(a.data.as_slice(), b"12");
        assert!(a.le_present);
        // Lc + dados sem Le.
        let a = parse_apdu(&[0x00, 0x20, 0x00, 0x80, 0x01, 0xFF]).unwrap();
        assert_eq!(a.data.as_slice(), &[0xFF]);
        assert!(!a.le_present);
        // Truncados e sobras.
        assert_eq!(parse_apdu(&[0x00, 0x20, 0x00]), Err(ApduError::TooShort));
        assert_eq!(
            parse_apdu(&[0x00, 0x20, 0x00, 0x80, 0x02, 0x31]),
            Err(ApduError::BadLength)
        );
        assert_eq!(
            parse_apdu(&[0x00, 0x20, 0x00, 0x80, 0x01, 0xFF, 0x00, 0x00]),
            Err(ApduError::BadLength)
        );
        // Estendido negado; total gigante negado.
        assert_eq!(
            parse_apdu(&[0x00, 0x20, 0x00, 0x80, 0x00]),
            Err(ApduError::UnsupportedExtended)
        );
        let huge = alloc::vec![0u8; APDU_MAX_TOTAL + 1];
        assert_eq!(parse_apdu(&huge), Err(ApduError::TooLarge));
        // Teto exato passa (4 + 1 + 255 + 1).
        let mut max = alloc::vec![0u8; APDU_MAX_TOTAL];
        max[4] = 255;
        assert!(parse_apdu(&max).is_ok());
    }
}
