/// GET DATA instruction (ISO 7816-4 / NIST SP 800-73).
pub(crate) const INS_GET_DATA: u8 = 0xCB;
/// SELECT instruction.
pub(crate) const INS_SELECT: u8 = 0xA4;
/// VERIFY instruction (PIN).
pub(crate) const INS_VERIFY: u8 = 0x20;
/// CHANGE REFERENCE DATA instruction (troca PIN/PUK com o valor antigo).
pub(crate) const INS_CHANGE: u8 = 0x24;
/// RESET RETRY COUNTER instruction (desbloqueio com PUK + PIN novo).
pub(crate) const INS_UNBLOCK: u8 = 0x2C;
/// GENERAL AUTHENTICATE instruction (operações com o slot).
pub(crate) const INS_GENERAL_AUTH: u8 = 0x87;
/// PUT DATA instruction (grava cert do slot).
pub(crate) const INS_PUT_DATA: u8 = 0xDB;
/// GENERATE ASYMMETRIC KEY PAIR instruction.
pub(crate) const INS_GENERATE: u8 = 0x47;

/// Referência do PIN (P2 no VERIFY/CHANGE/UNBLOCK).
pub(crate) const P2_PIN: u8 = 0x80;
/// Referência do PUK (P2 no CHANGE).
pub(crate) const P2_PUK: u8 = 0x81;

/// Tamanho mínimo do PIN (bytes).
pub const PIV_PIN_MIN_LEN: usize = 6;
/// Tamanho máximo do PIN (bytes).
pub const PIV_PIN_MAX_LEN: usize = 8;
/// Tentativas do PIN (zerou = bloqueado, exige PUK).
pub const PIV_PIN_MAX_RETRIES: u8 = 3;
/// Tamanho exato do PUK (bytes).
pub const PIV_PUK_LEN: usize = 8;
/// Tentativas do PUK (zerou = wipe total PIV).
pub const PIV_PUK_MAX_RETRIES: u8 = 3;
/// Tamanho do salt (TRNG 16B, padrão `recovery.rs`).
pub const PIV_SALT_LEN: usize = 16;
/// Tamanho do hash `SHA-256(salt || pin)` (32B).
pub const PIV_HASH_LEN: usize = 32;
/// Teto do cert DER por slot (sem número mágico nos handlers).
pub const MAX_PIV_CERT_BYTES: usize = 2048;

/// Slot PIV Authentication.
pub const PIV_SLOT_9A: u8 = 0x9A;
/// Slot Digital Signature.
pub const PIV_SLOT_9C: u8 = 0x9C;
/// Slot Key Management.
pub const PIV_SLOT_9D: u8 = 0x9D;
/// Slot Card Authentication.
pub const PIV_SLOT_9E: u8 = 0x9E;

/// Chave NVS do hash do PIN.
pub const PIV_NVS_PIN_HASH: &str = "piv_pin_hash";
/// Chave NVS do salt do PIN.
pub const PIV_NVS_PIN_SALT: &str = "piv_pin_salt";
/// Chave NVS das tentativas restantes do PIN (1B).
pub const PIV_NVS_PIN_RETRIES: &str = "piv_pin_retries";
/// Chave NVS do hash do PUK.
pub const PIV_NVS_PUK_HASH: &str = "piv_puk_hash";
/// Chave NVS do salt do PUK.
pub const PIV_NVS_PUK_SALT: &str = "piv_puk_salt";
/// Chave NVS das tentativas restantes do PUK (1B).
pub const PIV_NVS_PUK_RETRIES: &str = "piv_puk_retries";

/// Slot de chave PIV (somente `9A`/`9C`/`9D`/`9E`; resto = `6B 00`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivSlot {
    /// `9A` PIV Authentication (default do `last_slot`).
    Auth9A,
    /// `9C` Digital Signature.
    Sign9C,
    /// `9D` Key Management.
    Mgmt9D,
    /// `9E` Card Authentication.
    Card9E,
}

impl PivSlot {
    /// Converte a referência de chave (P2) em slot; `None` = slot inválido.
    pub fn from_key_ref(key_ref: u8) -> Option<Self> {
        match key_ref {
            PIV_SLOT_9A => Some(Self::Auth9A),
            PIV_SLOT_9C => Some(Self::Sign9C),
            PIV_SLOT_9D => Some(Self::Mgmt9D),
            PIV_SLOT_9E => Some(Self::Card9E),
            _ => None,
        }
    }

    /// Referência de chave (byte P2) do slot.
    pub fn key_ref(self) -> u8 {
        match self {
            Self::Auth9A => PIV_SLOT_9A,
            Self::Sign9C => PIV_SLOT_9C,
            Self::Mgmt9D => PIV_SLOT_9D,
            Self::Card9E => PIV_SLOT_9E,
        }
    }

    /// Chave NVS do cert (DER) deste slot.
    pub fn cert_nvs_key(self) -> &'static str {
        match self {
            Self::Auth9A => "piv_cert_9a",
            Self::Sign9C => "piv_cert_9c",
            Self::Mgmt9D => "piv_cert_9d",
            Self::Card9E => "piv_cert_9e",
        }
    }

    /// Todos os slots (para wipe e iteração).
    pub fn all() -> [Self; 4] {
        [Self::Auth9A, Self::Sign9C, Self::Mgmt9D, Self::Card9E]
    }
}

/// LAB-ONLY mock FCI returned on PIV SELECT (matches legacy `ccid.rs` bytes).
///
/// Only compiled with `#[cfg(any(test, feature = "lab-mocks"))]`; production
/// builds without `lab-mocks` return an empty `90 00` on SELECT.
#[cfg(any(test, feature = "lab-mocks"))]
pub(crate) const PIV_FCI: &[u8] = &[0x61, 0x05, 0x4F, 0x03, 0xA0, 0x00, 0x00];
/// LAB-ONLY mock CHUID container bytes (no full cert allocated).
#[cfg(any(test, feature = "lab-mocks"))]
pub(crate) const CHUID_MOCK: &[u8] = &[0x5F, 0xC1, 0x02, 0x00];
/// LAB-ONLY mock CCC container bytes (no full cert allocated).
#[cfg(any(test, feature = "lab-mocks"))]
pub(crate) const CCC_MOCK: &[u8] = &[0x5F, 0xC1, 0x07, 0x00];