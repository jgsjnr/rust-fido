//! PIV (NIST SP 800-73-4) applet — VERIFY/AUTH/PUT/GEN + PIN/PUK NVS (Wave 1 Step 1).
//!
//! `PivApplet` receives a parsed [`CommandApdu`] and returns a
//! [`ResponseApdu`]. SELECT with AID `A0 00 00 03 08` selects the applet
//! and returns a lab-mock FCI; GET DATA serves mock CHUID (`5F C1 02`)
//! and CCC (`5F C1 07`) plus X.509 certs (`5F C1 05`) stored via PUT DATA.
//! Unknown AID yields `6A 82`; any command while deselected yields `69 85`.
//!
//! PIN/PUK (sem PIN default — aparelho novo responde `6A 88` até provisionar):
//! - PIN 6-8 bytes, 3 tentativas persistidas; zerou = bloqueado (`69 83`, exige PUK).
//! - PUK exatamente 8 bytes, 3 tentativas persistidas; zerou = wipe total PIV.
//! - Hash `SHA-256(salt 16B || pin)`, comparação em tempo constante, zeroize.
//! - Provisionamento inicial SÓ via [`PivApplet::provision_pin`] (enrollment com UP
//!   no firmware); nunca via APDU não autenticado.
//!
//! NVS (firmware pluga [`PivRecordStore`] no envelope AES-GCM AEGN v1; aqui só as chaves):
//! `piv_pin_hash` (32B) / `piv_pin_salt` (16B) / `piv_pin_retries` (1B) /
//! `piv_puk_hash` (32B) / `piv_puk_salt` (16B) / `piv_puk_retries` (1B) /
//! `piv_cert_9a` / `piv_cert_9c` / `piv_cert_9d` / `piv_cert_9e` (DER, até 2048B).
//!
//! Desvios documentados do 800-73 puro (LAB, sem quebrar o fio padrão):
//! - PUT DATA usa P2 = slot (`9A`/`9C`/`9D`/`9E`); dado `5C 03 5F C1 05 53 <len> <cert>`.
//! - GET DATA `5F C1 05` serve o cert do último slot endereçado (default `9A`).
//! - GENERATE/AUTH delegam a [`PivKeyBackend`] (firmware injeta; sem backend = `69 85`
//!   fail-closed). Sem store (transporte puro) tudo sensível = fail-closed.
//! - MSCP (visão Windows BaseCSP/minidriver): ver tabela em `ccid.rs` (parcial,
//!   TODOs de Security Object/Discovery/SAN-UPN documentados lá).

use super::ccid::{
    AID_PIV, CommandApdu, ResponseApdu, PIV_TAG_CCC, PIV_TAG_CHUID, PIV_TAG_X509_CERT,
    SW_AUTH_BLOCKED, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED, SW_NOT_FOUND,
    SW_REFERENCED_DATA_NOT_FOUND, SW_SECURITY_STATUS_NOT_SATISFIED, SW_UNKNOWN_ERROR,
    SW_WRONG_DATA, SW_WRONG_LENGTH, SW_WRONG_P1P2, sw_retries_left,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// GET DATA instruction (ISO 7816-4 / NIST SP 800-73).
const INS_GET_DATA: u8 = 0xCB;
/// SELECT instruction.
const INS_SELECT: u8 = 0xA4;
/// VERIFY instruction (PIN).
const INS_VERIFY: u8 = 0x20;
/// CHANGE REFERENCE DATA instruction (troca PIN/PUK com o valor antigo).
const INS_CHANGE: u8 = 0x24;
/// RESET RETRY COUNTER instruction (desbloqueio com PUK + PIN novo).
const INS_UNBLOCK: u8 = 0x2C;
/// GENERAL AUTHENTICATE instruction (operações com o slot).
const INS_GENERAL_AUTH: u8 = 0x87;
/// PUT DATA instruction (grava cert do slot).
const INS_PUT_DATA: u8 = 0xDB;
/// GENERATE ASYMMETRIC KEY PAIR instruction.
const INS_GENERATE: u8 = 0x47;

/// Referência do PIN (P2 no VERIFY/CHANGE/UNBLOCK).
const P2_PIN: u8 = 0x80;
/// Referência do PUK (P2 no CHANGE).
const P2_PUK: u8 = 0x81;

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

/// Erro tipado do store PIV (firmware mapeia do `StorageError`; sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivStoreError {
    /// Registro ausente (= não provisionado).
    NotFound,
    /// Registro parcial/corrompido.
    Corrupted,
    /// Falha de escrita/leitura.
    Io,
}

/// Store byte-a-byte dos registros PIV.
///
/// O firmware implementa com `SecureStorage` (envelope AES-GCM AEGN v1 +
/// retry de escrita); aqui só o contrato. Exemplo de adapter no firmware:
/// `load_record(k)` = `secure.load(k).map_err(...)`, `store_record(k, v)` =
/// `secure.store(k, v, &IGNORED)` (nonce TRNG interno).
pub trait PivRecordStore {
    /// Lê o registro `key`; `NotFound` = ausente.
    fn load_record(&self, key: &str) -> Result<Vec<u8>, PivStoreError>;
    /// Grava o registro `key` (sobrescreve).
    fn store_record(&mut self, key: &str, value: &[u8]) -> Result<(), PivStoreError>;
    /// Apaga o registro `key` (ausente = ok, idempotente).
    fn delete_record(&mut self, key: &str) -> Result<(), PivStoreError>;
}

/// Store nulo: nenhum registro (transporte puro sem NVS; tudo fail-closed).
struct NullStore;

impl PivRecordStore for NullStore {
    fn load_record(&self, _key: &str) -> Result<Vec<u8>, PivStoreError> {
        Err(PivStoreError::NotFound)
    }

    fn store_record(&mut self, _key: &str, _value: &[u8]) -> Result<(), PivStoreError> {
        Err(PivStoreError::Io)
    }

    fn delete_record(&mut self, _key: &str) -> Result<(), PivStoreError> {
        Ok(())
    }
}

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

/// Erro tipado do backend cripto PIV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivCryptoError {
    /// Operação indisponível (sem backend injetado).
    Unavailable,
    /// Algoritmo não suportado pelo backend.
    BadAlg,
    /// Falha na operação.
    Failed,
}

/// Backend cripto dos slots (firmware injeta; chave/RNG/assinatura ficam no firmware).
///
/// `generate` retorna a chave pública (bytes do template `7F 49`);
/// `authenticate` recebe o desafio (`7C` interno) e retorna a resposta (`82`).
pub trait PivKeyBackend {
    /// Gera par no `slot` para `alg` (byte `80` do template `AC`); retorna pública.
    fn generate(&mut self, slot: PivSlot, alg: u8) -> Result<Vec<u8>, PivCryptoError>;
    /// Opera com a privada do `slot` sobre `challenge`; retorna resposta.
    fn authenticate(
        &mut self,
        slot: PivSlot,
        alg: u8,
        challenge: &[u8],
    ) -> Result<Vec<u8>, PivCryptoError>;
}

/// Backend ausente: toda operação = `Unavailable` (vira `69 85` fail-closed).
pub struct NoBackend;

impl PivKeyBackend for NoBackend {
    fn generate(&mut self, _slot: PivSlot, _alg: u8) -> Result<Vec<u8>, PivCryptoError> {
        Err(PivCryptoError::Unavailable)
    }

    fn authenticate(
        &mut self,
        _slot: PivSlot,
        _alg: u8,
        _challenge: &[u8],
    ) -> Result<Vec<u8>, PivCryptoError> {
        Err(PivCryptoError::Unavailable)
    }
}

/// Hash do PIN/PUK: `SHA-256(salt || pin)` (segredo nunca sai; padrão `recovery.rs`).
fn hash_pin(salt: &[u8; PIV_SALT_LEN], pin: &[u8]) -> [u8; PIV_HASH_LEN] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    let digest = h.finalize();
    let mut out = [0u8; PIV_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compara 32B em tempo constante (sem oráculo de tempo; padrão `recovery.rs`).
fn ct_eq_32(a: &[u8; PIV_HASH_LEN], b: &[u8; PIV_HASH_LEN]) -> bool {
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
fn write_credential<S: PivRecordStore>(
    store: &mut S,
    salt_key: &str,
    hash_key: &str,
    retries_key: &str,
    secret: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
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
        let back_hash = store.load_record(hash_key).map_err(|_| PivPinError::Storage)?;
        let back_salt = store.load_record(salt_key).map_err(|_| PivPinError::Storage)?;
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
pub fn provision_pin<S: PivRecordStore>(
    store: &mut S,
    new_pin: &[u8],
    new_puk: &[u8],
) -> Result<(), PivPinError> {
    let mut rng = rand_core::OsRng;
    provision_pin_with_rng(store, &mut rng, new_pin, new_puk)
}

/// Variante com RNG injetável (testes determinísticos).
pub fn provision_pin_with_rng<S: PivRecordStore, R: RngCore + CryptoRng>(
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
    if store.load_record(PIV_NVS_PIN_HASH).is_ok()
        || store.load_record(PIV_NVS_PUK_HASH).is_ok()
    {
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
fn wipe_pin_records<S: PivRecordStore>(store: &mut S) {
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

/// LAB-ONLY mock FCI returned on PIV SELECT (matches legacy `ccid.rs` bytes).
///
/// Only compiled with `#[cfg(any(test, feature = "lab-mocks"))]`; production
/// builds without `lab-mocks` return an empty `90 00` on SELECT.
#[cfg(any(test, feature = "lab-mocks"))]
pub(crate) const PIV_FCI: &[u8] = &[0x61, 0x05, 0x4F, 0x03, 0xA0, 0x00, 0x00];
/// LAB-ONLY mock CHUID container bytes (no full cert allocated).
#[cfg(any(test, feature = "lab-mocks"))]
const CHUID_MOCK: &[u8] = &[0x5F, 0xC1, 0x02, 0x00];
/// LAB-ONLY mock CCC container bytes (no full cert allocated).
#[cfg(any(test, feature = "lab-mocks"))]
const CCC_MOCK: &[u8] = &[0x5F, 0xC1, 0x07, 0x00];

/// Applet PIV: seleção + PIN verificado (RAM) + último slot endereçado.
///
/// Segredos (hash/salt/retries/certs) vivem no [`PivRecordStore`] (NVS cifrada no
/// firmware); RAM guarda só flags. `Clone`/`Copy` seguros (sem segredo em RAM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PivApplet {
    selected: bool,
    pin_verified: bool,
    last_slot: u8,
}

impl PivApplet {
    /// Creates a deselected applet (PIN não verificado, slot default `9A`).
    pub fn new() -> Self {
        Self {
            selected: false,
            pin_verified: false,
            last_slot: PIV_SLOT_9A,
        }
    }

    /// Returns true when the applet was selected via SELECT AID.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Returns true quando o PIN foi verificado nesta sessão de seleção.
    pub fn is_verified(&self) -> bool {
        self.pin_verified
    }

    /// Dispatches one command APDU to the PIV applet (transporte puro, sem NVS).
    ///
    /// SELECT/GET DATA funcionam; tudo sensível = fail-closed (`6A 88`/`69 82`).
    pub fn handle(&mut self, apdu: &CommandApdu) -> ResponseApdu {
        let mut store = NullStore;
        let mut crypto = NoBackend;
        self.handle_store(apdu, &mut store, &mut crypto)
    }

    /// Dispatches one command APDU with NVS ([`PivRecordStore`]) e crypto
    /// ([`PivKeyBackend`]) — caminho do firmware.
    pub fn handle_store<S: PivRecordStore, B: PivKeyBackend>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
        crypto: &mut B,
    ) -> ResponseApdu {
        if apdu.ins == INS_SELECT {
            if apdu.p1 == 0x04 {
                return self.handle_select(apdu);
            }
            return ResponseApdu::status(SW_INS_NOT_SUPPORTED);
        }
        if !self.selected {
            return ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED);
        }
        match apdu.ins {
            INS_GET_DATA => self.handle_get_data(apdu, store),
            INS_VERIFY => self.handle_verify(apdu, store),
            INS_CHANGE => self.handle_change(apdu, store),
            INS_UNBLOCK => self.handle_unblock(apdu, store),
            INS_PUT_DATA => self.handle_put(apdu, store),
            INS_GENERATE => self.handle_generate(apdu, store, crypto),
            INS_GENERAL_AUTH => self.handle_auth(apdu, store, crypto),
            _ => ResponseApdu::status(SW_INS_NOT_SUPPORTED),
        }
    }

    /// Handles SELECT by AID; only `AID_PIV` selects the applet.
    ///
    /// (Re)seleção sempre derruba `pin_verified` (fail-closed) e volta o slot `9A`.
    fn handle_select(&mut self, apdu: &CommandApdu) -> ResponseApdu {
        self.pin_verified = false;
        self.last_slot = PIV_SLOT_9A;
        if apdu.data == AID_PIV {
            self.selected = true;
            #[cfg(any(test, feature = "lab-mocks"))]
            {
                ResponseApdu::ok(PIV_FCI.to_vec())
            }
            #[cfg(not(any(test, feature = "lab-mocks")))]
            {
                ResponseApdu::ok(Vec::new())
            }
        } else {
            self.selected = false;
            ResponseApdu::status(SW_NOT_FOUND)
        }
    }

    /// Handles GET DATA; requires prior SELECT.
    ///
    /// CHUID/CCC continuam LAB-ONLY (gate `lab-mocks`); o cert `5F C1 05` é dado
    /// real via PUT DATA (slot = último endereçado, default `9A`); ausente = `6A 82`.
    fn handle_get_data<S: PivRecordStore>(&self, apdu: &CommandApdu, store: &S) -> ResponseApdu {
        match parse_get_tag(&apdu.data) {
            Some(t) if t == PIV_TAG_CHUID.as_slice() => {
                #[cfg(any(test, feature = "lab-mocks"))]
                {
                    ResponseApdu::ok(CHUID_MOCK.to_vec())
                }
                #[cfg(not(any(test, feature = "lab-mocks")))]
                {
                    ResponseApdu::status(SW_NOT_FOUND)
                }
            }
            Some(t) if t == PIV_TAG_CCC.as_slice() => {
                #[cfg(any(test, feature = "lab-mocks"))]
                {
                    ResponseApdu::ok(CCC_MOCK.to_vec())
                }
                #[cfg(not(any(test, feature = "lab-mocks")))]
                {
                    ResponseApdu::status(SW_NOT_FOUND)
                }
            }
            Some(t) if t == PIV_TAG_X509_CERT.as_slice() => {
                let slot = PivSlot::from_key_ref(self.last_slot).unwrap_or(PivSlot::Auth9A);
                match store.load_record(slot.cert_nvs_key()) {
                    Ok(cert) => ResponseApdu::ok(cert),
                    Err(_) => ResponseApdu::status(SW_NOT_FOUND),
                }
            }
            _ => ResponseApdu::status(SW_NOT_FOUND),
        }
    }

    /// VERIFY (`00 20 00 80 <pin>`): vazio consulta (`90 00`/`63 CX`/`69 83`).
    ///
    /// PIN certo = verificado + retries resetados (persistidos); errado consome 1
    /// (persistido contra queda, devolve `63 CX`); a tentativa que zera devolve
    /// `63 C0` e dali em diante `69 83` (exige PUK). Virgem = `6A 88`.
    /// Tamanho inválido = `67 00` sem consumir. Persist falhou = `6F 00` fechado.
    fn handle_verify<S: PivRecordStore>(&mut self, apdu: &CommandApdu, store: &mut S) -> ResponseApdu {
        if apdu.p1 != 0x00 || apdu.p2 != P2_PIN {
            return ResponseApdu::status(SW_WRONG_P1P2);
        }
        let (salt, expected, retries) = match load_triple_or_fail(
            store,
            PIV_NVS_PIN_SALT,
            PIV_NVS_PIN_HASH,
            PIV_NVS_PIN_RETRIES,
        ) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if retries == 0 {
            self.pin_verified = false;
            return ResponseApdu::status(SW_AUTH_BLOCKED);
        }
        if apdu.data.is_empty() {
            if self.pin_verified {
                return ResponseApdu::ok(Vec::new());
            }
            return ResponseApdu::status(sw_retries_left(retries));
        }
        if !is_valid_piv_pin(&apdu.data) {
            return ResponseApdu::status(SW_WRONG_LENGTH);
        }
        if secret_matches_piv(&salt, &expected, &apdu.data) {
            if store.store_record(PIV_NVS_PIN_RETRIES, &[PIV_PIN_MAX_RETRIES]).is_err() {
                self.pin_verified = false;
                return ResponseApdu::status(SW_UNKNOWN_ERROR);
            }
            self.pin_verified = true;
            return ResponseApdu::ok(Vec::new());
        }
        self.pin_verified = false;
        match consume_retry(store, PIV_NVS_PIN_RETRIES, retries) {
            Some(left) => ResponseApdu::status(sw_retries_left(left)),
            None => ResponseApdu::status(SW_UNKNOWN_ERROR),
        }
    }

    /// CHANGE REFERENCE DATA (`00 24 00 80 <old||new>` PIN, `00 24 00 81` PUK).
    ///
    /// Conhecimento do valor antigo é a auth (não exige verificado). Acerto grava
    /// credencial nova (salt novo, retries cheios); erro consome 1 e devolve `63 CX`
    /// (a tentativa que zera devolve `63 C0`; PUK zerou = wipe total).
    /// Geometria inválida = `67 00` sem consumir. Falha de gravação = wipe + `6F 00`
    /// (fail-closed para re-enrollment; padrão do provisionamento).
    fn handle_change<S: PivRecordStore>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
    ) -> ResponseApdu {
        if apdu.p1 != 0x00 || (apdu.p2 != P2_PIN && apdu.p2 != P2_PUK) {
            return ResponseApdu::status(SW_WRONG_P1P2);
        }
        if apdu.p2 == P2_PUK {
            return self.handle_change_puk(apdu, store);
        }
        let geometry_ok = (PIV_PIN_MIN_LEN..=PIV_PIN_MAX_LEN)
            .any(|s| apdu.data.len() >= s && is_valid_piv_pin(&apdu.data[s..]));
        if !geometry_ok {
            return ResponseApdu::status(SW_WRONG_LENGTH);
        }
        let (salt, expected, retries) = match load_triple_or_fail(
            store,
            PIV_NVS_PIN_SALT,
            PIV_NVS_PIN_HASH,
            PIV_NVS_PIN_RETRIES,
        ) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if retries == 0 {
            return ResponseApdu::status(SW_AUTH_BLOCKED);
        }
        // Ordem descendente: o driver PIV envia o old com padding FF até 8B, então
        // o split correto tem o old mais longo (`s=8` casa via strip do padding
        // com o new limpo); ascendente casaria `s=6` exato e gravaria o new com
        // o prefixo `FF FF` do padding junto.
        for s in (PIV_PIN_MIN_LEN..=PIV_PIN_MAX_LEN).rev() {
            if apdu.data.len() < s || !is_valid_piv_pin(&apdu.data[s..]) {
                continue;
            }
            if secret_matches_piv(&salt, &expected, &apdu.data[..s]) {
                let new_pin = Zeroizing::new(apdu.data[s..].to_vec());
                return match rewrite_credential(
                    store,
                    PIV_NVS_PIN_SALT,
                    PIV_NVS_PIN_HASH,
                    PIV_NVS_PIN_RETRIES,
                    &new_pin,
                    PIV_PIN_MAX_RETRIES,
                ) {
                    Ok(()) => ResponseApdu::ok(Vec::new()),
                    Err(resp) => resp,
                };
            }
        }
        match consume_retry(store, PIV_NVS_PIN_RETRIES, retries) {
            Some(left) => ResponseApdu::status(sw_retries_left(left)),
            None => ResponseApdu::status(SW_UNKNOWN_ERROR),
        }
    }

    /// CHANGE PUK (`00 24 00 81 <old8||new8>`); PUK zerou = wipe total.
    fn handle_change_puk<S: PivRecordStore>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
    ) -> ResponseApdu {
        if apdu.data.len() != 2 * PIV_PUK_LEN {
            return ResponseApdu::status(SW_WRONG_LENGTH);
        }
        let (salt, expected, retries) = match load_triple_or_fail(
            store,
            PIV_NVS_PUK_SALT,
            PIV_NVS_PUK_HASH,
            PIV_NVS_PUK_RETRIES,
        ) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if retries == 0 {
            return ResponseApdu::status(SW_AUTH_BLOCKED);
        }
        if secret_matches_piv(&salt, &expected, &apdu.data[..PIV_PUK_LEN]) {
            let new_puk = Zeroizing::new(apdu.data[PIV_PUK_LEN..].to_vec());
            return match rewrite_credential(
                store,
                PIV_NVS_PUK_SALT,
                PIV_NVS_PUK_HASH,
                PIV_NVS_PUK_RETRIES,
                &new_puk,
                PIV_PUK_MAX_RETRIES,
            ) {
                Ok(()) => ResponseApdu::ok(Vec::new()),
                Err(resp) => resp,
            };
        }
        match consume_retry(store, PIV_NVS_PUK_RETRIES, retries) {
            Some(left) => {
                if left == 0 {
                    self.wipe_piv_all(store);
                }
                ResponseApdu::status(sw_retries_left(left))
            }
            None => ResponseApdu::status(SW_UNKNOWN_ERROR),
        }
    }

    /// RESET RETRY COUNTER (`00 2C 00 80 <puk8||new_pin>`): desbloqueia o PIN.
    ///
    /// Não auto-verifica (host faz VERIFY em seguida). PUK zerou = wipe total.
    /// PIN/PUK ausentes = `6A 88` (nada a desbloquear).
    fn handle_unblock<S: PivRecordStore>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
    ) -> ResponseApdu {
        if apdu.p1 != 0x00 || apdu.p2 != P2_PIN {
            return ResponseApdu::status(SW_WRONG_P1P2);
        }
        if apdu.data.len() < PIV_PUK_LEN + PIV_PIN_MIN_LEN
            || apdu.data.len() > PIV_PUK_LEN + PIV_PIN_MAX_LEN
            || !is_valid_piv_pin(&apdu.data[PIV_PUK_LEN..])
        {
            return ResponseApdu::status(SW_WRONG_LENGTH);
        }
        if load_triple(store, PIV_NVS_PIN_SALT, PIV_NVS_PIN_HASH, PIV_NVS_PIN_RETRIES).is_err() {
            return ResponseApdu::status(SW_REFERENCED_DATA_NOT_FOUND);
        }
        let (salt, expected, retries) = match load_triple_or_fail(
            store,
            PIV_NVS_PUK_SALT,
            PIV_NVS_PUK_HASH,
            PIV_NVS_PUK_RETRIES,
        ) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if retries == 0 {
            return ResponseApdu::status(SW_AUTH_BLOCKED);
        }
        if secret_matches_piv(&salt, &expected, &apdu.data[..PIV_PUK_LEN]) {
            let new_pin = Zeroizing::new(apdu.data[PIV_PUK_LEN..].to_vec());
            let pin_ok = rewrite_credential(
                store,
                PIV_NVS_PIN_SALT,
                PIV_NVS_PIN_HASH,
                PIV_NVS_PIN_RETRIES,
                &new_pin,
                PIV_PIN_MAX_RETRIES,
            )
            .is_ok();
            let puk_ok = store
                .store_record(PIV_NVS_PUK_RETRIES, &[PIV_PUK_MAX_RETRIES])
                .is_ok();
            if !pin_ok || !puk_ok {
                wipe_pin_records(store);
                return ResponseApdu::status(SW_UNKNOWN_ERROR);
            }
            return ResponseApdu::ok(Vec::new());
        }
        match consume_retry(store, PIV_NVS_PUK_RETRIES, retries) {
            Some(left) => {
                if left == 0 {
                    self.wipe_piv_all(store);
                }
                ResponseApdu::status(sw_retries_left(left))
            }
            None => ResponseApdu::status(SW_UNKNOWN_ERROR),
        }
    }

    /// PUT DATA (`00 DB 3F <slot> 5C 03 5F C1 05 53 <len> <cert>`).
    ///
    /// Exige PIN verificado (`69 82` sem). P2 = slot (desvio LAB documentado no
    /// cabeçalho do módulo). Grava DER (teto [`MAX_PIV_CERT_BYTES`]) e move o
    /// `last_slot` (leitura do GET).
    fn handle_put<S: PivRecordStore>(&mut self, apdu: &CommandApdu, store: &mut S) -> ResponseApdu {
        if !self.pin_verified {
            return ResponseApdu::status(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        let slot = match PivSlot::from_key_ref(apdu.p2) {
            Some(s) => s,
            None => return ResponseApdu::status(SW_WRONG_P1P2),
        };
        let cert = match parse_put_cert(&apdu.data) {
            Some(c) => c,
            None => return ResponseApdu::status(SW_WRONG_DATA),
        };
        if cert.len() > MAX_PIV_CERT_BYTES {
            return ResponseApdu::status(SW_WRONG_LENGTH);
        }
        if store.store_record(slot.cert_nvs_key(), cert).is_err() {
            return ResponseApdu::status(SW_UNKNOWN_ERROR);
        }
        self.last_slot = slot.key_ref();
        ResponseApdu::ok(Vec::new())
    }

    /// GENERATE ASYMMETRIC KEY (`00 47 00 <slot> AC <params com 80=alg>`).
    ///
    /// Exige PIN verificado. Chave pública volta em `7F 49`; o cert do slot é
    /// invalidado (chave nova). Sem backend = `69 85` fail-closed.
    fn handle_generate<S: PivRecordStore, B: PivKeyBackend>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
        crypto: &mut B,
    ) -> ResponseApdu {
        if !self.pin_verified {
            return ResponseApdu::status(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        let slot = match PivSlot::from_key_ref(apdu.p2) {
            Some(s) => s,
            None => return ResponseApdu::status(SW_WRONG_P1P2),
        };
        let alg = match parse_gen_alg(&apdu.data) {
            Some(a) => a,
            None => return ResponseApdu::status(SW_WRONG_DATA),
        };
        match crypto.generate(slot, alg) {
            Ok(pubkey) => {
                let _ = store.delete_record(slot.cert_nvs_key());
                self.last_slot = slot.key_ref();
                ResponseApdu::ok(tlv(&[0x7F, 0x49], &pubkey))
            }
            Err(PivCryptoError::Unavailable) => {
                ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED)
            }
            Err(PivCryptoError::BadAlg) => ResponseApdu::status(SW_WRONG_DATA),
            Err(PivCryptoError::Failed) => ResponseApdu::status(SW_UNKNOWN_ERROR),
        }
    }

    /// GENERAL AUTHENTICATE (`00 87 <alg> <slot> 7C <witness>`).
    ///
    /// Exige PIN verificado. P1 = referência do algoritmo (repassada opaca ao
    /// backend); desafio/resposta transitam opacos (sem cripto neste crate).
    /// Resposta em `7C { 82 <resp> }`. Sem backend = `69 85` fail-closed.
    fn handle_auth<S: PivRecordStore, B: PivKeyBackend>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
        crypto: &mut B,
    ) -> ResponseApdu {
        if !self.pin_verified {
            return ResponseApdu::status(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        let slot = match PivSlot::from_key_ref(apdu.p2) {
            Some(s) => s,
            None => return ResponseApdu::status(SW_WRONG_P1P2),
        };
        let witness = match parse_auth_witness(&apdu.data) {
            Some(w) => w,
            None => return ResponseApdu::status(SW_WRONG_DATA),
        };
        let _ = store;
        match crypto.authenticate(slot, apdu.p1, witness) {
            Ok(resp) => {
                self.last_slot = slot.key_ref();
                ResponseApdu::ok(tlv(&[0x7C], &tlv(&[0x82], &resp)))
            }
            Err(PivCryptoError::Unavailable) => {
                ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED)
            }
            Err(PivCryptoError::BadAlg) => ResponseApdu::status(SW_WRONG_DATA),
            Err(PivCryptoError::Failed) => ResponseApdu::status(SW_UNKNOWN_ERROR),
        }
    }

    /// Wipe total PIV: 6 registros PIN/PUK + 4 certs; RAM volta a virgem (`9A`).
    ///
    /// Seleção mantida (cartão segue selecionado, sem dados). Idempotente.
    fn wipe_piv_all<S: PivRecordStore>(&mut self, store: &mut S) {
        wipe_pin_records(store);
        for slot in PivSlot::all() {
            let _ = store.delete_record(slot.cert_nvs_key());
        }
        self.pin_verified = false;
        self.last_slot = PIV_SLOT_9A;
    }
}

/// Erro ao carregar a tripla salt+hash+retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TripleError {
    /// Algum registro ausente (= não provisionado).
    Missing,
    /// Parcial, tamanho errado ou I/O (= corrompido, fail-closed).
    Corrupted,
}

/// Carrega a tripla `(salt 16B, hash 32B, retries)`; valida tamanhos.
fn load_triple<S: PivRecordStore>(
    store: &S,
    salt_key: &str,
    hash_key: &str,
    retries_key: &str,
) -> Result<([u8; PIV_SALT_LEN], [u8; PIV_HASH_LEN], u8), TripleError> {
    let raw_salt = store.load_record(salt_key).map_err(|e| match e {
        PivStoreError::NotFound => TripleError::Missing,
        _ => TripleError::Corrupted,
    })?;
    let raw_hash = store.load_record(hash_key).map_err(|e| match e {
        PivStoreError::NotFound => TripleError::Missing,
        _ => TripleError::Corrupted,
    })?;
    let raw_ret = store.load_record(retries_key).map_err(|e| match e {
        PivStoreError::NotFound => TripleError::Missing,
        _ => TripleError::Corrupted,
    })?;
    if raw_salt.len() != PIV_SALT_LEN || raw_hash.len() != PIV_HASH_LEN || raw_ret.len() != 1 {
        return Err(TripleError::Corrupted);
    }
    let mut salt = [0u8; PIV_SALT_LEN];
    let mut hash = [0u8; PIV_HASH_LEN];
    salt.copy_from_slice(&raw_salt);
    hash.copy_from_slice(&raw_hash);
    Ok((salt, hash, raw_ret[0]))
}

/// Consome 1 tentativa persistida e devolve as restantes; `None` = persist falhou
/// (chamador responde `6F 00` fail-closed).
fn consume_retry<S: PivRecordStore>(store: &mut S, retries_key: &str, retries: u8) -> Option<u8> {
    let left = retries.saturating_sub(1);
    store.store_record(retries_key, &[left]).ok()?;
    Some(left)
}

/// Compara `candidate` com `expected` via `SHA-256(salt || candidate)` em tempo
/// constante; zeroiza o digest transitório (sem oráculo de tempo).
fn secret_matches(
    salt: &[u8; PIV_SALT_LEN],
    expected: &[u8; PIV_HASH_LEN],
    candidate: &[u8],
) -> bool {
    let mut digest = hash_pin(salt, candidate);
    let ok = ct_eq_32(expected, &digest);
    digest.zeroize();
    ok
}

/// Compara tolerando o padding `FF` do driver PIV real (PIN sempre 8B no fio).
///
/// Tenta o `secret_matches` exato primeiro (preserva PINs crus com `FF`
/// legítimo); se falhar E `candidate.len() == 8` E termina em `0xFF`,
/// remove os `FF`s finais e tenta de novo quando o resto fica em 6..=8.
/// Uma única chamada = uma única tentativa lógica (sem consumir retry extra).
fn secret_matches_piv(
    salt: &[u8; PIV_SALT_LEN],
    expected: &[u8; PIV_HASH_LEN],
    candidate: &[u8],
) -> bool {
    if secret_matches(salt, expected, candidate) {
        return true;
    }
    if candidate.len() == PIV_PIN_MAX_LEN && candidate.last() == Some(&0xFF) {
        let mut n = candidate.len();
        while n > 0 && candidate[n - 1] == 0xFF {
            n -= 1;
        }
        if (PIV_PIN_MIN_LEN..=PIV_PIN_MAX_LEN).contains(&n) && n != candidate.len() {
            return secret_matches(salt, expected, &candidate[..n]);
        }
    }
    false
}

/// Tripla carregada: salt+hash com zeroize no `drop` + retries restantes.
type LoadedTriple = (
    Zeroizing<[u8; PIV_SALT_LEN]>,
    Zeroizing<[u8; PIV_HASH_LEN]>,
    u8,
);

/// Carrega a tripla (salt/hash auto-zeroizados no `drop`) ou devolve a resposta
/// fail-closed pronta (`6A 88` virgem / `6F 00` corrompido).
fn load_triple_or_fail<S: PivRecordStore>(
    store: &S,
    salt_key: &str,
    hash_key: &str,
    retries_key: &str,
) -> Result<LoadedTriple, ResponseApdu> {
    load_triple(store, salt_key, hash_key, retries_key)
        .map(|(salt, hash, retries)| (Zeroizing::new(salt), Zeroizing::new(hash), retries))
        .map_err(|e| match e {
            TripleError::Missing => ResponseApdu::status(SW_REFERENCED_DATA_NOT_FOUND),
            TripleError::Corrupted => ResponseApdu::status(SW_UNKNOWN_ERROR),
        })
}

/// Regrava credencial (salt novo, retries cheios); falha = wipe PIN/PUK + `Err`
/// (chamador responde `6F 00`; fail-closed para re-enrollment).
fn rewrite_credential<S: PivRecordStore>(
    store: &mut S,
    salt_key: &str,
    hash_key: &str,
    retries_key: &str,
    new_secret: &[u8],
    max_retries: u8,
) -> Result<(), ResponseApdu> {
    let mut rng = rand_core::OsRng;
    if write_credential(store, salt_key, hash_key, retries_key, new_secret, &mut rng, max_retries)
        .is_err()
    {
        wipe_pin_records(store);
        return Err(ResponseApdu::status(SW_UNKNOWN_ERROR));
    }
    Ok(())
}

/// Lê `len` BER-TLV curta (`<128`), `81 XX` ou `82 XX XX` em `pos`.
/// Retorna `(tamanho, bytes_do_campo_len)`; `None` = malformado.
fn read_len(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    if first == 0x81 {
        return Some((*data.get(pos + 1)? as usize, 2));
    }
    if first == 0x82 {
        let hi = *data.get(pos + 1)? as usize;
        let lo = *data.get(pos + 2)? as usize;
        return Some(((hi << 8) | lo, 3));
    }
    None
}

/// Monta `tag || len || value` (suporta valor até 65535).
fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 3 + value.len());
    out.extend_from_slice(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push((value.len() & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

/// Extrai a tag do objeto de um GET DATA (`5C <len> <tag>`); `None` = malformado.
fn parse_get_tag(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 2 || data[0] != 0x5C {
        return None;
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        return None;
    }
    Some(&data[2..2 + len])
}

/// Extrai o cert de um PUT DATA (`5C 03 5F C1 05 53 <len> <bytes>`, exato).
/// `None` = malformado (teto de tamanho checado no handler, `67 00`).
fn parse_put_cert(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 8 || data[0] != 0x5C || data[1] != 0x03 || data[5] != 0x53 {
        return None;
    }
    if data[2..5] != PIV_TAG_X509_CERT {
        return None;
    }
    let (len, lb) = read_len(data, 6)?;
    let start = 6 + lb;
    let end = start.checked_add(len)?;
    if end != data.len() {
        return None;
    }
    Some(&data[start..end])
}

/// Extrai o byte de algoritmo (`80`) do template `AC` do GENERATE.
/// `None` = malformado ou sem `80`.
fn parse_gen_alg(data: &[u8]) -> Option<u8> {
    if data.first() != Some(&0xAC) {
        return None;
    }
    let (ilen, lb) = read_len(data, 1)?;
    let start = 1 + lb;
    let inner = data.get(start..start.checked_add(ilen)?)?;
    let mut pos = 0;
    while pos + 2 <= inner.len() {
        let tag = inner[pos];
        let (llen, lb2) = read_len(inner, pos + 1)?;
        let vstart = pos + 1 + lb2;
        let vend = vstart.checked_add(llen)?;
        if vend > inner.len() {
            return None;
        }
        if tag == 0x80 && llen == 1 {
            return Some(inner[vstart]);
        }
        pos = vend;
    }
    None
}

/// Extrai o witness (`7C <len> <bytes>`, exato) do GENERAL AUTHENTICATE.
/// `None` = malformado.
fn parse_auth_witness(data: &[u8]) -> Option<&[u8]> {
    if data.first() != Some(&0x7C) {
        return None;
    }
    let (len, lb) = read_len(data, 1)?;
    let start = 1 + lb;
    let end = start.checked_add(len)?;
    if end != data.len() {
        return None;
    }
    Some(&data[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_apdu(data: &[u8]) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_SELECT,
            p1: 0x04,
            p2: 0x00,
            data: data.to_vec(),
            le: None,
        }
    }

    fn get_data_apdu(tag: &[u8]) -> CommandApdu {
        // Arrange data field: 5C <len> <tag bytes>
        let mut data = vec![0x5C, tag.len() as u8];
        data.extend_from_slice(tag);
        CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data,
            le: None,
        }
    }

    #[test]
    fn should_select_piv_aid_and_return_fci() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = select_apdu(AID_PIV);

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(applet.is_selected());
        assert_eq!(resp.sw1, 0x90);
        assert_eq!(resp.sw2, 0x00);
        assert_eq!(resp.data, PIV_FCI);
    }

    #[test]
    fn should_return_chuid_mock_when_selected() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert_eq!(resp.data, CHUID_MOCK);
    }

    #[test]
    fn should_return_ccc_mock_when_selected() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x07]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert_eq!(resp.data, CCC_MOCK);
    }

    #[test]
    fn should_reject_unknown_aid_with_6a82() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = select_apdu(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(!applet.is_selected());
        assert_eq!((resp.sw1, resp.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_get_data_when_not_selected_with_6985() {
        // Arrange
        let mut applet = PivApplet::new();

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn should_return_6a82_for_malformed_get_data() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x00, 0xFF],
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_return_6d00_for_unknown_ins() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: 0xFF,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_INS_NOT_SUPPORTED);
    }

    #[test]
    fn should_reject_select_with_wrong_p1() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_SELECT,
            p1: 0x00,
            p2: 0x00,
            data: AID_PIV.to_vec(),
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(!applet.is_selected());
        assert_eq!((resp.sw1, resp.sw2), SW_INS_NOT_SUPPORTED);
    }
}

/// BEHAVIOR Wave 1 Step 1 (TDD): VERIFY/AUTH/PUT/GEN + PIN/PUK NVS.
///
/// RED-first: estes testes falham enquanto os handlers retornam `6D 00` (stub).
#[cfg(test)]
mod secure_tests {
    use super::*;
    use crate::ccid::{
        sw_retries_left, SW_AUTH_BLOCKED, SW_REFERENCED_DATA_NOT_FOUND,
        SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_DATA, SW_WRONG_P1P2,
    };
    use std::collections::HashMap;

    const PIN: &[u8] = b"123456";
    const NEW_PIN: &[u8] = b"654321";
    const PUK: &[u8] = b"12345678";
    const NEW_PUK: &[u8] = b"87654321";
    const CERT_9A: &[u8] = &[0x30, 0x82, 0x01, 0x0A, 0xAA, 0xBB];
    const CERT_9C: &[u8] = &[0x30, 0x82, 0x02, 0x0B, 0xCC, 0xDD];

    /// Store em RAM (contrato `PivRecordStore`; firmware pluga `SecureStorage`).
    #[derive(Default)]
    struct MemStore {
        map: HashMap<String, Vec<u8>>,
    }

    impl PivRecordStore for MemStore {
        fn load_record(&self, key: &str) -> Result<Vec<u8>, PivStoreError> {
            self.map.get(key).cloned().ok_or(PivStoreError::NotFound)
        }

        fn store_record(&mut self, key: &str, value: &[u8]) -> Result<(), PivStoreError> {
            self.map.insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete_record(&mut self, key: &str) -> Result<(), PivStoreError> {
            self.map.remove(key);
            Ok(())
        }
    }

    /// RNG determinístico (xorshift64*; só para testes).
    struct SeqRng(u64);

    impl rand_core::RngCore for SeqRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = 0;
            while i < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let n = (dest.len() - i).min(8);
                dest[i..i + n].copy_from_slice(&v[..n]);
                i += n;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for SeqRng {}

    /// Backend cripto stub (chave/RNG ficam no firmware; aqui bytes enlatados).
    struct StubCrypto {
        pubkey: Vec<u8>,
        response: Vec<u8>,
    }

    impl PivKeyBackend for StubCrypto {
        fn generate(&mut self, _slot: PivSlot, _alg: u8) -> Result<Vec<u8>, PivCryptoError> {
            Ok(self.pubkey.clone())
        }

        fn authenticate(
            &mut self,
            _slot: PivSlot,
            _alg: u8,
            _challenge: &[u8],
        ) -> Result<Vec<u8>, PivCryptoError> {
            Ok(self.response.clone())
        }
    }

    struct Harness {
        applet: PivApplet,
        store: MemStore,
        crypto: StubCrypto,
        rng: SeqRng,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                applet: PivApplet::new(),
                store: MemStore::default(),
                crypto: StubCrypto {
                    pubkey: vec![0x04, 0x11, 0x22],
                    response: vec![0xAA, 0xBB],
                },
                rng: SeqRng(0x1234_5678_9ABC_DEF0),
            }
        }

        fn select(&mut self) {
            let apdu = CommandApdu {
                cla: 0x00,
                ins: INS_SELECT,
                p1: 0x04,
                p2: 0x00,
                data: AID_PIV.to_vec(),
                le: None,
            };
            let resp = self.applet.handle(&apdu);
            assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        }

        fn provision(&mut self) {
            provision_pin_with_rng(&mut self.store, &mut self.rng, PIN, PUK)
                .expect("provision ok");
        }

        fn run(&mut self, apdu: &CommandApdu) -> ResponseApdu {
            self.applet.handle_store(apdu, &mut self.store, &mut self.crypto)
        }
    }

    fn verify_apdu(pin: &[u8]) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_VERIFY,
            p1: 0x00,
            p2: P2_PIN,
            data: pin.to_vec(),
            le: None,
        }
    }

    fn put_cert_apdu(slot: u8, cert: &[u8]) -> CommandApdu {
        let mut data = vec![0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, cert.len() as u8];
        data.extend_from_slice(cert);
        CommandApdu {
            cla: 0x00,
            ins: INS_PUT_DATA,
            p1: 0x3F,
            p2: slot,
            data,
            le: None,
        }
    }

    fn get_cert_apdu() -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x5C, 0x03, 0x5F, 0xC1, 0x05],
            le: None,
        }
    }

    fn generate_apdu(slot: u8) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_GENERATE,
            p1: 0x00,
            p2: slot,
            data: vec![0xAC, 0x03, 0x80, 0x01, 0x11],
            le: None,
        }
    }

    fn auth_apdu(slot: u8, challenge: &[u8]) -> CommandApdu {
        let mut data = vec![0x7C, (challenge.len() + 2) as u8, 0x81, challenge.len() as u8];
        data.extend_from_slice(challenge);
        CommandApdu {
            cla: 0x00,
            ins: INS_GENERAL_AUTH,
            p1: 0x00,
            p2: slot,
            data,
            le: None,
        }
    }

    #[test]
    fn should_reject_bad_pin_and_puk_lengths() {
        // Arrange
        let mut h = Harness::new();

        // Act + Assert
        assert_eq!(
            provision_pin_with_rng(&mut h.store, &mut h.rng, b"12345", PUK),
            Err(PivPinError::BadPin)
        );
        assert_eq!(
            provision_pin_with_rng(&mut h.store, &mut h.rng, b"123456789", PUK),
            Err(PivPinError::BadPin)
        );
        assert_eq!(
            provision_pin_with_rng(&mut h.store, &mut h.rng, PIN, b"1234567"),
            Err(PivPinError::BadPuk)
        );
        assert!(h.store.load_record(PIV_NVS_PIN_HASH).is_err());
    }

    #[test]
    fn should_reject_second_provision() {
        // Arrange
        let mut h = Harness::new();
        h.provision();

        // Act
        let res = provision_pin_with_rng(&mut h.store, &mut h.rng, NEW_PIN, NEW_PUK);

        // Assert
        assert_eq!(res, Err(PivPinError::AlreadyProvisioned));
    }

    #[test]
    fn should_verify_ok_and_set_verified() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&verify_apdu(PIN));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
    }

    #[test]
    fn should_query_empty_verify_returns_retries() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&verify_apdu(&[]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(3));
    }

    #[test]
    fn should_wrong_pin_decrement_and_persist() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&verify_apdu(b"000000"));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(2));
        assert!(!h.applet.is_verified());
        let raw = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw, vec![2]);
    }

    #[test]
    fn should_block_after_three_wrongs_then_6983() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act: 3 PINs errados consomem as tentativas
        let r1 = h.run(&verify_apdu(b"000000"));
        let r2 = h.run(&verify_apdu(b"000000"));
        let r3 = h.run(&verify_apdu(b"000000"));

        // Assert: 63 C2 → 63 C1 → 63 C0, depois PIN certo segue bloqueado
        assert_eq!((r1.sw1, r1.sw2), sw_retries_left(2));
        assert_eq!((r2.sw1, r2.sw2), sw_retries_left(1));
        assert_eq!((r3.sw1, r3.sw2), sw_retries_left(0));
        let blocked = h.run(&verify_apdu(PIN));
        assert_eq!((blocked.sw1, blocked.sw2), SW_AUTH_BLOCKED);
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_verify_unprovisioned_returns_6a88() {
        // Arrange
        let mut h = Harness::new();
        h.select();

        // Act
        let resp = h.run(&verify_apdu(PIN));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_REFERENCED_DATA_NOT_FOUND);
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_match_nist_verify_vector_encoding() {
        // Arrange: vetor NIST SP 800-73 (VERIFY `00 20 00 80 06 <PIN>`)
        let raw = [0x00, 0x20, 0x00, 0x80, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let apdu = CommandApdu::parse(&raw).expect("vetor NIST parseia");
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!(apdu.data, b"123456");
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
    }

    #[test]
    fn should_reject_verify_wrong_p1p2_with_6b00() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_VERIFY,
            p1: 0x00,
            p2: 0x00,
            data: PIN.to_vec(),
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_P1P2);
    }

    #[test]
    fn should_reselect_drop_verified() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let ok = h.run(&verify_apdu(PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: reseleciona o PIV
        h.select();

        // Assert: verificação caiu (fail-closed)
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_change_pin_with_old_ok() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = PIN.to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        let ok = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
    }

    #[test]
    fn should_change_pin_wrong_old_consumes_retry() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = b"000000".to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(2));
    }

    #[test]
    fn should_change_puk_with_old_ok() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = PUK.to_vec();
        data.extend_from_slice(NEW_PUK);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PUK,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
    }

    #[test]
    fn should_unblock_with_puk_after_block() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        for _ in 0..3 {
            let _ = h.run(&verify_apdu(b"000000"));
        }
        let still_blocked = h.run(&verify_apdu(PIN));
        assert_eq!((still_blocked.sw1, still_blocked.sw2), SW_AUTH_BLOCKED);
        let mut data = PUK.to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_UNBLOCK,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        let ok = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        let raw_retries = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw_retries, vec![PIV_PIN_MAX_RETRIES]);
    }

    #[test]
    fn should_wipe_after_three_wrong_puks() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let verified = h.run(&verify_apdu(PIN));
        assert_eq!((verified.sw1, verified.sw2), (0x90, 0x00));
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((put.sw1, put.sw2), (0x90, 0x00));
        let mut data = b"00000000".to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_UNBLOCK,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act: 3 PUKs errados (63 C2 → 63 C1 → 63 C0 + wipe)
        let w1 = h.run(&apdu);
        let w2 = h.run(&apdu);
        let w3 = h.run(&apdu);
        assert_eq!((w1.sw1, w1.sw2), sw_retries_left(2));
        assert_eq!((w2.sw1, w2.sw2), sw_retries_left(1));
        assert_eq!((w3.sw1, w3.sw2), sw_retries_left(0));

        // Assert: wipe total — PIN virou virgem, cert sumiu
        assert!(!h.applet.is_verified());
        let no_pin = h.run(&verify_apdu(PIN));
        assert_eq!((no_pin.sw1, no_pin.sw2), SW_REFERENCED_DATA_NOT_FOUND);
        let no_cert = h.run(&get_cert_apdu());
        assert_eq!((no_cert.sw1, no_cert.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_put_without_pin_with_6982() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_put_then_get_cert_roundtrip() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let verified = h.run(&verify_apdu(PIN));
        assert_eq!((verified.sw1, verified.sw2), (0x90, 0x00));

        // Act
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        let get = h.run(&get_cert_apdu());

        // Assert
        assert_eq!((put.sw1, put.sw2), (0x90, 0x00));
        assert_eq!((get.sw1, get.sw2), (0x90, 0x00));
        assert_eq!(get.data, CERT_9A);
    }

    #[test]
    fn should_get_cert_default_slot_9a_after_put_9c() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let _ = h.run(&put_cert_apdu(PIV_SLOT_9C, CERT_9C));
        let get = h.run(&get_cert_apdu());

        // Assert: último slot endereçado (documentado)
        assert_eq!((get.sw1, get.sw2), (0x90, 0x00));
        assert_eq!(get.data, CERT_9C);
    }

    #[test]
    fn should_reject_put_bad_slot_with_6b00() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&put_cert_apdu(0xFF, CERT_9A));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_P1P2);
    }

    #[test]
    fn should_reject_put_malformed_with_6a80() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_PUT_DATA,
            p1: 0x3F,
            p2: PIV_SLOT_9A,
            data: vec![0x00, 0xFF],
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_DATA);
    }

    #[test]
    fn should_reject_generate_without_pin_with_6982() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&generate_apdu(PIV_SLOT_9A));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_generate_with_stub_returns_7f49() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&generate_apdu(PIV_SLOT_9A));

        // Assert: template `7F 49` carrega a pública do backend
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(resp.data.len() >= 4);
        assert_eq!(&resp.data[..2], &[0x7F, 0x49]);
        assert!(resp.data.windows(3).any(|w| w == [0x04, 0x11, 0x22]));
    }

    #[test]
    fn should_generate_without_backend_returns_6985() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let mut no_backend = NoBackend;

        // Act: firmware ainda sem backend cripto = fail-closed
        let resp = h.applet.handle_store(&generate_apdu(PIV_SLOT_9A), &mut h.store, &mut no_backend);

        // Assert
        assert_eq!(
            (resp.sw1, resp.sw2),
            (SW_CONDITIONS_NOT_SATISFIED.0, SW_CONDITIONS_NOT_SATISFIED.1)
        );
    }

    #[test]
    fn should_generate_invalidates_cert() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let verified = h.run(&verify_apdu(PIN));
        assert_eq!((verified.sw1, verified.sw2), (0x90, 0x00));
        let first_put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((first_put.sw1, first_put.sw2), (0x90, 0x00));

        // Act
        let gen = h.run(&generate_apdu(PIV_SLOT_9A));

        // Assert: chave nova invalida o cert antigo
        assert_eq!((gen.sw1, gen.sw2), (0x90, 0x00));
        let gone = h.run(&get_cert_apdu());
        assert_eq!((gone.sw1, gone.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_generate_bad_slot_with_6b00() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&generate_apdu(0x00));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_P1P2);
    }

    #[test]
    fn should_reject_generate_malformed_with_6a80() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GENERATE,
            p1: 0x00,
            p2: PIV_SLOT_9A,
            data: vec![0x00],
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_DATA);
    }

    #[test]
    fn should_reject_auth_without_pin_with_6982() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&auth_apdu(PIV_SLOT_9A, &[0x01, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_auth_with_stub_returns_7c82() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&auth_apdu(PIV_SLOT_9A, &[0x01, 0x02]));

        // Assert: `7C .. 82 .. <resposta do backend>`
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(!resp.data.is_empty());
        assert_eq!(resp.data[0], 0x7C);
        assert!(resp.data.windows(2).any(|w| w == [0xAA, 0xBB]));
    }

    #[test]
    fn should_auth_without_backend_returns_6985() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let mut no_backend = NoBackend;

        // Act
        let resp = h.applet.handle_store(&auth_apdu(PIV_SLOT_9A, &[0x01]), &mut h.store, &mut no_backend);

        // Assert
        assert_eq!(
            (resp.sw1, resp.sw2),
            (SW_CONDITIONS_NOT_SATISFIED.0, SW_CONDITIONS_NOT_SATISFIED.1)
        );
    }

    #[test]
    fn should_reject_auth_malformed_with_6a80() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GENERAL_AUTH,
            p1: 0x00,
            p2: PIV_SLOT_9A,
            data: vec![0x00, 0x01],
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_DATA);
    }

    #[test]
    fn should_blocked_pin_require_puk_not_verify() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        for _ in 0..3 {
            let _ = h.run(&verify_apdu(b"000000"));
        }

        // Act: PIN certo com retries zerados continua bloqueado
        let resp = h.run(&verify_apdu(PIN));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_AUTH_BLOCKED);
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_failed_verify_drop_verified_session() {
        // Arrange: sessão verificada (fail-closed exige derrubar no 1º erro)
        let mut h = Harness::new();
        h.select();
        h.provision();
        let ok = h.run(&verify_apdu(PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: um VERIFY com PIN errado
        let bad = h.run(&verify_apdu(b"000000"));

        // Assert: sessão caiu; PUT bloqueado com 69 82
        assert_eq!((bad.sw1, bad.sw2), sw_retries_left(2));
        assert!(!h.applet.is_verified());
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((put.sw1, put.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_lockout_drop_verified_session() {
        // Arrange: sessão verificada antes do lockout
        let mut h = Harness::new();
        h.select();
        h.provision();
        let ok = h.run(&verify_apdu(PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: 3 erros → 63 C2, 63 C1, 63 C0 (lockout)
        let _ = h.run(&verify_apdu(b"000000"));
        let _ = h.run(&verify_apdu(b"000000"));
        let last = h.run(&verify_apdu(b"000000"));
        assert_eq!((last.sw1, last.sw2), sw_retries_left(0));

        // Assert: sessão NÃO sobrevive ao lockout; PIN certo exige PUK
        assert!(!h.applet.is_verified());
        let blocked = h.run(&verify_apdu(PIN));
        assert_eq!((blocked.sw1, blocked.sw2), SW_AUTH_BLOCKED);
        assert!(!h.applet.is_verified());
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((put.sw1, put.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_change_and_unblock_new_secrets_roundtrip() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act: CHANGE PIN (PIN -> NEW_PIN); buffer novo zeroizado no drop
        let mut ch_pin = PIN.to_vec();
        ch_pin.extend_from_slice(NEW_PIN);
        let ch_pin_apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data: ch_pin,
            le: None,
        };
        let ch_pin_resp = h.run(&ch_pin_apdu);
        assert_eq!((ch_pin_resp.sw1, ch_pin_resp.sw2), (0x90, 0x00));

        // Assert: PIN novo autentica
        let ok_new = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok_new.sw1, ok_new.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: CHANGE PUK (PUK -> NEW_PUK); buffer novo zeroizado no drop
        let mut ch_puk = PUK.to_vec();
        ch_puk.extend_from_slice(NEW_PUK);
        let ch_puk_apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PUK,
            data: ch_puk,
            le: None,
        };
        let ch_puk_resp = h.run(&ch_puk_apdu);
        assert_eq!((ch_puk_resp.sw1, ch_puk_resp.sw2), (0x90, 0x00));

        // Act: bloqueia o PIN novo e desbloqueia com o PUK novo
        for _ in 0..3 {
            let _ = h.run(&verify_apdu(b"000000"));
        }
        assert_eq!(
            (h.run(&verify_apdu(NEW_PIN)).sw1, h.run(&verify_apdu(NEW_PIN)).sw2),
            SW_AUTH_BLOCKED
        );
        let mut unb = NEW_PUK.to_vec();
        unb.extend_from_slice(PIN);
        let unb_apdu = CommandApdu {
            cla: 0x00,
            ins: INS_UNBLOCK,
            p1: 0x00,
            p2: P2_PIN,
            data: unb,
            le: None,
        };
        let unb_resp = h.run(&unb_apdu);
        assert_eq!((unb_resp.sw1, unb_resp.sw2), (0x90, 0x00));

        // Assert: PIN restaurado autentica (prova que os 3 buffers novos funcionaram)
        let ok_restored = h.run(&verify_apdu(PIN));
        assert_eq!((ok_restored.sw1, ok_restored.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
    }

    #[test]
    fn should_verify_padded_ff_matches_raw_6b_pin() {
        // Arrange: PIN cru 6B provisionado, driver real envia 8B com padding FF
        let mut h = Harness::new();
        h.select();
        h.provision();
        let padded = b"123456\xFF\xFF";

        // Act
        let resp = h.run(&verify_apdu(padded));

        // Assert: casa sem consumir retry
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
        let raw = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw, vec![PIV_PIN_MAX_RETRIES]);
    }

    #[test]
    fn should_verify_raw_8b_ending_ff_still_exact() {
        // Arrange: PIN cru 8B terminado em FF (FF legítimo, não padding)
        let mut h = Harness::new();
        h.select();
        let raw_pin = b"1234567\xFF";
        provision_pin_with_rng(&mut h.store, &mut h.rng, raw_pin, PUK).expect("provision ok");

        // Act
        let resp = h.run(&verify_apdu(raw_pin));

        // Assert: exato casa na primeira tentativa
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
    }

    #[test]
    fn should_reject_padded_wrong_pin() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act: PIN errado com padding FF (63 C2, consome só 1 retry)
        let resp = h.run(&verify_apdu(b"000000\xFF\xFF"));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(2));
        assert!(!h.applet.is_verified());
        let raw = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw, vec![2]);
    }

    #[test]
    fn should_change_pin_with_padded_old_ok() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = b"123456\xFF\xFF".to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        let ok = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
    }
}
