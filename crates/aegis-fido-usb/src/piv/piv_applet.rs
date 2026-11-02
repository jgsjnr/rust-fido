//! PIV applet: `PivApplet` + APDU dispatch (INS) + handler-only helpers.
//!
//! Owner split (move-only, no behavior change):
//! - `piv_cmd`: consts INS/P2/limits, `PivSlot`, traits (`PivRecordStore`,
//!   `PivKeyBackend`), provision fns, shared hash/secret helpers +
//!   re-export + tests.
//! - `piv_applet` (this file): `PivApplet`, dispatch by INS, handlers
//!   (SELECT/GET/VERIFY/CHANGE/UNBLOCK/PUT/GENERATE/AUTH), `NullStore` and
//!   helpers used ONLY by the handlers (`TripleError`, `load_triple`,
//!   `consume_retry`, `secret_matches*`, `load_triple_or_fail`,
//!   `rewrite_credential`).
//!
//! Helpers used by BOTH sides (`hash_pin`, `ct_eq_32`, `write_credential`,
//! `wipe_pin_records`, `is_valid_piv_*`) stay in the owner (no duplicates);
//! `CommandApdu::parse` stays in the `ccid.rs` transport.

use super::apdu::{parse_auth_witness, parse_gen_alg, parse_get_tag, parse_put_cert, tlv};
#[cfg(feature = "getrandom")]
use super::piv_cmd::write_credential;
use super::piv_cmd::{
    ct_eq_32, hash_pin, is_valid_piv_pin, wipe_pin_records, NoBackend, PivCryptoError,
    PivKeyBackend, PivRecordStore, PivSlot, PivStoreError, INS_CHANGE, INS_GENERAL_AUTH,
    INS_GENERATE, INS_GET_DATA, INS_PUT_DATA, INS_SELECT, INS_UNBLOCK, INS_VERIFY,
    MAX_PIV_CERT_BYTES, P2_PIN, P2_PUK, PIV_HASH_LEN, PIV_NVS_PIN_HASH, PIV_NVS_PIN_RETRIES,
    PIV_NVS_PIN_SALT, PIV_NVS_PUK_HASH, PIV_NVS_PUK_RETRIES, PIV_NVS_PUK_SALT, PIV_PIN_MAX_LEN,
    PIV_PIN_MAX_RETRIES, PIV_PIN_MIN_LEN, PIV_PUK_LEN, PIV_PUK_MAX_RETRIES, PIV_SALT_LEN,
    PIV_SLOT_9A,
};
#[cfg(any(test, feature = "lab-mocks"))]
use super::piv_cmd::{CCC_MOCK, CHUID_MOCK, PIV_FCI};
use crate::ccid::{
    sw_retries_left, CommandApdu, ResponseApdu, AID_PIV, PIV_TAG_CCC, PIV_TAG_CHUID,
    PIV_TAG_X509_CERT, SW_AUTH_BLOCKED, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_NOT_FOUND, SW_REFERENCED_DATA_NOT_FOUND, SW_SECURITY_STATUS_NOT_SATISFIED, SW_UNKNOWN_ERROR,
    SW_WRONG_DATA, SW_WRONG_LENGTH, SW_WRONG_P1P2,
};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

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
    fn handle_verify<S: PivRecordStore>(
        &mut self,
        apdu: &CommandApdu,
        store: &mut S,
    ) -> ResponseApdu {
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
            if store
                .store_record(PIV_NVS_PIN_RETRIES, &[PIV_PIN_MAX_RETRIES])
                .is_err()
            {
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
        if load_triple(
            store,
            PIV_NVS_PIN_SALT,
            PIV_NVS_PIN_HASH,
            PIV_NVS_PIN_RETRIES,
        )
        .is_err()
        {
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
            Err(PivCryptoError::Unavailable) => ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED),
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
            Err(PivCryptoError::Unavailable) => ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED),
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
///
/// Requer a feature `getrandom` (ligada por padrão via `std`): o salt novo vem
/// do RNG do SO. Sem `getrandom` (bare-metal/ESP32 sem RNG de SO) não há como
/// cunhar salt fresco — fail-closed `6F 00` após wipe, mesmo semanticamente
/// que falha de gravação. Para trocar PIN/PUK nesses alvos, re-provisione via
/// `provision_pin_with_rng` com RNG semeado explicitamente.
#[cfg(feature = "getrandom")]
fn rewrite_credential<S: PivRecordStore>(
    store: &mut S,
    salt_key: &str,
    hash_key: &str,
    retries_key: &str,
    new_secret: &[u8],
    max_retries: u8,
) -> Result<(), ResponseApdu> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    if write_credential(
        store,
        salt_key,
        hash_key,
        retries_key,
        new_secret,
        &mut rng,
        max_retries,
    )
    .is_err()
    {
        wipe_pin_records(store);
        return Err(ResponseApdu::status(SW_UNKNOWN_ERROR));
    }
    Ok(())
}

/// Sem `getrandom` (bare-metal/ESP32 sem RNG de SO): sem salt fresco não há
/// rewrite seguro — fail-closed `6F 00` após wipe (mesma semântica da falha
/// de gravação acima). CHANGE/UNBLOCK nesses alvos sempre devolvem `6F 00`;
/// re-provisione via `provision_pin_with_rng` com RNG explícito.
#[cfg(not(feature = "getrandom"))]
fn rewrite_credential<S: PivRecordStore>(
    store: &mut S,
    _salt_key: &str,
    _hash_key: &str,
    _retries_key: &str,
    _new_secret: &[u8],
    _max_retries: u8,
) -> Result<(), ResponseApdu> {
    wipe_pin_records(store);
    Err(ResponseApdu::status(SW_UNKNOWN_ERROR))
}
