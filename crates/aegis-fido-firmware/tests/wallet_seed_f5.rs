#![cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
//! F5 host: cerimonia da semente wallet (provision -> persist -> reload -> wipe).
//!
//! Host-only (sem placa/push, sem hardware real): a cerimonia
//! `SeedCeremony` provisiona a frase oficial de teste, sela via envelope
//! PIN-bound existente e o `wallet_seed_store` persiste o bundle
//! (routing + envelope selado) sobre NVS simulada com snapshot/rollback e
//! verify-after-write herdado do `NamespacedStore`:
//! - provision -> persist -> reload -> wipe fecha o ciclo com a mesma frase;
//! - queda no meio do save (falha transiente na 1a/2a escrita) restaura o
//!   bundle antigo (ou nada, se nunca provisionado) — nunca meio-estado;
//! - NVS parcial (metade apagada) carrega como `Storage` (corrompido),
//!   nunca meio-estado;
//! - PIN errado ou envelope adulterado nunca reabre.

use std::vec::Vec;

use aegis_fido_core::vault::AegisVault;
use aegis_fido_core::wallet::{
    CryptoNetwork, SeedCeremony, SeedCeremonyError, SeedSession, WalletStore,
};
use aegis_fido_firmware::persistence::{
    FlashStorageBackend, MockFlashBackend, SecureStorage, StorageError,
};
use aegis_fido_firmware::wallet_seed_store::{
    load_seed_bundle, save_seed_bundle, wipe_wallet_seed, WalletSeedError,
    WALLET_SEED_ENVELOPE_KEY, WALLET_SEED_ROUTE_KEY,
};

const OFFICIAL_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const PIN: &[u8] = b"f5-seed-store-pin";

fn session() -> SeedSession {
    SeedSession::authorize(true, true)
}

fn storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
}

/// Backend que falha exatamente na N-esima escrita e volta a funcionar
/// (falha transiente: modela queda/torn-write onde o retry/rollback
/// posterior ainda alcanca o flash).
struct FailNthWrite {
    inner: MockFlashBackend,
    writes: usize,
    fail_at: usize,
}

impl FailNthWrite {
    fn new(inner: MockFlashBackend, fail_at: usize) -> Self {
        Self {
            inner,
            writes: 0,
            fail_at,
        }
    }
}

impl FlashStorageBackend for FailNthWrite {
    fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.read_raw(key)
    }

    fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        self.writes += 1;
        if self.writes == self.fail_at {
            return Err(StorageError::FlashWriteError);
        }
        self.inner.write_raw(key, data)
    }

    fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
        self.inner.delete_raw(key)
    }

    fn exists(&self, key: &str) -> bool {
        self.inner.exists(key)
    }
}

fn provision_bundle(rng: &mut impl rand_core::CryptoRng) -> (Vec<u8>, Vec<u8>, AegisVault) {
    // Gera routing real: duas slots GEN (redes distintas) exportadas.
    let mut store = WalletStore::new();
    store
        .generate(CryptoNetwork::Bitcoin, 3, "btc", 1, true, rng)
        .expect("gen btc");
    store
        .generate(CryptoNetwork::Solana, 7, "sol", 1, true, rng)
        .expect("gen sol");
    let route = store.export_routing();
    assert_eq!(route, Vec::from([3u8, 0x01, 7, 0x03]));

    let vault = AegisVault::new([0x5Au8; 32]);
    let ceremony = SeedCeremony::import(&session(), OFFICIAL_PHRASE).expect("import");
    ceremony
        .confirm(&session(), OFFICIAL_PHRASE)
        .expect("confirm");
    let sealed = ceremony
        .export_sealed(&session(), &vault, PIN, rng)
        .expect("seal");
    (route, sealed, vault)
}

#[test]
fn provision_persist_reload_wipe_roundtrip() {
    let mut rng = rand::rng();
    let (route, sealed, vault) = provision_bundle(&mut rng);

    let mut st = storage();
    assert_eq!(
        load_seed_bundle(&st).unwrap_err(),
        WalletSeedError::NotFound
    );
    save_seed_bundle(&mut st, &route, &sealed).expect("save");

    // Reload: NVS simulada sobrevive ao "reboot" (novo SecureStorage sobre
    // os mesmos bytes) e a cerimonia reabre a mesma frase.
    let rebooted = SecureStorage::new(st.backend().clone(), &[0x55u8; 32], &[0xAAu8; 32]);
    let bundle = load_seed_bundle(&rebooted).expect("reload");
    assert_eq!(bundle.route, route);
    let reopened = SeedCeremony::import_sealed(&session(), &vault, PIN, &bundle.sealed_entropy)
        .expect("reopen");
    assert_eq!(
        reopened.reveal_phrase(&session()).expect("reveal"),
        OFFICIAL_PHRASE
    );
    assert_eq!(
        reopened.metadata(&session()).expect("meta").fingerprint,
        SeedCeremony::import(&session(), OFFICIAL_PHRASE)
            .expect("import")
            .metadata(&session())
            .expect("meta")
            .fingerprint
    );

    // Wipe: some tudo e é idempotente.
    let mut st = rebooted;
    wipe_wallet_seed(&mut st).expect("wipe");
    assert_eq!(
        load_seed_bundle(&st).unwrap_err(),
        WalletSeedError::NotFound
    );
    wipe_wallet_seed(&mut st).expect("wipe idempotente");
}

#[test]
fn drop_mid_save_rolls_back_to_old_bundle() {
    let mut rng = rand::rng();
    let (route_v1, sealed_v1, _) = provision_bundle(&mut rng);
    let mut st = storage();
    save_seed_bundle(&mut st, &route_v1, &sealed_v1).expect("save v1");

    // Falha transiente na 2a escrita (envelope novo): rollback restaura v1.
    let backend = st.backend().clone();
    let mut flaky = SecureStorage::new(FailNthWrite::new(backend, 2), &[0x55u8; 32], &[0xAAu8; 32]);
    let (route_v2, sealed_v2, _) = provision_bundle(&mut rng);
    assert_ne!(sealed_v2, sealed_v1);
    assert_eq!(
        save_seed_bundle(&mut flaky, &route_v2, &sealed_v2).unwrap_err(),
        WalletSeedError::Storage
    );
    assert_eq!(load_seed_bundle(&flaky).expect("rollback").route, route_v1);

    // Falha na 1a escrita em storage virgem: nada persiste (nunca parcial).
    let mut fresh_fail = SecureStorage::new(
        FailNthWrite::new(MockFlashBackend::new(), 1),
        &[0x55u8; 32],
        &[0xAAu8; 32],
    );
    assert_eq!(
        save_seed_bundle(&mut fresh_fail, &route_v2, &sealed_v2).unwrap_err(),
        WalletSeedError::Storage
    );
    assert_eq!(
        load_seed_bundle(&fresh_fail).unwrap_err(),
        WalletSeedError::NotFound
    );
}

#[test]
fn partial_nvs_loads_as_corrupted_never_half_state() {
    let mut rng = rand::rng();
    let (route, sealed, _) = provision_bundle(&mut rng);
    let mut st = storage();
    save_seed_bundle(&mut st, &route, &sealed).expect("save");

    // Metade apagada (qualquer lado) = corrompido, nunca meio-estado.
    st.backend_mut()
        .delete_raw(WALLET_SEED_ENVELOPE_KEY)
        .expect("delete envelope");
    assert_eq!(load_seed_bundle(&st).unwrap_err(), WalletSeedError::Storage);
    save_seed_bundle(&mut st, &route, &sealed).expect("save again");
    st.backend_mut()
        .delete_raw(WALLET_SEED_ROUTE_KEY)
        .expect("delete route");
    assert_eq!(load_seed_bundle(&st).unwrap_err(), WalletSeedError::Storage);
}

#[test]
fn wrong_pin_or_tampered_bundle_never_reopens() {
    let mut rng = rand::rng();
    let (route, sealed, vault) = provision_bundle(&mut rng);
    let mut st = storage();
    save_seed_bundle(&mut st, &route, &sealed).expect("save");
    let bundle = load_seed_bundle(&st).expect("load");

    assert_eq!(
        SeedCeremony::import_sealed(&session(), &vault, b"wrong-pin", &bundle.sealed_entropy)
            .unwrap_err(),
        SeedCeremonyError::BadEnvelope
    );
    let mut tampered = bundle.sealed_entropy.clone();
    tampered[20] ^= 0x55;
    assert_eq!(
        SeedCeremony::import_sealed(&session(), &vault, PIN, &tampered).unwrap_err(),
        SeedCeremonyError::BadEnvelope
    );
    // Frase errada nem provisiona.
    assert_eq!(
        SeedCeremony::import(&session(), "abandon abandon").unwrap_err(),
        SeedCeremonyError::BadEnvelope
    );
}
