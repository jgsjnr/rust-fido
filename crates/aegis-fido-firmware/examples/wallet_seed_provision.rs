//! F5 seed-provisioning demo (host-only, no board, no eFuse).
//!
//! Walks the wallet seed ceremony end to end through public APIs only:
//! authorize -> import the (official test-vector) phrase -> confirm ->
//! seal -> persist the bundle -> reload after a simulated reboot -> wipe.
//! Only public metadata (word count, fingerprint) is printed; the phrase
//! and the seed never leave the ceremony.

#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
fn main() {
    use aegis_fido_core::vault::AegisVault;
    use aegis_fido_core::wallet::{CryptoNetwork, SeedCeremony, SeedSession, WalletStore};
    use aegis_fido_firmware::persistence::{MockFlashBackend, SecureStorage};
    use aegis_fido_firmware::wallet_seed_store::{
        load_seed_bundle, save_seed_bundle, wipe_wallet_seed, WalletSeedError,
    };

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const PIN: &[u8] = b"f5-seed-demo-pin";

    let mut rng = rand::rng();
    let session = SeedSession::authorize(true, true);

    // Provision: routing from two GEN slots + sealed entropy from the ceremony.
    let mut store = WalletStore::new();
    store
        .generate(CryptoNetwork::Bitcoin, 3, "btc", 1, true, &mut rng)
        .expect("gen btc");
    let route = store.export_routing();
    let vault = AegisVault::new([0x5Au8; 32]);
    let ceremony = SeedCeremony::import(&session, PHRASE).expect("import");
    ceremony.confirm(&session, PHRASE).expect("confirm");
    let sealed = ceremony
        .export_sealed(&session, &vault, PIN, &mut rng)
        .expect("seal");
    let meta = ceremony.metadata(&session).expect("metadata");
    println!(
        "provisioned: words={} fingerprint={} backed_up={}",
        meta.word_count,
        hex::encode(meta.fingerprint),
        meta.backed_up
    );

    // Persist, reboot (same NVS bytes, fresh storage handle), reload, wipe.
    let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
    save_seed_bundle(&mut st, &route, &sealed).expect("save");
    let rebooted = SecureStorage::new(st.backend().clone(), &[0x55u8; 32], &[0xAAu8; 32]);
    let bundle = load_seed_bundle(&rebooted).expect("reload");
    let reopened =
        SeedCeremony::import_sealed(&session, &vault, PIN, &bundle.sealed_entropy).expect("reopen");
    assert_eq!(reopened.metadata(&session).expect("meta"), meta);
    println!("reload: same fingerprint, same phrase");
    let mut st = rebooted;
    wipe_wallet_seed(&mut st).expect("wipe");
    assert_eq!(
        load_seed_bundle(&st).unwrap_err(),
        WalletSeedError::NotFound
    );
    println!("wipe: bundle gone (NotFound)");
}

#[cfg(any(feature = "cap-fido-only", feature = "cap-fido-totp"))]
fn main() {}
