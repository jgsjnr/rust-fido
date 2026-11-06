//! F3 xpub-export integration test (host, no device).
//!
//! Exercises the F3 surface only: the pure account/full-path exporters and
//! the session-gated [`WalletStore::export_xpub`]. Independent evidence comes
//! from the official protocol derivation vectors (every `xpub` below is a
//! published chain string, asserted verbatim through the NEW functions).
//! Account-shape outputs (`m/84'/0'/0'`, `m/44'/60'/0'`) have no published
//! string in those vectors, so they are pinned structurally instead:
//! determinism, depth, parent-fingerprint linkage, public-derivation identity,
//! and seed isolation — never a hardcoded value computed by this same code.
//! No device, no transport, no secrets retained (seeds are test-only locals).

use aegis_fido_core::wallet::{
    decode_extended_key, wallet_account_path, wallet_address_path, xpub_at_account, xpub_at_path,
    CryptoNetwork, DecodedExtendedKey, DerivationPath, ExtendedPrivateKey, WalletError,
    WalletStore,
};

fn seed_of(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("test seed hex")
}

/// Asserts an official chain: full-path export through the new function must
/// render the published `xpub` verbatim.
fn assert_official_chain(seed_hex: &str, path: &str, xpub: &str) {
    let seed = seed_of(seed_hex);
    let parsed: DerivationPath = path.parse().expect("test path parses");
    let node = xpub_at_path(&seed, &parsed).expect("test path derives");
    assert_eq!(node.to_extended_string(), xpub, "xpub {path}");
    assert_eq!(node.depth() as usize, parsed.len());
}

#[test]
fn official_vector_1_chains_export_verbatim() {
    let seed = "000102030405060708090a0b0c0d0e0f";
    assert_official_chain(
        seed,
        "m",
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    );
    assert_official_chain(
        seed,
        "m/0'",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    );
    assert_official_chain(
        seed,
        "m/0'/1/2'",
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    );
    assert_official_chain(
        seed,
        "m/0'/1/2'/2/1000000000",
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    );
}

#[test]
fn official_vector_2_chain_exports_verbatim() {
    assert_official_chain(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0/2147483647'/1",
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
    );
}

#[test]
fn official_vector_3_leading_zeros_chain_exports_verbatim() {
    assert_official_chain(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        "m/0'",
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
    );
}

#[test]
fn account_shapes_are_deterministic_and_structurally_sound() {
    let seed = seed_of("000102030405060708090a0b0c0d0e0f");
    for network in [CryptoNetwork::Bitcoin, CryptoNetwork::EthereumEvm] {
        let first = xpub_at_account(&seed, network, 0).expect("account derives");
        // Determinism: same inputs always render the same string.
        assert_eq!(
            first.to_extended_string(),
            xpub_at_account(&seed, network, 0)
                .expect("account re-derives")
                .to_extended_string()
        );
        // Account nodes sit three hardened levels below the master.
        assert_eq!(first.depth(), 3);
        // Parent fingerprint links to the purpose'/coin' node (lineage is
        // real, not zeroed): recompute the parent independently.
        let parent_path = match network {
            CryptoNetwork::Bitcoin => "m/84'/0'",
            CryptoNetwork::EthereumEvm => "m/44'/60'",
            CryptoNetwork::Solana => unreachable!("loop covers secp256k1 only"),
        }
        .parse::<DerivationPath>()
        .expect("parent path parses");
        let parent = xpub_at_path(&seed, &parent_path).expect("parent derives");
        assert_eq!(first.parent_fingerprint(), parent.fingerprint());
        // Distinct accounts and networks never share an xpub.
        assert_ne!(
            first.to_extended_bytes(),
            xpub_at_account(&seed, network, 1)
                .expect("sibling derives")
                .to_extended_bytes()
        );
    }
    assert_ne!(
        xpub_at_account(&seed, CryptoNetwork::Bitcoin, 0)
            .expect("btc derives")
            .to_extended_bytes(),
        xpub_at_account(&seed, CryptoNetwork::EthereumEvm, 0)
            .expect("evm derives")
            .to_extended_bytes()
    );
    // Distinct seeds never share an xpub (derivation isolation).
    let other = seed_of("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
    assert_ne!(
        xpub_at_account(&seed, CryptoNetwork::Bitcoin, 0)
            .expect("derives")
            .to_extended_bytes(),
        xpub_at_account(&other, CryptoNetwork::Bitcoin, 0)
            .expect("derives")
            .to_extended_bytes()
    );
}

#[test]
fn public_derivation_from_account_xpub_matches_private_derivation() {
    // Protocol identity: N(m/account.../change/index) == M/account.../change/index.
    let seed = seed_of("000102030405060708090a0b0c0d0e0f");
    let account_path = wallet_account_path(CryptoNetwork::Bitcoin, 0).expect("path builds");
    let master = ExtendedPrivateKey::master_from_seed(&seed).expect("master derives");
    let account_public = master
        .derive_path(&account_path)
        .expect("account derives")
        .neutered();
    // The exporter must agree with the manual account node.
    assert_eq!(
        xpub_at_account(&seed, CryptoNetwork::Bitcoin, 0)
            .expect("exports")
            .to_extended_bytes(),
        account_public.to_extended_bytes()
    );
    // Non-hardened tail derives identically from the exported public node.
    let addr_path =
        wallet_address_path(CryptoNetwork::Bitcoin, 0, 0, 0).expect("address path builds");
    let via_private = master.derive_path(&addr_path).expect("derives").neutered();
    let tail: DerivationPath = "m/0/0".parse().expect("tail parses");
    let via_public = account_public.derive_path(&tail).expect("tail derives");
    assert_eq!(
        via_public.to_extended_bytes(),
        via_private.to_extended_bytes()
    );
}

#[test]
fn session_gate_denies_without_presence_and_never_emits_secrets() {
    let store = WalletStore::new();
    let seed = seed_of("000102030405060708090a0b0c0d0e0f");
    // No latch: denial, nothing derived.
    assert_eq!(
        store.export_xpub(&seed, CryptoNetwork::Bitcoin, 0, false),
        Err(WalletError::NeedUp)
    );
    // Latched: output matches the pure function and decodes as public-only.
    let gated = store
        .export_xpub(&seed, CryptoNetwork::Bitcoin, 0, true)
        .expect("exports");
    assert_eq!(
        gated,
        xpub_at_account(&seed, CryptoNetwork::Bitcoin, 0)
            .expect("derives")
            .to_extended_string()
    );
    match decode_extended_key(&gated).expect("decodes") {
        DecodedExtendedKey::Public(_) => {}
        DecodedExtendedKey::Private(_) => panic!("export must never carry private bytes"),
    }
}

#[test]
fn invalid_inputs_fail_closed_through_the_gate() {
    let store = WalletStore::new();
    let seed = seed_of("000102030405060708090a0b0c0d0e0f");
    // ed25519 has no extended-key protocol: rejected, never zero-mapped.
    assert_eq!(
        store.export_xpub(&seed, CryptoNetwork::Solana, 0, true),
        Err(WalletError::BadEnvelope)
    );
    // Short/long seeds and out-of-range accounts map onto BadEnvelope.
    assert_eq!(
        store.export_xpub(&[0u8; 15], CryptoNetwork::Bitcoin, 0, true),
        Err(WalletError::BadEnvelope)
    );
    assert_eq!(
        store.export_xpub(&seed, CryptoNetwork::Bitcoin, 0x8000_0000, true),
        Err(WalletError::BadEnvelope)
    );
}
