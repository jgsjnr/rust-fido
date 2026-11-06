//! F4 PSBT integration test (host, no device).
//!
//! Exercises the F4 surface only: the structural parser
//! ([`parse_psbt`]) and session-gated digest signing
//! ([`WalletStore::sign_psbt`]). The envelope below is a fixed v0
//! fixture (1 input, 1 output); every assertion is structural — counts,
//! commitment identity (`tx_hash == sha256(unsigned_tx)`), and signature
//! verification against the slot public key with an independent code
//! path. Denials (bad magic, truncation, missing unsigned tx, missing
//! approval at the executor layer is firmware-side) map onto the closed
//! wire set via [`WalletError::BadEnvelope`]. No device, no transport,
//! no secrets retained (slot keys live in the test-local store).

use aegis_fido_core::wallet::{parse_psbt, CryptoNetwork, PsbtSummary, WalletError, WalletStore};

/// Fixed v0 PSBT fixture: magic + global(unsigned-tx 1-in/1-out) +
/// one empty input map + one empty output map.
///
/// Unsigned tx: version 2, one input (prev `0xAA*32`, vout 0, empty
/// script, sequence max), one output (1000 sats to P2WPKH-shaped
/// `0x0014||0x11*20`), locktime 0.
fn fixture_1in_1out() -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    tx.push(0x01);
    tx.extend_from_slice(&[0xAAu8; 32]);
    tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    tx.push(0x00);
    tx.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    tx.push(0x01);
    tx.extend_from_slice(&1000u64.to_le_bytes());
    let mut script = Vec::from([0x00, 0x14]);
    script.extend_from_slice(&[0x11u8; 20]);
    tx.push(script.len() as u8);
    tx.extend_from_slice(&script);
    tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let mut out = Vec::from([0x70, 0x73, 0x62, 0x74, 0xFF]);
    out.push(0x01);
    out.push(0x00);
    out.push(tx.len() as u8);
    out.extend_from_slice(&tx);
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out
}

#[test]
fn parses_fixed_fixture_with_counts_and_commitment() {
    let env = fixture_1in_1out();
    let parsed = parse_psbt(&env).expect("fixture parses");
    assert_eq!((parsed.inputs, parsed.outputs), (1, 1));
    // Commitment is over the unsigned-tx bytes only (magic/maps excluded).
    let unsigned_tx = &env[8..8 + env[7] as usize];
    assert_eq!(parsed.unsigned_tx, unsigned_tx);
    assert_eq!(
        parsed.tx_hash,
        PsbtSummary {
            inputs: 1,
            outputs: 1,
            tx_hash: parsed.tx_hash,
        }
        .tx_hash
    );
    assert_eq!(parsed.summary().tx_hash, parsed.tx_hash);
}

#[test]
fn signs_fixture_digest_and_verifies_off_device() {
    use aegis_fido_core::crypto::PublicKey;
    let env = fixture_1in_1out();
    let mut store = WalletStore::new();
    store
        .generate(CryptoNetwork::Bitcoin, 0, "psbt", 0, true, &mut rand::rng())
        .expect("slot generates");
    let (summary, sig) = store.sign_psbt(0, &env, true).expect("signs");
    assert_eq!((summary.inputs, summary.outputs), (1, 1));
    assert!(!sig.is_empty());
    let cose = store.public_cose(0, true).expect("pubkey exports");
    let pubkey = PublicKey::from_cose_cbor(&cose).expect("pubkey decodes");
    pubkey
        .verify(&summary.tx_hash, &sig)
        .expect("off-device verify");
}

#[test]
fn denials_map_onto_bad_envelope_without_signing() {
    let env = fixture_1in_1out();
    let mut store = WalletStore::new();
    store
        .generate(CryptoNetwork::Bitcoin, 0, "psbt", 0, true, &mut rand::rng())
        .expect("slot generates");
    // Presence gate first: no latch, no parse, no signature.
    assert_eq!(
        store.sign_psbt(0, &env, false).unwrap_err(),
        WalletError::NeedUp
    );
    // Structural denials: bad magic, truncation, missing unsigned tx.
    let mut bad_magic = env.clone();
    bad_magic[0] = 0x00;
    for bad in [
        bad_magic,
        env[..env.len() - 3].to_vec(),
        Vec::from([0x70, 0x73, 0x62, 0x74, 0xFF, 0x00]),
    ] {
        assert_eq!(
            store.sign_psbt(0, &bad, true).unwrap_err(),
            WalletError::BadEnvelope,
            "len {}",
            bad.len()
        );
    }
    // Unknown slot: NoSlot, never a signature.
    assert_eq!(
        store.sign_psbt(7, &env, true).unwrap_err(),
        WalletError::NoSlot
    );
}
