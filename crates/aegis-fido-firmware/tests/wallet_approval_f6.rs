#![cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
//! F6 host: app-mediated approval on the headless board (no plate, no push).
//!
//! - The firmware exposes the pending preview (`0x4B` → `[slot, tx_hash,
//!   counts]`); the app displays it and decides approve/deny.
//! - Signing (`0x4A`) denies without the explicit approval receipt
//!   (tag `0x0C` == `approve`), without UP (`0x01`), and without a live
//!   PIN session (`0x02`): gates binding -> UP -> PIN, canonical order.
//! - Tamper denies: a preview of A followed by a sign of B (or a mutated
//!   receipt) fails closed (`0x04`) and consumes the preview, without
//!   touching keys. Signatures verify off-device against the slot pubkey.

use std::vec::Vec;

use aegis_fido_core::oath::tlv;
use aegis_fido_core::wallet::{parse_psbt, CryptoNetwork, WalletStore};
use aegis_fido_firmware::ble_gatt::{
    authorize_wallet_op, authorize_wallet_sign_op, BleGattError, OP_WALLET_PENDING, OP_WALLET_PSBT,
};
use aegis_fido_firmware::wallet_approval::WalletPendingApproval;
use aegis_fido_firmware::wallet_exec::{TAG_WALLET_APPROVAL, TAG_WALLET_PSBT, TAG_WALLET_SLOT};
use aegis_fido_firmware::wallet_sign::{
    wallet_dispatch, wallet_pending_summary, wallet_sign_psbt, TAG_WALLET_SIGNATURE,
};

fn psbt_1in_1out() -> Vec<u8> {
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

fn preview_payload(slot: u8, psbt: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    tlv::write_tlv(&mut out, TAG_WALLET_SLOT, &[slot]);
    tlv::write_tlv(&mut out, TAG_WALLET_PSBT, psbt);
    out
}

fn sign_payload(slot: u8, psbt: &[u8], approval: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    tlv::write_tlv(&mut out, TAG_WALLET_SLOT, &[slot]);
    tlv::write_tlv(&mut out, TAG_WALLET_PSBT, psbt);
    if let Some(receipt) = approval {
        tlv::write_tlv(&mut out, TAG_WALLET_APPROVAL, receipt);
    }
    out
}

fn keyed_store() -> WalletStore {
    let mut rng = rand::rng();
    let mut store = WalletStore::new();
    store
        .generate(CryptoNetwork::Bitcoin, 3, "btc", 1, true, &mut rng)
        .unwrap();
    store
}

#[test]
fn preview_exposes_slot_hash_and_counts_for_display() {
    let mut pending = WalletPendingApproval::new();
    let psbt = psbt_1in_1out();
    let (st, body) = wallet_pending_summary(&mut pending, &preview_payload(3, &psbt), true);
    assert_eq!(st, 0x00);
    let recs = tlv::parse_tlv_records(&body).unwrap();
    assert_eq!(tlv::find_tlv(&recs, TAG_WALLET_SLOT), Some(&[3u8][..]));
    let parsed = parse_psbt(&psbt).unwrap();
    assert_eq!(
        tlv::find_tlv(&recs, 0x0E),
        Some(&parsed.tx_hash[..]),
        "preview commits to sha256(unsigned_tx)"
    );
    let counts = tlv::find_tlv(&recs, 0x0F).unwrap();
    assert_eq!(counts.len(), 4);
    assert_eq!(
        (
            u16::from_le_bytes([counts[0], counts[1]]),
            u16::from_le_bytes([counts[2], counts[3]])
        ),
        (1, 1)
    );
    // Without UP the preview denies (display still gated binding -> UP).
    let mut fresh = WalletPendingApproval::new();
    let (st, _) = wallet_pending_summary(&mut fresh, &preview_payload(3, &psbt), false);
    assert_eq!(st, 0x01);
    assert_eq!(fresh.pending(), None);
}

#[test]
fn sign_denies_without_receipt_up_or_pin() {
    let mut store = keyed_store();
    let mut pending = WalletPendingApproval::new();
    let psbt = psbt_1in_1out();
    // No receipt, `deny`, mutated case, or garbage PSBT: 0x04, no key touch.
    for bad in [
        sign_payload(3, &psbt, None),
        sign_payload(3, &psbt, Some(b"deny")),
        sign_payload(3, &psbt, Some(b"APPROVE")),
        sign_payload(3, b"not-psbt", Some(b"approve")),
    ] {
        let (st, _) = wallet_sign_psbt(&mut store, &mut pending, &bad, true, true);
        assert_eq!(st, 0x04);
    }
    // No UP: 0x01; no PIN: 0x02 (canonical binding -> UP -> PIN order).
    let (st, _) = wallet_sign_psbt(
        &mut store,
        &mut pending,
        &sign_payload(3, &psbt, Some(b"approve")),
        false,
        true,
    );
    assert_eq!(st, 0x01);
    let (st, _) = wallet_sign_psbt(
        &mut store,
        &mut pending,
        &sign_payload(3, &psbt, Some(b"approve")),
        true,
        false,
    );
    assert_eq!(st, 0x02);
}

#[test]
fn tamper_between_preview_and_sign_denies_and_clears() {
    let mut store = keyed_store();
    let mut pending = WalletPendingApproval::new();
    let psbt = psbt_1in_1out();
    let (st, _) = wallet_pending_summary(&mut pending, &preview_payload(3, &psbt), true);
    assert_eq!(st, 0x00);
    // Drift one digest byte: tamper denies 0x04 and consumes the preview.
    let mut other = psbt.clone();
    other[20] ^= 0x55;
    let (st, _) = wallet_sign_psbt(
        &mut store,
        &mut pending,
        &sign_payload(3, &other, Some(b"approve")),
        true,
        true,
    );
    assert_eq!(st, 0x04);
    assert_eq!(pending.pending(), None);
    // Wrong slot against the same bytes denies the same way.
    wallet_pending_summary(&mut pending, &preview_payload(3, &psbt), true);
    let (st, _) = wallet_sign_psbt(
        &mut store,
        &mut pending,
        &sign_payload(4, &psbt, Some(b"approve")),
        true,
        true,
    );
    assert_eq!(st, 0x04);
    assert_eq!(pending.pending(), None);
}

#[test]
fn intact_preview_with_receipt_and_gates_signs_and_verifies() {
    let mut rng = rand::rng();
    let mut store = keyed_store();
    let mut pending = WalletPendingApproval::new();
    let psbt = psbt_1in_1out();
    // Dispatch through the single funnel point: PENDING then PSBT.
    let (st, _) = wallet_dispatch(
        &mut store,
        &mut pending,
        OP_WALLET_PENDING,
        &preview_payload(3, &psbt),
        1,
        true,
        false,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    let (st, body) = wallet_dispatch(
        &mut store,
        &mut pending,
        OP_WALLET_PSBT,
        &sign_payload(3, &psbt, Some(b"approve")),
        1,
        true,
        true,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    let recs = tlv::parse_tlv_records(&body).unwrap();
    let sig = tlv::find_tlv(&recs, TAG_WALLET_SIGNATURE).unwrap();
    assert!(!sig.is_empty());
    let cose = store.public_cose(3, true).unwrap();
    let pubkey = aegis_fido_core::crypto::PublicKey::from_cose_cbor(&cose).unwrap();
    let digest = parse_psbt(&psbt).unwrap().tx_hash;
    pubkey.verify(&digest, sig).unwrap();
}

#[test]
fn sign_gate_binds_binding_up_pin_in_order() {
    if aegis_fido_firmware::binding::binding_bypass_enabled() {
        assert_eq!(
            authorize_wallet_sign_op(OP_WALLET_PSBT, false, false, false),
            Err(BleGattError::PresenceRequired)
        );
    } else {
        assert_eq!(
            authorize_wallet_sign_op(OP_WALLET_PSBT, false, true, true),
            Err(BleGattError::NeedBinding)
        );
    }
    assert_eq!(
        authorize_wallet_sign_op(OP_WALLET_PSBT, true, false, true),
        Err(BleGattError::PresenceRequired)
    );
    assert_eq!(
        authorize_wallet_sign_op(OP_WALLET_PSBT, true, true, false),
        Err(BleGattError::PinRequired)
    );
    assert!(authorize_wallet_sign_op(OP_WALLET_PSBT, true, true, true).is_ok());
    // The preview gate stays binding -> UP (no PIN).
    assert!(authorize_wallet_op(OP_WALLET_PENDING, true, true).is_ok());
}
