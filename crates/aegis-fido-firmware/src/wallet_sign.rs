//! PSBT signing executor + single wallet dispatch point (F4/F6).
//!
//! [`wallet_sign_psbt`] parses the PSBT envelope, requires the explicit
//! app-mediated approval receipt ([`APPROVAL_RECEIPT_APPROVE`], owner
//! decision: no on-device display, the companion app shows the details
//! and returns approve/deny) and only then signs the digest with the
//! slot key. Without approval, no signature — fail-closed `0x04`
//! before any key touch. [`wallet_dispatch`] is the single `match` for
//! the four funnels (serial legacy, FreeRTOS, BLE, serial-vendor) after
//! the canonical transport gates (binding -> UP, plus PIN for `0x4A`);
//! `0x48`/`0x49` (DERIVE/XPUB) stay `0x04` fail-closed (execution in F2/F3
//! in core). Diet builds exclude this module (see `lib.rs`); the funnels
//! answer `0x06` there without touching the store.
//!
//! F6 (headless board): the pending preview lives in
//! [`WalletPendingApproval`] (announced via [`wallet_pending_summary`],
//! opcode `0x4B`); signing additionally requires `pin_authenticated`
//! (`0x02` without it, canonical order binding -> UP -> PIN) and consumes
//! the preview single-use — any slot/digest drift denies as tamper
//! (`0x04`) and clears, without touching keys.
//!
//! Split from `wallet_exec` (dep-track: keeps both files under the
//! god-file ceiling); shared helpers (`fail`, `slot_of`, TLV tags) stay
//! there as `pub(crate)`. No new wire status, no secret on the wire.

use rand_core::CryptoRng;
use std::vec::Vec;

use super::wallet_approval as approval;
use super::wallet_exec as exec;
use crate::ble_gatt as gatt;
use aegis_fido_core::oath::tlv;
use aegis_fido_core::wallet::{WalletError, WalletStore};

/// TLV: assinatura opaca de PSBT (resposta; acima das congeladas, decoders
/// antigos ignoram por §9.6).
pub const TAG_WALLET_SIGNATURE: u8 = 0x0D;

/// Recibo de aprovacao mediada pelo app que autoriza uma assinatura PSBT.
///
/// Comparacao exata de bytes: qualquer outro valor (incluindo `deny`,
/// vazio ou ausente) nega fail-closed com `0x04`, sem tocar em chave.
/// Vocabulario de protocolo, sem marcas. Canonical home is
/// [`approval::APPROVAL_RECEIPT_APPROVE`]; re-exported here so existing
/// funnels keep compiling.
pub use approval::APPROVAL_RECEIPT_APPROVE;

/// Preview exposure: `[slot, psbt]` → `[slot, tx_hash, counts]`.
///
/// `presence` arrives from the UP latch. Fail-closed order: envelope
/// malformado (`0x04`), UP ausente (`0x01`), parse (`0x04`). Stores the
/// parsed commitment in `pending` (latest preview wins) for the app to
/// display before it decides approve/deny. No PIN here: display precedes
/// authentication. No secrets in the response.
pub fn wallet_pending_summary(
    pending: &mut approval::WalletPendingApproval,
    payload: &[u8],
    presence: bool,
) -> (u8, Vec<u8>) {
    let records = match tlv::parse_tlv_records(payload) {
        Ok(r) => r,
        Err(_) => return exec::fail(WalletError::BadEnvelope),
    };
    let slot_id = match exec::slot_of(&records) {
        Ok(s) => s,
        Err(e) => return exec::fail(e),
    };
    let psbt = match tlv::find_tlv(&records, exec::TAG_WALLET_PSBT) {
        Some(v) if !v.is_empty() => v,
        _ => return exec::fail(WalletError::BadEnvelope),
    };
    if !presence {
        return exec::fail(WalletError::NeedUp);
    }
    match pending.announce(slot_id, psbt) {
        Ok(preview) => (0x00, approval::encode_pending_summary(&preview)),
        Err(e) => exec::fail(e),
    }
}

/// PSBT: `[slot, psbt, approval]` → `[slot, signature]`.
///
/// `presence` vem do latch UP (uso único, consumido pelo chamador);
/// `pin_authenticated` vem da sessao PIN viva (plumbing ClientPIN; fail-closed
/// sem ela). Ordem fail-closed: envelope malformado (`0x04`), recibo de
/// aprovação ausente ou diferente de [`APPROVAL_RECEIPT_APPROVE`] (`0x04`,
/// antes de qualquer toque em chave), preview adulterado (`0x04`, tamper
/// consome o preview sem tocar em chave), UP ausente (`0x01`), PIN ausente
/// (`0x02`), slot inexistente (`0x03`). A assinatura é message-sign sobre
/// o digest do PSBT (ver [`aegis_fido_core::wallet::psbt`]); nenhum segredo
/// no fio.
pub fn wallet_sign_psbt(
    store: &mut WalletStore,
    pending: &mut approval::WalletPendingApproval,
    payload: &[u8],
    presence: bool,
    pin_authenticated: bool,
) -> (u8, Vec<u8>) {
    let records = match tlv::parse_tlv_records(payload) {
        Ok(r) => r,
        Err(_) => return exec::fail(WalletError::BadEnvelope),
    };
    let slot_id = match exec::slot_of(&records) {
        Ok(s) => s,
        Err(e) => return exec::fail(e),
    };
    match tlv::find_tlv(&records, exec::TAG_WALLET_PSBT) {
        Some(v) if !v.is_empty() => {}
        _ => return exec::fail(WalletError::BadEnvelope),
    }
    match tlv::find_tlv(&records, exec::TAG_WALLET_APPROVAL) {
        Some(v) if v == APPROVAL_RECEIPT_APPROVE => {}
        _ => return exec::fail(WalletError::BadEnvelope),
    }
    let psbt = tlv::find_tlv(&records, exec::TAG_WALLET_PSBT).unwrap_or(&[]);
    if pending.verify_match(slot_id, psbt).is_err() {
        return exec::fail(WalletError::BadEnvelope);
    }
    if !presence {
        return exec::fail(WalletError::NeedUp);
    }
    if !pin_authenticated {
        return exec::fail(WalletError::NeedPin);
    }
    match store.sign_psbt(slot_id, psbt, true) {
        Ok((_, sig)) => {
            let mut out = Vec::new();
            tlv::write_tlv(&mut out, exec::TAG_WALLET_SLOT, &[slot_id]);
            tlv::write_tlv(&mut out, TAG_WALLET_SIGNATURE, &sig);
            (0x00, out)
        }
        Err(e) => exec::fail(e),
    }
}

/// Ponto único de despacho wallet (F4/F6): um `match` para os quatro funis.
///
/// Serial legado, FreeRTOS, BLE e serial-vendor chamam aqui depois dos
/// gates canônicos de transporte (binding -> UP, mais PIN para `0x4A`).
/// `0x4B` expõe o preview pendente (display precede autenticação: sem PIN);
/// `0x4A` exige recibo + preview íntegro + UP + PIN. `0x48`/`0x49`
/// (DERIVE/XPUB) seguem `0x04` fail-closed (execução em F2/F3 no core);
/// desconhecidos também `0x04`.
#[allow(clippy::too_many_arguments)]
// Oito args explícitos de sessão (store + preview + gates + relógio +
// latches + RNG): cada gate chega separado de propósito (fail-closed sem
// agregador opaco); mesmo padrão dos despachantes `route_ctaphid_event` e
// `serial_ctx` nos testes deste arquivo.
pub fn wallet_dispatch<R: CryptoRng>(
    store: &mut WalletStore,
    pending: &mut approval::WalletPendingApproval,
    op: u8,
    payload: &[u8],
    now_secs: u64,
    presence: bool,
    pin_authenticated: bool,
    rng: &mut R,
) -> (u8, Vec<u8>) {
    match op {
        gatt::OP_WALLET_GEN => exec::wallet_gen(store, payload, now_secs, presence, rng),
        gatt::OP_WALLET_LIST => exec::wallet_list(store, presence),
        gatt::OP_WALLET_ADDR => exec::wallet_addr(store, payload, presence),
        gatt::OP_WALLET_PENDING => wallet_pending_summary(pending, payload, presence),
        gatt::OP_WALLET_PSBT => {
            wallet_sign_psbt(store, pending, payload, presence, pin_authenticated)
        }
        _ => (0x04, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psbt_envelope_1in_1out() -> Vec<u8> {
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

    fn sign_payload(slot: u8, psbt: &[u8], approval: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        tlv::write_tlv(&mut out, exec::TAG_WALLET_SLOT, &[slot]);
        tlv::write_tlv(&mut out, exec::TAG_WALLET_PSBT, psbt);
        if let Some(receipt) = approval {
            tlv::write_tlv(&mut out, exec::TAG_WALLET_APPROVAL, receipt);
        }
        out
    }

    fn preview_payload(slot: u8, psbt: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        tlv::write_tlv(&mut out, exec::TAG_WALLET_SLOT, &[slot]);
        tlv::write_tlv(&mut out, exec::TAG_WALLET_PSBT, psbt);
        out
    }

    #[test]
    fn psbt_sign_requires_explicit_app_approval_before_any_key_touch() {
        let mut rng = rand::rng();
        let mut store = WalletStore::new();
        let mut pending = approval::WalletPendingApproval::new();
        store
            .generate(
                aegis_fido_core::wallet::types::CryptoNetwork::Bitcoin,
                3,
                "btc",
                1,
                true,
                &mut rng,
            )
            .unwrap();
        let psbt = psbt_envelope_1in_1out();
        // Sem recibo, recibo vazio via TLV ausente, ou `deny`: 0x04,
        // sem tocar em chave (mesmo com UP + PIN válidos).
        for bad in [
            sign_payload(3, &psbt, None),
            sign_payload(3, &psbt, Some(b"deny")),
            sign_payload(3, &psbt, Some(b"APPROVE")),
            sign_payload(3, b"not-psbt", Some(b"approve")),
        ] {
            let (st, _) = wallet_sign_psbt(&mut store, &mut pending, &bad, true, true);
            assert_eq!(st, 0x04);
        }
        // Com aprovação + UP + PIN: 0x00 com `[slot, signature]`; assinatura
        // verifica off-device contra a pubkey do slot.
        let (st, body) = wallet_sign_psbt(
            &mut store,
            &mut pending,
            &sign_payload(3, &psbt, Some(b"approve")),
            true,
            true,
        );
        assert_eq!(st, 0x00);
        let recs = tlv::parse_tlv_records(&body).unwrap();
        assert_eq!(
            tlv::find_tlv(&recs, exec::TAG_WALLET_SLOT),
            Some(&[3u8][..])
        );
        let sig = tlv::find_tlv(&recs, TAG_WALLET_SIGNATURE).unwrap();
        assert!(!sig.is_empty());
        // Sem UP (aprovação válida): 0x01; sem PIN: 0x02; slot inexistente:
        // 0x03. Ordem canônica binding -> UP -> PIN preservada no executor.
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
        let (st, _) = wallet_sign_psbt(
            &mut store,
            &mut pending,
            &sign_payload(9, &psbt, Some(b"approve")),
            true,
            true,
        );
        assert_eq!(st, 0x03);
    }

    #[test]
    fn pending_preview_feeds_sign_and_tamper_denies() {
        let mut rng = rand::rng();
        let mut store = WalletStore::new();
        let mut pending = approval::WalletPendingApproval::new();
        store
            .generate(
                aegis_fido_core::wallet::types::CryptoNetwork::Bitcoin,
                3,
                "btc",
                1,
                true,
                &mut rng,
            )
            .unwrap();
        let psbt = psbt_envelope_1in_1out();
        // Preview expõe `[slot, tx_hash, counts]` sem PIN (display precede
        // autenticação); sem UP nega 0x01.
        let (st, _) = wallet_pending_summary(&mut pending, &preview_payload(3, &psbt), false);
        assert_eq!(st, 0x01);
        let (st, body) = wallet_pending_summary(&mut pending, &preview_payload(3, &psbt), true);
        assert_eq!(st, 0x00);
        assert!(!body.is_empty());
        // Tamper: preview de A, assinatura de B (mesmo recibo + gates) nega
        // 0x04 e consome o preview, sem tocar em chave.
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
        // Preview íntegro + recibo + UP + PIN assina.
        wallet_pending_summary(&mut pending, &preview_payload(3, &psbt), true);
        let (st, body) = wallet_sign_psbt(
            &mut store,
            &mut pending,
            &sign_payload(3, &psbt, Some(b"approve")),
            true,
            true,
        );
        assert_eq!(st, 0x00);
        assert!(!body.is_empty());
        // Preview é uso único: segundo sign do mesmo envelope sem novo
        // preview segue o caminho compatível (recibo + gates) e assina.
        let (st, _) = wallet_sign_psbt(
            &mut store,
            &mut pending,
            &sign_payload(3, &psbt, Some(b"approve")),
            true,
            true,
        );
        assert_eq!(st, 0x00);
    }

    #[test]
    fn dispatch_routes_psbt_and_pending_and_keeps_derive_xpub_fail_closed() {
        let mut rng = rand::rng();
        let mut store = WalletStore::new();
        let mut pending = approval::WalletPendingApproval::new();
        store
            .generate(
                aegis_fido_core::wallet::types::CryptoNetwork::Bitcoin,
                3,
                "btc",
                1,
                true,
                &mut rng,
            )
            .unwrap();
        let psbt = psbt_envelope_1in_1out();
        let (st, body) = wallet_dispatch(
            &mut store,
            &mut pending,
            gatt::OP_WALLET_PENDING,
            &preview_payload(3, &psbt),
            1,
            true,
            false,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(!body.is_empty());
        let (st, body) = wallet_dispatch(
            &mut store,
            &mut pending,
            gatt::OP_WALLET_PSBT,
            &sign_payload(3, &psbt, Some(b"approve")),
            1,
            true,
            true,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(!body.is_empty());
        // Sem PIN no despacho: 0x02 fail-closed.
        let (st, _) = wallet_dispatch(
            &mut store,
            &mut pending,
            gatt::OP_WALLET_PSBT,
            &sign_payload(3, &psbt, Some(b"approve")),
            1,
            true,
            false,
            &mut rng,
        );
        assert_eq!(st, 0x02);
        // DERIVE/XPUB seguem sem execução: 0x04 fail-closed.
        for op in [gatt::OP_WALLET_DERIVE, gatt::OP_WALLET_XPUB, 0x00] {
            let (st, _) =
                wallet_dispatch(&mut store, &mut pending, op, &[], 1, true, true, &mut rng);
            assert_eq!(st, 0x04, "op 0x{op:02X}");
        }
    }
}
