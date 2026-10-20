//! Carteira Fase7 — executor on-device (sessão; NVS = follow-up).
//!
//! Executa GEN/LIST/ADDR sobre um [`WalletStore`] em RAM depois que o
//! transporte aprovou os gates (binding + UP). Erros viram wire status
//! do conjunto 9.5 fechado via [`WalletError::status`]; nenhum status
//! novo, nenhum segredo no fio (só slot/label/address públicos).
//!
//! Escopo: sessão de boot (sem NVS aqui — o codec
//! `export/import_routing` + chaves `wallet_slot_*` já prontos no core
//! viram persistência no follow-up com envelope-por-slot). TLV BER igual
//! ao app (`VendorOps`) e ao `oath/tlv.rs`: tags `0x01` slot, `0x02`
//! label, `0x07` address (resposta), `0x08` network (pedido GEN).

use std::string::String;
use std::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use aegis_fido_core::oath::tlv::{find_tlv, parse_tlv_records, write_tlv};
use aegis_fido_core::wallet::{types::CryptoNetwork, WalletError, WalletStore};

/// TLV: id do slot (1B).
pub const TAG_WALLET_SLOT: u8 = 0x01;
/// TLV: label utf8 (1..32B).
pub const TAG_WALLET_LABEL: u8 = 0x02;
/// TLV: endereço derivado (resposta; ignorado por decoders antigos per §9.6).
pub const TAG_WALLET_ADDRESS: u8 = 0x07;
/// TLV: rede (`CryptoNetwork` discriminant, 1B) no pedido GEN.
pub const TAG_WALLET_NETWORK: u8 = 0x08;

fn fail(e: WalletError) -> (u8, Vec<u8>) {
    (e.status(), Vec::new())
}

fn slot_of(records: &[aegis_fido_core::oath::tlv::TlvRecord<'_>]) -> Result<u8, WalletError> {
    match find_tlv(records, TAG_WALLET_SLOT) {
        Some(v) if v.len() == 1 => Ok(v[0]),
        _ => Err(WalletError::BadEnvelope),
    }
}

fn label_of(records: &[aegis_fido_core::oath::tlv::TlvRecord<'_>]) -> Result<String, WalletError> {
    match find_tlv(records, TAG_WALLET_LABEL) {
        Some(v) if !v.is_empty() && v.len() <= 32 => {
            core::str::from_utf8(v)
                .map(String::from)
                .map_err(|_| WalletError::BadEnvelope)
        }
        _ => Err(WalletError::BadEnvelope),
    }
}

fn network_of(
    records: &[aegis_fido_core::oath::tlv::TlvRecord<'_>],
) -> Result<CryptoNetwork, WalletError> {
    match find_tlv(records, TAG_WALLET_NETWORK) {
        Some(v) if v.len() == 1 => CryptoNetwork::from_u8(v[0]).ok_or(WalletError::BadEnvelope),
        _ => Err(WalletError::BadEnvelope),
    }
}

fn record_body(slot_id: u8, label: &str, address: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_tlv(&mut out, TAG_WALLET_SLOT, &[slot_id]);
    write_tlv(&mut out, TAG_WALLET_LABEL, label.as_bytes());
    write_tlv(&mut out, TAG_WALLET_ADDRESS, address.as_bytes());
    out
}

/// GEN: `[slot, label, network]` → `[slot, label, address]`.
///
/// `presence` vem do latch UP (uso único, consumido pelo chamador);
/// `created` = unix secs do relógio do device.
pub fn wallet_gen<R: RngCore + CryptoRng>(
    store: &mut WalletStore,
    payload: &[u8],
    created: u64,
    presence: bool,
    rng: &mut R,
) -> (u8, Vec<u8>) {
    let records = match parse_tlv_records(payload) {
        Ok(r) => r,
        Err(_) => return fail(WalletError::BadEnvelope),
    };
    let slot_id = match slot_of(&records) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let label = match label_of(&records) {
        Ok(l) => l,
        Err(e) => return fail(e),
    };
    let network = match network_of(&records) {
        Ok(n) => n,
        Err(e) => return fail(e),
    };
    match store.generate(network, slot_id, &label, created, presence, rng) {
        Ok(rec) => (0x00, record_body(rec.slot_id, &rec.label, &rec.address)),
        Err(e) => fail(e),
    }
}

/// LIST: `[]` → repetição de `[slot, label, address]` (só metadados).
pub fn wallet_list(store: &WalletStore, presence: bool) -> (u8, Vec<u8>) {
    match store.list(presence) {
        Ok(recs) => {
            let mut out = Vec::new();
            for rec in &recs {
                out.extend_from_slice(&record_body(rec.slot_id, &rec.label, &rec.address));
            }
            (0x00, out)
        }
        Err(e) => fail(e),
    }
}

/// ADDR: `[slot]` → `[address]`.
pub fn wallet_addr(store: &WalletStore, payload: &[u8], presence: bool) -> (u8, Vec<u8>) {
    let records = match parse_tlv_records(payload) {
        Ok(r) => r,
        Err(_) => return fail(WalletError::BadEnvelope),
    };
    let slot_id = match slot_of(&records) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    match store.address(slot_id, presence) {
        Ok(address) => {
            let mut out = Vec::new();
            write_tlv(&mut out, TAG_WALLET_ADDRESS, address.as_bytes());
            (0x00, out)
        }
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_payload(slot: u8, label: &[u8], net: u8) -> Vec<u8> {
        let mut out = Vec::new();
        write_tlv(&mut out, TAG_WALLET_SLOT, &[slot]);
        write_tlv(&mut out, TAG_WALLET_LABEL, label);
        write_tlv(&mut out, TAG_WALLET_NETWORK, &[net]);
        out
    }

    #[test]
    fn gen_list_addr_roundtrip_session() {
        let mut rng = rand::rngs::OsRng;
        let mut store = WalletStore::new();
        // Sem UP: nega NEED_UP (0x01).
        let (st, _) = wallet_gen(&mut store, &gen_payload(3, b"btc", 0x01), 1, false, &mut rng);
        assert_eq!(st, 0x01);
        // Com UP: gera; endereço bech32 no corpo.
        let (st, body) = wallet_gen(&mut store, &gen_payload(3, b"btc", 0x01), 1, true, &mut rng);
        assert_eq!(st, 0x00);
        let recs = parse_tlv_records(&body).unwrap();
        assert_eq!(find_tlv(&recs, TAG_WALLET_SLOT), Some(&[3u8][..]));
        let addr = find_tlv(&recs, TAG_WALLET_ADDRESS).unwrap();
        assert!(addr.starts_with(b"bc1q"), "{}", String::from_utf8_lossy(addr));
        // LIST traz o registro; ADDR confere o mesmo endereço.
        let (st, list) = wallet_list(&store, true);
        assert_eq!(st, 0x00);
        assert!(list.windows(addr.len()).any(|w| w == addr));
        let mut slot_req = Vec::new();
        write_tlv(&mut slot_req, TAG_WALLET_SLOT, &[3]);
        let (st, abody) = wallet_addr(&store, &slot_req, true);
        assert_eq!(st, 0x00);
        let arecs = parse_tlv_records(&abody).unwrap();
        assert_eq!(find_tlv(&arecs, TAG_WALLET_ADDRESS), Some(addr));
    }

    #[test]
    fn malformed_requests_fail_closed() {
        let mut rng = rand::rngs::OsRng;
        let mut store = WalletStore::new();
        // Rede desconhecida, slot ausente, label vazia, lixo binário.
        for bad in [
            gen_payload(0, b"x", 0x09),
            gen_payload(0, b"", 0x01),
            Vec::from([0x01]),
            Vec::from([0xFF, 0x00]),
        ] {
            let (st, _) = wallet_gen(&mut store, &bad, 1, true, &mut rng);
            assert_eq!(st, 0x04);
        }
        // Slot inexistente no ADDR.
        let mut slot_req = Vec::new();
        write_tlv(&mut slot_req, TAG_WALLET_SLOT, &[9]);
        let (st, _) = wallet_addr(&store, &slot_req, true);
        assert_eq!(st, 0x03);
        // LIST sem UP.
        let (st, _) = wallet_list(&store, false);
        assert_eq!(st, 0x01);
    }
}
