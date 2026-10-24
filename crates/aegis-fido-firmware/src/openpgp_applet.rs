// OpenPGP applet: objetos de dados, chaves e despacho APDU.
//
// Split do dono (move-only, sem mudanca de comportamento):
// - `openpgp_cmd`: consts (AID/CLA/INS/PW/RC/SALT/HASH/DO), `PinSlot`,
//   `OpgpError` + Display + From + `status_word`, `OpgpSession`, NVS
//   (`opgp_ns`, label, `store/load_blob`, retries, `hash_pin`, `ct_eq`,
//   `slot_keys`, `do_key`), PIN (`is_provisioned`, `check_terminated`,
//   `provision`, `verify`, `change_pin`, `reset_factory`), ciclo de vida
//   (`terminate`, `activate`, `aid`) + re-export + tests.
// - `openpgp_applet` (este arquivo): `tag_to_bytes`, `tlv`, `pw_status`,
//   `get_data`, `put_data`, `generate_sign_key`, `import_sign_key`,
//   `store_pub_and_fp`, `load_sign_key`, `pso_sign`, `pso_decrypt`,
//   `get_challenge`, `parse_tag`, `dispatch`, `split_half`,
//   `dispatch_raw` + `MAX_RETRY_GEN`.
//
// Helpers usados pelos DOIS lados ficam no dono com `pub(crate)`
// (sem duplicar); o parse APDU vive em `crate::apdu` (dono unico).

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::openpgp_cmd::{
    activate, aid, change_pin, check_terminated, do_key, is_provisioned, load_blob, load_retries,
    opgp_label, opgp_ns, store_blob, terminate, verify, OpgpError, OpgpSession, PinSlot, CLA_ISO,
    EPH_LEN, INS_ACTIVATE, INS_CHALLENGE, INS_CHANGE, INS_GET_DATA, INS_PSO, INS_PUT_DATA,
    INS_SELECT, INS_TERMINATE, INS_VERIFY, K_FPSIGN, K_PW1R, K_PW3R, K_RCR, K_SIGN, MAX_DEC_CT,
    MAX_DO_LEN, MAX_SIGN_INPUT, OPGP_AID_PREFIX, P2_PW1, P2_PW3, PSO_DEC_P1P2, PSO_SIGN_P1P2,
    PW_MAX, RC_LEN,
};
use crate::apdu::{parse_apdu, Apdu};
use crate::crypto_hrng::HrngSource;
use crate::crypto_p256::{ecdh_p256, P256Secret};
use crate::persistence::{FlashStorageBackend, NamespacedStoreError, SecureStorage};

fn tag_to_bytes(tag: u16) -> Vec<u8> {
    if tag < 0x100 {
        alloc::vec![tag as u8]
    } else {
        alloc::vec![(tag >> 8) as u8, (tag & 0xFF) as u8]
    }
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = tag_to_bytes(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}

/// Bytes do PW-status (DO C4): [00, maxPW1, maxRC, maxPW3, e1, erc, e3].
pub fn pw_status<B: FlashStorageBackend>(store: &SecureStorage<B>) -> Result<[u8; 7], OpgpError> {
    if !is_provisioned(store) {
        return Err(OpgpError::NotProvisioned);
    }
    let e1 = load_retries(store, K_PW1R)?;
    let er = load_retries(store, K_RCR)?;
    let e3 = load_retries(store, K_PW3R)?;
    Ok([0x00, PW_MAX as u8, RC_LEN as u8, PW_MAX as u8, e1, er, e3])
}

/// GET DATA (retorna TLV completo). Tags: 4F 5E 5B 5F2D 5F35 5F50 C4 C7 6E.
pub fn get_data<B: FlashStorageBackend>(
    store: &SecureStorage<B>,
    tag: u16,
) -> Result<Vec<u8>, OpgpError> {
    check_terminated(store)?;
    match tag {
        0x004F => Ok(tlv(0x4F, &aid(store)?)),
        0x00C4 => Ok(tlv(0xC4, &pw_status(store)?)),
        0x005E | 0x005B | 0x5F2D | 0x5F35 | 0x5F50 => {
            let key = do_key(tag);
            match opgp_ns().get(store, opgp_label(key.as_str())) {
                Ok(v) => Ok(tlv(tag, &v)),
                Err(NamespacedStoreError::NotFound) => Ok(tlv(tag, &[])),
                Err(_) => Err(OpgpError::Storage),
            }
        }
        0x00C7 => match opgp_ns().get(store, opgp_label(K_FPSIGN)) {
            Ok(v) => Ok(tlv(0xC7, &v)),
            Err(NamespacedStoreError::NotFound) => {
                if !is_provisioned(store) {
                    return Err(OpgpError::NotProvisioned);
                }
                Ok(tlv(0xC7, &[]))
            }
            Err(_) => Err(OpgpError::Storage),
        },
        0x006E => {
            let mut inner = tlv(0x4F, &aid(store)?);
            inner.extend_from_slice(&tlv(0xC4, &pw_status(store)?));
            let login_key = do_key(0x5E);
            let login = match opgp_ns().get(store, opgp_label(login_key.as_str())) {
                Ok(v) => v,
                Err(NamespacedStoreError::NotFound) => Vec::new(),
                Err(_) => return Err(OpgpError::Storage),
            };
            inner.extend_from_slice(&tlv(0x5E, &login));
            Ok(tlv(0x6E, &inner))
        }
        _ => Err(OpgpError::UnknownTag),
    }
}

/// PUT DATA (exige sessao PW1; C7/4F/C4/6E sao ReadOnly).
pub fn put_data<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    session: &OpgpSession,
    tag: u16,
    value: &[u8],
) -> Result<(), OpgpError> {
    if !is_provisioned(store) {
        return Err(OpgpError::NotProvisioned);
    }
    check_terminated(store)?;
    if !session.pw1 {
        return Err(OpgpError::NotAuthorized);
    }
    match tag {
        0x005E | 0x005B | 0x5F2D | 0x5F35 | 0x5F50 => {
            if value.len() > MAX_DO_LEN {
                return Err(OpgpError::TooLarge);
            }
            store_blob(store, do_key(tag).as_str(), value)
        }
        0x004F | 0x00C4 | 0x00C7 | 0x006E => Err(OpgpError::ReadOnly),
        _ => Err(OpgpError::UnknownTag),
    }
}

/// Gera a chave de assinatura no device (GEN-DEVICE; exige PW3).
/// Gera a chave de assinatura no device (GEN-DEVICE; exige PW3).
pub fn generate_sign_key<B, R>(
    store: &mut SecureStorage<B>,
    rng: &mut R,
    session: &OpgpSession,
) -> Result<[u8; 33], OpgpError>
where
    B: FlashStorageBackend,
    R: HrngSource,
{
    if !is_provisioned(store) {
        return Err(OpgpError::NotProvisioned);
    }
    check_terminated(store)?;
    if !session.pw3 {
        return Err(OpgpError::NotAuthorized);
    }
    let mut raw = [0u8; 32];
    for _ in 0..MAX_RETRY_GEN {
        rng.fill(&mut raw)?;
        if P256Secret::from_bytes(raw).is_ok() {
            let secret = P256Secret::from_bytes(raw).map_err(|_| OpgpError::Storage)?;
            let public = secret.public_compressed();
            store_blob(store, K_SIGN, &raw)?;
            raw.zeroize();
            return store_pub_and_fp(store, &public);
        }
    }
    raw.zeroize();
    Err(OpgpError::Rng)
}

const MAX_RETRY_GEN: usize = 8;

/// Importa a chave via envelope (GEN-APP-STORE; exige PW3). Guarda + FP.
pub fn import_sign_key<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    session: &OpgpSession,
    raw32: &[u8; 32],
) -> Result<[u8; 33], OpgpError> {
    if !is_provisioned(store) {
        return Err(OpgpError::NotProvisioned);
    }
    check_terminated(store)?;
    if !session.pw3 {
        return Err(OpgpError::NotAuthorized);
    }
    let secret = P256Secret::from_bytes(*raw32).map_err(|_| OpgpError::BadKey)?;
    let public = secret.public_compressed();
    store_blob(store, K_SIGN, raw32)?;
    store_pub_and_fp(store, &public)?;
    Ok(public)
}

fn store_pub_and_fp<B: FlashStorageBackend>(
    store: &mut SecureStorage<B>,
    public: &[u8; 33],
) -> Result<[u8; 33], OpgpError> {
    // Fingerprint = SHA256(pub)[..20].
    let mut h = Sha256::new();
    h.update(public);
    let digest = h.finalize();
    let mut fp = [0u8; 20];
    fp.copy_from_slice(&digest[..20]);
    store_blob(store, K_FPSIGN, &fp)?;
    let mut out = [0u8; 33];
    out.copy_from_slice(public);
    Ok(out)
}

fn load_sign_key<B: FlashStorageBackend>(store: &SecureStorage<B>) -> Result<[u8; 32], OpgpError> {
    let raw = load_blob(store, K_SIGN, 32, OpgpError::NoKey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// PSO SIGN: ECDSA-SHA256 P-256 (dado 1..=256 B; exige PW1; sai r||s).
pub fn pso_sign<B: FlashStorageBackend>(
    store: &SecureStorage<B>,
    session: &OpgpSession,
    data: &[u8],
) -> Result<[u8; 64], OpgpError> {
    check_terminated(store)?;
    if !session.pw1 {
        return Err(OpgpError::NotAuthorized);
    }
    if data.is_empty() || data.len() > MAX_SIGN_INPUT {
        return Err(OpgpError::TooLarge);
    }
    let raw = load_sign_key(store)?;
    let secret = P256Secret::from_bytes(raw).map_err(|_| OpgpError::Storage)?;
    Ok(secret.sign(data))
}

/// PSO DEC: ECDH + KDF(HMAC-SHA256) XOR (pub 33 B || ct; exige PW1).
pub fn pso_decrypt<B: FlashStorageBackend>(
    store: &SecureStorage<B>,
    session: &OpgpSession,
    input: &[u8],
) -> Result<Vec<u8>, OpgpError> {
    check_terminated(store)?;
    if !session.pw1 {
        return Err(OpgpError::NotAuthorized);
    }
    if input.len() < EPH_LEN + 1 || input.len() > EPH_LEN + MAX_DEC_CT {
        return Err(OpgpError::TooLarge);
    }
    let mut peer = [0u8; EPH_LEN];
    peer.copy_from_slice(&input[..EPH_LEN]);
    let raw = load_sign_key(store)?;
    let z = ecdh_p256(&raw, &peer).map_err(|_| OpgpError::BadPeer)?;
    // KDF: SHA256(z || dominio); keystream XOR.
    let mut h = Sha256::new();
    h.update(z);
    h.update(b"aegis-openpgp-ecdh-v1");
    let ks = h.finalize();
    let ct = &input[EPH_LEN..];
    let mut pt = Vec::with_capacity(ct.len());
    for (i, b) in ct.iter().enumerate() {
        pt.push(b ^ ks[i % 32]);
    }
    Ok(pt)
}

/// GET CHALLENGE: n aleatorios (8..=255 B; sem estado).
pub fn get_challenge<R: HrngSource>(rng: &mut R, n: usize) -> Result<Vec<u8>, OpgpError> {
    if !(8..=255).contains(&n) {
        return Err(OpgpError::TooLarge);
    }
    let mut out = alloc::vec![0u8; n];
    rng.fill(&mut out)?;
    Ok(out)
}

/// Decodifica a tag do P1P2 (0x00XX ou 0x5FXX).
pub fn parse_tag(p1: u8, p2: u8) -> Result<u16, OpgpError> {
    if p1 == 0x00 {
        Ok(u16::from(p2))
    } else if p1 == 0x5F {
        Ok(0x5F00 | u16::from(p2))
    } else {
        Err(OpgpError::BadP1P2)
    }
}

/// Despacha um APDU curto ja parseado; retorna os bytes de resposta.
pub fn dispatch<B, R>(
    store: &mut SecureStorage<B>,
    session: &mut OpgpSession,
    rng: &mut R,
    apdu: &Apdu,
) -> Result<Vec<u8>, OpgpError>
where
    B: FlashStorageBackend,
    R: HrngSource,
{
    if apdu.cla != CLA_ISO {
        return Err(OpgpError::BadCla);
    }
    match apdu.ins {
        INS_SELECT => {
            if apdu.data.len() < OPGP_AID_PREFIX.len() || apdu.data[..6] != OPGP_AID_PREFIX {
                return Err(OpgpError::UnknownTag);
            }
            *session = OpgpSession::new();
            Ok(tlv(0x4F, &aid(store)?))
        }
        INS_GET_DATA => {
            check_terminated(store)?;
            let tag = parse_tag(apdu.p1, apdu.p2)?;
            get_data(store, tag)
        }
        INS_PUT_DATA => {
            let tag = parse_tag(apdu.p1, apdu.p2)?;
            put_data(store, session, tag, &apdu.data)?;
            Ok(Vec::new())
        }
        INS_VERIFY => {
            check_terminated(store)?;
            let slot = match apdu.p2 {
                P2_PW1 => PinSlot::Pw1,
                P2_PW3 => PinSlot::Pw3,
                _ => return Err(OpgpError::BadP1P2),
            };
            verify(store, session, slot, &apdu.data)?;
            Ok(Vec::new())
        }
        INS_CHANGE => {
            check_terminated(store)?;
            let slot = match apdu.p2 {
                P2_PW1 => PinSlot::Pw1,
                P2_PW3 => PinSlot::Pw3,
                _ => return Err(OpgpError::BadP1P2),
            };
            // data = old || 0x00 sep? Formato: Lc cobre old+new sem borda;
            // usa metade/metade so se par; senao nega (fail-closed).
            let (old, new) = split_half(&apdu.data)?;
            change_pin(store, rng, slot, old, new)?;
            Ok(Vec::new())
        }
        INS_PSO => {
            if (apdu.p1, apdu.p2) == PSO_SIGN_P1P2 {
                Ok(pso_sign(store, session, &apdu.data)?.to_vec())
            } else if (apdu.p1, apdu.p2) == PSO_DEC_P1P2 {
                pso_decrypt(store, session, &apdu.data)
            } else {
                Err(OpgpError::BadP1P2)
            }
        }
        INS_CHALLENGE => {
            check_terminated(store)?;
            // Le descartado pelo parser curto; desafio fixo de 32 B aqui.
            Ok(get_challenge(rng, 32)?)
        }
        INS_TERMINATE => {
            terminate(store, session)?;
            Ok(Vec::new())
        }
        INS_ACTIVATE => {
            activate(store)?;
            Ok(Vec::new())
        }
        _ => Err(OpgpError::BadIns),
    }
}

/// Divide old||new ao meio (comprimento par e >= 2*min); senao nega.
fn split_half(data: &[u8]) -> Result<(&[u8], &[u8]), OpgpError> {
    if data.len() < 2 || !data.len().is_multiple_of(2) || data.len() > 2 * PW_MAX {
        return Err(OpgpError::BadPin);
    }
    let mid = data.len() / 2;
    Ok((&data[..mid], &data[mid..]))
}

/// Parse + dispatch a partir dos bytes (atalho p/ transporte).
pub fn dispatch_raw<B: FlashStorageBackend, R: HrngSource>(
    store: &mut SecureStorage<B>,
    session: &mut OpgpSession,
    rng: &mut R,
    raw: &[u8],
) -> Result<Vec<u8>, OpgpError> {
    let apdu = parse_apdu(raw).map_err(OpgpError::BadApdu)?;
    dispatch(store, session, rng, &apdu)
}
