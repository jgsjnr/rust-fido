//! Executor Vendor CBOR para o Secure Guard (0x3A..0x3E)
//!
//! Implementa os opcodes de gerenciamento, provisionamento, desbloqueio, bloqueio,
//! configuração e wipe seletivo do subsistema Secure Guard:
//! - 0x3A: OP_SECURE_GUARD_STATUS
//! - 0x3B: OP_SECURE_GUARD_UNLOCK (provision, unlock, change_pin, recover)
//! - 0x3C: OP_SECURE_GUARD_LOCK
//! - 0x3D: OP_SECURE_GUARD_CONFIG
//! - 0x3E: OP_SECURE_GUARD_WIPE_SELECTIVE

use super::{
    handle_config, handle_lock, handle_status_with_ota, handle_unlock_or_mgmt,
    handle_wipe_selective,
};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, OP_SECURE_GUARD_CONFIG, OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS,
    OP_SECURE_GUARD_UNLOCK, OP_SECURE_GUARD_WIPE_SELECTIVE,
};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;
use rand_core::CryptoRng;
use std::format;
use std::string::String;
use std::vec::Vec;

/// Código CTAP2 de erro quando PIN / desbloqueio é requerido (0x36).
pub const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
/// Código CTAP2 de erro quando PIN fornecido é inválido (0x33).
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
/// Código CTAP2 de erro genérico / vendor.
pub const CTAP2_ERR_VENDOR_INTERNAL: u8 = 0xF0;

/// Auxiliar para serializar `Value` CBOR em `Vec<u8>`.
pub(crate) fn to_cbor_bytes(val: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = ciborium::into_writer(val, &mut out);
    out
}

/// Auxiliar para buscar texto ou inteiro em um mapa CBOR.
pub(crate) fn get_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

/// Extrai bytes de um `Value::Bytes` ou converte `Value::Text` em bytes.
pub(crate) fn extract_bytes(val: &Value) -> Option<Vec<u8>> {
    match val {
        Value::Bytes(b) => Some(b.clone()),
        Value::Text(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// Multiplicação no corpo de Galois GF(256) com polinômio redutor 0x11B (AES).
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// Inverso multiplicativo em GF(256) via a^254 (Pequeno Teorema de Fermat).
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Divisão no corpo GF(256).
fn gf256_div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_inv(b))
}

/// Divide um segredo em 3 partes com limiar de 2 partes (Shamir 2-de-3 sobre GF(256)).
/// Cada share é formado por `[x_coord, y_0, y_1, ..., y_{n-1}]`.
pub fn shamir_2_of_3_split<R: CryptoRng>(secret: &[u8], rng: &mut R) -> [Vec<u8>; 3] {
    let len = secret.len();
    let mut share1 = Vec::with_capacity(1 + len);
    let mut share2 = Vec::with_capacity(1 + len);
    let mut share3 = Vec::with_capacity(1 + len);

    // Coordenadas x para as 3 partes (1, 2, 3)
    share1.push(1);
    share2.push(2);
    share3.push(3);

    for &s in secret {
        // Coeficiente aleatório não nulo em GF(256)
        let mut coef = 0u8;
        while coef == 0 {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            coef = buf[0];
        }

        // f(x) = s ^ (coef * x)
        let y1 = s ^ gf256_mul(coef, 1);
        let y2 = s ^ gf256_mul(coef, 2);
        let y3 = s ^ gf256_mul(coef, 3);

        share1.push(y1);
        share2.push(y2);
        share3.push(y3);
    }

    [share1, share2, share3]
}

/// Reconstrói o segredo a partir de quaisquer 2 partes distintas (Shamir 2-de-3).
pub fn shamir_2_of_3_recover(share_a: &[u8], share_b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if share_a.is_empty() || share_b.is_empty() {
        return Err("Share cannot be empty");
    }
    if share_a.len() != share_b.len() {
        return Err("Shares length mismatch");
    }
    let x_a = share_a[0];
    let x_b = share_b[0];
    if x_a == 0 || x_b == 0 {
        return Err("Invalid share x coordinate 0");
    }
    if x_a == x_b {
        return Err("Shares must have distinct coordinates");
    }

    let denom = x_a ^ x_b;
    let l_a = gf256_div(x_b, denom);
    let l_b = gf256_div(x_a, denom);

    let len = share_a.len() - 1;
    let mut recovered = Vec::with_capacity(len);

    for i in 1..share_a.len() {
        let y_a = share_a[i];
        let y_b = share_b[i];
        let term_a = gf256_mul(y_a, l_a);
        let term_b = gf256_mul(y_b, l_b);
        recovered.push(term_a ^ term_b);
    }

    Ok(recovered)
}

/// Executa qualquer opcode do Secure Guard (0x3A..0x3E).
///
/// Sem `ota_progress` (via serial sem sessao OTA ou chamada legada): 0x3A
/// omite o campo, byte-identico ao anterior. Para expor progresso real na
/// via serial, use [`exec_secure_guard_op_with_ota`] com
/// `Some(OtaState::progress)` somente quando houver sessao (ver
/// `handle_status_with_ota`).
#[allow(clippy::too_many_arguments)]
pub fn exec_secure_guard_op<B, R>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    op: u8,
    payload: &[u8],
    now_ms: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: CryptoRng,
{
    exec_secure_guard_op_with_ota(
        engine, storage, wallet, key_mgr, oath, op, payload, now_ms, rng, None,
    )
}

/// Executa qualquer opcode do Secure Guard (0x3A..0x3E) com progresso OTA
/// opcional no 0x3A.
///
/// `ota_progress = Some(p)` (0..=100, vindo de `OtaState::progress` quando
/// houver sessao) anexa `ota_progress` ao CBOR do 0x3A via
/// `handle_status_with_ota` (clamp 100; nunca fabricado alem do teto);
/// `None` (sem sessao OTA) omite o campo, preservando o corpo legado.
/// Demais opcodes ignoram o argumento (semantica intacta).
/// Antes do dispatch, reaplica a policy de bancada quando ativa
/// (`apply_bench_policy_if_active`): o engine da rota CTAPHID serial criado
/// ou recarregado apos `TEST_BENCH_ON` senao carimbaria 300 s. No-op em
/// release (producao intacta).
#[allow(clippy::too_many_arguments)]
pub fn exec_secure_guard_op_with_ota<B, R>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    op: u8,
    payload: &[u8],
    now_ms: u64,
    rng: &mut R,
    ota_progress: Option<u8>,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: CryptoRng,
{
    crate::secure_guard_exec::bench::policy::apply_bench_policy_if_active(engine);
    match op {
        OP_SECURE_GUARD_STATUS => handle_status_with_ota(engine, now_ms, ota_progress),
        OP_SECURE_GUARD_UNLOCK => {
            handle_unlock_or_mgmt(engine, storage, wallet, key_mgr, oath, payload, now_ms, rng)
        }
        OP_SECURE_GUARD_LOCK => handle_lock(engine, storage, now_ms),
        OP_SECURE_GUARD_CONFIG => handle_config(engine, storage, payload, now_ms),
        OP_SECURE_GUARD_WIPE_SELECTIVE => {
            handle_wipe_selective(engine, storage, wallet, key_mgr, oath, payload, now_ms)
        }
        _ => (0x04, Vec::new()),
    }
}

pub(crate) fn cbor_err(msg: &str) -> Value {
    Value::Map(vec![(Value::Text("error".into()), Value::Text(msg.into()))])
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub(crate) fn hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let hi = hex_val(s[i])?;
        let lo = hex_val(s[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
