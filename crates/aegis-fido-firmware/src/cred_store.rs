//! T-FD-02 cofre de credenciais FIDO2 sobre `persistence` (GEN-DEVICE).
//!
//! Motivo: a credencial residente nasce no device e precisa sobreviver ao
//! power-cycle sem permitir replay de blob antigo com `signCount` menor
//! (secao 9: persistencia + power-loss + rollback-resistencia).
//!
//! - Nao edita `persistence.rs`: usa `SecureStorage` + `NamespacedStore`
//!   (`cred/` + indice `cred/index`, quota 32, verify-after-write herdado).
//! - Registro binario versionado (`FC` 0x01 + flags + contador + rpHash +
//!   credId + segredo opaco); truncado/magica errada nega fail-closed.
//! - Rollback: `cred_put` rejeita contador menor que o gravado
//!   (`CounterRegression`); avancar usa `cred_bump_counter` (soma checada).
//! - Atomico/SOLID: funcoes puras sobre `&SecureStorage`/`&mut SecureStorage`;
//!   HW via trait `FlashStorageBackend`; `no_std` compativel (`alloc`-only).
//! - Segredo nunca em log: `Debug` de `CredRecord` mostra so comprimentos.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage,
};

/// Prefixo NVS dos slots (`cred/<label>`).
pub const CRED_PREFIX: &str = "cred/";
/// Indice de quota (lista CBOR cifrada de labels).
pub const CRED_INDEX_KEY: &str = "cred/index";
/// Maximo de credenciais residentes (passkeys descobriveis).
pub const CRED_MAX_SLOTS: usize = 32;
/// Teto do blob codificado por slot (cabe no envelope de 4096 B).
pub const CRED_SLOT_MAX_BYTES: usize = 1024;
/// Teto do `credentialId`.
pub const CRED_ID_MAX_BYTES: usize = 128;
/// Teto do segredo opaco (chave privada selada pelo chamador T-ST-01).
pub const CRED_PRIV_MAX_BYTES: usize = 512;
/// Magica do registro (`FC` = FIDO Credential).
pub const CRED_MAGIC: [u8; 2] = [0x46, 0x43];
/// Versao do registro (rejeita futuro sem migrador).
pub const CRED_VERSION: u8 = 0x01;
/// Label reservado (colide com o indice de quota).
const CRED_INDEX_LABEL: &str = "index";

/// Falha tipada do cofre (sem segredo nas variantes, sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredStoreError {
    /// Label fora de 1..=64 B UTF-8 ou reservado `index`.
    BadLabel,
    /// Blob acima do orcamento do slot.
    TooLarge,
    /// Quota de 32 labels distintos atingida.
    QuotaExceeded,
    /// Slot ausente.
    NotFound,
    /// Falha de storage, verify-after-write ou indice corrupto.
    Storage,
    /// Registro malformado/truncado/magica ou versao errada.
    InvalidRecord,
    /// Tentativa de gravar contador menor que o gravado (replay).
    CounterRegression,
}

impl core::fmt::Display for CredStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLabel => write!(f, "bad credential label"),
            Self::TooLarge => write!(f, "credential blob too large"),
            Self::QuotaExceeded => write!(f, "credential quota exceeded"),
            Self::NotFound => write!(f, "credential slot not found"),
            Self::Storage => write!(f, "credential storage failure"),
            Self::InvalidRecord => write!(f, "invalid credential record"),
            Self::CounterRegression => write!(f, "credential counter regression"),
        }
    }
}

impl From<NamespacedStoreError> for CredStoreError {
    fn from(e: NamespacedStoreError) -> Self {
        match e {
            NamespacedStoreError::BadLabel => Self::BadLabel,
            NamespacedStoreError::TooLarge => Self::TooLarge,
            NamespacedStoreError::QuotaExceeded => Self::QuotaExceeded,
            NamespacedStoreError::NotFound => Self::NotFound,
            NamespacedStoreError::Storage => Self::Storage,
        }
    }
}

/// Registro de credencial residente (dono dos bytes; apaga no `Drop`).
pub struct CredRecord {
    /// Flags CTAP (ex.: `0x01` discoverable; bitmask opaca aqui).
    pub flags: u8,
    /// Contador de assinaturas (monotonico, nunca recua).
    pub sign_count: u32,
    /// `SHA-256(rpId)` (32 B).
    pub rp_id_hash: [u8; 32],
    /// `credentialId` (1..=128 B).
    pub cred_id: Vec<u8>,
    /// Segredo opaco (0..=512 B; chave selada pelo cofre T-ST-01).
    pub priv_blob: Vec<u8>,
}

impl Drop for CredRecord {
    fn drop(&mut self) {
        self.rp_id_hash.zeroize();
        self.cred_id.zeroize();
        self.priv_blob.zeroize();
    }
}

impl core::fmt::Debug for CredRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredRecord")
            .field("flags", &self.flags)
            .field("sign_count", &self.sign_count)
            .field("rp_id_hash_len", &self.rp_id_hash.len())
            .field("cred_id_len", &self.cred_id.len())
            .field("priv_blob_len", &self.priv_blob.len())
            .finish()
    }
}

fn cred_label_ok(label: &str) -> bool {
    let n = label.len();
    (1..=64).contains(&n) && label != CRED_INDEX_LABEL
}

fn cred_ns_write() -> NamespacedStore {
    NamespacedStore {
        prefix: CRED_PREFIX,
        max_bytes: Some(CRED_SLOT_MAX_BYTES),
        quota_index_key: Some(CRED_INDEX_KEY),
        max_slots: CRED_MAX_SLOTS,
        delete_absent_ok: false,
        strict_index_reads: true,
        validate: cred_label_ok,
    }
}

fn cred_ns_read() -> NamespacedStore {
    NamespacedStore {
        prefix: CRED_PREFIX,
        max_bytes: Some(CRED_SLOT_MAX_BYTES),
        quota_index_key: Some(CRED_INDEX_KEY),
        max_slots: 0,
        delete_absent_ok: false,
        strict_index_reads: true,
        validate: cred_label_ok,
    }
}

/// Codifica o registro (cabecalho fixo 44 B + id + segredo).
pub fn encode_record(rec: &CredRecord) -> Result<Vec<u8>, CredStoreError> {
    if rec.cred_id.is_empty() || rec.cred_id.len() > CRED_ID_MAX_BYTES {
        return Err(CredStoreError::InvalidRecord);
    }
    if rec.priv_blob.len() > CRED_PRIV_MAX_BYTES {
        return Err(CredStoreError::TooLarge);
    }
    let total = 2 + 1 + 1 + 4 + 32 + 2 + 2 + rec.cred_id.len() + rec.priv_blob.len();
    if total > CRED_SLOT_MAX_BYTES {
        return Err(CredStoreError::TooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&CRED_MAGIC);
    out.push(CRED_VERSION);
    out.push(rec.flags);
    out.extend_from_slice(&rec.sign_count.to_be_bytes());
    out.extend_from_slice(&rec.rp_id_hash);
    let id_len = rec.cred_id.len() as u16;
    let pr_len = rec.priv_blob.len() as u16;
    out.extend_from_slice(&id_len.to_be_bytes());
    out.extend_from_slice(&pr_len.to_be_bytes());
    out.extend_from_slice(&rec.cred_id);
    out.extend_from_slice(&rec.priv_blob);
    Ok(out)
}

/// Decodifica com validacao estrita (truncado/magica/versao/tamanho = erro).
pub fn decode_record(blob: &[u8]) -> Result<CredRecord, CredStoreError> {
    if blob.len() < 44 {
        return Err(CredStoreError::InvalidRecord);
    }
    if blob[0..2] != CRED_MAGIC {
        return Err(CredStoreError::InvalidRecord);
    }
    if blob[2] != CRED_VERSION {
        return Err(CredStoreError::InvalidRecord);
    }
    let flags = blob[3];
    let mut ctr = [0u8; 4];
    ctr.copy_from_slice(&blob[4..8]);
    let sign_count = u32::from_be_bytes(ctr);
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&blob[8..40]);
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(&blob[40..42]);
    let id_len = u16::from_be_bytes(tmp) as usize;
    tmp.copy_from_slice(&blob[42..44]);
    let pr_len = u16::from_be_bytes(tmp) as usize;
    if id_len == 0 || id_len > CRED_ID_MAX_BYTES {
        return Err(CredStoreError::InvalidRecord);
    }
    if pr_len > CRED_PRIV_MAX_BYTES {
        return Err(CredStoreError::InvalidRecord);
    }
    if blob.len() != 44 + id_len + pr_len {
        return Err(CredStoreError::InvalidRecord);
    }
    let mut cred_id = Vec::with_capacity(id_len);
    cred_id.extend_from_slice(&blob[44..44 + id_len]);
    let mut priv_blob = Vec::with_capacity(pr_len);
    priv_blob.extend_from_slice(&blob[44 + id_len..]);
    Ok(CredRecord {
        flags,
        sign_count,
        rp_id_hash,
        cred_id,
        priv_blob,
    })
}

/// Grava o slot com verify-after-write; reescrita com contador menor nega.
pub fn cred_put<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
    rec: &CredRecord,
) -> Result<(), CredStoreError> {
    let blob = encode_record(rec)?;
    if let Ok(raw) = cred_ns_read().get(storage, label) {
        if let Ok(old) = decode_record(&raw) {
            if rec.sign_count < old.sign_count {
                return Err(CredStoreError::CounterRegression);
            }
        }
    }
    let mut owned = blob;
    let res = cred_ns_write().put(storage, label, &owned);
    owned.zeroize();
    Ok(res?)
}

/// Le e decodifica o slot (indice corrupto nega antes da leitura).
pub fn cred_get<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    label: &str,
) -> Result<CredRecord, CredStoreError> {
    let raw = cred_ns_read().get(storage, label)?;
    decode_record(&raw)
}

/// Apaga o slot e libera a quota; ausente = `NotFound`.
pub fn cred_delete<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
) -> Result<(), CredStoreError> {
    Ok(cred_ns_read().delete(storage, label)?)
}

/// Avanca o contador em +1 de forma atomica (estouro = `Storage`).
///
/// Le, soma com checagem e regrava com verify-after-write; falha no meio
/// mantem o valor antigo (fail-closed, sem recuo).
pub fn cred_bump_counter<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
) -> Result<u32, CredStoreError> {
    let mut rec = cred_get(storage, label)?;
    rec.sign_count = rec
        .sign_count
        .checked_add(1)
        .ok_or(CredStoreError::Storage)?;
    let next = rec.sign_count;
    cred_put(storage, label, &rec)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;
    use alloc::string::String;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn sample(fill: u8) -> CredRecord {
        let mut id = vec![0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = fill.wrapping_add(i as u8);
        }
        CredRecord {
            flags: 0x01,
            sign_count: 7,
            rp_id_hash: [0xABu8; 32],
            cred_id: id,
            priv_blob: vec![0xCDu8; 64],
        }
    }

    fn slot_name(i: usize) -> String {
        let mut s = String::from("c");
        s.push((b'0' + (i / 10) as u8) as char);
        s.push((b'0' + (i % 10) as u8) as char);
        s
    }

    #[test]
    fn vector_roundtrip_known_bytes() {
        let mut st = test_storage();
        // Vetor fixo: mesmos bytes sempre decodificam igual.
        let rec = sample(0x10);
        cred_put(&mut st, "host", &rec).unwrap();
        let back = cred_get(&st, "host").unwrap();
        assert_eq!(back.flags, 0x01);
        assert_eq!(back.sign_count, 7);
        assert_eq!(back.rp_id_hash, [0xABu8; 32]);
        assert_eq!(back.cred_id.len(), 16);
        assert_eq!(back.priv_blob, vec![0xCDu8; 64]);
        let enc = encode_record(&back).unwrap();
        // Cabecalho: FC 01 flags ctr rpHash idLen privLen.
        assert_eq!(&enc[0..2], &CRED_MAGIC);
        assert_eq!(enc[2], CRED_VERSION);
        assert_eq!(&enc[4..8], &7u32.to_be_bytes());
        assert_eq!(decode_record(&enc).unwrap().sign_count, 7);
    }

    #[test]
    fn rejects_invalid_truncated() {
        let mut st = test_storage();
        assert_eq!(
            cred_put(&mut st, "", &sample(1)),
            Err(CredStoreError::BadLabel)
        );
        assert_eq!(
            cred_put(&mut st, "index", &sample(1)),
            Err(CredStoreError::BadLabel)
        );
        // id vazio e priv gigante.
        let mut bad = sample(2);
        bad.cred_id.clear();
        assert_eq!(
            cred_put(&mut st, "a", &bad),
            Err(CredStoreError::InvalidRecord)
        );
        let mut big = sample(3);
        big.priv_blob = vec![0u8; CRED_PRIV_MAX_BYTES + 1];
        assert_eq!(cred_put(&mut st, "a", &big), Err(CredStoreError::TooLarge));
        // Truncados e magica/versao errada.
        let enc = encode_record(&sample(4)).unwrap();
        assert!(matches!(
            decode_record(&enc[..10]),
            Err(CredStoreError::InvalidRecord)
        ));
        assert!(matches!(
            decode_record(&enc[..enc.len() - 1]),
            Err(CredStoreError::InvalidRecord)
        ));
        let mut wrong = enc.clone();
        wrong[0] ^= 0xFF;
        assert!(matches!(
            decode_record(&wrong),
            Err(CredStoreError::InvalidRecord)
        ));
        let mut verv = enc.clone();
        verv[2] = 0x7F;
        assert!(matches!(
            decode_record(&verv),
            Err(CredStoreError::InvalidRecord)
        ));
        // Resto maior que o declarado tambem nega.
        let mut trailed = enc.clone();
        trailed.push(0x00);
        assert!(matches!(
            decode_record(&trailed),
            Err(CredStoreError::InvalidRecord)
        ));
        // Ausente.
        assert!(matches!(
            cred_get(&st, "ghost"),
            Err(CredStoreError::NotFound)
        ));
        assert_eq!(cred_delete(&mut st, "ghost"), Err(CredStoreError::NotFound));
    }

    #[test]
    fn quota_limit_32_slots() {
        let mut st = test_storage();
        for i in 0..CRED_MAX_SLOTS {
            cred_put(&mut st, &slot_name(i), &sample(i as u8)).unwrap();
        }
        assert_eq!(
            cred_put(&mut st, "overflow", &sample(9)),
            Err(CredStoreError::QuotaExceeded)
        );
        // Delete libera a quota.
        cred_delete(&mut st, &slot_name(0)).unwrap();
        cred_put(&mut st, "overflow", &sample(9)).unwrap();
    }

    #[test]
    fn counter_monotonic_and_regression_rejected() {
        let mut st = test_storage();
        cred_put(&mut st, "k", &sample(5)).unwrap();
        assert_eq!(cred_bump_counter(&mut st, "k").unwrap(), 8);
        assert_eq!(cred_get(&st, "k").unwrap().sign_count, 8);
        // Replay com contador antigo nega sem gravar.
        let mut old = sample(5);
        old.sign_count = 7;
        assert_eq!(
            cred_put(&mut st, "k", &old),
            Err(CredStoreError::CounterRegression)
        );
        assert_eq!(cred_get(&st, "k").unwrap().sign_count, 8);
        // Estouro u32::MAX nega fail-closed.
        let mut top = sample(6);
        top.sign_count = u32::MAX;
        cred_put(&mut st, "top", &top).unwrap();
        assert_eq!(
            cred_bump_counter(&mut st, "top"),
            Err(CredStoreError::Storage)
        );
    }

    #[test]
    fn persists_across_powerloss_and_isolates_tamper() {
        let master = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut st = SecureStorage::new(backend, &master, &salt);
        cred_put(&mut st, "a", &sample(0xA0)).unwrap();
        cred_put(&mut st, "b", &sample(0xB0)).unwrap();
        // Simula power-cycle: reconstroi sobre o mesmo backend cru.
        let raw_backend = st.backend().clone();
        let rebooted = SecureStorage::new(raw_backend, &master, &salt);
        assert_eq!(cred_get(&rebooted, "a").unwrap().sign_count, 7);
        // Adultera so o slot B no flash cru: A segue intacto, B nega.
        let mut tampered = rebooted.backend().clone();
        let key_b = String::from("cred/b");
        let mut raw = tampered.read_raw(&key_b).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        tampered.write_raw(&key_b, &raw).unwrap();
        let st2 = SecureStorage::new(tampered, &master, &salt);
        assert_eq!(cred_get(&st2, "a").unwrap().cred_id.len(), 16);
        assert!(matches!(cred_get(&st2, "b"), Err(CredStoreError::Storage)));
    }

    #[test]
    fn debug_never_leaks_secret() {
        let rec = sample(0xEE);
        let dbg = format!("{:?}", rec);
        assert!(dbg.contains("CredRecord"));
        assert!(dbg.contains("cred_id_len"));
        assert!(!dbg.contains("cdcd"));
        assert!(!dbg.contains("CDCD"));
        let err = format!("{:?}", CredStoreError::CounterRegression);
        assert!(!err.contains("cd"));
    }
}
