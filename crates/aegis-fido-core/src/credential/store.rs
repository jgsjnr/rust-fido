use alloc::string::String;
use alloc::vec::Vec;
use crate::credential::record::CredentialRecord;
use crate::crypto::hash::sha256;

pub trait CredentialStore {
    fn save(&mut self, record: CredentialRecord) -> Result<(), &'static str>;
    fn get(&self, id: &[u8]) -> Option<&CredentialRecord>;
    fn get_mut(&mut self, id: &[u8]) -> Option<&mut CredentialRecord>;
    fn delete(&mut self, id: &[u8]) -> Result<bool, &'static str>;
    fn find_by_rp_id(&self, rp_id: &str) -> Vec<&CredentialRecord>;
    fn find_by_rp_id_hash(&self, rp_id_hash: &[u8; 32]) -> Vec<&CredentialRecord>;
    fn list_rps(&self) -> Vec<(String, [u8; 32])>;
    fn list_resident_credentials(&self, rp_id_hash: &[u8; 32]) -> Vec<&CredentialRecord>;
    fn count_resident(&self) -> usize;
    fn max_resident(&self) -> usize;
    fn increment_sign_count(&mut self, id: &[u8]) -> Result<u32, &'static str>;
    fn get_persistent_sign_count(&self, id: &[u8]) -> u32;
}

pub const SIGN_JOURNAL_MAGIC: u32 = 0x534A4E31;
pub const SIGN_JOURNAL_MAX_BLOB_ENTRIES: usize = 256;

/// Fase6 — maximo de KeySlots (§9 TLV total <=512B, label 1..32B).
pub const MAX_KEY_SLOTS: usize = 32;
/// Fase6 — bounds do label KeySlot (§9.2 tag 0x02 utf8 1..32B).
pub const MAX_KEY_LABEL_BYTES: usize = 32;
pub const MIN_KEY_LABEL_BYTES: usize = 1;
/// Fase6 — flags de uso (bitmask; 0 reservado).
pub const KEY_USE_SIGN: u8 = 0x01;
pub const KEY_USE_AUTH: u8 = 0x02;

/// Fase6 — metadados de chave (nunca privada; §9.7 SAI so metadados).
/// Reutiliza journal existente (`sign_count` monotonico) e zeroize on drop.
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KeySlot {
    /// Slot id (0..MAX_KEY_SLOTS).
    pub id: u8,
    /// Algoritmo COSE (-7,-8,-35,-36,-47; sem nova cripto).
    pub alg: i32,
    /// Rotulo utf8 1..32B (§9.2 tag 0x02).
    pub label: String,
    /// Uso bitmask (KEY_USE_*; 0 invalido).
    pub uso: u8,
    /// Timestamp de criacao (opaco, sem relogio no core).
    pub created: u64,
    /// Contador monotonico (journal existente).
    pub sign_count: u32,
}

impl KeySlot {
    /// Cria slot validando bounds §9.2.
    pub fn new(id: u8, alg: i32, label: String, uso: u8, created: u64) -> Result<Self, &'static str> {
        if (id as usize) >= MAX_KEY_SLOTS {
            return Err("bad slot");
        }
        if !matches!(alg, -7 | -8 | -35 | -36 | -47) {
            return Err("bad alg");
        }
        let n = label.len();
        if !(MIN_KEY_LABEL_BYTES..=MAX_KEY_LABEL_BYTES).contains(&n) {
            return Err("bad label");
        }
        if uso == 0 {
            return Err("bad uso");
        }
        Ok(Self { id, alg, label, uso, created, sign_count: 0 })
    }

    /// Incremento monotonico saturante (mesmo padrao do journal).
    pub fn increment_sign_count(&mut self) -> u32 {
        self.sign_count = self.sign_count.saturating_add(1);
        self.sign_count
    }
}

pub struct MemoryCredentialStore {
    credentials: Vec<CredentialRecord>,
    max_credentials: usize,
    non_resident_counts: Vec<([u8; 32], u32)>,
    journal_seq: u32,
}

impl MemoryCredentialStore {
    pub fn new(max_credentials: usize) -> Self {
        Self {
            credentials: Vec::new(),
            max_credentials,
            non_resident_counts: Vec::new(),
            journal_seq: 0,
        }
    }
    fn nr_key(id: &[u8]) -> [u8; 32] {
        sha256(id)
    }
    pub fn export_sign_counts(&self) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&SIGN_JOURNAL_MAGIC.to_be_bytes());
        body.extend_from_slice(&self.journal_seq.to_be_bytes());
        let mut entries: Vec<([u8; 32], u32)> = Vec::new();
        for c in self.credentials.iter() {
            entries.push((Self::nr_key(&c.id), c.sign_count));
        }
        for e in self.non_resident_counts.iter() {
            if !entries.iter().any(|(h, _)| h == &e.0) {
                entries.push((e.0, e.1));
            }
        }
        let n = entries.len().min(SIGN_JOURNAL_MAX_BLOB_ENTRIES);
        body.extend_from_slice(&(n as u16).to_be_bytes());
        for (h, v) in entries.iter().take(n) {
            body.extend_from_slice(h);
            body.extend_from_slice(&v.to_be_bytes());
        }
        let mut sum: u32 = 0;
        for b in body.iter() {
            sum = sum.wrapping_add(*b as u32);
        }
        body.extend_from_slice(&sum.to_be_bytes());
        body
    }
    pub fn import_sign_counts(&mut self, blob: &[u8]) -> Result<(), &'static str> {
        if blob.len() < 12 {
            return Err("short");
        }
        let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
        if magic != SIGN_JOURNAL_MAGIC {
            return Err("magic");
        }
        let seq = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        let n = u16::from_be_bytes([blob[8], blob[9]]) as usize;
        let expect = 10 + n * 36 + 4;
        if blob.len() < expect {
            return Err("trunc");
        }
        if n > SIGN_JOURNAL_MAX_BLOB_ENTRIES {
            return Err("many");
        }
        let mut sum: u32 = 0;
        for b in blob[..expect - 4].iter() {
            sum = sum.wrapping_add(*b as u32);
        }
        let want = u32::from_be_bytes([blob[expect-4], blob[expect-3], blob[expect-2], blob[expect-1]]);
        if sum != want {
            return Err("crc");
        }
        let mut off = 10;
        for _ in 0..n {
            let mut h = [0u8; 32];
            h.copy_from_slice(&blob[off..off+32]);
            off += 32;
            let v = u32::from_be_bytes([blob[off], blob[off+1], blob[off+2], blob[off+3]]);
            off += 4;
            let mut placed = false;
            for c in self.credentials.iter_mut() {
                if Self::nr_key(&c.id) == h {
                    if v > c.sign_count {
                        c.sign_count = v;
                    }
                    placed = true;
                    break;
                }
            }
            if !placed {
                match self.non_resident_counts.iter_mut().find(|(k, _)| *k == h) {
                    Some(e) => { if v > e.1 { e.1 = v; } }
                    None => { if self.non_resident_counts.len() >= SIGN_JOURNAL_MAX_BLOB_ENTRIES { self.non_resident_counts.remove(0); } self.non_resident_counts.push((h, v)); }
                }
            }
        }
        if seq > self.journal_seq {
            self.journal_seq = seq;
        }
        Ok(())
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn save(&mut self, record: CredentialRecord) -> Result<(), &'static str> {
        if let Some(pos) = self.credentials.iter().position(|c| c.id == record.id) {
            self.credentials[pos] = record;
            return Ok(());
        }

        // If it's a resident key and user_id already exists for same rp_id, overwrite it per CTAP2 spec
        if record.is_resident {
            if let Some(pos) = self.credentials.iter().position(|c| {
                c.is_resident && c.rp_id == record.rp_id && c.user_id == record.user_id
            }) {
                self.credentials[pos] = record;
                return Ok(());
            }

            if self.count_resident() >= self.max_credentials {
                return Err("Credential storage is full");
            }
        }

        self.credentials.push(record);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Option<&CredentialRecord> {
        self.credentials.iter().find(|c| c.id == id)
    }

    fn get_mut(&mut self, id: &[u8]) -> Option<&mut CredentialRecord> {
        self.credentials.iter_mut().find(|c| c.id == id)
    }

    fn delete(&mut self, id: &[u8]) -> Result<bool, &'static str> {
        if let Some(pos) = self.credentials.iter().position(|c| c.id == id) {
            self.credentials.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn find_by_rp_id(&self, rp_id: &str) -> Vec<&CredentialRecord> {
        self.credentials.iter().filter(|c| c.rp_id == rp_id).collect()
    }

    fn find_by_rp_id_hash(&self, rp_id_hash: &[u8; 32]) -> Vec<&CredentialRecord> {
        self.credentials
            .iter()
            .filter(|c| sha256(c.rp_id.as_bytes()) == *rp_id_hash)
            .collect()
    }

    fn list_rps(&self) -> Vec<(String, [u8; 32])> {
        let mut rps = Vec::new();
        for cred in &self.credentials {
            if cred.is_resident {
                let hash = sha256(cred.rp_id.as_bytes());
                if !rps.iter().any(|(_, h)| h == &hash) {
                    rps.push((cred.rp_id.clone(), hash));
                }
            }
        }
        rps
    }

    fn list_resident_credentials(&self, rp_id_hash: &[u8; 32]) -> Vec<&CredentialRecord> {
        self.credentials
            .iter()
            .filter(|c| c.is_resident && sha256(c.rp_id.as_bytes()) == *rp_id_hash)
            .collect()
    }

    fn count_resident(&self) -> usize {
        self.credentials.iter().filter(|c| c.is_resident).count()
    }

    fn max_resident(&self) -> usize {
        self.max_credentials
    }

    fn increment_sign_count(&mut self, id: &[u8]) -> Result<u32, &'static str> {
        if let Some(c) = self.credentials.iter_mut().find(|c| c.id == id) {
            c.sign_count = c.sign_count.saturating_add(1);
            self.journal_seq = self.journal_seq.saturating_add(1);
            Ok(c.sign_count)
        } else {
            let h = Self::nr_key(id);
            self.journal_seq = self.journal_seq.saturating_add(1);
            if let Some(e) = self.non_resident_counts.iter_mut().find(|(k, _)| *k == h) {
                e.1 = e.1.saturating_add(1);
                Ok(e.1)
            } else {
                if self.non_resident_counts.len() >= SIGN_JOURNAL_MAX_BLOB_ENTRIES { self.non_resident_counts.remove(0); } self.non_resident_counts.push((h, 1));
                Ok(1)
            }
        }
    }
    fn get_persistent_sign_count(&self, id: &[u8]) -> u32 {
        if let Some(c) = self.credentials.iter().find(|c| c.id == id) {
            return c.sign_count;
        }
        let h = Self::nr_key(id);
        if let Some(e) = self.non_resident_counts.iter().find(|(k, _)| *k == h) {
            return e.1;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::record::CredentialRecord;
    use alloc::vec;
    #[test]
    fn sign_count_monotonico() {
        let mut s = MemoryCredentialStore::new(10);
        let rec = CredentialRecord {
            id: vec![9, 9, 9],
            rp_id: alloc::string::String::new(),
            rp_name: None,
            user_id: vec![1],
            user_name: None,
            user_display_name: None,
            algorithm: -7,
            private_key: vec![2],
            public_key_cose: vec![3],
            sign_count: 0,
            is_resident: true,
            created_at: 0,
            expires_at: None,
            is_revoked: false,
            cred_protect: None,
            large_blob_key: None,
            cred_blob: None,
            hmac_secret_key: None,
        };
        s.save(rec).unwrap();
        assert_eq!(s.increment_sign_count(&[9, 9, 9]).unwrap(), 1);
        assert_eq!(s.increment_sign_count(&[9, 9, 9]).unwrap(), 2);
        assert_eq!(s.get_persistent_sign_count(&[9, 9, 9]), 2);
        let a = s.increment_sign_count(&[7, 7, 7]).unwrap();
        let b = s.increment_sign_count(&[7, 7, 7]).unwrap();
        assert_eq!(a, 1);
        assert_eq!(b, 2);
        assert_eq!(s.get_persistent_sign_count(&[7, 7, 7]), 2);
        let blob = s.export_sign_counts();
        let mut s2 = MemoryCredentialStore::new(10);
        s2.import_sign_counts(&blob).unwrap();
        assert_eq!(s2.get_persistent_sign_count(&[7, 7, 7]), 2);
        let blob2 = s2.export_sign_counts();
        s.increment_sign_count(&[7, 7, 7]).unwrap();
        s.import_sign_counts(&blob2).unwrap();
        assert_eq!(s.get_persistent_sign_count(&[7, 7, 7]), 3);
    }

    #[test]
    fn keyslot_bounds_fase6() {
        let ok = KeySlot::new(0, -7, alloc::string::String::from("a"), KEY_USE_SIGN, 0).unwrap();
        assert_eq!(ok.sign_count, 0);
        assert!(KeySlot::new(0, -7, alloc::string::String::from(""), KEY_USE_SIGN, 0).is_err());
        let big = alloc::string::String::from_utf8(vec![b'x'; MAX_KEY_LABEL_BYTES + 1]).unwrap();
        assert!(KeySlot::new(0, -7, big, KEY_USE_SIGN, 0).is_err());
        assert!(KeySlot::new(MAX_KEY_SLOTS as u8, -7, alloc::string::String::from("a"), KEY_USE_SIGN, 0).is_err());
        assert!(KeySlot::new(0, -99, alloc::string::String::from("a"), KEY_USE_SIGN, 0).is_err());
        assert!(KeySlot::new(0, -7, alloc::string::String::from("a"), 0, 0).is_err());
        let mut s = KeySlot::new(1, -8, alloc::string::String::from("k"), KEY_USE_SIGN | KEY_USE_AUTH, 7).unwrap();
        assert_eq!(s.increment_sign_count(), 1);
        assert_eq!(s.increment_sign_count(), 2);
    }
}


