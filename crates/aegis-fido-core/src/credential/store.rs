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
}

pub struct MemoryCredentialStore {
    credentials: Vec<CredentialRecord>,
    max_credentials: usize,
}

impl MemoryCredentialStore {
    pub fn new(max_credentials: usize) -> Self {
        Self {
            credentials: Vec::new(),
            max_credentials,
        }
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
            Ok(c.sign_count)
        } else {
            Err("Credential not found")
        }
    }
}
