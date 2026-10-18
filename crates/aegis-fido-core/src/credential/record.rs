use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub algorithm: i32,
    pub private_key: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    pub is_resident: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub is_revoked: bool,
    pub cred_protect: Option<u8>,
    pub large_blob_key: Option<[u8; 32]>,
    pub cred_blob: Option<Vec<u8>>,
    pub hmac_secret_key: Option<[u8; 32]>,
}

impl CredentialRecord {
    pub fn is_valid(&self, current_time: u64) -> bool {
        if self.is_revoked {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if current_time > exp {
                return false;
            }
        }
        true
    }
}
