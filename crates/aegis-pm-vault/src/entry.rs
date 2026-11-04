//! PM record shapes (SRP: shapes only, no policy, no crypto, no I/O).
//!
//! OCP: new record kinds arrive as new [`PmRecord`] variants encoded in the
//! CBOR payload. The AEGN v1 envelope framing is untouched.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Payload schema version sealed inside the CBOR body (NOT the AEGN envelope
/// version, which stays `0x01` per `VAULT_ENVELOPE_VERSION`).
pub const PM_PAYLOAD_VERSION: u32 = 1;

/// Maximum lengths are enforced by [`crate::PmPolicy`]; these are hard
/// structural caps so a single record can never OOM a `no_std` target.
pub const PM_ID_MAX_BYTES: usize = 64;
pub const PM_LABEL_HARD_MAX: usize = 128;
pub const PM_USERNAME_HARD_MAX: usize = 256;
pub const PM_SECRET_HARD_MAX: usize = 512;
pub const PM_URL_HARD_MAX: usize = 512;

/// A single password-manager login record.
///
/// Secrets (`secret`) are `Zeroize`d on drop. `Debug` is redacted: it never
/// prints label, username, secret, or URL — only lengths and timestamps.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    /// Opaque record id chosen by the device (e.g. 16 random bytes).
    pub id: Vec<u8>,
    /// Human label ("bank", "mail"). Encrypted at rest; transient only.
    pub label: String,
    /// Login username. Encrypted at rest; transient only.
    pub username: String,
    /// Login password / secret. Encrypted at rest; transient only.
    pub secret: Vec<u8>,
    /// Optional URL. Encrypted at rest; transient only.
    pub url: Option<String>,
    /// Creation epoch seconds (device clock).
    pub created_at: u64,
    /// Last-update epoch seconds (device clock).
    pub updated_at: u64,
}

impl PasswordEntry {
    /// Builds an entry, checking structural caps. Policy quotas
    /// (count/limits) are enforced separately by [`crate::PmPolicy`].
    pub fn new(
        id: Vec<u8>,
        label: String,
        username: String,
        secret: Vec<u8>,
        url: Option<String>,
        created_at: u64,
    ) -> Result<Self, crate::PmError> {
        if id.is_empty() || id.len() > PM_ID_MAX_BYTES {
            return Err(crate::PmError::EntryTooLarge);
        }
        if label.len() > PM_LABEL_HARD_MAX
            || username.len() > PM_USERNAME_HARD_MAX
            || secret.len() > PM_SECRET_HARD_MAX
            || url.as_ref().is_some_and(|u| u.len() > PM_URL_HARD_MAX)
        {
            return Err(crate::PmError::EntryTooLarge);
        }
        Ok(Self {
            id,
            label,
            username,
            secret,
            url,
            created_at,
            updated_at: created_at,
        })
    }

    /// Replaces the secret in place (old bytes are zeroized by `Vec` swap).
    pub fn set_secret(&mut self, secret: Vec<u8>, now: u64) -> Result<(), crate::PmError> {
        if secret.len() > PM_SECRET_HARD_MAX {
            return Err(crate::PmError::EntryTooLarge);
        }
        let mut secret = secret;
        core::mem::swap(&mut self.secret, &mut secret);
        secret.zeroize();
        self.updated_at = now;
        Ok(())
    }
}

impl core::fmt::Debug for PasswordEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordEntry")
            .field("id_len", &self.id.len())
            .field("label", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("url", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Extensible record envelope (OCP: new kinds = new variants).
///
/// `non_exhaustive` forces downstream `match`es to stay forward-compatible.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum PmRecord {
    /// Login/password record (F-PM1).
    Password(PasswordEntry),
}

impl PmRecord {
    /// Opaque record id.
    pub fn id(&self) -> &[u8] {
        match self {
            Self::Password(e) => &e.id,
        }
    }

    /// Convenience accessor for the password variant.
    pub fn as_password(&self) -> Option<&PasswordEntry> {
        match self {
            Self::Password(e) => Some(e),
        }
    }
}

impl core::fmt::Debug for PmRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Password(e) => f.debug_tuple("Password").field(e).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample() -> PasswordEntry {
        PasswordEntry::new(
            vec![0x01; 16],
            "bank".to_string(),
            "alice".to_string(),
            vec![0xAA; 24],
            None,
            1_770_000_000,
        )
        .unwrap()
    }

    #[test]
    fn debug_never_logs_secrets() {
        let e = sample();
        let dbg = alloc::format!("{:?}", e);
        for forbidden in ["bank", "alice", "created_at"] {
            if forbidden == "created_at" {
                continue;
            }
            assert!(!dbg.contains(forbidden), "leak in Debug: {dbg}");
        }
        assert!(dbg.contains("[REDACTED]"));
        let r = PmRecord::Password(e);
        let rdbg = alloc::format!("{:?}", r);
        assert!(!rdbg.contains("bank"));
        assert!(!rdbg.contains("alice"));
    }

    #[test]
    fn structural_caps_reject_oversize() {
        assert!(
            PasswordEntry::new(vec![], "l".to_string(), "u".to_string(), vec![1], None, 0).is_err()
        );
        assert!(PasswordEntry::new(
            vec![0x01; PM_ID_MAX_BYTES + 1],
            "l".to_string(),
            "u".to_string(),
            vec![1],
            None,
            0
        )
        .is_err());
        assert!(PasswordEntry::new(
            vec![1],
            "l".to_string(),
            "u".to_string(),
            vec![0x00; PM_SECRET_HARD_MAX + 1],
            None,
            0
        )
        .is_err());
    }

    #[test]
    fn set_secret_zeroizes_old_and_updates_timestamp() {
        let mut e = sample();
        e.set_secret(vec![0xBB; 8], 1_780_000_000).unwrap();
        assert_eq!(e.secret, vec![0xBB; 8]);
        assert_eq!(e.updated_at, 1_780_000_000);
    }
}
