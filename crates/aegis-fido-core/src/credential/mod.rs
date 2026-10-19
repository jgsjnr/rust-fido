pub mod key_manager;
pub mod non_resident;
pub mod record;
pub mod store;

pub use non_resident::CredentialWrapper;
pub use record::CredentialRecord;
pub use store::{CredentialStore, KeySlot, MemoryCredentialStore, KEY_USE_AUTH, KEY_USE_SIGN, MAX_KEY_LABEL_BYTES, MAX_KEY_SLOTS, MIN_KEY_LABEL_BYTES};
pub use key_manager::{KeyManager, KeyManagerError, STATUS_BAD_ENVELOPE, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_NO_SLOT, STATUS_OK};
