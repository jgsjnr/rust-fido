//! Wave3 P0 — validated device configuration (bounds-checked).
//!
//! Defaults equal current hardcoded behavior (G0 preservation):
//! - `max_resident_credentials = 50` (`CtapEngine::new`, `AuthenticatorInfoConfig`)
//! - `max_plaintext_bytes = 512` (`persistence::MAX_PLAINTEXT_BYTES`)
//! - `min_pin_length = 4`, `pin_retries = 8`, `uv_retries = 3` (`ClientPinState`)
//!
//! Pattern: `DeviceConfig::new() -> Result` with `consts com bound`.
//! MAX-ESP: plain `Copy` struct, no alloc, no I/O in validation.
// AUDIT-PREP: wiring na Wave4

/// Default resident credential capacity (current behavior).
pub const DEFAULT_MAX_RESIDENT_CREDENTIALS: usize = 50;
/// Lower bound for resident capacity.
pub const MIN_RESIDENT_CREDENTIALS: usize = 1;
/// Upper bound (`const com bound`) for resident capacity.
pub const MAX_RESIDENT_CREDENTIALS_BOUND: usize = 256;

/// Default plaintext limit (matches `persistence::MAX_PLAINTEXT_BYTES`).
pub const DEFAULT_MAX_PLAINTEXT_BYTES: usize = 512;
/// Upper bound for plaintext (MAX-ESP envelope budget).
pub const MAX_PLAINTEXT_BYTES_BOUND: usize = 512;
/// Lower bound for plaintext.
pub const MIN_PLAINTEXT_BYTES: usize = 1;

/// Default CTAP minimum PIN length (current behavior).
pub const DEFAULT_MIN_PIN_LENGTH: u32 = 4;
/// Lower bound per CTAP2.1 (`setMinPINLength`).
pub const MIN_PIN_LENGTH_LOWER: u32 = 4;
/// Upper bound (client_pin rejects `> 63`).
pub const MIN_PIN_LENGTH_UPPER: u32 = 63;

/// Default PIN retries (current behavior).
pub const DEFAULT_PIN_RETRIES: u8 = 8;
/// Upper bound for PIN retries.
pub const MAX_PIN_RETRIES_BOUND: u8 = 8;

/// Default UV retries (current behavior).
pub const DEFAULT_UV_RETRIES: u8 = 3;
/// Upper bound for UV retries.
pub const MAX_UV_RETRIES_BOUND: u8 = 3;
/// Fase6 - default key slots (9 TLV <=512B; sem quebra Wave3).
pub const DEFAULT_MAX_KEYS: usize = 32;
/// Lower bound for key slots.
pub const MIN_KEYS: usize = 1;
/// Upper bound (const com bound) for key slots.
pub const MAX_KEYS_BOUND: usize = 64;

/// Fase6 - default OATH slots (9 MAX_CREDENTIALS=64).
pub const DEFAULT_MAX_OATH: usize = 64;
/// Lower bound for OATH slots.
pub const MIN_OATH: usize = 1;
/// Upper bound for OATH slots (igual MAX_CREDENTIALS).
pub const MAX_OATH_BOUND: usize = 64;

/// Vault - default per-item slots (`vault/<label>`, quota via `vault/index`).
pub const DEFAULT_MAX_VAULT_SLOTS: usize = 32;
/// Lower bound for vault slots.
pub const MIN_VAULT_SLOTS: usize = 1;
/// Upper bound (const com bound) for vault slots.
pub const MAX_VAULT_SLOTS_BOUND: usize = 64;

/// Fase6 - label maximo compartilhado (9.2/9.3 1..32B utf8).
pub const MAX_LABEL_BYTES: usize = 32;

/// Wave4 — long-press to enter pairing (GPIO0, debounce 50ms).
pub const LONG_PRESS_MS: u64 = 5000;
/// Wave4 — pairing window (BLE advertising + AP) in seconds.
pub const PAIRING_WINDOW_SECS: u64 = 60;
/// Wave4 — pairing window in milliseconds (derived, no logic change).
pub const PAIRING_WINDOW_MS: u64 = PAIRING_WINDOW_SECS * 1000;
/// Wave4 — Vault auto-clear after UP display (seconds).
pub const VAULT_AUTO_CLEAR_SECS: u64 = 15;

/// Typed config validation failure (no stringly errors in prod path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// Resident capacity out of bound.
    InvalidMaxResident,
    /// Plaintext limit out of bound.
    InvalidMaxPlaintext,
    /// Minimum PIN length out of bound.
    InvalidMinPinLength,
    /// PIN retries out of bound.
    InvalidPinRetries,
    /// UV retries out of bound.
    InvalidUvRetries,
    /// Fase6: key slots out of bound.
    InvalidMaxKeys,
    /// Fase6: OATH slots out of bound.
    InvalidMaxOath,
    /// Vault: per-item slots out of bound.
    InvalidMaxVault,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMaxResident => write!(f, "max_resident out of bound"),
            Self::InvalidMaxPlaintext => write!(f, "max_plaintext out of bound"),
            Self::InvalidMinPinLength => write!(f, "min_pin_length out of bound"),
            Self::InvalidPinRetries => write!(f, "pin_retries out of bound"),
            Self::InvalidUvRetries => write!(f, "uv_retries out of bound"),
            Self::InvalidMaxKeys => write!(f, "max_keys out of bound"),
            Self::InvalidMaxOath => write!(f, "max_oath out of bound"),
            Self::InvalidMaxVault => write!(f, "max_vault_slots out of bound"),
        }
    }
}

/// Validated device limits. Construct via `new()`; `default()` = current behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceConfig {
    /// Maximum resident credentials.
    pub max_resident_credentials: usize,
    /// Maximum plaintext bytes per envelope.
    pub max_plaintext_bytes: usize,
    /// CTAP minimum PIN length.
    pub min_pin_length: u32,
    /// PIN retries.
    pub pin_retries: u8,
    /// UV retries.
    pub uv_retries: u8,
    /// Fase6: max key slots.
    pub max_keys: usize,
    /// Fase6: max OATH slots.
    pub max_oath: usize,
    /// Vault: max per-item slots (`vault/<label>`).
    pub max_vault_slots: usize,
}

impl DeviceConfig {
    /// Validates bounds; returns `Err` on any out-of-bound input.
    #[allow(clippy::too_many_arguments)]
    // Eight validated limits in one positional constructor (established
    // `new()` pattern); arity grew 7 -> 8 with `max_vault_slots`.
    pub fn new(
        max_resident_credentials: usize,
        max_plaintext_bytes: usize,
        min_pin_length: u32,
        pin_retries: u8,
        uv_retries: u8,
        max_keys: usize,
        max_oath: usize,
        max_vault_slots: usize,
    ) -> Result<Self, ConfigError> {
        if !(MIN_RESIDENT_CREDENTIALS..=MAX_RESIDENT_CREDENTIALS_BOUND)
            .contains(&max_resident_credentials)
        {
            return Err(ConfigError::InvalidMaxResident);
        }
        if !(MIN_PLAINTEXT_BYTES..=MAX_PLAINTEXT_BYTES_BOUND).contains(&max_plaintext_bytes) {
            return Err(ConfigError::InvalidMaxPlaintext);
        }
        if !(MIN_PIN_LENGTH_LOWER..=MIN_PIN_LENGTH_UPPER).contains(&min_pin_length) {
            return Err(ConfigError::InvalidMinPinLength);
        }
        if pin_retries == 0 || pin_retries > MAX_PIN_RETRIES_BOUND {
            return Err(ConfigError::InvalidPinRetries);
        }
        if uv_retries == 0 || uv_retries > MAX_UV_RETRIES_BOUND {
            return Err(ConfigError::InvalidUvRetries);
        }
        if !(MIN_KEYS..=MAX_KEYS_BOUND).contains(&max_keys) {
            return Err(ConfigError::InvalidMaxKeys);
        }
        if !(MIN_OATH..=MAX_OATH_BOUND).contains(&max_oath) {
            return Err(ConfigError::InvalidMaxOath);
        }
        if !(MIN_VAULT_SLOTS..=MAX_VAULT_SLOTS_BOUND).contains(&max_vault_slots) {
            return Err(ConfigError::InvalidMaxVault);
        }
        Ok(Self {
            max_resident_credentials,
            max_plaintext_bytes,
            min_pin_length,
            pin_retries,
            uv_retries,
            max_keys,
            max_oath,
            max_vault_slots,
        })
    }

    /// Current hardcoded behavior (no semantic change).
    pub fn default_config() -> Self {
        Self {
            max_resident_credentials: DEFAULT_MAX_RESIDENT_CREDENTIALS,
            max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
            min_pin_length: DEFAULT_MIN_PIN_LENGTH,
            pin_retries: DEFAULT_PIN_RETRIES,
            uv_retries: DEFAULT_UV_RETRIES,
            max_keys: DEFAULT_MAX_KEYS,
            max_oath: DEFAULT_MAX_OATH,
            max_vault_slots: DEFAULT_MAX_VAULT_SLOTS,
        }
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_equals_current_behavior() {
        let cfg = DeviceConfig::default();
        assert_eq!(cfg.max_resident_credentials, 50);
        assert_eq!(cfg.max_plaintext_bytes, 512);
        assert_eq!(cfg.min_pin_length, 4);
        assert_eq!(cfg.pin_retries, 8);
        assert_eq!(cfg.uv_retries, 3);
        assert_eq!(cfg.max_keys, DEFAULT_MAX_KEYS);
        assert_eq!(cfg.max_oath, DEFAULT_MAX_OATH);
        assert_eq!(cfg.max_vault_slots, DEFAULT_MAX_VAULT_SLOTS);
    }

    #[test]
    fn new_accepts_defaults() {
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS).expect("defaults valid");
        assert_eq!(cfg, DeviceConfig::default());
    }

    #[test]
    fn rejects_zero_resident() {
        assert_eq!(
            DeviceConfig::new(0, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxResident)
        );
    }

    #[test]
    fn rejects_over_bound_resident() {
        assert_eq!(
            DeviceConfig::new(MAX_RESIDENT_CREDENTIALS_BOUND + 1, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxResident)
        );
    }

    #[test]
    fn rejects_over_bound_plaintext() {
        assert_eq!(
            DeviceConfig::new(50, MAX_PLAINTEXT_BYTES_BOUND + 1, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxPlaintext)
        );
    }

    #[test]
    fn rejects_zero_plaintext() {
        assert_eq!(
            DeviceConfig::new(50, 0, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxPlaintext)
        );
    }

    #[test]
    fn rejects_pin_length_bounds() {
        assert_eq!(
            DeviceConfig::new(50, 512, MIN_PIN_LENGTH_LOWER - 1, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMinPinLength)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, MIN_PIN_LENGTH_UPPER + 1, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMinPinLength)
        );
    }

    #[test]
    fn rejects_retries_bounds() {
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 0, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidPinRetries)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, MAX_PIN_RETRIES_BOUND + 1, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidPinRetries)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 0, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidUvRetries)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, MAX_UV_RETRIES_BOUND + 1, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidUvRetries)
        );
    }

    #[test]
    fn fase6_keys_oath_bounds() {
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS).expect("fase6 defaults valid");
        assert_eq!(cfg.max_keys, 32);
        assert_eq!(cfg.max_oath, 64);
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 3, 0, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxKeys)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 3, MAX_KEYS_BOUND + 1, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxKeys)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, 0, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxOath)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, MAX_OATH_BOUND + 1, DEFAULT_MAX_VAULT_SLOTS),
            Err(ConfigError::InvalidMaxOath)
        );
        assert_eq!(MAX_LABEL_BYTES, 32);
    }

    #[test]
    fn vault_slots_bounds() {
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, DEFAULT_MAX_VAULT_SLOTS)
            .expect("vault defaults valid");
        assert_eq!(cfg.max_vault_slots, 32);
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, 0),
            Err(ConfigError::InvalidMaxVault)
        );
        assert_eq!(
            DeviceConfig::new(50, 512, 4, 8, 3, DEFAULT_MAX_KEYS, DEFAULT_MAX_OATH, MAX_VAULT_SLOTS_BOUND + 1),
            Err(ConfigError::InvalidMaxVault)
        );
    }
}
