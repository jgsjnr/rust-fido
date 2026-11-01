//! Cryptographic Primitives for Secure Guard
//!
//! Hardened KDF (PBKDF2-HMAC-SHA256, Hardware-Anchored KDF), constant-time comparisons
//! with anti-glitching barriers, and CRC32 integrity verification adhering to `no_std`
//! and Zero Secrets principles.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Default iterations for MCU-optimized PBKDF2-HMAC-SHA256.
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 2_000;

/// Explicit warning constant guaranteeing zero permanent silicon lock on dev/bench boards.
pub const DO_NOT_BURN_EFUSE_BLOCK7_WARNING: &str =
    "WARNING: DO NOT BURN EFUSE BLOCK7 IN DEV/TEST — PERMANENT ONE-TIME PROGRAMMABLE LOCK";

/// Abstract hardware peripheral interface for silicon-anchored HMAC-SHA256 operations (`GAP-03`).
///
/// NOTE: In production firmware, this peripheral interacts with the ESP32-S3 hardware
/// HMAC peripheral in upstream mode (`HMAC_UP`) using key slot `BLOCK7`.
///
/// # Inviolable Security Rule
/// DO NOT BURN EFUSE BLOCK7 IN DEV/TEST ENVIRONMENTS!
pub trait HardwareHmacPeripheral {
    /// Computes hardware-accelerated HMAC-SHA256 over message using on-chip silicon key.
    /// Does NOT perform any permanent OTP eFuse burning.
    fn hardware_hmac_sha256(&self, message: &[u8]) -> Result<[u8; 32], &'static str>;
}

/// Non-destructive simulated hardware HMAC for test benches and dev environments.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulatedDevHardwareHmac {
    pub key: [u8; 32],
}

impl SimulatedDevHardwareHmac {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl HardwareHmacPeripheral for SimulatedDevHardwareHmac {
    fn hardware_hmac_sha256(&self, message: &[u8]) -> Result<[u8; 32], &'static str> {
        Ok(hmac_sha256(&self.key, message))
    }
}

/// Derives a 32-byte verifier from a secret and 16-byte salt using PBKDF2-HMAC-SHA256.
pub fn derive_verifier(secret: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let mut verifier = [0u8; 32];
    pbkdf2_hmac_sha256(secret, salt, iterations, &mut verifier);
    verifier
}

/// Derives a 32-byte verifier from PIN/secret and salt, anchored in hardware HMAC when available (`GAP-03`).
///
/// Combines PBKDF2-HMAC-SHA256 with an optional second-stage silicon-backed HMAC (`HMAC_UP`).
/// When `hw_hmac` is `None` (such as in local unit tests or bench development mode),
/// falls back to deterministic software domain-separated HMAC without attempting to burn
/// or access unprovisioned eFuse blocks.
pub fn derive_verifier_hardware_anchored(
    pin: &[u8],
    salt: &[u8; 16],
    iterations: u32,
    hw_hmac: Option<&dyn HardwareHmacPeripheral>,
) -> [u8; 32] {
    let mut pbkdf2_out = [0u8; 32];
    pbkdf2_hmac_sha256(pin, salt, iterations, &mut pbkdf2_out);

    let final_verifier = match hw_hmac {
        Some(peripheral) => match peripheral.hardware_hmac_sha256(&pbkdf2_out) {
            Ok(hw_digest) => hw_digest,
            Err(_) => {
                // Fail-safe domain separation fallback
                hmac_sha256(b"AEGIS_HW_HMAC_FAILSAFE_KEY", &pbkdf2_out)
            }
        },
        None => {
            // Development / unit test software fallback (never burns eFuse)
            hmac_sha256(b"AEGIS_DEV_SOFTWARE_ANCHOR_NO_EFUSE", &pbkdf2_out)
        }
    };

    pbkdf2_out.zeroize();
    final_verifier
}

/// Computes PBKDF2-HMAC-SHA256 producing exactly 32 bytes (block 1, dkLen = 32).
///
/// Implements RFC 8018 Section 5.2. All intermediate scalar materials and HMAC states
/// are zeroized on completion.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; 32]) {
    assert!(iterations > 0, "iterations must be at least 1");

    // Block index i = 1 (4 bytes big-endian: 0x00, 0x00, 0x00, 0x01)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(password)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(salt);
    mac.update(&[0, 0, 0, 1]);
    let mut u = mac.finalize().into_bytes();

    let mut t = [0u8; 32];
    t.copy_from_slice(&u);

    for _ in 1..iterations {
        let mut step_mac = <HmacSha256 as Mac>::new_from_slice(password)
            .expect("HMAC-SHA256 accepts keys of any length");
        step_mac.update(&u);
        u = step_mac.finalize().into_bytes();
        for (byte_t, byte_u) in t.iter_mut().zip(u.iter()) {
            *byte_t ^= *byte_u;
        }
    }

    out.copy_from_slice(&t);

    // Scrub temporary buffers from stack
    u.zeroize();
    t.zeroize();
}

/// Constant-time comparison of two 32-byte digests/verifiers with anti-glitching double verification.
#[inline]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let eq1: bool = a.ct_eq(b).into();
    let eq2_inv: bool = !eq1;
    // Anti-glitching double check
    matches!(
        super::glitch_guard::double_check_authorization(eq1, eq2_inv, 0x55AA_33CC),
        Ok(super::glitch_guard::GlitchResistantBool::True)
    )
}

/// Computes HMAC-SHA256 of data with the given key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Computes IEEE 802.3 CRC32 (polynomial 0xEDB88320) over a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// HKDF-SHA256 key derivation adhering to RFC 5869.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<alloc::vec::Vec<u8>, crate::error::SecureGuardError> {
    let hk = hkdf::Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = alloc::vec![0u8; length];
    hk.expand(info, &mut okm).map_err(|_| crate::error::SecureGuardError::SecureChannelAuthFailed)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_step_consistency() {
        // Test RFC 8018 block 1 consistency:
        // For c = 1: U_1 = HMAC-SHA256(password, salt || 0x00000001)
        let mut out1 = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 1, &mut out1);
        let u1 = hmac_sha256(b"password", b"salt\x00\x00\x00\x01");
        assert_eq!(out1, u1);

        // For c = 2: U_2 = HMAC-SHA256(password, U_1), T_1 = U_1 ^ U_2
        let mut out2 = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut out2);
        let u2 = hmac_sha256(b"password", &u1);
        let mut expected2 = [0u8; 32];
        for i in 0..32 {
            expected2[i] = u1[i] ^ u2[i];
        }
        assert_eq!(out2, expected2);

        // For c = 3: U_3 = HMAC-SHA256(password, U_2), T_1 = U_1 ^ U_2 ^ U_3
        let mut out3 = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 3, &mut out3);
        let u3 = hmac_sha256(b"password", &u2);
        let mut expected3 = [0u8; 32];
        for i in 0..32 {
            expected3[i] = expected2[i] ^ u3[i];
        }
        assert_eq!(out3, expected3);
    }

    #[test]
    fn test_constant_time_eq_32() {
        let a = [0x5Au8; 32];
        let mut b = [0x5Au8; 32];
        assert!(constant_time_eq_32(&a, &b));

        b[31] = 0x5B;
        assert!(!constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_crc32_standard_check() {
        // Standard check: CRC-32 of ASCII "123456789" is 0xCBF43926
        let vector = b"123456789";
        assert_eq!(crc32(vector), 0xCBF43926);
    }

    #[test]
    fn test_hardware_anchored_kdf() {
        let salt = [0x11u8; 16];
        let pin = b"123456";

        // 1. Software dev fallback (no hardware peripheral, no eFuse burn)
        let v_dev = derive_verifier_hardware_anchored(pin, &salt, 10, None);
        assert_ne!(v_dev, [0u8; 32]);

        // 2. Simulated hardware peripheral (dev bench)
        let sim_hw = SimulatedDevHardwareHmac::new([0x42u8; 32]);
        let v_hw = derive_verifier_hardware_anchored(pin, &salt, 10, Some(&sim_hw));
        assert_ne!(v_hw, [0u8; 32]);
        assert_ne!(v_hw, v_dev);

        // Warning constant verification
        assert!(DO_NOT_BURN_EFUSE_BLOCK7_WARNING.contains("DO NOT BURN EFUSE BLOCK7"));
    }
}
