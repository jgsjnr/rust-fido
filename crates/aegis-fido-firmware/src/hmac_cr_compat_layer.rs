//! HMAC-SHA1 Challenge-Response Compatible Layer (HMAC-SHA1 + CRC-16 ISO 13239) for KeePassXC & USB HID Feature Reports.
//!
//! Implements slot configuration and on-demand HMAC-SHA1 challenge-response computation
//! with immediate memory zeroization (Zeroize) in internal SRAM.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::sync::Mutex;
use zeroize::Zeroize;

use aegis_fido_core::otp::legacy_otp_compat::calculate_crc;

type HmacSha1 = Hmac<Sha1>;

pub const SLOT_CHAL_HMAC1: u8 = 0x30;
pub const SLOT_CHAL_HMAC2: u8 = 0x38;

#[derive(Default)]
pub struct CrCompatSlot {
    pub key: [u8; 20],
    pub is_configured: bool,
    pub require_touch: bool,
}

impl Drop for CrCompatSlot {
    fn drop(&mut self) {
        self.key.zeroize();
        self.is_configured = false;
        self.require_touch = false;
    }
}

// Global slots storage (Slot 1 and Slot 2)
static CR_COMPAT_SLOTS: Mutex<(CrCompatSlot, CrCompatSlot)> = Mutex::new((
    CrCompatSlot {
        key: [0u8; 20],
        is_configured: false,
        require_touch: false,
    },
    CrCompatSlot {
        key: [0u8; 20],
        is_configured: false,
        require_touch: false,
    },
));

static SECURE_GUARD_UNLOCKED: AtomicBool = AtomicBool::new(false);

pub fn set_secure_guard_unlocked(unlocked: bool) {
    SECURE_GUARD_UNLOCKED.store(unlocked, Ordering::SeqCst);
}

pub fn is_secure_guard_unlocked() -> bool {
    SECURE_GUARD_UNLOCKED.load(Ordering::SeqCst)
}

/// Configure Slot 1 or Slot 2 with a 20-byte HMAC-SHA1 key.
pub fn configure_cr_compat_slot(slot_num: u8, key: &[u8], require_touch: bool) -> Result<(), &'static str> {
    if key.len() != 20 {
        return Err("invalid_key_length_must_be_20_bytes");
    }
    let mut guard = CR_COMPAT_SLOTS.lock().map_err(|_| "mutex_poisoned")?;
    let slot_target = match slot_num {
        1 | SLOT_CHAL_HMAC1 => &mut guard.0,
        2 | SLOT_CHAL_HMAC2 => &mut guard.1,
        _ => return Err("invalid_slot_number"),
    };

    slot_target.key.copy_from_slice(key);
    slot_target.is_configured = true;
    slot_target.require_touch = require_touch;
    Ok(())
}

/// Clear Slot 1 or Slot 2.
pub fn clear_cr_compat_slot(slot_num: u8) -> Result<(), &'static str> {
    let mut guard = CR_COMPAT_SLOTS.lock().map_err(|_| "mutex_poisoned")?;
    let slot_target = match slot_num {
        1 | SLOT_CHAL_HMAC1 => &mut guard.0,
        2 | SLOT_CHAL_HMAC2 => &mut guard.1,
        _ => return Err("invalid_slot_number"),
    };

    slot_target.key.zeroize();
    slot_target.is_configured = false;
    slot_target.require_touch = false;
    Ok(())
}

/// Calculate 20-byte HMAC-SHA1 + 2-byte CRC-16 ISO 13239 (22 bytes total).
/// Loads key on-demand in internal SRAM buffer with immediate Zeroize upon exit.
pub fn process_cr_compat_challenge(slot_num: u8, challenge: &[u8]) -> Result<[u8; 22], &'static str> {
    if challenge.len() > 64 {
        return Err("challenge_too_long");
    }

    let mut key_buf = [0u8; 20];
    let is_cfg: bool;

    {
        let guard = CR_COMPAT_SLOTS.lock().map_err(|_| "mutex_poisoned")?;
        let slot_ref = match slot_num {
            1 | SLOT_CHAL_HMAC1 => &guard.0,
            2 | SLOT_CHAL_HMAC2 => &guard.1,
            _ => return Err("invalid_slot_number"),
        };
        is_cfg = slot_ref.is_configured;
        if is_cfg {
            key_buf.copy_from_slice(&slot_ref.key);
        }
    }

    if !is_cfg {
        return Err("slot_not_configured");
    }

    // Just-in-Time HMAC-SHA1 calculation
    let mut mac = HmacSha1::new_from_slice(&key_buf).map_err(|_| "hmac_init_failed")?;
    mac.update(challenge);
    let digest = mac.finalize().into_bytes();

    // Immediate zeroize of key buffer
    key_buf.zeroize();

    let mut out = [0u8; 22];
    out[..20].copy_from_slice(&digest);

    // Calculate CRC-16 ISO 13239
    let crc = calculate_crc(&out[..20]);
    out[20..22].copy_from_slice(&crc.to_le_bytes());

    Ok(out)
}

/// FFI Bridge function called by TinyUSB HID stack in `aegis_usb.c`.
/// Returns 0 on success, negative error code on failure.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegis_usb_cr_compat_layer_process(
    slot: u8,
    challenge: *const u8,
    challenge_len: u16,
    response_out: *mut u8,
    response_out_len: *mut u16,
) -> i32 {
    if challenge.is_null() || response_out.is_null() || response_out_len.is_null() {
        return -1;
    }
    if challenge_len > 64 {
        return -2;
    }

    // Fail-closed security check: SecureGuard must not be locked
    // If not explicitly unlocked, check if provisioned or locked
    if !is_secure_guard_unlocked() {
        // Protected: refuse challenge response while locked
        return -3;
    }

    let chal_slice = unsafe { core::slice::from_raw_parts(challenge, challenge_len as usize) };
    match process_cr_compat_challenge(slot, chal_slice) {
        Ok(resp) => {
            unsafe {
                core::ptr::copy_nonoverlapping(resp.as_ptr(), response_out, 22);
                *response_out_len = 22;
            }
            0
        }
        Err(_) => -4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_cr_compat_layer_workflow() {
        // Known secret key 20 bytes
        let secret = [0x33u8; 20];
        configure_cr_compat_slot(2, &secret, false).expect("slot 2 config succeeds");

        set_secure_guard_unlocked(true);
        assert!(is_secure_guard_unlocked());

        let challenge = b"KeePassXC-Challenge-Test-Vector";
        let resp = process_cr_compat_challenge(2, challenge).expect("process challenge succeeds");

        // Response must be 22 bytes (20 bytes HMAC-SHA1 + 2 bytes CRC)
        assert_eq!(resp.len(), 22);

        // Verify CRC-16
        let crc = u16::from_le_bytes([resp[20], resp[21]]);
        let expected_crc = calculate_crc(&resp[..20]);
        assert_eq!(crc, expected_crc);

        // Test FFI bridge function
        let mut out = [0u8; 36];
        let mut out_len = 0u16;
        let ret = aegis_usb_cr_compat_layer_process(
            2,
            challenge.as_ptr(),
            challenge.len() as u16,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(ret, 0);
        assert_eq!(out_len, 22);
        assert_eq!(&out[..22], &resp[..22]);

        // When locked, FFI bridge refuses to respond
        set_secure_guard_unlocked(false);
        let ret_locked = aegis_usb_cr_compat_layer_process(
            2,
            challenge.as_ptr(),
            challenge.len() as u16,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(ret_locked, -3);

        // Restore unlocked state
        set_secure_guard_unlocked(true);
    }
}
