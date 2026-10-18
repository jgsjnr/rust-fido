//! AegisKey OTP, Auxiliary Protocols & Multi-Protocol Tool Compatibility
//! 100% Native Rust Implementation for ESP32-S3
//!
//! Features:
//! - Full YubiKey OTP emulation (Modhex encoding, 16-byte payload with session/usage counter, 8Hz timestamp, CRC-16, AES-128-ECB).
//! - Dual-slot Challenge-Response (HMAC-SHA1 in Slot 1 and Slot 2 with optional touch requirement).
//! - USB HID Keyboard scancode generator for auto-typing OTP + Enter upon GPIO 0 button press.
//! - External tools compatibility: Yubico YKMAN CLI (Management Applet AID, Device Info TLV) and Nitrokey nitropy/nitroapp.
//! - Rescue Protocol (Interface de Resgate) for emergency hardware diagnostics, factory wipe, and recovery.

pub mod challenge_response;
pub mod modhex;
pub mod nitrokey;
pub mod rescue;
pub mod scancodes;
pub mod ykman;
pub mod yubikey_otp;

pub use challenge_response::{ChallengeResponseError, ChallengeResponseManager, ChallengeResponseSlot, SlotIndex};
pub use modhex::{decode as modhex_decode, encode as modhex_encode, hex_to_modhex, modhex_to_hex, ModhexError};
pub use nitrokey::{NitrokeyStatus, NK_CMD_STATUS, NK_CMD_VERSION, NK_STATUS_SUCCESS};
pub use rescue::{RescueEngine, EMERGENCY_WIPE_TOKEN, RESCUE_CMD_PING, RESCUE_MAGIC, RESCUE_STATUS_OK};
pub use scancodes::{char_to_hid_scancode, string_to_hid_reports, HidKeyboardReport, OtpAutoTyper, HID_KEY_ENTER};
pub use ykman::{YkmanDeviceInfo, YubiOtpStatus, ALL_SUPPORTED_CAPS, YK_MGMT_AID};
pub use yubikey_otp::{calculate_crc, YubiOtpError, YubiOtpGenerator, YubiOtpPayload, CRC_OK_RESIDUE};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oath::presence::AlwaysPresentVerifier;

    #[test]
    fn test_end_to_end_otp_workflow() {
        let public_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let private_id = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let aes_key = [0x55u8; 16];

        // 1. Initialize YubiKey OTP generator
        let mut otp_gen = YubiOtpGenerator::new(&public_id, private_id, aes_key);

        // 2. Generate OTP token
        let token = otp_gen.generate_token(0xABCD);
        assert_eq!(token.len(), 12 + 32);

        // 3. Verify OTP token decryption and CRC
        let verified = otp_gen.verify_token(&token, Some(&public_id)).unwrap();
        assert_eq!(verified.uid, private_id);
        assert_eq!(verified.use_counter, 1);
        assert_eq!(verified.session_counter, 1);
        assert_eq!(verified.random_number, 0xABCD);

        // 4. Test USB HID Keyboard Scancode Auto-Typer
        let auto_typer = OtpAutoTyper::new(true);
        let reports = auto_typer.on_button_press(&mut otp_gen, 0x1111);
        assert_eq!(reports.len(), 90);
        // Ensure enter keycode is at end
        assert_eq!(reports[reports.len() - 2][2], HID_KEY_ENTER);

        // 5. Test Challenge-Response Slot 1
        let mut cr_mgr = ChallengeResponseManager::new();
        let hmac_key = b"slot1_secret_hmac_sha1";
        cr_mgr.configure_slot(SlotIndex::Slot1, hmac_key, false);

        let mut presence = AlwaysPresentVerifier;
        let challenge = b"my_challenge_nonce";
        let resp = cr_mgr
            .process_challenge(SlotIndex::Slot1, challenge, &mut presence)
            .unwrap();
        assert_eq!(resp.len(), 20);

        // 6. Test YKMAN Management Device Info TLV
        let ykman = YkmanDeviceInfo::new(99887766);
        let tlv = ykman.encode_tlv();
        assert!(!tlv.is_empty());
        assert_eq!(tlv[0] as usize, tlv.len() - 1);

        // 7. Test Nitrokey compatibility
        let mut nk = NitrokeyStatus::default();
        let (nk_status, nk_resp) = nk.handle_command(NK_CMD_STATUS, &[], &mut presence);
        assert_eq!(nk_status, NK_STATUS_SUCCESS);
        assert!(!nk_resp.is_empty());

        // 8. Test Rescue Protocol Ping
        let mut rescue = RescueEngine::new();
        rescue.set_user_presence(true);
        let mut ping_frame = Vec::new();
        ping_frame.extend_from_slice(&RESCUE_MAGIC);
        ping_frame.push(1); // version
        ping_frame.push(RESCUE_CMD_PING);
        ping_frame.extend_from_slice(&0u16.to_be_bytes());
        let (res_status, _) = rescue.handle_packet(&ping_frame);
        assert_eq!(res_status, RESCUE_STATUS_OK);
    }
}
