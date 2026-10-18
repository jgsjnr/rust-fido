//! AegisKey YKOATH Protocol Engine
//! 100% Native Rust Implementation for ESP32-S3
//!
//! Compliant with Yubico Authenticator (YKOATH v5.4.3 specification):
//! - Full TOTP and HOTP support (RFC 6238 and RFC 4226)
//! - HMAC-SHA1, HMAC-SHA256, HMAC-SHA512 algorithms
//! - Presence verification via GPIO 0 touch button
//! - Password protection and authentication via PBKDF2-HMAC-SHA1
//! - Full APDU support: SELECT, LIST, CALCULATE, CALCULATE ALL, PUT, DELETE, SET CODE, RESET

pub mod applet;
pub mod crypto;
pub mod presence;
pub mod tlv;
pub mod types;

pub use applet::{OathApplet, APPLET_VERSION, MAX_CREDENTIALS};
pub use crypto::{calculate_code, calculate_code_from_challenge, compute_hmac, pbkdf2_sha1, truncate_digest};
pub use presence::{
    AlwaysPresentVerifier, Gpio0TouchVerifier, MockPresenceVerifier, NeverPresentVerifier,
    PresenceError, PresenceVerifier,
};
pub use tlv::{find_tlv, parse_tlv_records, write_tlv, TlvRecord};
pub use types::*;

/// Engine wrapper for interoperability
pub type OathEngine = OathApplet;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_ykoath_select() {
        let mut applet = OathApplet::new();
        let mut rng = OsRng;
        let mut presence = AlwaysPresentVerifier;

        let mut apdu = vec![0x00, INS_SELECT, 0x04, 0x00, 0x07];
        apdu.extend_from_slice(&YKOATH_AID);

        let (resp, sw) = applet.handle_apdu(&apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);

        let records = parse_tlv_records(&resp).unwrap();
        assert_eq!(find_tlv(&records, TAG_VERSION).unwrap(), &APPLET_VERSION);
        assert_eq!(find_tlv(&records, TAG_NAME).unwrap(), &applet.salt);
        assert_eq!(find_tlv(&records, TAG_ALGORITHM).unwrap(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_ykoath_put_list_calculate_delete() {
        let mut applet = OathApplet::new();
        let mut rng = OsRng;
        let mut presence = AlwaysPresentVerifier;

        // 1. SELECT
        let mut select_apdu = vec![0x00, INS_SELECT, 0x04, 0x00, 0x07];
        select_apdu.extend_from_slice(&YKOATH_AID);
        let (_, sw) = applet.handle_apdu(&select_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);

        // 2. PUT: Store a TOTP SHA1 credential "TestService:alice"
        let secret = b"12345678901234567890";
        let mut put_data = Vec::new();
        write_tlv(&mut put_data, TAG_NAME, b"TestService:alice");
        let mut key_val = vec![0x21, 0x06]; // 0x20 = TOTP, 0x01 = SHA1, digits = 6
        key_val.extend_from_slice(secret);
        write_tlv(&mut put_data, TAG_KEY, &key_val);

        let mut put_apdu = vec![0x00, INS_PUT, 0x00, 0x00, put_data.len() as u8];
        put_apdu.extend_from_slice(&put_data);
        let (_, sw) = applet.handle_apdu(&put_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);

        // 3. LIST
        let list_apdu = vec![0x00, INS_LIST, 0x00, 0x00];
        let (list_resp, sw) = applet.handle_apdu(&list_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);
        let list_records = parse_tlv_records(&list_resp).unwrap();
        assert_eq!(list_records.len(), 1);
        assert_eq!(list_records[0].tag, TAG_NAME);
        assert_eq!(list_records[0].value[0], 0x21); // type/algo
        assert_eq!(&list_records[0].value[1..], b"TestService:alice");

        // 4. CALCULATE with challenge = 1 (T = 1)
        let challenge = 1u64.to_be_bytes();
        let mut calc_data = Vec::new();
        write_tlv(&mut calc_data, TAG_NAME, b"TestService:alice");
        write_tlv(&mut calc_data, TAG_CHALLENGE, &challenge);

        // P2 = 0x01 (truncated response)
        let mut calc_apdu = vec![0x00, INS_CALCULATE, 0x00, 0x01, calc_data.len() as u8];
        calc_apdu.extend_from_slice(&calc_data);
        let (calc_resp, sw) = applet.handle_apdu(&calc_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);

        let calc_records = parse_tlv_records(&calc_resp).unwrap();
        let trunc = find_tlv(&calc_records, TAG_TRUNCATED_RESPONSE).unwrap();
        assert_eq!(trunc[0], 6); // 6 digits
        let code = u32::from_be_bytes([trunc[1], trunc[2], trunc[3], trunc[4]]);
        // RFC 4226 counter 1 is 287082
        assert_eq!(code, 287082);

        // 5. CALCULATE ALL
        let mut calc_all_data = Vec::new();
        write_tlv(&mut calc_all_data, TAG_CHALLENGE, &challenge);
        let mut calc_all_apdu = vec![0x00, INS_CALCULATE_ALL, 0x00, 0x01, calc_all_data.len() as u8];
        calc_all_apdu.extend_from_slice(&calc_all_data);
        let (calc_all_resp, sw) = applet.handle_apdu(&calc_all_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);
        let all_records = parse_tlv_records(&calc_all_resp).unwrap();
        assert_eq!(find_tlv(&all_records, TAG_NAME).unwrap(), b"TestService:alice");
        let all_trunc = find_tlv(&all_records, TAG_TRUNCATED_RESPONSE).unwrap();
        let all_code = u32::from_be_bytes([all_trunc[1], all_trunc[2], all_trunc[3], all_trunc[4]]);
        assert_eq!(all_code, 287082);

        // 6. DELETE
        let mut del_data = Vec::new();
        write_tlv(&mut del_data, TAG_NAME, b"TestService:alice");
        let mut del_apdu = vec![0x00, INS_DELETE, 0x00, 0x00, del_data.len() as u8];
        del_apdu.extend_from_slice(&del_data);
        let (_, sw) = applet.handle_apdu(&del_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);

        // Verify LIST is now empty
        let (list_resp_after, sw) = applet.handle_apdu(&list_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);
        assert!(list_resp_after.is_empty());
    }

    #[test]
    fn test_ykoath_touch_requirement() {
        let mut applet = OathApplet::new();
        let mut rng = OsRng;

        // PUT a credential requiring touch
        let mut put_data = Vec::new();
        write_tlv(&mut put_data, TAG_NAME, b"TouchRequiredService");
        let mut key_val = vec![0x21, 0x06];
        key_val.extend_from_slice(b"12345678901234567890");
        write_tlv(&mut put_data, TAG_KEY, &key_val);
        write_tlv(&mut put_data, TAG_PROPERTY, &[0x01]); // 0x01 = Touch required

        let mut put_apdu = vec![0x00, INS_PUT, 0x00, 0x00, put_data.len() as u8];
        put_apdu.extend_from_slice(&put_data);
        let mut presence = AlwaysPresentVerifier;
        let (_, sw) = applet.handle_apdu(&put_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);

        // CALCULATE with NeverPresentVerifier (simulates no touch / timeout)
        let challenge = 1u64.to_be_bytes();
        let mut calc_data = Vec::new();
        write_tlv(&mut calc_data, TAG_NAME, b"TouchRequiredService");
        write_tlv(&mut calc_data, TAG_CHALLENGE, &challenge);
        let mut calc_apdu = vec![0x00, INS_CALCULATE, 0x00, 0x01, calc_data.len() as u8];
        calc_apdu.extend_from_slice(&calc_data);

        let mut no_presence = NeverPresentVerifier;
        let (resp, sw) = applet.handle_apdu(&calc_apdu, &mut rng, &mut no_presence);
        assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
        let records = parse_tlv_records(&resp).unwrap();
        assert!(find_tlv(&records, TAG_TOUCH).is_some());

        // Now with touch confirmed:
        let mut with_presence = MockPresenceVerifier::new(true);
        let (resp2, sw2) = applet.handle_apdu(&calc_apdu, &mut rng, &mut with_presence);
        assert_eq!(sw2, SW_SUCCESS);
        let records2 = parse_tlv_records(&resp2).unwrap();
        assert!(find_tlv(&records2, TAG_TRUNCATED_RESPONSE).is_some());
    }

    #[test]
    fn test_ykoath_password_protection_and_validation() {
        let mut applet = OathApplet::new();
        let mut rng = OsRng;
        let mut presence = AlwaysPresentVerifier;

        // Set a password
        applet.set_password(b"secret_password");
        assert!(!applet.is_authenticated());

        // SELECT to get challenge
        let mut select_apdu = vec![0x00, INS_SELECT, 0x04, 0x00, 0x07];
        select_apdu.extend_from_slice(&YKOATH_AID);
        let (select_resp, sw) = applet.handle_apdu(&select_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);
        let records = parse_tlv_records(&select_resp).unwrap();
        let challenge = find_tlv(&records, TAG_CHALLENGE).unwrap();
        assert_eq!(challenge.len(), 8);

        // Attempt LIST before validate -> should fail with SW_SECURITY_STATUS_NOT_SATISFIED
        let list_apdu = vec![0x00, INS_LIST, 0x00, 0x00];
        let (_, sw) = applet.handle_apdu(&list_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED);

        // VALIDATE with incorrect response -> should fail
        let mut bad_val_data = Vec::new();
        write_tlv(&mut bad_val_data, TAG_RESPONSE, &[0u8; 20]);
        let mut bad_val_apdu = vec![0x00, INS_VALIDATE, 0x00, 0x00, bad_val_data.len() as u8];
        bad_val_apdu.extend_from_slice(&bad_val_data);
        let (_, sw) = applet.handle_apdu(&bad_val_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED);

        // VALIDATE with correct response
        let derived_key = pbkdf2_sha1(b"secret_password", &applet.salt, 1000, 16);
        let expected_response = compute_hmac(OathAlgorithm::Sha1, &derived_key, challenge);

        let mut good_val_data = Vec::new();
        write_tlv(&mut good_val_data, TAG_RESPONSE, &expected_response);
        let mut good_val_apdu = vec![0x00, INS_VALIDATE, 0x00, 0x00, good_val_data.len() as u8];
        good_val_apdu.extend_from_slice(&good_val_data);
        let (_, sw) = applet.handle_apdu(&good_val_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);
        assert!(applet.is_authenticated());

        // Now LIST succeeds
        let (_, sw) = applet.handle_apdu(&list_apdu, &mut rng, &mut presence);
        assert_eq!(sw, SW_SUCCESS);
    }
}
