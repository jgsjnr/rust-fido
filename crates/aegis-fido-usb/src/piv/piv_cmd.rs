//! PIV command surface (re-export shim; move-only split, no behavior change).
//!
//! Concrete items live in `cmd`: `parse` (INS/P2, slots, consts, fixtures),
//! `auth` (PIN/PUK validation + provisioning), `admin` (store/backend contracts).
//! Every `piv_cmd::X` path keeps compiling via the re-exports below.
#[cfg(test)]
use crate::ccid::{
    CommandApdu, ResponseApdu, AID_PIV, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_NOT_FOUND,
};

pub use super::cmd::*;
pub use super::piv_applet::PivApplet;

#[cfg(test)]
mod tests {
    use super::*;

    fn select_apdu(data: &[u8]) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_SELECT,
            p1: 0x04,
            p2: 0x00,
            data: data.to_vec(),
            le: None,
        }
    }

    fn get_data_apdu(tag: &[u8]) -> CommandApdu {
        // Arrange data field: 5C <len> <tag bytes>
        let mut data = vec![0x5C, tag.len() as u8];
        data.extend_from_slice(tag);
        CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data,
            le: None,
        }
    }

    #[test]
    fn should_select_piv_aid_and_return_fci() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = select_apdu(AID_PIV);

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(applet.is_selected());
        assert_eq!(resp.sw1, 0x90);
        assert_eq!(resp.sw2, 0x00);
        assert_eq!(resp.data, PIV_FCI);
    }

    #[test]
    fn should_return_chuid_mock_when_selected() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert_eq!(resp.data, CHUID_MOCK);
    }

    #[test]
    fn should_return_ccc_mock_when_selected() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x07]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert_eq!(resp.data, CCC_MOCK);
    }

    #[test]
    fn should_reject_unknown_aid_with_6a82() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = select_apdu(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(!applet.is_selected());
        assert_eq!((resp.sw1, resp.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_get_data_when_not_selected_with_6985() {
        // Arrange
        let mut applet = PivApplet::new();

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn should_return_6a82_for_malformed_get_data() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x00, 0xFF],
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_return_6d00_for_unknown_ins() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: 0xFF,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_INS_NOT_SUPPORTED);
    }

    #[test]
    fn should_reject_select_with_wrong_p1() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_SELECT,
            p1: 0x00,
            p2: 0x00,
            data: AID_PIV.to_vec(),
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(!applet.is_selected());
        assert_eq!((resp.sw1, resp.sw2), SW_INS_NOT_SUPPORTED);
    }
}

/// BEHAVIOR Wave 1 Step 1 (TDD): VERIFY/AUTH/PUT/GEN + PIN/PUK NVS.
///
/// RED-first: estes testes falham enquanto os handlers retornam `6D 00` (stub).
#[cfg(test)]
mod secure_tests {
    use super::*;
    use crate::ccid::{
        sw_retries_left, SW_AUTH_BLOCKED, SW_REFERENCED_DATA_NOT_FOUND,
        SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_DATA, SW_WRONG_P1P2,
    };
    use std::collections::HashMap;

    const PIN: &[u8] = b"123456";
    const NEW_PIN: &[u8] = b"654321";
    const PUK: &[u8] = b"12345678";
    const NEW_PUK: &[u8] = b"87654321";
    const CERT_9A: &[u8] = &[0x30, 0x82, 0x01, 0x0A, 0xAA, 0xBB];
    const CERT_9C: &[u8] = &[0x30, 0x82, 0x02, 0x0B, 0xCC, 0xDD];

    /// Store em RAM (contrato `PivRecordStore`; firmware pluga `SecureStorage`).
    #[derive(Default)]
    struct MemStore {
        map: HashMap<String, Vec<u8>>,
    }

    impl PivRecordStore for MemStore {
        fn load_record(&self, key: &str) -> Result<Vec<u8>, PivStoreError> {
            self.map.get(key).cloned().ok_or(PivStoreError::NotFound)
        }

        fn store_record(&mut self, key: &str, value: &[u8]) -> Result<(), PivStoreError> {
            self.map.insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete_record(&mut self, key: &str) -> Result<(), PivStoreError> {
            self.map.remove(key);
            Ok(())
        }
    }

    /// RNG determinístico (xorshift64*; só para testes).
    struct SeqRng(u64);

    impl rand_core::TryRng for SeqRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64().unwrap() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            Ok(x.wrapping_mul(0x2545_F491_4F6C_DD1D))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            let mut i = 0;
            while i < dest.len() {
                let v = self.try_next_u64().unwrap().to_le_bytes();
                let n = (dest.len() - i).min(8);
                dest[i..i + n].copy_from_slice(&v[..n]);
                i += n;
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for SeqRng {}

    /// Backend cripto stub (chave/RNG ficam no firmware; aqui bytes enlatados).
    struct StubCrypto {
        pubkey: Vec<u8>,
        response: Vec<u8>,
    }

    impl PivKeyBackend for StubCrypto {
        fn generate(&mut self, _slot: PivSlot, _alg: u8) -> Result<Vec<u8>, PivCryptoError> {
            Ok(self.pubkey.clone())
        }

        fn authenticate(
            &mut self,
            _slot: PivSlot,
            _alg: u8,
            _challenge: &[u8],
        ) -> Result<Vec<u8>, PivCryptoError> {
            Ok(self.response.clone())
        }
    }

    struct Harness {
        applet: PivApplet,
        store: MemStore,
        crypto: StubCrypto,
        rng: SeqRng,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                applet: PivApplet::new(),
                store: MemStore::default(),
                crypto: StubCrypto {
                    pubkey: vec![0x04, 0x11, 0x22],
                    response: vec![0xAA, 0xBB],
                },
                rng: SeqRng(0x1234_5678_9ABC_DEF0),
            }
        }

        fn select(&mut self) {
            let apdu = CommandApdu {
                cla: 0x00,
                ins: INS_SELECT,
                p1: 0x04,
                p2: 0x00,
                data: AID_PIV.to_vec(),
                le: None,
            };
            let resp = self.applet.handle(&apdu);
            assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        }

        fn provision(&mut self) {
            provision_pin_with_rng(&mut self.store, &mut self.rng, PIN, PUK).expect("provision ok");
        }

        fn run(&mut self, apdu: &CommandApdu) -> ResponseApdu {
            self.applet
                .handle_store(apdu, &mut self.store, &mut self.crypto)
        }
    }

    fn verify_apdu(pin: &[u8]) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_VERIFY,
            p1: 0x00,
            p2: P2_PIN,
            data: pin.to_vec(),
            le: None,
        }
    }

    fn put_cert_apdu(slot: u8, cert: &[u8]) -> CommandApdu {
        let mut data = vec![0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, cert.len() as u8];
        data.extend_from_slice(cert);
        CommandApdu {
            cla: 0x00,
            ins: INS_PUT_DATA,
            p1: 0x3F,
            p2: slot,
            data,
            le: None,
        }
    }

    fn get_cert_apdu() -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x5C, 0x03, 0x5F, 0xC1, 0x05],
            le: None,
        }
    }

    fn generate_apdu(slot: u8) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_GENERATE,
            p1: 0x00,
            p2: slot,
            data: vec![0xAC, 0x03, 0x80, 0x01, 0x11],
            le: None,
        }
    }

    fn auth_apdu(slot: u8, challenge: &[u8]) -> CommandApdu {
        let mut data = vec![
            0x7C,
            (challenge.len() + 2) as u8,
            0x81,
            challenge.len() as u8,
        ];
        data.extend_from_slice(challenge);
        CommandApdu {
            cla: 0x00,
            ins: INS_GENERAL_AUTH,
            p1: 0x00,
            p2: slot,
            data,
            le: None,
        }
    }

    #[test]
    fn should_reject_bad_pin_and_puk_lengths() {
        // Arrange
        let mut h = Harness::new();

        // Act + Assert
        assert_eq!(
            provision_pin_with_rng(&mut h.store, &mut h.rng, b"12345", PUK),
            Err(PivPinError::BadPin)
        );
        assert_eq!(
            provision_pin_with_rng(&mut h.store, &mut h.rng, b"123456789", PUK),
            Err(PivPinError::BadPin)
        );
        assert_eq!(
            provision_pin_with_rng(&mut h.store, &mut h.rng, PIN, b"1234567"),
            Err(PivPinError::BadPuk)
        );
        assert!(h.store.load_record(PIV_NVS_PIN_HASH).is_err());
    }

    #[test]
    fn should_reject_second_provision() {
        // Arrange
        let mut h = Harness::new();
        h.provision();

        // Act
        let res = provision_pin_with_rng(&mut h.store, &mut h.rng, NEW_PIN, NEW_PUK);

        // Assert
        assert_eq!(res, Err(PivPinError::AlreadyProvisioned));
    }

    #[test]
    fn should_verify_ok_and_set_verified() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&verify_apdu(PIN));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
    }

    #[test]
    fn should_query_empty_verify_returns_retries() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&verify_apdu(&[]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(3));
    }

    #[test]
    fn should_wrong_pin_decrement_and_persist() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&verify_apdu(b"000000"));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(2));
        assert!(!h.applet.is_verified());
        let raw = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw, vec![2]);
    }

    #[test]
    fn should_block_after_three_wrongs_then_6983() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act: 3 PINs errados consomem as tentativas
        let r1 = h.run(&verify_apdu(b"000000"));
        let r2 = h.run(&verify_apdu(b"000000"));
        let r3 = h.run(&verify_apdu(b"000000"));

        // Assert: 63 C2 → 63 C1 → 63 C0, depois PIN certo segue bloqueado
        assert_eq!((r1.sw1, r1.sw2), sw_retries_left(2));
        assert_eq!((r2.sw1, r2.sw2), sw_retries_left(1));
        assert_eq!((r3.sw1, r3.sw2), sw_retries_left(0));
        let blocked = h.run(&verify_apdu(PIN));
        assert_eq!((blocked.sw1, blocked.sw2), SW_AUTH_BLOCKED);
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_verify_unprovisioned_returns_6a88() {
        // Arrange
        let mut h = Harness::new();
        h.select();

        // Act
        let resp = h.run(&verify_apdu(PIN));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_REFERENCED_DATA_NOT_FOUND);
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_match_nist_verify_vector_encoding() {
        // Arrange: vetor NIST SP 800-73 (VERIFY `00 20 00 80 06 <PIN>`)
        let raw = [
            0x00, 0x20, 0x00, 0x80, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        ];
        let apdu = CommandApdu::parse(&raw).expect("vetor NIST parseia");
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!(apdu.data, b"123456");
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
    }

    #[test]
    fn should_reject_verify_wrong_p1p2_with_6b00() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_VERIFY,
            p1: 0x00,
            p2: 0x00,
            data: PIN.to_vec(),
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_P1P2);
    }

    #[test]
    fn should_reselect_drop_verified() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let ok = h.run(&verify_apdu(PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: reseleciona o PIV
        h.select();

        // Assert: verificação caiu (fail-closed)
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_change_pin_with_old_ok() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = PIN.to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        let ok = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
    }

    #[test]
    fn should_change_pin_wrong_old_consumes_retry() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = b"000000".to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(2));
    }

    #[test]
    fn should_change_puk_with_old_ok() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = PUK.to_vec();
        data.extend_from_slice(NEW_PUK);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PUK,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
    }

    #[test]
    fn should_unblock_with_puk_after_block() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        for _ in 0..3 {
            let _ = h.run(&verify_apdu(b"000000"));
        }
        let still_blocked = h.run(&verify_apdu(PIN));
        assert_eq!((still_blocked.sw1, still_blocked.sw2), SW_AUTH_BLOCKED);
        let mut data = PUK.to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_UNBLOCK,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        let ok = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        let raw_retries = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw_retries, vec![PIV_PIN_MAX_RETRIES]);
    }

    #[test]
    fn should_wipe_after_three_wrong_puks() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let verified = h.run(&verify_apdu(PIN));
        assert_eq!((verified.sw1, verified.sw2), (0x90, 0x00));
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((put.sw1, put.sw2), (0x90, 0x00));
        let mut data = b"00000000".to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_UNBLOCK,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act: 3 PUKs errados (63 C2 → 63 C1 → 63 C0 + wipe)
        let w1 = h.run(&apdu);
        let w2 = h.run(&apdu);
        let w3 = h.run(&apdu);
        assert_eq!((w1.sw1, w1.sw2), sw_retries_left(2));
        assert_eq!((w2.sw1, w2.sw2), sw_retries_left(1));
        assert_eq!((w3.sw1, w3.sw2), sw_retries_left(0));

        // Assert: wipe total — PIN virou virgem, cert sumiu
        assert!(!h.applet.is_verified());
        let no_pin = h.run(&verify_apdu(PIN));
        assert_eq!((no_pin.sw1, no_pin.sw2), SW_REFERENCED_DATA_NOT_FOUND);
        let no_cert = h.run(&get_cert_apdu());
        assert_eq!((no_cert.sw1, no_cert.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_put_without_pin_with_6982() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_put_then_get_cert_roundtrip() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let verified = h.run(&verify_apdu(PIN));
        assert_eq!((verified.sw1, verified.sw2), (0x90, 0x00));

        // Act
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        let get = h.run(&get_cert_apdu());

        // Assert
        assert_eq!((put.sw1, put.sw2), (0x90, 0x00));
        assert_eq!((get.sw1, get.sw2), (0x90, 0x00));
        assert_eq!(get.data, CERT_9A);
    }

    #[test]
    fn should_get_cert_default_slot_9a_after_put_9c() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let _ = h.run(&put_cert_apdu(PIV_SLOT_9C, CERT_9C));
        let get = h.run(&get_cert_apdu());

        // Assert: último slot endereçado (documentado)
        assert_eq!((get.sw1, get.sw2), (0x90, 0x00));
        assert_eq!(get.data, CERT_9C);
    }

    #[test]
    fn should_reject_put_bad_slot_with_6b00() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&put_cert_apdu(0xFF, CERT_9A));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_P1P2);
    }

    #[test]
    fn should_reject_put_malformed_with_6a80() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_PUT_DATA,
            p1: 0x3F,
            p2: PIV_SLOT_9A,
            data: vec![0x00, 0xFF],
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_DATA);
    }

    #[test]
    fn should_reject_generate_without_pin_with_6982() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&generate_apdu(PIV_SLOT_9A));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_generate_with_stub_returns_7f49() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&generate_apdu(PIV_SLOT_9A));

        // Assert: template `7F 49` carrega a pública do backend
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(resp.data.len() >= 4);
        assert_eq!(&resp.data[..2], &[0x7F, 0x49]);
        assert!(resp.data.windows(3).any(|w| w == [0x04, 0x11, 0x22]));
    }

    #[test]
    fn should_generate_without_backend_returns_6985() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let mut no_backend = NoBackend;

        // Act: firmware ainda sem backend cripto = fail-closed
        let resp =
            h.applet
                .handle_store(&generate_apdu(PIV_SLOT_9A), &mut h.store, &mut no_backend);

        // Assert
        assert_eq!(
            (resp.sw1, resp.sw2),
            (SW_CONDITIONS_NOT_SATISFIED.0, SW_CONDITIONS_NOT_SATISFIED.1)
        );
    }

    #[test]
    fn should_generate_invalidates_cert() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let verified = h.run(&verify_apdu(PIN));
        assert_eq!((verified.sw1, verified.sw2), (0x90, 0x00));
        let first_put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((first_put.sw1, first_put.sw2), (0x90, 0x00));

        // Act
        let gen = h.run(&generate_apdu(PIV_SLOT_9A));

        // Assert: chave nova invalida o cert antigo
        assert_eq!((gen.sw1, gen.sw2), (0x90, 0x00));
        let gone = h.run(&get_cert_apdu());
        assert_eq!((gone.sw1, gone.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_generate_bad_slot_with_6b00() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&generate_apdu(0x00));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_P1P2);
    }

    #[test]
    fn should_reject_generate_malformed_with_6a80() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GENERATE,
            p1: 0x00,
            p2: PIV_SLOT_9A,
            data: vec![0x00],
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_DATA);
    }

    #[test]
    fn should_reject_auth_without_pin_with_6982() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act
        let resp = h.run(&auth_apdu(PIV_SLOT_9A, &[0x01, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_auth_with_stub_returns_7c82() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));

        // Act
        let resp = h.run(&auth_apdu(PIV_SLOT_9A, &[0x01, 0x02]));

        // Assert: `7C .. 82 .. <resposta do backend>`
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(!resp.data.is_empty());
        assert_eq!(resp.data[0], 0x7C);
        assert!(resp.data.windows(2).any(|w| w == [0xAA, 0xBB]));
    }

    #[test]
    fn should_auth_without_backend_returns_6985() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let mut no_backend = NoBackend;

        // Act
        let resp = h.applet.handle_store(
            &auth_apdu(PIV_SLOT_9A, &[0x01]),
            &mut h.store,
            &mut no_backend,
        );

        // Assert
        assert_eq!(
            (resp.sw1, resp.sw2),
            (SW_CONDITIONS_NOT_SATISFIED.0, SW_CONDITIONS_NOT_SATISFIED.1)
        );
    }

    #[test]
    fn should_reject_auth_malformed_with_6a80() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let _ = h.run(&verify_apdu(PIN));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GENERAL_AUTH,
            p1: 0x00,
            p2: PIV_SLOT_9A,
            data: vec![0x00, 0x01],
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_WRONG_DATA);
    }

    #[test]
    fn should_blocked_pin_require_puk_not_verify() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        for _ in 0..3 {
            let _ = h.run(&verify_apdu(b"000000"));
        }

        // Act: PIN certo com retries zerados continua bloqueado
        let resp = h.run(&verify_apdu(PIN));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_AUTH_BLOCKED);
        assert!(!h.applet.is_verified());
    }

    #[test]
    fn should_failed_verify_drop_verified_session() {
        // Arrange: sessão verificada (fail-closed exige derrubar no 1º erro)
        let mut h = Harness::new();
        h.select();
        h.provision();
        let ok = h.run(&verify_apdu(PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: um VERIFY com PIN errado
        let bad = h.run(&verify_apdu(b"000000"));

        // Assert: sessão caiu; PUT bloqueado com 69 82
        assert_eq!((bad.sw1, bad.sw2), sw_retries_left(2));
        assert!(!h.applet.is_verified());
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((put.sw1, put.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_lockout_drop_verified_session() {
        // Arrange: sessão verificada antes do lockout
        let mut h = Harness::new();
        h.select();
        h.provision();
        let ok = h.run(&verify_apdu(PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: 3 erros → 63 C2, 63 C1, 63 C0 (lockout)
        let _ = h.run(&verify_apdu(b"000000"));
        let _ = h.run(&verify_apdu(b"000000"));
        let last = h.run(&verify_apdu(b"000000"));
        assert_eq!((last.sw1, last.sw2), sw_retries_left(0));

        // Assert: sessão NÃO sobrevive ao lockout; PIN certo exige PUK
        assert!(!h.applet.is_verified());
        let blocked = h.run(&verify_apdu(PIN));
        assert_eq!((blocked.sw1, blocked.sw2), SW_AUTH_BLOCKED);
        assert!(!h.applet.is_verified());
        let put = h.run(&put_cert_apdu(PIV_SLOT_9A, CERT_9A));
        assert_eq!((put.sw1, put.sw2), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn should_change_and_unblock_new_secrets_roundtrip() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act: CHANGE PIN (PIN -> NEW_PIN); buffer novo zeroizado no drop
        let mut ch_pin = PIN.to_vec();
        ch_pin.extend_from_slice(NEW_PIN);
        let ch_pin_apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data: ch_pin,
            le: None,
        };
        let ch_pin_resp = h.run(&ch_pin_apdu);
        assert_eq!((ch_pin_resp.sw1, ch_pin_resp.sw2), (0x90, 0x00));

        // Assert: PIN novo autentica
        let ok_new = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok_new.sw1, ok_new.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());

        // Act: CHANGE PUK (PUK -> NEW_PUK); buffer novo zeroizado no drop
        let mut ch_puk = PUK.to_vec();
        ch_puk.extend_from_slice(NEW_PUK);
        let ch_puk_apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PUK,
            data: ch_puk,
            le: None,
        };
        let ch_puk_resp = h.run(&ch_puk_apdu);
        assert_eq!((ch_puk_resp.sw1, ch_puk_resp.sw2), (0x90, 0x00));

        // Act: bloqueia o PIN novo e desbloqueia com o PUK novo
        for _ in 0..3 {
            let _ = h.run(&verify_apdu(b"000000"));
        }
        assert_eq!(
            (
                h.run(&verify_apdu(NEW_PIN)).sw1,
                h.run(&verify_apdu(NEW_PIN)).sw2
            ),
            SW_AUTH_BLOCKED
        );
        let mut unb = NEW_PUK.to_vec();
        unb.extend_from_slice(PIN);
        let unb_apdu = CommandApdu {
            cla: 0x00,
            ins: INS_UNBLOCK,
            p1: 0x00,
            p2: P2_PIN,
            data: unb,
            le: None,
        };
        let unb_resp = h.run(&unb_apdu);
        assert_eq!((unb_resp.sw1, unb_resp.sw2), (0x90, 0x00));

        // Assert: PIN restaurado autentica (prova que os 3 buffers novos funcionaram)
        let ok_restored = h.run(&verify_apdu(PIN));
        assert_eq!((ok_restored.sw1, ok_restored.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
    }

    #[test]
    fn should_verify_padded_ff_matches_raw_6b_pin() {
        // Arrange: PIN cru 6B provisionado, driver real envia 8B com padding FF
        let mut h = Harness::new();
        h.select();
        h.provision();
        let padded = b"123456\xFF\xFF";

        // Act
        let resp = h.run(&verify_apdu(padded));

        // Assert: casa sem consumir retry
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
        let raw = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw, vec![PIV_PIN_MAX_RETRIES]);
    }

    #[test]
    fn should_verify_raw_8b_ending_ff_still_exact() {
        // Arrange: PIN cru 8B terminado em FF (FF legítimo, não padding)
        let mut h = Harness::new();
        h.select();
        let raw_pin = b"1234567\xFF";
        provision_pin_with_rng(&mut h.store, &mut h.rng, raw_pin, PUK).expect("provision ok");

        // Act
        let resp = h.run(&verify_apdu(raw_pin));

        // Assert: exato casa na primeira tentativa
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert!(h.applet.is_verified());
    }

    #[test]
    fn should_reject_padded_wrong_pin() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();

        // Act: PIN errado com padding FF (63 C2, consome só 1 retry)
        let resp = h.run(&verify_apdu(b"000000\xFF\xFF"));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), sw_retries_left(2));
        assert!(!h.applet.is_verified());
        let raw = h.store.load_record(PIV_NVS_PIN_RETRIES).unwrap();
        assert_eq!(raw, vec![2]);
    }

    #[test]
    fn should_change_pin_with_padded_old_ok() {
        // Arrange
        let mut h = Harness::new();
        h.select();
        h.provision();
        let mut data = b"123456\xFF\xFF".to_vec();
        data.extend_from_slice(NEW_PIN);
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_CHANGE,
            p1: 0x00,
            p2: P2_PIN,
            data,
            le: None,
        };

        // Act
        let resp = h.run(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        let ok = h.run(&verify_apdu(NEW_PIN));
        assert_eq!((ok.sw1, ok.sw2), (0x90, 0x00));
    }
}
