//! Dispatch CCID → PIV on-device (F4).
//!
//! Um [`CcidTransport`] (framing CCID 1.1) + [`CcidPivHandler`] (applet com
//! NVS + `KeyManager` reais) por boot; cada frame bulk do driver C vira
//! APDU via `handle_store` e volta como RPDU. OATH/FIDO sobre CCID estão
//! fora do escopo v1 (`6D 00` honesto em vez de mock).

extern crate alloc;

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_usb::ccid::{
    CcidApduHandler, CcidTransport, CommandApdu, ResponseApdu, SW_INS_NOT_SUPPORTED,
};
use alloc::vec::Vec;

use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::piv_store::{PivFwBackend, PivNvsStore};

/// Handler dos applets auxiliares: OATH/FIDO sobre CCID estão fora do
/// escopo v1 (`6D 00` honesto). O PIV é servido pelo applet do próprio
/// `CcidTransport` (estado persiste entre frames) com store/backend reais.
struct NoExtraApplets;

impl CcidApduHandler for NoExtraApplets {
    fn handle_oath_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
        ResponseApdu::status(SW_INS_NOT_SUPPORTED)
    }

    fn handle_fido_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
        ResponseApdu::status(SW_INS_NOT_SUPPORTED)
    }
}

/// Processa um frame CCID completo (10B header + payload) e devolve o
/// RPDU pronto p/ bulk-IN. `None` = frame malformado (sem resposta).
pub fn process_ccid_frame<B: FlashStorageBackend>(
    transport: &mut CcidTransport,
    frame: &[u8],
    storage: &mut SecureStorage<B>,
    keys: &mut KeyManager,
    now_secs: u64,
) -> Option<Vec<u8>> {
    let mut store = PivNvsStore::new(storage);
    let mut crypto = PivFwBackend::new(keys, now_secs);
    let mut handler = NoExtraApplets;
    transport
        .process_ccid_message_store(frame, &mut handler, &mut store, &mut crypto)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
    }

    fn xfr(seq: u8, apdu: &[u8]) -> Vec<u8> {
        let mut m = vec![0x6Fu8];
        m.extend_from_slice(&(apdu.len() as u32).to_le_bytes());
        m.push(0);
        m.push(seq);
        m.extend_from_slice(&[0, 0, 0]);
        m.extend_from_slice(apdu);
        m
    }

    fn enroll(storage: &mut SecureStorage<MockFlashBackend>) {
        let mut req = vec![6u8];
        req.extend_from_slice(b"123456");
        req.extend_from_slice(b"12345678");
        let (st, _) = crate::vendor_exec::exec_vendor_op(
            &mut KeyManager::new(),
            &mut aegis_fido_core::oath::applet::OathApplet::new(),
            storage,
            crate::ble_gatt::OP_PIV_ENROLL,
            &req,
            true,
            false,
            true,
            0,
            &mut rand_core::OsRng,
        );
        assert_eq!(st, 0x00);
    }

    #[test]
    fn ccid_power_select_verify_gen_auth_fim_a_fim() {
        let mut storage = test_storage();
        enroll(&mut storage);
        let mut keys = KeyManager::new();
        let mut t = CcidTransport::new();
        // POWER_ON → ATR.
        let on = [0x62u8, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        let r = process_ccid_frame(&mut t, &on, &mut storage, &mut keys, 0).expect("atr");
        assert_eq!(r[0], 0x80);
        // SELECT PIV.
        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
        let r = process_ccid_frame(&mut t, &xfr(2, &sel), &mut storage, &mut keys, 0).expect("sel");
        assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x90, 0x00));
        // GEN sem VERIFY → 69 82.
        let gen = [0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11];
        let r = process_ccid_frame(&mut t, &xfr(3, &gen), &mut storage, &mut keys, 0).expect("gen");
        assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x69, 0x82));
        // VERIFY ok.
        let mut v = vec![0x00, 0x20, 0x00, 0x80, 0x06];
        v.extend_from_slice(b"123456");
        let r = process_ccid_frame(&mut t, &xfr(4, &v), &mut storage, &mut keys, 0).expect("vfy");
        assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x90, 0x00));
        // GEN agora gera P-256 de verdade (template 7F 49).
        let r = process_ccid_frame(&mut t, &xfr(5, &gen), &mut storage, &mut keys, 1).expect("gen2");
        assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x90, 0x00));
        assert_eq!(&r[10..12], &[0x7F, 0x49]);
        // AUTH com witness → assinatura real (7C{82..}).
        let mut a = vec![0x00, 0x87, 0x11, 0x9A, 0x24, 0x7C, 0x22, 0x81, 0x20];
        a.extend_from_slice(&[0x5Au8; 32]);
        a.push(0x00);
        let r = process_ccid_frame(&mut t, &xfr(6, &a), &mut storage, &mut keys, 1).expect("auth");
        assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x90, 0x00));
        assert_eq!(r[10], 0x7C);
        let _ = &mut sel;
    }

    #[test]
    fn ccid_frame_curto_nao_responde() {
        let mut storage = test_storage();
        let mut keys = KeyManager::new();
        let mut t = CcidTransport::new();
        assert!(process_ccid_frame(&mut t, &[0x6F, 0x00], &mut storage, &mut keys, 0).is_none());
    }
}
