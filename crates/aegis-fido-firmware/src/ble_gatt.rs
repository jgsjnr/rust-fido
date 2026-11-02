//! Wave4 -- GATT 0xFFFD (casca fina de compat; ver `ble`).
//!
//! Conteudo movido para `ble::gatt_core` + `ble::dispatch_bind`
//! sem mudanca de comportamento. Testes `mod tests` ficam aqui.
pub use crate::ble::dispatch_bind::*;
pub use crate::ble::gatt_core::*;
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
use alloc::vec::Vec;

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_fragment(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + payload.len());
        v.push(opcode);
        v.push(((payload.len() >> 8) & 0xFF) as u8);
        v.push((payload.len() & 0xFF) as u8);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn single_fragment_msg_reassembles() {
        let mut s = BleGattServer::new();
        let frag = msg_fragment(OP_MSG, b"hello-ctap");
        let done = s
            .control_write(&frag, true)
            .expect("up ok")
            .expect("completa em 1 frag");
        assert_eq!(done.opcode, OP_MSG);
        assert_eq!(done.payload, b"hello-ctap");
        assert_eq!(s.read_len(), 0);
    }

    #[test]
    fn multi_fragment_msg_reassembles() {
        let mut r = BleReassembler::new();
        // Total 10B: primeiro leva 4B, resto em continuacoes [seq + dados].
        let first = [OP_MSG, 0x00, 0x0A, 1, 2, 3, 4];
        assert!(r.feed(&first).expect("ok").is_none());
        assert_eq!(r.pending_len(), 10);
        let cont = [0x00, 5, 6, 7, 8, 9, 10];
        let done = r.feed(&cont).expect("ok").expect("completa");
        assert_eq!(done.payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn collision_rejected_when_active() {
        let mut r = BleReassembler::new();
        r.start_new(OP_MSG, 10).expect("inicia");
        assert_eq!(r.start_new(OP_MSG, 2), Err(BleGattError::TransactionBusy));
    }

    #[test]
    fn overflow_rejected_by_control_point_length() {
        let mut r = BleReassembler::new();
        assert_eq!(
            r.start_new(OP_MSG, CONTROL_POINT_LENGTH + 1),
            Err(BleGattError::Overflow)
        );
        let big = [OP_MSG, 0xFF, 0xFF];
        assert_eq!(r.feed(&big), Err(BleGattError::Overflow));
    }

    #[test]
    fn up_required_per_operation() {
        let mut s = BleGattServer::new();
        let frag = msg_fragment(OP_PING, b"p");
        assert_eq!(
            s.control_write(&frag, false),
            Err(BleGattError::PresenceRequired)
        );
    }

    #[test]
    fn wallet_ops_live_in_free_range() {
        for op in [OP_WALLET_GEN, OP_WALLET_LIST, OP_WALLET_ADDR] {
            assert!(is_wallet_op(op));
            assert!(!is_vendor_keys_oath_op(op));
            assert!(!is_bind_mgmt_op(op));
            assert_ne!(op, 0x2E);
            assert!(!(0x30..=0x34).contains(&op));
        }
        assert_eq!(
            (OP_WALLET_GEN, OP_WALLET_LIST, OP_WALLET_ADDR),
            (0x35, 0x36, 0x37)
        );
        assert!(!is_wallet_op(0x20));
        assert!(!is_wallet_op(0x2F));
        assert!(!is_wallet_op(0x34));
    }

    #[test]
    fn wallet_gate_order_binding_then_up() {
        // Ordem canônica: binding -> UP (app alheio sempre vê NEED_BINDING).
        // Com test-mode o bypass de vínculo documentado (binding.rs) pula a
        // primeira barreira e o gate cai para UP — mesma ordem, sem vínculo.
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(
                authorize_wallet_op(OP_WALLET_GEN, false, false),
                Err(BleGattError::PresenceRequired)
            );
        } else {
            assert_eq!(
                authorize_wallet_op(OP_WALLET_GEN, false, false),
                Err(BleGattError::NeedBinding)
            );
        }
        assert_eq!(
            authorize_wallet_op(OP_WALLET_LIST, true, false),
            Err(BleGattError::PresenceRequired)
        );
        assert!(authorize_wallet_op(OP_WALLET_ADDR, true, true).is_ok());
        assert_eq!(
            authorize_wallet_op(0x20, true, true),
            Err(BleGattError::InvalidOpcode)
        );
    }

    #[test]
    fn fw_log_gate_bonded_sem_up_nem_pin() {
        // Sem vínculo: NEED_BINDING (0x05) — app alheio não lê o log.
        assert_eq!(
            authorize_fw_log_op(crate::fw_log::OP_FW_LOG, false),
            Err(BleGattError::NeedBinding)
        );
        assert_eq!(
            BleGattError::NeedBinding.to_vendor_status(),
            VENDOR_STATUS_NEED_BINDING
        );
        // Com vínculo: ok direto, sem UP/PIN (diagnóstico sem segredos).
        assert!(authorize_fw_log_op(crate::fw_log::OP_FW_LOG, true).is_ok());
        assert_eq!(
            authorize_fw_log_op(0x37, true),
            Err(BleGattError::InvalidOpcode)
        );
    }

    #[test]
    fn cancel_aborts_and_reports() {
        let mut s = BleGattServer::new();
        let mut r = BleReassembler::new();
        r.start_new(OP_MSG, 10).expect("inicia");
        r.cancel();
        assert!(!r.is_active());
        let done = s
            .control_write(&[OP_CANCEL, 0x00, 0x00], true)
            .expect("cancel ok")
            .expect("retorna msg cancel");
        assert_eq!(done.opcode, OP_CANCEL);
    }

    #[test]
    fn revision_roundtrip() {
        let mut s = BleGattServer::new();
        assert_eq!(s.read_revision(), GATT_REVISION);
        assert!(s.write_revision(GATT_REVISION).is_ok());
        assert!(s.write_revision(0xFF).is_err());
    }

    #[test]
    fn ping_echoes_without_ctap() {
        assert_eq!(BleGattServer::dispatch_ping(b"abc"), b"abc");
    }

    #[test]
    fn fase6_vendor_ops_reservados() {
        assert_eq!(VENDOR_OP_MIN, 0x20);
        assert_eq!(VENDOR_OP_MAX, 0x27);
        for op in [
            OP_KEY_GEN_ONDEVICE,
            OP_KEY_IMPORT_ENVELOPE,
            OP_KEY_LIST,
            OP_KEY_DELETE,
            OP_OATH_PUT,
            OP_OATH_LIST,
            OP_OATH_CODE,
            OP_OATH_DELETE,
        ] {
            assert!(is_vendor_keys_oath_op(op));
            assert!(op != OP_PING && op != OP_MSG && op != OP_CANCEL);
        }
        assert!(!is_vendor_keys_oath_op(OP_PING));
        assert!(!is_vendor_keys_oath_op(OP_MSG));
        assert!(!is_vendor_keys_oath_op(OP_CANCEL));
        assert!(!is_vendor_keys_oath_op(0x1F));
        assert!(!is_vendor_keys_oath_op(0x28));
    }

    #[test]
    fn bind_mgmt_ops_reservados_sem_colisao() {
        // 0x28-0x2D fora de 0x20-0x27 e CTAP-BLE (0x81/0x83/0xBE), revisao intacta.
        for op in [
            OP_BIND_CLAIM,
            OP_BIND_CHALLENGE,
            OP_BIND_VERIFY,
            OP_BIND_RELEASE,
            OP_RECOVERY_SET,
            OP_RECOVERY_UNLOCK,
        ] {
            assert!(is_bind_mgmt_op(op));
            assert!(!is_vendor_keys_oath_op(op));
            assert!(op != OP_PING && op != OP_MSG && op != OP_CANCEL);
        }
        assert_eq!(BIND_MGMT_OP_MIN, 0x28);
        assert_eq!(BIND_MGMT_OP_MAX, 0x2D);
        assert!(!is_bind_mgmt_op(0x20));
        assert!(!is_bind_mgmt_op(0x27));
        assert!(!is_bind_mgmt_op(0x2E));
        assert_eq!(GATT_REVISION, 0x01);
    }

    #[test]
    fn rescue_transport_op_nunca_desvia_para_vendor_ou_fragmento() {
        // Pre-condicao dos ramos rescue (USB-C, serial-D, BLE OP_MSG):
        // 0x2E (RESCUE_TRANSPORT_OP, crates/aegis-fido-core/src/otp/rescue.rs)
        // nao e vendor, nao e bind-mgmt e nao e opcode de fragmento, entao
        // um payload [0x2E, frame...] sempre alcanca o dispatch rescue.
        assert!(!is_vendor_keys_oath_op(0x2E));
        assert!(!is_bind_mgmt_op(0x2E));
        // 0x2E nao abre transacao no reassembler: rescue viaja como
        // payload de OP_MSG, nunca como opcode de fragmento.
        assert_eq!(
            BleReassembler::new().start_new(0x2E, 1),
            Err(BleGattError::InvalidOpcode)
        );
        assert!(!is_usage_op(0x2E));
        assert!(!is_config_op(0x2E));
    }

    #[test]
    fn split_uso_config_no_transporte() {
        // USO nunca exige vinculo; CONFIG exige em release, bypass em teste.
        assert!(is_usage_op(OP_KEY_LIST));
        assert!(is_usage_op(OP_OATH_LIST));
        assert!(is_usage_op(OP_OATH_CODE));
        assert!(!is_usage_op(OP_KEY_GEN_ONDEVICE));
        assert!(is_config_op(OP_KEY_GEN_ONDEVICE));
        assert!(is_config_op(OP_KEY_IMPORT_ENVELOPE));
        assert!(is_config_op(OP_KEY_DELETE));
        assert!(is_config_op(OP_OATH_PUT));
        assert!(is_config_op(OP_OATH_DELETE));
        assert!(!is_config_op(OP_OATH_CODE));
        // USO sem vinculo passa com UP em qualquer modo.
        authorize_vendor_op(OP_OATH_CODE, false, false, true).expect("uso passa");
        authorize_vendor_op(OP_KEY_LIST, false, true, true).expect("uso passa");
        assert_eq!(
            authorize_vendor_op(OP_OATH_CODE, false, false, false),
            Err(BleGattError::PresenceRequired)
        );
        // CONFIG sem vinculo: release nega, teste bypassa.
        if crate::binding::binding_bypass_enabled() {
            authorize_vendor_op(OP_KEY_DELETE, false, true, true).expect("bypass passa");
        } else {
            assert_eq!(
                authorize_vendor_op(OP_KEY_DELETE, false, true, true),
                Err(BleGattError::NeedBinding)
            );
        }
    }

    #[test]
    fn dispatch_claim_challenge_release_roundtrip() {
        use crate::binding::{BindingManager, BIND_ID_LEN, BIND_PUB_LEN};
        use crate::persistence::{MockFlashBackend, SecureStorage};
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let mut m = BindingManager::new();
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("scalar");
        let pt = sk.verifying_key().to_sec1_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        let id = [0xABu8; BIND_ID_LEN];
        // Claim via GATT (Unclaimed+pareamento+UP).
        dispatch_bind_claim(&mut m, &mut st, &sec1, &id, true, true).expect("claim gatt ok");
        assert!(m.is_claimed());
        // Segundo claim nega (dono preservado).
        assert!(dispatch_bind_claim(&mut m, &mut st, &sec1, &id, true, true).is_err());
        // Challenge emite 32B; verify consome (uso unico).
        let ch = dispatch_bind_challenge(&mut m, &st, &mut rand_core::UnwrapErr(getrandom::SysRng)).expect("ch");
        assert!(m.has_active_challenge());
        let ph = [0x11u8; 32];
        let msg = BindingManager::signed_message(&ch, OP_KEY_LIST, &ph);
        let sig = {
            use signature::Signer;
            let s: p256::ecdsa::Signature = sk.sign(&msg);
            s.to_der().as_bytes().to_vec()
        };
        dispatch_bind_verify(&mut m, &sig, &ch, OP_KEY_LIST, &ph).expect("verify gatt ok");
        assert!(!m.has_active_challenge());
        // Release com prova valida faz wipe (re-claim liberado).
        let ch2 = dispatch_bind_challenge(&mut m, &st, &mut rand_core::UnwrapErr(getrandom::SysRng)).expect("ch2");
        let id_hash = {
            use sha2::{Digest, Sha256};
            let d = Sha256::digest(id);
            let mut o = [0u8; 32];
            o.copy_from_slice(&d);
            o
        };
        let msg2 = BindingManager::signed_message(&ch2, crate::binding::BIND_OP_RELEASE, &id_hash);
        let sig2 = {
            use signature::Signer;
            let s: p256::ecdsa::Signature = sk.sign(&msg2);
            s.to_der().as_bytes().to_vec()
        };
        if crate::binding::binding_bypass_enabled() {
            dispatch_bind_release(&mut m, &mut st, &sig2, &ch2, &id_hash, true)
                .expect("release bypass ok");
        } else {
            // Lixo nega e mantem dono.
            assert!(dispatch_bind_release(&mut m, &mut st, b"lixo", &ch2, &id_hash, true).is_err());
            assert!(m.is_claimed());
            dispatch_bind_release(&mut m, &mut st, &sig2, &ch2, &id_hash, true)
                .expect("release ok");
        }
        assert!(!m.is_claimed());
    }

    #[test]
    fn dispatch_recovery_set_unlock_via_gatt() {
        use crate::binding::{BindingManager, BIND_ID_LEN, BIND_PUB_LEN};
        use crate::persistence::{MockFlashBackend, SecureStorage};
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let mut m = BindingManager::new();
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("scalar");
        let pt = sk.verifying_key().to_sec1_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        m.claim(&sec1, &[0xABu8; BIND_ID_LEN], true, true)
            .expect("claim");
        m.persist(&mut st).expect("persist");
        // SET exige UP e PIN valido.
        assert_eq!(
            dispatch_recovery_set(&mut st, "123", true),
            Err(BleGattError::PinRequired)
        );
        dispatch_recovery_set(&mut st, "4242", true).expect("set ok");
        // UNLOCK com PIN errado nao destrava; certo + UP destrava e libera re-claim.
        assert!(dispatch_recovery_unlock(&mut st, &mut m, "0000", true).is_err());
        assert!(m.is_claimed());
        dispatch_recovery_unlock(&mut st, &mut m, "4242", true).expect("unlock ok");
        assert!(!m.is_claimed());
    }

    #[test]
    fn proximity_service_uuid_separate_from_fffd() {
        // Arrange: FIDO 0xFFFD congelado (§1); proximidade isolada.
        // Act/Assert: UUIDs distintos, nunca colidem com FFF1-FFF4.
        assert_ne!(PROXIMITY_SERVICE_UUID, BLE_SERVICE_UUID);
        assert_eq!(BLE_SERVICE_UUID, 0xFFFD);
        assert!(is_fido_service_uuid(0xFFFD));
        assert!(!is_fido_service_uuid(PROXIMITY_SERVICE_UUID));
        assert!(is_proximity_service_uuid(PROXIMITY_SERVICE_UUID));
        assert!(!is_proximity_service_uuid(0xFFFD));
        for ch in [
            CHAR_CONTROL_UUID,
            CHAR_STATUS_UUID,
            CHAR_LEN_UUID,
            CHAR_REVISION_UUID,
        ] {
            assert_ne!(PROXIMITY_SERVICE_UUID, ch);
        }
        assert_eq!(GATT_REVISION, 0x01);
    }

    #[test]
    fn coex_mutually_exclusive_usb_blocks_proximity() {
        // Arrange: BLE-proximidade vs USB/CTAP nunca simultaneo.
        // Act/Assert
        assert!(!proximity_coex_allow(true));
        assert!(proximity_coex_allow(false));
    }

    #[test]
    fn authorize_proximity_ble_order_binding_up_coex() {
        // Arrange: ordem canonica binding -> UP -> coex.
        // Act/Assert: sem bond nega primeiro, mesmo sem UP/coex.
        assert_eq!(
            authorize_proximity_ble(false, false, false),
            Err(BleGattError::NeedBinding)
        );
        assert_eq!(
            authorize_proximity_ble(false, true, true),
            Err(BleGattError::NeedBinding)
        );
        // Act/Assert: bonded sem UP nega presenca.
        assert_eq!(
            authorize_proximity_ble(true, false, false),
            Err(BleGattError::PresenceRequired)
        );
        // Act/Assert: bonded + UP + USB ativo nega coex.
        assert_eq!(
            authorize_proximity_ble(true, true, true),
            Err(BleGattError::CoexBlocked)
        );
        // Act/Assert: tudo ok libera.
        assert_eq!(authorize_proximity_ble(true, true, false), Ok(()));
    }

    #[test]
    fn coex_blocked_maps_to_generic_status() {
        // Arrange: CoexBlocked e falha generica sem retry (§9.6), nunca 0x05.
        // Act/Assert
        assert_eq!(BleGattError::CoexBlocked.to_vendor_status(), 0x04);
        assert_ne!(
            BleGattError::CoexBlocked.to_vendor_status(),
            VENDOR_STATUS_NEED_BINDING
        );
        assert_eq!(
            format!("{}", BleGattError::CoexBlocked),
            "coex blocked (USB active)"
        );
    }
}
