//! Etapa B -- BLE real via NimBLE (casca fina de compat; ver `ble`).
//!
//! Conteudo movido para `ble::nimble_backend` sem mudanca de
//! comportamento. Testes `mod tests` ficam aqui.
pub use crate::ble::nimble_backend::*;
#[cfg(test)]
extern crate alloc;
#[cfg(all(test, feature = "proximity"))]
use crate::ble::gatt_core::BLE_SERVICE_UUID;
#[cfg(test)]
use crate::ble::gatt_core::{BleGattError, BleGattServer, CONTROL_POINT_LENGTH, GATT_REVISION};
#[cfg(test)]
use crate::pairing::{PairingManager, PairingState};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble_gatt::{OP_CANCEL, OP_MSG, OP_PING};

    #[test]
    fn ble_start_gate_borda_tenta_backoff_desiste_e_rearma() {
        let mut g = BleStartGate::new();
        // Mudo: nunca tenta e zera.
        assert!(!g.allow(false, 1000));
        // Borda de subida: tenta de imediato.
        assert!(g.allow(true, 1000));
        g.on_result(false);
        // Backoff: 1s depois, não tenta.
        assert!(!g.allow(true, 2000));
        // Após 5s: tenta (2ª).
        assert!(g.allow(true, 6000));
        g.on_result(false);
        // 3ª após backoff; 4ª nega (desistiu até nova borda).
        assert!(g.allow(true, 11000));
        g.on_result(false);
        assert!(!g.allow(true, 16000));
        assert!(!g.allow(true, 60000));
        // Janela fechou e reabriu: zera e tenta de novo.
        assert!(!g.allow(false, 61000));
        assert!(g.allow(true, 62000));
        // Sucesso zera a contagem: a próxima falha recomeça do zero.
        g.on_result(true);
        assert!(g.allow(true, 67000));
        g.on_result(false);
        assert!(!g.allow(true, 67500)); // backoff, contando de 1
        assert!(g.allow(true, 72000));
    }

    #[test]
    fn rc_519_nao_consome_retry_do_gate() {
        assert_eq!(BLE_ADV_RC_NOMEM, 519);
        let mut g = BleStartGate::new();
        // Borda tenta; 519 (NOMEM residual) nao conta como falha.
        assert!(g.allow(true, 1000));
        g.on_nomem();
        // Backoff de 5 s segue valendo (last_try ja registrado), mas o gate
        // nao esgotou: apos o backoff ainda tenta (fails intacto).
        assert!(!g.allow(true, 2000));
        assert!(g.allow(true, 6000));
        // Duas falhas reais depois: ainda restam tentativas (519 nao gastou).
        g.on_result(false);
        assert!(!g.allow(true, 6500));
        assert!(g.allow(true, 11000));
        g.on_result(false);
        assert!(g.allow(true, 16000));
        g.on_result(false);
        // So agora (3 falhas reais) o gate fecha ate nova borda.
        assert!(!g.allow(true, 21000));
        assert!(!g.allow(false, 22000));
        assert!(g.allow(true, 23000));
    }

    #[test]
    fn adv_payload_carrega_uuid_e_cabe_em_31b() {
        for pairing in [false, true] {
            let p = encode_adv_payload(pairing);
            assert!((p.len as usize) <= ADV_MAX_BYTES);
            let b = p.as_bytes();
            // Flags AD.
            assert_eq!(&b[0..3], &[0x02, 0x01, 0x06]);
            // CompleteList16 com 0xFFFD.
            assert_eq!(&b[3..7], &[0x03, 0x03, 0xFD, 0xFF]);
            // ServiceData16 com 0xFFFD + flag.
            let flag = if pairing {
                ADV_PAIRING_ON
            } else {
                ADV_PAIRING_OFF
            };
            assert_eq!(&b[7..12], &[0x04, 0x16, 0xFD, 0xFF, flag]);
            // Nome completo presente.
            assert!(b.len() > 12);
            assert_eq!(b[12], (BLE_DEVICE_NAME.len() + 1) as u8);
            assert_eq!(b[13], 0x09);
            assert_eq!(
                &b[14..14 + BLE_DEVICE_NAME.len()],
                BLE_DEVICE_NAME.as_bytes()
            );
        }
    }

    #[test]
    fn flag_pareamento_so_com_janela_aberta() {
        let off = encode_adv_payload(false);
        let on = encode_adv_payload(true);
        // Só o byte de flag difere.
        let bo = off.as_bytes();
        let bn = on.as_bytes();
        assert_eq!(bo.len(), bn.len());
        let mut diffs = 0;
        for (x, y) in bo.iter().zip(bn.iter()) {
            if x != y {
                diffs += 1;
                assert_eq!((*x, *y), (ADV_PAIRING_OFF, ADV_PAIRING_ON));
            }
        }
        assert_eq!(diffs, 1);
    }

    #[test]
    fn so_anuncia_em_pairing_ble_com_janela_aberta() {
        use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
        let mut m = PairingManager::new();
        // Idle/Arming: mudo.
        assert!(!should_advertise(&m, 0));
        m.on_button_level(true, 0);
        assert!(!should_advertise(&m, LONG_PRESS_MS - 1));
        // Entrou em PairingBle: anuncia.
        m.on_button_level(true, LONG_PRESS_MS);
        assert!(should_advertise(&m, LONG_PRESS_MS + 1));
        // Janela expirada: mudo.
        m.tick(LONG_PRESS_MS + PAIRING_WINDOW_MS);
        assert!(!should_advertise(&m, LONG_PRESS_MS + PAIRING_WINDOW_MS));
        // AP: mudo (BLE cede o rádio ao WiFi).
        let mut m2 = PairingManager::new();
        m2.on_button_level(true, 0);
        m2.on_button_level(true, LONG_PRESS_MS);
        m2.enter_ap_mode();
        assert!(m2.is_pairing_window_open(LONG_PRESS_MS + 10));
        assert!(!should_advertise(&m2, LONG_PRESS_MS + 10));
    }

    #[test]
    fn reconnect_sem_janela_so_com_confianca() {
        use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
        // Novo/sem vínculo: mudo (privacidade preservada).
        let m = PairingManager::new();
        assert!(!should_advertise_reconnect(m.state(), false));
        // Pareado na sessão: anuncia em Idle mesmo sem janela.
        let mut b = PairingManager::new();
        b.on_button_level(true, 0);
        b.on_button_level(true, LONG_PRESS_MS);
        assert!(b.complete_pairing(true, LONG_PRESS_MS + 10));
        assert!(b.is_bonded());
        assert_eq!(b.state(), PairingState::Idle);
        assert!(!should_advertise(
            &b,
            LONG_PRESS_MS + 10 + PAIRING_WINDOW_MS
        ));
        assert!(should_advertise_reconnect(b.state(), true));
        // Fora de Idle (ex.: Locked): sem anúncio de reconexão.
        b.lock();
        assert!(!should_advertise_reconnect(b.state(), true));
    }

    #[test]
    fn intervalo_lento_quando_wifi_ativo() {
        assert_eq!(
            adv_intervals(false),
            (ADV_ITVL_NORMAL_MIN, ADV_ITVL_NORMAL_MAX)
        );
        assert_eq!(adv_intervals(true), (ADV_ITVL_COEX_MIN, ADV_ITVL_COEX_MAX));
        // Coex lento de verdade (cede airtime): min lento > max normal.
        // Intentional spec guard on frozen constants (clippy::assertions_on_constants).
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(ADV_ITVL_COEX_MIN > ADV_ITVL_NORMAL_MAX);
        }
    }

    #[test]
    fn notify_frame_layout_e_teto() {
        let f = notify_frame(OP_PING, 0x00, b"abc");
        assert_eq!(f, [OP_PING, 0x00, b'a', b'b', b'c']);
        // §3B fail-closed: excedente vira [op, 0x04] sem vazar prefixo truncado.
        let big = alloc::vec![0xAAu8; CONTROL_POINT_LENGTH + 100];
        let f2 = notify_frame(OP_MSG, 0x04, &big);
        assert_eq!(f2, [OP_MSG, 0x04]);
        // Teto exato ainda passa intacto.
        let exact = alloc::vec![0xBBu8; CONTROL_POINT_LENGTH];
        let f3 = notify_frame(OP_MSG, 0x00, &exact);
        assert_eq!(f3.len(), 2 + CONTROL_POINT_LENGTH);
        assert_eq!((f3[0], f3[1]), (OP_MSG, 0x00));
        assert_eq!(&f3[2..], &exact[..]);
    }

    #[test]
    fn glue_repassa_fragmento_e_len() {
        let mut s = BleGattServer::new();
        // Sem UP: nega (UP por operação preservado).
        let frag = [OP_PING, 0x00, 0x01, 0x42];
        assert_eq!(
            feed_control_write(&mut s, &frag, false),
            Err(BleGattError::PresenceRequired)
        );
        // Com UP: completa PING de 1B.
        let done = feed_control_write(&mut s, &frag, true)
            .expect("up ok")
            .expect("completa");
        assert_eq!(done.opcode, OP_PING);
        assert_eq!(done.payload, [0x42]);
        assert_eq!(pending_len(&s), 0);
        assert_eq!(expected_revision(), GATT_REVISION);
    }

    #[test]
    fn glue_rejeita_fragmento_vazio_ou_grande() {
        let mut s = BleGattServer::new();
        assert_eq!(
            feed_control_write(&mut s, &[], true),
            Err(BleGattError::InvalidFragment)
        );
        let big = alloc::vec![0u8; BLE_RX_FRAGMENT_MAX + 1];
        assert_eq!(
            feed_control_write(&mut s, &big, true),
            Err(BleGattError::InvalidFragment)
        );
    }

    #[test]
    fn cancel_via_glue_aborta() {
        let mut s = BleGattServer::new();
        let done = feed_control_write(&mut s, &[OP_CANCEL, 0x00, 0x00], true)
            .expect("cancel ok")
            .expect("retorna cancel");
        assert_eq!(done.opcode, OP_CANCEL);
        assert!(done.payload.is_empty());
    }

    #[test]
    fn link_seguro_exige_janela_e_up() {
        use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
        let mut m = PairingManager::new();
        // Fora da janela: nega (mesmo com UP).
        assert_eq!(
            on_link_secured(&mut m, true, 0),
            BondOutcome::DeniedNoWindow
        );
        assert!(!m.is_bonded());
        // Na janela sem UP: nega, mantém advertising.
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        assert_eq!(
            on_link_secured(&mut m, false, LONG_PRESS_MS + 10),
            BondOutcome::DeniedNoPresence
        );
        assert!(!m.is_bonded());
        assert!(should_advertise(&m, LONG_PRESS_MS + 10));
        // Janela + UP: pareado, sai do modo (advertising para no main).
        assert_eq!(
            on_link_secured(&mut m, true, LONG_PRESS_MS + 20),
            BondOutcome::Paired
        );
        assert!(m.is_bonded());
        assert_eq!(m.state(), PairingState::Idle);
        assert!(!should_advertise(&m, LONG_PRESS_MS + 20));
        // Corrida com timeout: nega.
        let mut m2 = PairingManager::new();
        m2.on_button_level(true, 0);
        m2.on_button_level(true, LONG_PRESS_MS);
        assert_eq!(
            on_link_secured(&mut m2, true, LONG_PRESS_MS + PAIRING_WINDOW_MS),
            BondOutcome::DeniedNoWindow
        );
    }

    #[test]
    fn host_shims_inertes() {
        assert!(esp_ble_start(true, false) < 0);
        assert!(esp_ble_stop() < 0);
        assert_eq!(esp_ble_poll_event(), BLE_EVT_NONE);
        let mut b = [0u8; 8];
        assert!(esp_ble_fetch_rx(&mut b) < 0);
        assert!(esp_ble_notify(&[1, 2, 3]) < 0);
        esp_ble_set_pending_len(7);
        assert!(!esp_ble_conn_active());
    }

    #[test]
    fn sm_policy_requires_mitm_sc_bonding_no_justworks_fallback() {
        // F-01: espelho host-testavel da config NimBLE (sm_mitm/sc/bonding).
        // Intentional spec guard on frozen constants (clippy::assertions_on_constants).
        #[allow(clippy::assertions_on_constants)]
        {
        assert!(BLE_SM_MITM_REQUIRED);
        assert!(BLE_SM_SC_REQUIRED);
        assert!(BLE_SM_BONDING_REQUIRED);
        // Sem fallback JustWorks: as tres garantias andam juntas.
        assert!(BLE_SM_MITM_REQUIRED && BLE_SM_SC_REQUIRED && BLE_SM_BONDING_REQUIRED);
        // Texto de re-pareamento (one-way, owner-authorized) presente.
        let notice = mitm_repair_notice();
        assert!(notice.contains("MITM"));
        assert!(notice.contains("Re-pareie"));
        assert!(notice.contains("60 s"));
        }
    }
}

#[cfg(all(test, feature = "proximity"))]
mod proximity_tests {
    use super::*;
    use crate::ble_gatt::PROXIMITY_SERVICE_UUID;
    use crate::proximity::{
        encode_proximity_svc_data, proximity_adv_allowed, proximity_tag,
        PROXIMITY_BEACON_SVC_UUID16, PROXIMITY_BEACON_TAG_LEN, PROXIMITY_BEACON_VERSION,
    };

    fn tag_for(ctr: u32) -> [u8; PROXIMITY_BEACON_TAG_LEN] {
        proximity_tag(
            &[0x42u8; 16],
            PROXIMITY_BEACON_VERSION,
            ctr,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        )
    }

    #[test]
    fn presence_uuid_is_fffe_separate_from_gatt_fffd() {
        assert_eq!(PROXIMITY_SERVICE_UUID, 0xFFFE);
        assert_eq!(PROXIMITY_BEACON_SVC_UUID16, 0xFFFE);
        assert_eq!(BLE_SERVICE_UUID, 0xFFFD);
        assert!(crate::ble_gatt::is_proximity_service_uuid(
            PROXIMITY_BEACON_SVC_UUID16
        ));
        assert!(!crate::ble_gatt::is_proximity_service_uuid(0xFFFD));
    }

    #[test]
    fn presence_adv_layout_is_30b_with_fffe_svc_data_and_name() {
        let ctr = 0x01020304u32;
        let tag = tag_for(ctr);
        let p = encode_proximity_adv_payload(ctr, &tag);
        assert_eq!(p.len as usize, PROXIMITY_ADV_TOTAL_LEN);
        assert_eq!(p.len as usize, 30);
        let b = p.as_bytes();
        assert_eq!(&b[0..3], &[0x02, 0x01, 0x06]);
        assert_eq!(&b[3..7], &[0x03, 0x03, 0xFE, 0xFF]);
        assert_eq!(b[7], 0x0C);
        assert_eq!(b[8], 0x16);
        assert_eq!(&b[9..20], &encode_proximity_svc_data(ctr, &tag));
        assert_eq!(&b[9..11], &[0xFE, 0xFF]);
        assert_eq!(b[11], PROXIMITY_BEACON_VERSION);
        assert_eq!(&b[12..16], &ctr.to_le_bytes());
        assert_eq!(&b[16..20], &tag);
        assert_eq!(b[20], (BLE_DEVICE_NAME.len() + 1) as u8);
        assert_eq!(b[21], 0x09);
        assert_eq!(
            &b[22..22 + BLE_DEVICE_NAME.len()],
            BLE_DEVICE_NAME.as_bytes()
        );
    }

    #[test]
    fn presence_adv_needs_bonded_idle_trusted_no_usb_and_key() {
        use crate::pairing::PairingState;
        assert!(should_adv_proximity(
            PairingState::Idle,
            true,
            true,
            false,
            true
        ));
        assert!(!should_adv_proximity(
            PairingState::Idle,
            false,
            true,
            false,
            true
        ));
        assert!(!should_adv_proximity(
            PairingState::Locked,
            true,
            true,
            false,
            true
        ));
        assert!(!should_adv_proximity(
            PairingState::Idle,
            true,
            false,
            false,
            true
        ));
        assert!(!should_adv_proximity(
            PairingState::Idle,
            true,
            true,
            true,
            true
        ));
        assert!(!should_adv_proximity(
            PairingState::Idle,
            true,
            true,
            false,
            false
        ));
        assert_eq!(
            should_adv_proximity(PairingState::Idle, true, true, false, true),
            proximity_adv_allowed(true, true, true, false, true)
        );
    }

    #[test]
    fn presence_intervals_follow_wifi_coex() {
        assert_eq!(proximity_adv_intervals(false), adv_intervals(false));
        assert_eq!(proximity_adv_intervals(true), adv_intervals(true));
        assert_ne!(
            proximity_adv_intervals(false),
            proximity_adv_intervals(true)
        );
    }

    #[test]
    fn presence_shim_is_inert_on_host() {
        let tag = tag_for(9);
        let svc = encode_proximity_svc_data(9, &tag);
        assert_eq!(svc.len(), 11);
        assert_eq!(esp_ble_proximity_start(&svc, false), 0);
        assert_eq!(esp_ble_proximity_start(&svc, true), 0);
    }
}
