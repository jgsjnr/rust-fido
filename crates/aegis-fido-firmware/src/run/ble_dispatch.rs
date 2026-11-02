//! BLE complete-message dispatcher (D1 split from `run`, single owner).
//!
//! - `ble_dispatch_complete`: 1 mensagem GATT completa -> notify via FFF2
//!   (PING/CANCEL/MSG/rescue/bind/vendor/wallet/fw-log; thin composition).
//! - `extract_rp_and_user`: display names p/ registro/assertion (sem segredo).
//!
//! Contract (R15/R16): move-only de `run.rs`; fio byte-a-byte; tempo via
//! args; sem segredo em log; `kprintln!` herdado de `super` (run).
use crate::persistence::{PlatformFlashBackend, SecureStorage};
use aegis_fido_core::ctap::{CtapEngine, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL};
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::otp::rescue::{RescueEngine, RESCUE_TRANSPORT_OP};
use aegis_fido_core::wallet::WalletStore;

/// Etapa B — despacha 1 mensagem GATT completa e notifica via FFF2.
///
/// PING ecoa; CANCEL confirma vazio; MSG delega ao `CtapEngine` (mesmo
/// `[cmd, CBOR...]` do `CMD_CBOR` USB); bind-mgmt `0x28-0x2D` usa os helpers
/// de `ble_gatt` (gates binding -> UP -> PIN preservados); vendor `0x20-0x27`
/// executa de verdade via `vendor_exec` (GEN/LIST/DELETE + OATH, NVS;
/// IMPORT segue 0x04 = F2b). USB/CTAP intactos.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(feature = "freertos", allow(dead_code))]
pub(crate) fn ble_dispatch_complete(
    msg: crate::ble_gatt::BleCompleteMessage,
    up: bool,
    pairing_window_open: bool,
    now_secs: u64,
    ctap_engine: &mut CtapEngine,
    binding_mgr: &mut crate::binding::BindingManager,
    storage: &mut SecureStorage<PlatformFlashBackend>,
    rescue: &mut RescueEngine,
    wallet: &mut WalletStore,
    bonded: bool,
    now_ms: u64,
    fwlog: &mut crate::fw_log::FwLog,
    key_mgr: &mut aegis_fido_core::credential::key_manager::KeyManager,
    oath_applet: &mut OathApplet,
    secure_guard: &mut aegis_fido_core::secure_guard::SecureGuardEngine,
) {
    use crate::binding::{BIND_CHALLENGE_LEN, BIND_ID_LEN, BIND_PUB_LEN};
    use crate::ble_gatt as g;
    use crate::ble_nimble as ble;
    use crate::fw_log as fl;
    use crate::wallet_exec as w;

    let op = msg.opcode;
    let p = &msg.payload;
    // Log real do device: toda op recebida + UP quando presente.
    fwlog.record(fl::EV_OP_RX, op, now_ms);
    if up {
        fwlog.record(fl::EV_UP_OK, op, now_ms);
    }
    let frame: Vec<u8> = match op {
        g::OP_PING => ble::notify_frame(op, 0x00, &g::BleGattServer::dispatch_ping(p)),
        g::OP_CANCEL => ble::notify_frame(op, 0x00, &[]),
        g::OP_MSG => {
            // Rescue Wave2 Step3: OP_MSG com primeiro byte 0x2E carrega
            // um frame rescue (reassemble/framing intactos). UP do
            // latch + PIN via plumbing ClientPIN (fail-closed sem sessão).
            if p.first() == Some(&RESCUE_TRANSPORT_OP) {
                rescue.set_user_presence(up);
                // Plumbing ClientPIN: sessão pinUvAuth viva prova PIN
                // verificado (fail-closed sem ela).
                rescue.set_pin_uv_authenticated(ctap_engine.pin_state.has_valid_pin_uv_session());
                let (st, body) = crate::serial_ctaphid::dispatch_serial_rescue(rescue, &p[1..]);
                kprintln!("[BLE] rescue 0x2E (status 0x{:02X}).", st);
                ble::notify_frame(op, st, &body)
            } else {
                ctap_engine.set_user_presence(up);
                let mut rng = rand_core::OsRng;
                let resp = ctap_engine.process_packet(p, now_secs, &mut rng);
                // F3: ClientPIN (0x06) mudou estado? Persiste hash+retries.
                if p.first() == Some(&0x06)
                    && !crate::vendor_exec::save_pin_state(storage, &ctap_engine.pin_state)
                {
                    kprintln!("[WARN] NVS pin save falhou (BLE).");
                }
                ble::notify_frame(op, 0x00, &resp)
            }
        }
        g::OP_BIND_CLAIM => {
            if p.len() != BIND_PUB_LEN + BIND_ID_LEN {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let mut app_pub = [0u8; BIND_PUB_LEN];
                let mut binding_id = [0u8; BIND_ID_LEN];
                app_pub.copy_from_slice(&p[..BIND_PUB_LEN]);
                binding_id.copy_from_slice(&p[BIND_PUB_LEN..]);
                match g::dispatch_bind_claim(
                    binding_mgr,
                    storage,
                    &app_pub,
                    &binding_id,
                    pairing_window_open,
                    up,
                ) {
                    Ok(()) => ble::notify_frame(op, 0x00, &binding_id),
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_BIND_CHALLENGE => {
            if !p.is_empty() {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let mut rng = rand_core::OsRng;
                match g::dispatch_bind_challenge(binding_mgr, storage, &mut rng) {
                    Ok(ch) => ble::notify_frame(op, 0x00, &ch),
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_BIND_VERIFY => {
            if p.len() < 1 + BIND_CHALLENGE_LEN + 32 {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let vop = p[0];
                let mut ch = [0u8; BIND_CHALLENGE_LEN];
                let mut ph = [0u8; 32];
                ch.copy_from_slice(&p[1..1 + BIND_CHALLENGE_LEN]);
                ph.copy_from_slice(&p[1 + BIND_CHALLENGE_LEN..1 + BIND_CHALLENGE_LEN + 32]);
                match g::dispatch_bind_verify(binding_mgr, &p[65..], &ch, vop, &ph) {
                    Ok(()) => ble::notify_frame(op, 0x00, &[]),
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_BIND_RELEASE => {
            if p.len() < BIND_CHALLENGE_LEN + 32 {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let mut ch = [0u8; BIND_CHALLENGE_LEN];
                let mut ph = [0u8; 32];
                ch.copy_from_slice(&p[..BIND_CHALLENGE_LEN]);
                ph.copy_from_slice(&p[BIND_CHALLENGE_LEN..BIND_CHALLENGE_LEN + 32]);
                match g::dispatch_bind_release(
                    binding_mgr,
                    storage,
                    &p[BIND_CHALLENGE_LEN + 32..],
                    &ch,
                    &ph,
                    up,
                ) {
                    Ok(()) => {
                        // Wave2 proximidade: release revoga o K_prox
                        // (fail-closed; o loop limpa o cache RAM ao ver a NVS
                        // vazia). Nunca auto-unlock.
                        #[cfg(feature = "proximity")]
                        let _ = crate::proximity::delete_proximity_key(storage);
                        ble::notify_frame(op, 0x00, &[])
                    }
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_RECOVERY_SET => match core::str::from_utf8(p) {
            Ok(pin) => match g::dispatch_recovery_set(storage, pin, up) {
                Ok(()) => ble::notify_frame(op, 0x00, &[]),
                Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
            },
            Err(_) => {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            }
        },
        g::OP_RECOVERY_UNLOCK => match core::str::from_utf8(p) {
            Ok(pin) => match g::dispatch_recovery_unlock(storage, binding_mgr, pin, up) {
                Ok(()) => {
                    // Wave2 proximidade: recovery revoga o K_prox
                    // (fail-closed; o loop limpa o cache RAM ao ver a NVS
                    // vazia). Nunca auto-unlock.
                    #[cfg(feature = "proximity")]
                    let _ = crate::proximity::delete_proximity_key(storage);
                    ble::notify_frame(op, 0x00, &[])
                }
                Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
            },
            Err(_) => {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            }
        },
        o if g::is_vendor_keys_oath_op(o) || g::is_piv_enroll_op(o) => {
            // F2: executor real on-device (GEN/LIST/DELETE + OATH
            // PUT/LIST/CODE/DELETE, NVS persistente); IMPORT segue 0x04
            // (envelope AEGN + vault = F2b). F4: 0x39 enrollment PIV
            // (binding -> UP, sem PIN). Gates §9.4 intactos.
            let pin_ok = ctap_engine.pin_state.has_valid_pin_uv_session() || secure_guard.is_unlocked();
            let effective_claimed = binding_mgr.is_claimed() || secure_guard.is_unlocked();
            let effective_up = up || secure_guard.is_unlocked();
            let mut rng = rand_core::OsRng;
            let (st, body) = crate::vendor_exec::exec_vendor_op(
                key_mgr,
                oath_applet,
                storage,
                o,
                p,
                effective_claimed,
                pin_ok,
                effective_up,
                now_secs,
                &mut rng,
            );
            if st == 0x00 {
                kprintln!("[BLE] op vendor 0x{:02X} executada.", o);
            }
            ble::notify_frame(o, st, &body)
        }
        o if g::is_wallet_op(o) => {
            // Carteira Fase7 (R-07): binding + UP já aprovados; executa de
            // verdade no WalletStore de sessão (chaves TRNG no device).
            let effective_claimed = binding_mgr.is_claimed() || secure_guard.is_unlocked();
            let effective_up = up || secure_guard.is_unlocked();
            match g::authorize_wallet_op(o, effective_claimed, effective_up) {
                Ok(()) => {
                    let mut rng = rand_core::OsRng;
                    let (st, body) = match o {
                        g::OP_WALLET_GEN => w::wallet_gen(wallet, p, now_secs, true, &mut rng),
                        g::OP_WALLET_LIST => w::wallet_list(wallet, true),
                        g::OP_WALLET_ADDR => w::wallet_addr(wallet, p, true),
                        _ => (0x04, Vec::new()),
                    };
                    kprintln!(
                        "[BLE] op wallet 0x{:02X} executada (status 0x{:02X}).",
                        o,
                        st
                    );
                    ble::notify_frame(o, st, &body)
                }
                Err(e) => ble::notify_frame(o, e.to_vendor_status(), &[]),
            }
        }
        o if g::is_secure_guard_op(o) => {
            let mut rng = rand_core::OsRng;
            let (st, body) = crate::secure_guard_exec::exec_secure_guard_op(
                secure_guard,
                storage,
                wallet,
                key_mgr,
                oath_applet,
                o,
                p,
                now_ms,
                &mut rng,
            );
            kprintln!(
                "[BLE] op secure_guard 0x{:02X} executada (status 0x{:02X}).",
                o,
                st
            );
            ble::notify_frame(o, st, &body)
        }
        o if fl::is_fw_log_op(o) => {
            // Log da firmware (0x38): leitura sem segredos; BLE exige
            // vínculo (0x05 sem ele), nunca UP/PIN.
            match g::authorize_fw_log_op(o, bonded) {
                Ok(()) => {
                    let body = fwlog.render_ascii(fl::FW_LOG_MAX_BYTES);
                    kprintln!("[BLE] fw-log 0x38 ({} B).", body.len());
                    ble::notify_frame(o, 0x00, &body)
                }
                Err(e) => ble::notify_frame(o, e.to_vendor_status(), &[]),
            }
        }
        _ => ble::notify_frame(op, 0x04, &[]),
    };
    // Status respondido entra no log (frame = [op, status, ...]).
    if frame.len() >= 2 {
        fwlog.record(fl::EV_OP_RESP, frame[1], now_ms);
    }
    let _ = ble::esp_ble_notify(&frame);
}

#[allow(dead_code)]
pub(crate) fn extract_rp_and_user(cmd: u8, payload: &[u8]) -> (String, String, &'static str) {
    if payload.len() <= 1 {
        return ("Autenticador".into(), "Chave FIDO2".into(), "Autenticação");
    }
    let cbor_bytes = &payload[1..];
    if let Ok(map) = aegis_fido_core::ctap::cbor::decode_cbor_map(cbor_bytes) {
        if cmd == CTAP_CMD_MAKE_CREDENTIAL {
            let mut rp_id = String::from("localhost");
            let mut user_name = String::from("Passkey");
            if let Some(ciborium::value::Value::Map(rp_map)) =
                aegis_fido_core::ctap::cbor::get_int_key(&map, 2)
            {
                for (k, v) in rp_map {
                    if let (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) =
                        (k, v)
                    {
                        if key == "id" {
                            rp_id = val.clone();
                        }
                    }
                }
            }
            if let Some(ciborium::value::Value::Map(user_map)) =
                aegis_fido_core::ctap::cbor::get_int_key(&map, 3)
            {
                for (k, v) in user_map {
                    if let (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) =
                        (k, v)
                    {
                        if key == "name" || key == "displayName" {
                            user_name = val.clone();
                        }
                    }
                }
            }
            return (rp_id, user_name, "Registro de Passkey");
        } else if cmd == CTAP_CMD_GET_ASSERTION {
            let mut rp_id = String::from("localhost");
            if let Some(ciborium::value::Value::Text(s)) =
                aegis_fido_core::ctap::cbor::get_int_key(&map, 1)
            {
                rp_id = s.clone();
            }
            return (rp_id, "Credencial Residente".into(), "Autenticação FIDO2");
        }
    }
    ("WebAuthn".into(), "Chave FIDO2".into(), "Autorização FIDO2")
}
