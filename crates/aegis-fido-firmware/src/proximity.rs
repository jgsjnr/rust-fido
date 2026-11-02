//! Proximity NVS owner + compat shell (see `proximity::monitor`).
//! Monitor/beacon/gates moved to `proximity::monitor` verbatim (no behavior
//! change). `prox_k` NVS (save/load/delete/rekey) single owner stays here,
//! plus the FreeRTOS tick/gap shims. Tests stay here (`super::*` over the
//! re-export below).
pub mod monitor;
pub use self::monitor::*;
use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};

/// Chave NVS do K_prox (no maximo 15 chars; envelope AEGN via SecureStorage).
pub const PROXIMITY_BOND_NVS_KEY: &str = "prox_k";

/// Gera um K_prox aleatorio de 128 b (TRNG do chamador; zeroize apos salvar).
pub fn generate_proximity_key<R: rand_core::Rng>(rng: &mut R) -> [u8; PROXIMITY_KEY_LEN] {
    let mut key = [0u8; PROXIMITY_KEY_LEN];
    rng.fill_bytes(&mut key);
    key
}

/// Persiste o K_prox em NVS cifrada (envelope AEGN via SecureStorage).
///
/// A copia em RAM continua com o chamador: zeroize apos o uso.
pub fn save_proximity_key<B: FlashStorageBackend, R: rand_core::CryptoRng>(
    storage: &mut SecureStorage<B>,
    key: &[u8; PROXIMITY_KEY_LEN],
    rng: &mut R,
) -> Result<(), StorageError> {
    storage.store_with_rng(PROXIMITY_BOND_NVS_KEY, key, rng)
}

/// Carrega o K_prox da NVS cifrada (tamanho diferente de 16 B = corrompido).
pub fn load_proximity_key<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<[u8; PROXIMITY_KEY_LEN], StorageError> {
    let raw = storage.load(PROXIMITY_BOND_NVS_KEY)?;
    if raw.len() != PROXIMITY_KEY_LEN {
        return Err(StorageError::CorruptedEnvelope);
    }
    let mut key = [0u8; PROXIMITY_KEY_LEN];
    key.copy_from_slice(&raw);
    Ok(key)
}

/// Apaga o K_prox (release, recovery ou antes do rekey).
pub fn delete_proximity_key<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), StorageError> {
    storage.delete(PROXIMITY_BOND_NVS_KEY)
}

/// Rekey: gera e persiste um K_prox novo (chamar em release, recovery e
/// apos rollover; fiar apos BondOutcome::Paired no main.rs).
pub fn rekey_proximity<B: FlashStorageBackend, R: rand_core::CryptoRng>(
    storage: &mut SecureStorage<B>,
    rng: &mut R,
) -> Result<[u8; PROXIMITY_KEY_LEN], StorageError> {
    let key = generate_proximity_key(rng);
    save_proximity_key(storage, &key, rng)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Arrange
    fn monitor() -> ProximityMonitor {
        ProximityMonitor::new(ProximityConfig::default())
    }

    #[test]
    fn should_lock_away_when_weak_for_10s() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(Some(-80), 10);
        // Assert
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_not_lock_before_10s() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(Some(-80), 9);
        // Assert
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_hold_away_inside_hysteresis_band() {
        // Arrange: -75 threshold, histerese 5 => banda [-75, -70)
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        let st = m.update(Some(-72), 5);
        // Assert: anti-flap, continua Away
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_never_auto_unlock_from_locked_on_good_rssi() {
        // Arrange
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        m.confirm_lock();
        let st = m.update(Some(-50), 30);
        // Assert
        assert_eq!(st, ProximityState::Locked);
    }

    #[test]
    fn should_return_to_near_above_threshold_plus_hysteresis() {
        // Arrange: Away apos 10 s fraco
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        let st = m.update(Some(-65), 1);
        // Assert: -65 >= -75 + 5 (-70) => Near
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_need_confirm_to_reach_locked() {
        // Arrange
        let mut m = monitor();
        // Act: fraco por muito tempo nunca trava sozinho
        let st = m.update(Some(-80), 60);
        // Assert
        assert_eq!(st, ProximityState::Away);
        // Act: confirmacao leva a Locked
        let st = m.confirm_lock();
        // Assert
        assert_eq!(st, ProximityState::Locked);
    }

    #[test]
    fn should_unlock_only_with_presence_and_pin() {
        // Arrange
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        m.confirm_lock();
        // Assert: sem PIN nao destrava
        assert!(!m.unlock(true, false));
        assert_eq!(m.state(), ProximityState::Locked);
        // Assert: sem presenca nao destrava
        assert!(!m.unlock(false, true));
        assert_eq!(m.state(), ProximityState::Locked);
        // Act: presenca + PIN destrava para Near
        // Assert
        assert!(m.unlock(true, true));
        assert_eq!(m.state(), ProximityState::Near);
    }

    #[test]
    fn should_treat_missing_sample_as_weak() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(None, 10);
        // Assert
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_clamp_huge_elapsed_to_60s() {
        // Arrange: 1 s acumulado, depois amostra gigante com sinal fraco
        let mut m = monitor();
        m.update(Some(-80), 1);
        // Act: u32::MAX deve clampar para 60 s, nao estourar o acumulado
        let st = m.update(Some(-80), u32::MAX);
        // Assert: ainda trava (1 + 60 >= 10) mas sem overflow/panico
        assert_eq!(st, ProximityState::Away);
        // Act: sinal bom reseta normalmente apos o clamp
        let st = m.update(Some(-65), 1);
        // Assert
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_match_canonical_lock_policy_consts() {
        // Arrange: decisao congelada (lock < -75 dBm por 10 s, histerese 5 dB).
        // Act/Assert: consts canonicas + default em sync.
        assert_eq!(PROXIMITY_LOCK_RSSI_DBM, -75);
        assert_eq!(PROXIMITY_LOCK_SECS, 10);
        assert_eq!(PROXIMITY_HYSTERESIS_DB, 5);
        let d = ProximityConfig::default();
        assert_eq!(d.lock_rssi_dbm, PROXIMITY_LOCK_RSSI_DBM);
        assert_eq!(d.lock_secs, PROXIMITY_LOCK_SECS);
        assert_eq!(d.hysteresis_db, PROXIMITY_HYSTERESIS_DB);
    }

    #[test]
    fn should_block_proximity_when_usb_active_mutual_exclusion() {
        // Arrange: coexistencia mutuamente exclusiva (USB tem prioridade total).
        // Act/Assert
        assert!(!coex_proximity_allowed(true));
        assert!(coex_proximity_allowed(false));
    }

    #[test]
    fn should_require_bonding_for_proximity_sample() {
        // Arrange: bonding obrigatorio (JustWorks+bonding+UP).
        // Act/Assert
        assert!(bonding_required());
        assert!(authorize_proximity_sample(true, false));
        assert!(!authorize_proximity_sample(false, false));
        assert!(!authorize_proximity_sample(true, true));
        assert!(!authorize_proximity_sample(false, true));
    }

    #[test]
    fn should_treat_denied_sample_as_weak_fail_closed() {
        // Arrange: gate nega amostra sem bond.
        let mut m = monitor();
        // Act: chamador alimenta None (fraco) quando o gate nega.
        assert!(!authorize_proximity_sample(false, false));
        let st = m.update(None, 10);
        // Assert: fail-closed, trava para Away.
        assert_eq!(st, ProximityState::Away);
    }
}

#[cfg(test)]
mod rolling_tests {
    use super::*;
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use rand::SeedableRng;

    fn test_key() -> [u8; PROXIMITY_KEY_LEN] {
        [0x42u8; PROXIMITY_KEY_LEN]
    }

    fn test_fob() -> [u8; PROXIMITY_FOB_ID_LEN] {
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    }

    fn beacon_data(ctr: u32, tag: &[u8; PROXIMITY_BEACON_TAG_LEN]) -> [u8; 9] {
        let mut d = [0u8; 9];
        d[0] = PROXIMITY_BEACON_VERSION;
        d[1..5].copy_from_slice(&ctr.to_le_bytes());
        d[5..9].copy_from_slice(tag);
        d
    }

    fn storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn should_encode_svc_data_as_uuid_ver_ctr_tag() {
        let tag = [0x01, 0x02, 0x03, 0x04];
        let svc = encode_proximity_svc_data(0x01020304, &tag);
        assert_eq!(svc.len(), PROXIMITY_BEACON_SVC_DATA_LEN);
        assert_eq!(&svc[0..2], &[0xFE, 0xFF]);
        assert_eq!(svc[2], PROXIMITY_BEACON_VERSION);
        assert_eq!(&svc[3..7], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&svc[7..11], &tag);
    }

    #[test]
    fn should_bind_tag_to_key_ver_ctr_and_fob() {
        let key = test_key();
        let fob = test_fob();
        let good = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob);
        assert!(verify_proximity_tag(
            &key,
            PROXIMITY_BEACON_VERSION,
            7,
            &fob,
            &good
        ));
        let mut other = key;
        other[0] ^= 0xFF;
        assert!(!verify_proximity_tag(
            &other,
            PROXIMITY_BEACON_VERSION,
            7,
            &fob,
            &good
        ));
        assert!(!verify_proximity_tag(
            &key,
            PROXIMITY_BEACON_VERSION,
            8,
            &fob,
            &good
        ));
        let mut fob2 = fob;
        fob2[5] ^= 0x01;
        assert!(!verify_proximity_tag(
            &key,
            PROXIMITY_BEACON_VERSION,
            7,
            &fob2,
            &good
        ));
        let mut bad = good;
        bad[3] ^= 0x80;
        assert!(!verify_proximity_tag(
            &key,
            PROXIMITY_BEACON_VERSION,
            7,
            &fob,
            &bad
        ));
    }

    #[test]
    fn should_derive_distinct_tags_per_counter() {
        let key = test_key();
        let fob = test_fob();
        let a = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 1, &fob);
        let b = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 1, &fob);
        let c = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 2, &fob);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn should_ignore_non_fffe_parse_unsupported_ver_and_malformed() {
        let key = test_key();
        let fob = test_fob();
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 3, &fob);
        let data = beacon_data(3, &tag);
        assert_eq!(parse_proximity_svc_data(0xFFFD, &data), BeaconParse::Ignore);
        let mut wrong_ver = data;
        wrong_ver[0] = 0x02;
        assert_eq!(
            parse_proximity_svc_data(PROXIMITY_BEACON_SVC_UUID16, &wrong_ver),
            BeaconParse::Unsupported
        );
        assert_eq!(
            parse_proximity_svc_data(PROXIMITY_BEACON_SVC_UUID16, &data[..8]),
            BeaconParse::Malformed
        );
    }

    #[test]
    fn should_accept_in_order_and_reject_replay_without_advancing() {
        let key = test_key();
        let fob = test_fob();
        let mut v = ProximityVerifier::new();
        for ctr in [1u32, 2, 3] {
            let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
            let data = beacon_data(ctr, &tag);
            assert_eq!(
                v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data),
                BeaconVerdict::Accept {
                    ctr,
                    reverify: false
                }
            );
        }
        assert_eq!(v.last_ctr(), Some(3));
        let tag3 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 3, &fob);
        let data3 = beacon_data(3, &tag3);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data3),
            BeaconVerdict::Replay
        );
        let tag2 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 2, &fob);
        let data2 = beacon_data(2, &tag2);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data2),
            BeaconVerdict::Replay
        );
        assert_eq!(v.last_ctr(), Some(3));
    }

    #[test]
    fn should_reject_bad_tag_without_advancing() {
        let key = test_key();
        let fob = test_fob();
        let mut v = ProximityVerifier::new();
        let tag1 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 1, &fob);
        let data1 = beacon_data(1, &tag1);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data1),
            BeaconVerdict::Accept {
                ctr: 1,
                reverify: false
            }
        );
        let mut bad = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 2, &fob);
        bad[0] ^= 0xFF;
        let data_bad = beacon_data(2, &bad);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data_bad),
            BeaconVerdict::BadTag
        );
        assert_eq!(v.last_ctr(), Some(1));
    }

    #[test]
    fn should_flag_reverify_on_jump_over_1000() {
        let key = test_key();
        let fob = test_fob();
        let mut v = ProximityVerifier::new();
        let tag1 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 10, &fob);
        let data1 = beacon_data(10, &tag1);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data1),
            BeaconVerdict::Accept {
                ctr: 10,
                reverify: false
            }
        );
        let jump = 10 + PROXIMITY_REVERIFY_JUMP + 1;
        let tagj = proximity_tag(&key, PROXIMITY_BEACON_VERSION, jump, &fob);
        let dataj = beacon_data(jump, &tagj);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &dataj),
            BeaconVerdict::Accept {
                ctr: jump,
                reverify: true
            }
        );
        assert!(v.reverify_pending());
        v.clear_reverify();
        assert!(!v.reverify_pending());
        let tag_next = proximity_tag(&key, PROXIMITY_BEACON_VERSION, jump + 1, &fob);
        let data_next = beacon_data(jump + 1, &tag_next);
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data_next),
            BeaconVerdict::Accept {
                ctr: jump + 1,
                reverify: false
            }
        );
    }

    #[test]
    fn should_tick_about_once_per_second() {
        let mut b = ProximityBeacon::new();
        assert_eq!(b.counter(), 0);
        assert!(!b.tick_if_due(0, PROXIMITY_BEACON_TICK_MS - 1));
        assert_eq!(b.counter(), 0);
        assert!(b.tick_if_due(0, PROXIMITY_BEACON_TICK_MS));
        assert_eq!(b.counter(), 1);
        assert!(!b.tick_if_due(1000, 1500));
        assert!(b.tick_if_due(1000, 2000));
        assert_eq!(b.counter(), 2);
    }

    #[test]
    fn should_hold_max_on_rollover_until_rekey() {
        let mut b = ProximityBeacon { ctr: u32::MAX - 1 };
        assert!(!b.is_rollover());
        assert_eq!(b.tick(), u32::MAX);
        assert!(b.is_rollover());
        assert_eq!(b.tick(), u32::MAX);
        assert!(b.is_rollover());
        assert!(b.tick_if_due(0, 60_000));
        assert_eq!(b.counter(), u32::MAX);
    }

    #[test]
    fn should_roundtrip_k_prox_in_encrypted_nvs() {
        let mut s = storage();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA0E615);
        assert_eq!(load_proximity_key(&s), Err(StorageError::KeyNotFound));
        let key = rekey_proximity(&mut s, &mut rng).expect("rekey salva");
        assert_eq!(load_proximity_key(&s).expect("carrega"), key);
        let key2 = rekey_proximity(&mut s, &mut rng).expect("rekey troca");
        assert_ne!(key, key2);
        assert_eq!(load_proximity_key(&s).expect("carrega nova"), key2);
        delete_proximity_key(&mut s).expect("release apaga");
        assert_eq!(load_proximity_key(&s), Err(StorageError::KeyNotFound));
    }

    #[test]
    fn should_reject_tampered_or_short_k_prox() {
        let mut s = storage();
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let key = generate_proximity_key(&mut rng);
        save_proximity_key(&mut s, &key, &mut rng).expect("salva");
        s.backend_mut()
            .write_raw(PROXIMITY_BOND_NVS_KEY, &[1u8, 2, 3])
            .expect("injeta curto");
        assert_eq!(load_proximity_key(&s), Err(StorageError::CorruptedEnvelope));
        save_proximity_key(&mut s, &key, &mut rng).expect("salva de novo");
        let mut raw = s
            .backend()
            .read_raw(PROXIMITY_BOND_NVS_KEY)
            .expect("envelope");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        s.backend_mut()
            .write_raw(PROXIMITY_BOND_NVS_KEY, &raw)
            .expect("injeta tamper");
        assert_eq!(load_proximity_key(&s), Err(StorageError::DecryptionFailed));
    }

    #[test]
    fn should_require_every_gate_for_presence_adv() {
        assert!(proximity_adv_allowed(true, true, true, false, true));
        assert!(!proximity_adv_allowed(false, true, true, false, true));
        assert!(!proximity_adv_allowed(true, false, true, false, true));
        assert!(!proximity_adv_allowed(true, true, false, false, true));
        assert!(!proximity_adv_allowed(true, true, true, true, true));
        assert!(!proximity_adv_allowed(true, true, true, false, false));
    }

    #[test]
    fn should_never_unlock_monitor_on_beacon_accept() {
        let mut m = ProximityMonitor::new(ProximityConfig::default());
        m.update(Some(-80), 10);
        m.confirm_lock();
        assert_eq!(m.state(), ProximityState::Locked);
        let key = test_key();
        let fob = test_fob();
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 41, &fob);
        let data = beacon_data(41, &tag);
        let mut v = ProximityVerifier::new();
        assert_eq!(
            v.accept(&key, &fob, PROXIMITY_BEACON_SVC_UUID16, &data),
            BeaconVerdict::Accept {
                ctr: 41,
                reverify: false
            }
        );
        assert_eq!(m.state(), ProximityState::Locked);
        assert!(!m.unlock(false, false));
        assert_eq!(m.state(), ProximityState::Locked);
    }
}

// ---------------------------------------------------------------------------
// T8 FreeRTOS: amostra e gaps do scheduler (sem fabricar valores).
//
// - `freertos_tick_sample` = `None` sempre (sensor RSSI HW ausente no
//   scheduler: `EXTERNAL_BLOCKED: RssiSensor`; fail-closed, nunca zero).
//   Quando o sensor existir, o gate `authorize_proximity_sample(bonded,
//   usb)` decide entre a leitura real e `None` (ver
//   `prox_sched::tick_with_sample` no `main.rs`).
// - `FreertosTrustGap` reexportado aqui para o dominio de proximidade;
//   o ponto canonico de trava e `TrustFacade::confirm_lock` (nao chamar
//   `ProximityMonitor::confirm_lock` direto no caminho FreeRTOS).
//
// FAIL-SAFE / POWER-LOSS: K_prox em NVS cifrada; queda entre delete/save
// (rekey/release/recovery) => ausente no boot => sem adv ate novo
// pareamento (fail-closed). Envelope com tamanho errado => `Corrupted`.
// Rollover (ctr=u32::MAX) exige rekey antes de avancar (nunca wrap).
// ---------------------------------------------------------------------------

/// Gaps do small loop FreeRTOS no dominio de proximidade (canonico em `binding`).
pub use crate::binding::FreertosTrustGap;

/// Amostra RSSI do tick FreeRTOS: sempre `None` (fail-closed).
///
/// Sensor HW ausente no scheduler (`EXTERNAL_BLOCKED: RssiSensor`); `None`
/// conta como fraco no `update` (tende a travar). Nunca retorna zero
/// (zero seria sinal bom falso). R14 HW-first: leitura real so via
/// `tick_with_sample` com valor do radio.
pub fn freertos_tick_sample() -> Option<i16> {
    None
}

/// Gaps ainda abertos no small loop FreeRTOS (delega ao canonico).
pub fn freertos_open_gaps() -> [FreertosTrustGap; 7] {
    FreertosTrustGap::freertos_open_gaps()
}

#[cfg(test)]
mod proximity_freertos_tests {
    use super::*;
    use crate::persistence::{MockFlashBackend, SecureStorage};

    #[test]
    fn tick_sample_fail_closed_nunca_zero() {
        assert_eq!(freertos_tick_sample(), None);
        let mut m = ProximityMonitor::new(ProximityConfig::default());
        let st = m.update(freertos_tick_sample(), 10);
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn gaps_reexportados_iguais_ao_canonico() {
        assert_eq!(
            freertos_open_gaps().len(),
            FreertosTrustGap::freertos_open_gaps().len()
        );
        assert!(freertos_open_gaps().contains(&FreertosTrustGap::RssiSensor));
    }

    #[test]
    fn k_prox_queda_entre_delete_e_save_sem_adv() {
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let k = rekey_proximity(&mut st, &mut rng).expect("rekey ok");
        assert_eq!(load_proximity_key(&st).expect("load ok"), k);
        delete_proximity_key(&mut st).expect("delete ok");
        assert!(load_proximity_key(&st).is_err());
        assert!(!proximity_adv_allowed(true, true, true, false, false));
    }
}
