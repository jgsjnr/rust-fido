//! Integração FreeRTOS × proximidade BLE (host, sem hardware).
//!
//! Pina o contrato observável entre o firmware e os agents host
//! (`tools/host/{win,linux,macos}/proximity_agent.py`):
//!
//! - Vetor de interop: `K=0x42*16`, fob `AA:BB:CC:DD:EE:FF`, `ctr=7`,
//!   `VER=0x01` ⇒ `TAG=660d4941` (o mesmo que o `self-test` host valida).
//!   Um oráculo AES-128-ECB independente (test-only) cruza o cálculo com o
//!   `proximity_tag` do firmware: dois AES distintos concordando no vetor.
//! - Beacon `0xFFFE` válido alimenta `Near`; `0xFFFD`/VER curto/malformado
//!   é fail-closed (`None`/AWAY, nunca autentica).
//! - Anti-replay: `ctr` repetido ⇒ `Replay`; salto `> 1000` ⇒
//!   `Accept{reverify:true}` + `reverify_pending()` (host rejeita no tick e
//!   reavalia no próximo; ambos os lados nunca avançam sob replay).
//! - Gate FreeRTOS: `proximity_adv_allowed` / `should_adv_proximity` /
//!   `authorize_proximity_sample` — USB montado veta o beacon (amostra
//!   descartada ⇒ `Away`); trava só via `confirm_lock` (sem auto-unlock).

#![cfg(feature = "proximity")]

use aegis_fido_firmware::ble_gatt::PROXIMITY_SERVICE_UUID;
use aegis_fido_firmware::ble_nimble::{
    encode_proximity_adv_payload, should_adv_proximity, PROXIMITY_ADV_TOTAL_LEN,
};
use aegis_fido_firmware::freertos::{
    EventGroup, FirmwareEvent, FreeRtosScheduler, EVT_BLE_RX, EVT_SHUTDOWN,
};
use aegis_fido_firmware::pairing::PairingState;
use aegis_fido_firmware::proximity::{
    authorize_proximity_sample, bonding_required, coex_proximity_allowed,
    encode_proximity_svc_data, parse_proximity_svc_data, proximity_adv_allowed, proximity_tag,
    verify_proximity_tag, BeaconParse, BeaconVerdict, ProximityBeacon, ProximityConfig,
    ProximityMonitor, ProximityState, ProximityVerifier, PROXIMITY_BEACON_SVC_DATA_LEN,
    PROXIMITY_BEACON_SVC_UUID16, PROXIMITY_BEACON_TAG_LEN, PROXIMITY_BEACON_TICK_MS,
    PROXIMITY_BEACON_VERSION, PROXIMITY_FOB_ID_LEN, PROXIMITY_HYSTERESIS_DB, PROXIMITY_KEY_LEN,
    PROXIMITY_LOCK_RSSI_DBM, PROXIMITY_LOCK_SECS, PROXIMITY_REVERIFY_JUMP,
};

// ---------------------------------------------------------------------------
// Oráculo AES-128-ECB independente (test-only; cruza o `aes`-crate do firmware).
// ---------------------------------------------------------------------------

/// S-box padrão AES (FIPS-197 §5.1.1).
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Rcon AES-128 (10 rodadas).
const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn aes_xtime(x: u8) -> u8 {
    if x & 0x80 == 0 {
        x << 1
    } else {
        (x << 1) ^ 0x1b
    }
}

fn aes_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            // RotWord + SubWord + Rcon.
            t = (u32::from(AES_SBOX[((t >> 16) & 0xff) as usize]) << 24)
                | (u32::from(AES_SBOX[((t >> 8) & 0xff) as usize]) << 16)
                | (u32::from(AES_SBOX[(t & 0xff) as usize]) << 8)
                | u32::from(AES_SBOX[((t >> 24) & 0xff) as usize]);
            t ^= u32::from(AES_RCON[i / 4 - 1]) << 24;
        }
        w[i] = w[i - 4] ^ t;
    }
    let mut out = [[0u8; 16]; 11];
    for (r, chunk) in out.iter_mut().enumerate() {
        for i in 0..4 {
            chunk[4 * i..4 * i + 4].copy_from_slice(&w[r * 4 + i].to_be_bytes());
        }
    }
    out
}

fn oracle_aes128_ecb(key: &[u8; 16], pt: &[u8; 16]) -> [u8; 16] {
    let rk = aes_key_expand(key);
    let mut s = *pt;
    for (b, k) in s.iter_mut().zip(rk[0].iter()) {
        *b ^= *k;
    }
    for (round, rk_round) in rk.iter().enumerate().skip(1) {
        for b in s.iter_mut() {
            *b = AES_SBOX[*b as usize];
        }
        // ShiftRows (estado column-major; linha r rotaciona r).
        let t = s;
        for r in 0..4 {
            for c in 0..4 {
                s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
            }
        }
        // MixColumns (todas menos a última rodada).
        if round < 10 {
            for c in 0..4 {
                let a0 = s[c * 4];
                let a1 = s[c * 4 + 1];
                let a2 = s[c * 4 + 2];
                let a3 = s[c * 4 + 3];
                s[c * 4] = aes_xtime(a0) ^ (aes_xtime(a1) ^ a1) ^ a2 ^ a3;
                s[c * 4 + 1] = a0 ^ aes_xtime(a1) ^ (aes_xtime(a2) ^ a2) ^ a3;
                s[c * 4 + 2] = a0 ^ a1 ^ aes_xtime(a2) ^ (aes_xtime(a3) ^ a3);
                s[c * 4 + 3] = (aes_xtime(a0) ^ a0) ^ a1 ^ a2 ^ aes_xtime(a3);
            }
        }
        for (b, k) in s.iter_mut().zip(rk_round.iter()) {
            *b ^= *k;
        }
    }
    s
}

/// Réplica independente do `_ccm_tag` host / `proximity_tag` firmware.
fn oracle_ccm_tag(key: &[u8; 16], ver: u8, ctr: u32, fob: &[u8; 6]) -> [u8; 4] {
    let mut nonce = [0u8; 11];
    nonce[0] = ver;
    nonce[1..5].copy_from_slice(&ctr.to_le_bytes());
    nonce[5..11].copy_from_slice(fob);
    let mut b0 = [0u8; 16];
    b0[0] = 0x4B;
    b0[1..12].copy_from_slice(&nonce);
    let mut x = oracle_aes128_ecb(key, &b0);
    let mut aad = [0u8; 5];
    aad[0] = ver;
    aad[1..5].copy_from_slice(&ctr.to_le_bytes());
    let mut block = [0u8; 16];
    block[0] = 0x00;
    block[1] = aad.len() as u8;
    block[2..2 + aad.len()].copy_from_slice(&aad);
    for (xb, bb) in x.iter_mut().zip(block.iter()) {
        *xb ^= *bb;
    }
    x = oracle_aes128_ecb(key, &x);
    let mut s0in = [0u8; 16];
    s0in[0] = 0x03;
    s0in[1..12].copy_from_slice(&nonce);
    let s0 = oracle_aes128_ecb(key, &s0in);
    [x[0] ^ s0[0], x[1] ^ s0[1], x[2] ^ s0[2], x[3] ^ s0[3]]
}

// ---------------------------------------------------------------------------
// Acessórios.
// ---------------------------------------------------------------------------

fn interop_key() -> [u8; PROXIMITY_KEY_LEN] {
    [0x42u8; PROXIMITY_KEY_LEN]
}

fn interop_fob() -> [u8; PROXIMITY_FOB_ID_LEN] {
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
}

fn tag_hex(tag: &[u8; PROXIMITY_BEACON_TAG_LEN]) -> String {
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

/// Contexto do sampler do tick de proximidade: gate (bond+USB) antes do verifier.
struct Gate<'a> {
    verifier: &'a mut ProximityVerifier,
    key: &'a [u8; PROXIMITY_KEY_LEN],
    fob: &'a [u8; PROXIMITY_FOB_ID_LEN],
}

impl<'a> Gate<'a> {
    fn sample(
        &mut self,
        bonded: bool,
        usb_active: bool,
        svc_uuid: u16,
        data: &[u8],
        rssi: Option<i16>,
    ) -> Option<i16> {
        if !authorize_proximity_sample(bonded, usb_active) {
            return None;
        }
        if !matches!(
            self.verifier.accept(self.key, self.fob, svc_uuid, data),
            BeaconVerdict::Accept { .. }
        ) {
            return None;
        }
        rssi
    }
}

// ---------------------------------------------------------------------------
// Testes.
// ---------------------------------------------------------------------------

#[test]
fn aes_oraculo_confere_vetor_fips197() {
    // Apêndice B do FIPS-197: isola bugs do oráculo antes do interop.
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let pt = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    assert_eq!(oracle_aes128_ecb(&key, &pt), expected);
}

#[test]
fn interop_tag_vector_k42_ctr7_eq_660d4941() {
    // Vetor confirmado host↔firmware (`py-tag == rs-tag` no handoff).
    let key = interop_key();
    let fob = interop_fob();
    let oracle = oracle_ccm_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob);
    assert_eq!(tag_hex(&oracle), "660d4941");
    // O firmware concorda com o oráculo independente.
    let fw = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob);
    assert_eq!(fw, oracle, "firmware deve reproduzir o vetor interop");
    assert!(verify_proximity_tag(
        &key,
        PROXIMITY_BEACON_VERSION,
        7,
        &fob,
        &fw
    ));
}

#[test]
fn interop_tag_rejeita_chave_fob_ctr_divergentes() {
    let key = interop_key();
    let fob = interop_fob();
    let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, 7, &fob);
    assert!(!verify_proximity_tag(
        &key,
        PROXIMITY_BEACON_VERSION,
        8,
        &fob,
        &tag
    ));
    let mut other = fob;
    other[5] ^= 0x01;
    assert!(!verify_proximity_tag(
        &key,
        PROXIMITY_BEACON_VERSION,
        7,
        &other,
        &tag
    ));
    let mut bad_key = key;
    bad_key[0] ^= 0x01;
    assert!(!verify_proximity_tag(
        &bad_key,
        PROXIMITY_BEACON_VERSION,
        7,
        &fob,
        &tag
    ));
    assert!(!verify_proximity_tag(
        &key,
        PROXIMITY_BEACON_VERSION,
        7,
        &fob,
        &[0u8; 4]
    ));
}

#[test]
fn beacon_0xfffe_valido_parse_e_accept_alimenta_near() {
    assert_eq!(PROXIMITY_BEACON_SVC_UUID16, 0xFFFE);
    assert_eq!(PROXIMITY_SERVICE_UUID, 0xFFFE);
    assert_eq!(PROXIMITY_BEACON_SVC_DATA_LEN, 11);

    let key = interop_key();
    let fob = interop_fob();
    let mut beacon = ProximityBeacon::new();
    let ctr = beacon.tick();
    let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);

    // Service-data de 11 B: UUID16 LE + VER + CTR + TAG.
    let svc = encode_proximity_svc_data(ctr, &tag);
    assert_eq!(svc[0], 0xFE);
    assert_eq!(svc[1], 0xFF);
    assert_eq!(svc[2], PROXIMITY_BEACON_VERSION);
    // Adv completo cabe no legado (30 B ≤ 31 B) e carrega 0xFFFE, nunca 0xFFFD.
    let adv = encode_proximity_adv_payload(ctr, &tag);
    assert_eq!(adv.as_bytes().len(), PROXIMITY_ADV_TOTAL_LEN);
    assert!(adv.as_bytes().len() <= 31);

    // Parse dos 9 B após o UUID + Accept com TAG válida.
    let (uuid, data) = (u16::from_le_bytes([svc[0], svc[1]]), &svc[2..]);
    assert!(matches!(
        parse_proximity_svc_data(uuid, data),
        BeaconParse::Ok { .. }
    ));
    let mut verifier = ProximityVerifier::new();
    let verdict = verifier.accept(&key, &fob, uuid, data);
    assert!(matches!(
        verdict,
        BeaconVerdict::Accept {
            reverify: false,
            ..
        }
    ));
    assert_eq!(verifier.last_ctr(), Some(ctr));

    // Gate + monitor: presença válida alimenta `Near`.
    let mut monitor = ProximityMonitor::new(ProximityConfig::default());
    let mut gate = Gate {
        verifier: &mut verifier,
        key: &key,
        fob: &fob,
    };
    let sample = gate.sample(true, false, uuid, data, Some(-60));
    // ctr já consumido acima => replay aqui; reconstrói fluxo com novo tick.
    assert_eq!(sample, None);
    let ctr2 = beacon.tick();
    let tag2 = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr2, &fob);
    let svc2 = encode_proximity_svc_data(ctr2, &tag2);
    let sample = gate.sample(true, false, 0xFFFE, &svc2[2..], Some(-60));
    assert_eq!(sample, Some(-60));
    assert_eq!(monitor.update(sample, 1), ProximityState::Near);
}

#[test]
fn beacon_invalido_e_fail_closed_away() {
    let key = interop_key();
    let fob = interop_fob();
    let ctr = 1u32;
    let good_tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
    let good_svc = encode_proximity_svc_data(ctr, &good_tag);
    let good_data = good_svc[2..].to_vec();

    // UUID 0xFFFD (GATT FIDO) é ignorada no path de presença.
    assert_eq!(
        parse_proximity_svc_data(0xFFFD, &good_data),
        BeaconParse::Ignore
    );
    // VER desconhecido => Unsupported; tamanho errado => Malformed.
    let mut bad_ver = good_data.clone();
    bad_ver[0] = 0x02;
    assert_eq!(
        parse_proximity_svc_data(0xFFFE, &bad_ver),
        BeaconParse::Unsupported
    );
    assert_eq!(
        parse_proximity_svc_data(0xFFFE, &good_data[..8]),
        BeaconParse::Malformed
    );

    // Cada caso inválido vira `None`/AWAY e nunca avança `last_ctr`.
    let mut verifier = ProximityVerifier::new();
    let mut monitor = ProximityMonitor::new(ProximityConfig::default());
    let mut gate = Gate {
        verifier: &mut verifier,
        key: &key,
        fob: &fob,
    };
    let bad_tag_svc = encode_proximity_svc_data(ctr, &[0u8; 4]);
    let cases: Vec<(u16, Vec<u8>, BeaconVerdict)> = vec![
        (0xFFFD, good_data.clone(), BeaconVerdict::Ignore),
        (0xFFFE, bad_ver.clone(), BeaconVerdict::Unsupported),
        (0xFFFE, good_data[..8].to_vec(), BeaconVerdict::Malformed),
        (0xFFFE, bad_tag_svc[2..].to_vec(), BeaconVerdict::BadTag),
    ];
    for (uuid, data, _expect) in &cases {
        let sample = gate.sample(true, false, *uuid, data, Some(-60));
        assert_eq!(sample, None, "beacon inválido deve virar None/AWAY");
        monitor.update(sample, 1);
    }
    assert_eq!(gate.verifier.last_ctr(), None);
    // Fail-closed: 10 s sem beacon válido levam a `Away`.
    for _ in 0..6 {
        let sample = gate.sample(true, false, 0xFFFE, &bad_tag_svc[2..], Some(-60));
        monitor.update(sample, 1);
    }
    assert_eq!(monitor.state(), ProximityState::Away);
}

#[test]
fn replay_ctr_repetido_rejeitado_sem_avancar() {
    let key = interop_key();
    let fob = interop_fob();
    let mut verifier = ProximityVerifier::new();
    let mk = |ctr: u32| {
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
        encode_proximity_svc_data(ctr, &tag)
    };

    let first = mk(7);
    assert!(matches!(
        verifier.accept(&key, &fob, 0xFFFE, &first[2..]),
        BeaconVerdict::Accept { ctr: 7, .. }
    ));
    assert_eq!(verifier.last_ctr(), Some(7));
    // Replay: mesmo ctr rejeitado, `last_ctr` não anda.
    let replay = mk(7);
    assert_eq!(
        verifier.accept(&key, &fob, 0xFFFE, &replay[2..]),
        BeaconVerdict::Replay
    );
    assert_eq!(verifier.last_ctr(), Some(7));
    // ctr anterior também é replay.
    let older = mk(6);
    assert_eq!(
        verifier.accept(&key, &fob, 0xFFFE, &older[2..]),
        BeaconVerdict::Replay
    );
    assert_eq!(verifier.last_ctr(), Some(7));
    // Próximo ctr segue aceito.
    let next = mk(8);
    assert!(matches!(
        verifier.accept(&key, &fob, 0xFFFE, &next[2..]),
        BeaconVerdict::Accept { ctr: 8, .. }
    ));
}

#[test]
fn salto_maior_que_1000_marca_reverify() {
    let key = interop_key();
    let fob = interop_fob();
    let mk = |ctr: u32| {
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
        encode_proximity_svc_data(ctr, &tag)
    };
    assert_eq!(PROXIMITY_REVERIFY_JUMP, 1000);

    // Salto de exatamente 1000: aceito sem flag (limite inclusivo).
    let mut edge_verifier = ProximityVerifier::new();
    let base = mk(10);
    assert!(matches!(
        edge_verifier.accept(&key, &fob, 0xFFFE, &base[2..]),
        BeaconVerdict::Accept {
            reverify: false,
            ..
        }
    ));
    let edge = mk(10 + PROXIMITY_REVERIFY_JUMP);
    assert!(matches!(
        edge_verifier.accept(&key, &fob, 0xFFFE, &edge[2..]),
        BeaconVerdict::Accept {
            reverify: false,
            ..
        }
    ));
    assert!(!edge_verifier.reverify_pending());

    // Salto de 1001: aceito MAS com `reverify` — host re-confere bonding/UP.
    let mut verifier = ProximityVerifier::new();
    assert!(matches!(
        verifier.accept(&key, &fob, 0xFFFE, &base[2..]),
        BeaconVerdict::Accept { .. }
    ));
    let jump = 10 + PROXIMITY_REVERIFY_JUMP + 1;
    let far = mk(jump);
    assert!(matches!(
        verifier.accept(&key, &fob, 0xFFFE, &far[2..]),
        BeaconVerdict::Accept {
            ctr,
            reverify: true
        } if ctr == jump
    ));
    assert!(verifier.reverify_pending());
    verifier.clear_reverify();
    assert!(!verifier.reverify_pending());
    // Após reverify, o próximo ctr segue aceito sem flag.
    let retry = mk(jump + 1);
    assert!(matches!(
        verifier.accept(&key, &fob, 0xFFFE, &retry[2..]),
        BeaconVerdict::Accept {
            reverify: false,
            ..
        }
    ));
}

#[test]
fn beacon_tick_cadencia_1s_sem_wrap() {
    assert_eq!(PROXIMITY_BEACON_TICK_MS, 1000);
    let mut beacon = ProximityBeacon::default();
    assert_eq!(beacon.counter(), 0);
    assert!(!beacon.is_rollover());
    assert!(!beacon.tick_if_due(0, 999));
    assert_eq!(beacon.counter(), 0);
    assert!(beacon.tick_if_due(0, 1000));
    assert_eq!(beacon.counter(), 1);
    assert_eq!(beacon.tick(), 2);
    assert!(!beacon.is_rollover());
}

#[test]
fn gate_bonding_usb_e_adv_truth_table() {
    // Constantes canônicas em sync com agents host (`-75 dBm / 10 s / 5 dB`).
    assert_eq!(PROXIMITY_LOCK_RSSI_DBM, -75);
    assert_eq!(PROXIMITY_LOCK_SECS, 10);
    assert_eq!(PROXIMITY_HYSTERESIS_DB, 5);
    let defaults = ProximityConfig::default();
    assert_eq!(defaults.lock_rssi_dbm, PROXIMITY_LOCK_RSSI_DBM);
    assert_eq!(defaults.lock_secs, PROXIMITY_LOCK_SECS);
    assert_eq!(defaults.hysteresis_db, PROXIMITY_HYSTERESIS_DB);

    // Bonding sempre obrigatório; USB ativo veta; sem bond descarta.
    assert!(bonding_required());
    assert!(coex_proximity_allowed(false));
    assert!(!coex_proximity_allowed(true));
    assert!(authorize_proximity_sample(true, false));
    assert!(!authorize_proximity_sample(false, false));
    assert!(!authorize_proximity_sample(true, true));
    assert!(!authorize_proximity_sample(false, true));

    // Gate do anúncio: todos exigidos (bond, idle, trust, !usb, chave).
    assert!(proximity_adv_allowed(true, true, true, false, true));
    assert!(!proximity_adv_allowed(false, true, true, false, true));
    assert!(!proximity_adv_allowed(true, false, true, false, true));
    assert!(!proximity_adv_allowed(true, true, false, false, true));
    assert!(!proximity_adv_allowed(true, true, true, true, true));
    assert!(!proximity_adv_allowed(true, true, true, false, false));
    // Fiação BLE: Idle anuncia; fora de Idle (ex. Arming) fica mudo.
    assert!(should_adv_proximity(
        PairingState::Idle,
        true,
        true,
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
        PairingState::Arming { start_ms: 0 },
        true,
        true,
        false,
        true
    ));
}

#[test]
fn scheduler_freertos_usb_montado_veta_beacon() {
    let sched = FreeRtosScheduler::new(32);
    let events = EventGroup::new();
    let key = interop_key();
    let fob = interop_fob();

    // Fase 1: beacon VÁLIDO + fob bonded, MAS USB montado => veto total.
    // O gate nega antes do verifier: `last_ctr` nem avança.
    let mut verifier = ProximityVerifier::new();
    let mut monitor = ProximityMonitor::new(ProximityConfig::default());
    let mut gate = Gate {
        verifier: &mut verifier,
        key: &key,
        fob: &fob,
    };
    let mut beacon = ProximityBeacon::new();
    for tick in 0..12u32 {
        let ctr = beacon.tick();
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
        let svc = encode_proximity_svc_data(ctr, &tag);
        assert!(sched.queue.send(FirmwareEvent::Tick10ms(tick as u64)));
        let ev = sched.queue.receive(None);
        assert!(matches!(ev, Some(FirmwareEvent::Tick10ms(_))));
        // USB montado veta anúncio e amostra (coex: USB > BLE).
        assert!(!should_adv_proximity(
            PairingState::Idle,
            true,
            true,
            true,
            true
        ));
        let sample = gate.sample(true, true, 0xFFFE, &svc[2..], Some(-60));
        assert_eq!(sample, None, "USB montado deve vetar o beacon");
        if sample.is_some() {
            events.set_bits(EVT_BLE_RX);
        }
        monitor.update(sample, 1);
    }
    assert_eq!(
        verifier.last_ctr(),
        None,
        "veto USB não consome rolling-code"
    );
    assert_eq!(
        events.get() & EVT_BLE_RX,
        0,
        "nenhum beacon pode sinalizar presença com USB ativo"
    );
    assert_eq!(monitor.state(), ProximityState::Away);
    // Trava somente via confirmação (nunca automática).
    assert_eq!(monitor.confirm_lock(), ProximityState::Locked);

    // Fase 2: USB idle + bonded + beacon válido => presença alimenta `Near`.
    let mut verifier2 = ProximityVerifier::new();
    let mut monitor = ProximityMonitor::new(ProximityConfig::default());
    let mut gate = Gate {
        verifier: &mut verifier2,
        key: &key,
        fob: &fob,
    };
    for _ in 0..3u32 {
        let ctr = beacon.tick();
        let tag = proximity_tag(&key, PROXIMITY_BEACON_VERSION, ctr, &fob);
        let svc = encode_proximity_svc_data(ctr, &tag);
        assert!(should_adv_proximity(
            PairingState::Idle,
            true,
            true,
            false,
            true
        ));
        let sample = gate.sample(true, false, 0xFFFE, &svc[2..], Some(-60));
        assert_eq!(sample, Some(-60));
        if sample.is_some() {
            events.set_bits(EVT_BLE_RX);
        }
        monitor.update(sample, 1);
    }
    assert_eq!(monitor.state(), ProximityState::Near);
    assert_ne!(events.get() & EVT_BLE_RX, 0);

    // Desligamento cooperativo triplo do scheduler segue intacto.
    sched.request_stop();
    assert!(sched.stop.load(core::sync::atomic::Ordering::SeqCst));
    assert_ne!(sched.events.get() & EVT_SHUTDOWN, 0);
    assert_eq!(sched.queue.receive(None), Some(FirmwareEvent::Shutdown));
}

#[test]
fn monitor_lock_exige_confirmacao_e_unlock_presenca_pin() {
    let mut monitor = ProximityMonitor::new(ProximityConfig::default());
    // 9 s fracos ainda é `Near`; 10 s acumulados viram `Away`.
    assert_eq!(monitor.update(Some(-80), 9), ProximityState::Near);
    assert_eq!(monitor.update(Some(-80), 1), ProximityState::Away);
    // `update` sozinho nunca trava.
    assert_eq!(monitor.update(Some(-80), 60), ProximityState::Away);
    assert_eq!(monitor.confirm_lock(), ProximityState::Locked);
    // Nem RSSI bom destrava sozinho (sem auto-unlock).
    assert_eq!(monitor.update(Some(-50), 30), ProximityState::Locked);
    assert!(!monitor.unlock(true, false));
    assert!(!monitor.unlock(false, true));
    assert!(monitor.unlock(true, true));
    assert_eq!(monitor.state(), ProximityState::Near);
}
