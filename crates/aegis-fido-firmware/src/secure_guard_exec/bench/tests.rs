//! Cobertura da bancada (test-mode only + release no-op).
//!
//! Usa caminhos totalmente qualificados (sem `use`) de proposito: mantem o
//! `fan_out` do dep-track em zero neste arquivo de testes.

/// Serializa os testes de bancada (estado global compartilhado).
static BENCH_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Engine rapido p/ testes (PBKDF2 minimo; mesma policy padrao).
#[cfg(feature = "test-mode")]
fn fast_engine() -> aegis_fido_core::secure_guard::SecureGuardEngine {
    aegis_fido_core::secure_guard::SecureGuardEngine::new(
        aegis_fido_core::secure_guard::SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..aegis_fido_core::secure_guard::SecureGuardPolicy::default()
        },
    )
}

/// Garante a bancada desligada (idempotente; o engine e descartavel).
#[cfg(feature = "test-mode")]
fn bench_test_reset(engine: &mut aegis_fido_core::secure_guard::SecureGuardEngine) {
    let mut fw_log = crate::fw_log::FwLog::new();
    let _ = super::policy::bench_disable(engine, &mut fw_log, 0);
}

#[test]
#[cfg(feature = "test-mode")]
fn bancada_estende_sessao_sem_relock_idle() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);
    assert!(super::policy::bench_enable(&mut engine, &mut fw_log, 1_000));
    assert!(super::policy::is_bench_active());
    assert_eq!(
        engine.policy().session_duration_ms,
        super::policy::BENCH_SESSION_DURATION_MS
    );
    assert_eq!(
        engine.policy().inactivity_timeout_ms,
        super::policy::BENCH_INACTIVITY_TIMEOUT_MS
    );
    engine
        .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 1_000)
        .expect("provision ok");
    engine.unlock_with_pin(b"7391", 2_000).expect("unlock ok");
    assert!(engine.is_unlocked());
    // Passado o idle padrao (300 s): sem bancada travaria aqui.
    let _ = engine.check_and_touch_session(2_000 + 300_001);
    assert!(engine.is_unlocked(), "bancada: sem relock por ociosidade");
    // Absoluta continua finita (24 h): expira no prazo estendido.
    let _ = engine.check_and_touch_session(2_000 + super::policy::BENCH_SESSION_DURATION_MS);
    assert!(!engine.is_unlocked());
    assert_eq!(
        engine.state(),
        aegis_fido_core::secure_guard::SecureGuardState::Locked
    );
    bench_test_reset(&mut engine);
}

#[test]
#[cfg(feature = "test-mode")]
fn bancada_off_restaura_policy_e_idle_volta() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);
    assert!(super::policy::bench_enable(&mut engine, &mut fw_log, 1_000));
    assert!(super::policy::bench_disable(
        &mut engine,
        &mut fw_log,
        2_000
    ));
    assert!(!super::policy::bench_disable(
        &mut engine,
        &mut fw_log,
        3_000
    ));
    assert!(!super::policy::is_bench_active());
    assert_eq!(engine.policy().session_duration_ms, 300_000);
    assert_eq!(engine.policy().inactivity_timeout_ms, 300_000);
    engine
        .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 4_000)
        .expect("provision ok");
    engine.unlock_with_pin(b"7391", 5_000).expect("unlock ok");
    let _ = engine.check_and_touch_session(5_000 + 300_001);
    assert!(!engine.is_unlocked());
    // Policy padrao tem absoluta == inatividade (300 s); no empate a
    // absoluta vence (`check_and_touch_session` checa absoluta primeiro).
    // O ponto do teste e que a sessao volta a expirar apos o OFF.
    assert!(matches!(
        engine.audit_log().last().map(|event| &event.event_type),
        Some(
            aegis_fido_core::secure_guard::SecureGuardAuditEventType::SessionExpired {
                reason: aegis_fido_core::secure_guard::SessionExpiryReason::AbsoluteTimeout,
            }
        )
    ));
    bench_test_reset(&mut engine);
}

#[test]
#[cfg(feature = "test-mode")]
fn disconnect_lock_vale_com_bancada_ativa() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);
    assert!(super::policy::bench_enable(&mut engine, &mut fw_log, 1_000));
    engine
        .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 1_000)
        .expect("provision ok");
    engine.unlock_with_pin(b"7391", 2_000).expect("unlock ok");
    let mut pin = aegis_fido_core::ctap::client_pin::ClientPinState {
        pin_hash: Some([0x5A; 16]),
        active_session: Some(aegis_fido_core::ctap::client_pin::PinUvTokenSession {
            token: [0xAA; 32],
            protocol: 2,
            permissions: 0xFFFF_FFFF,
            rp_id: None,
        }),
        ..Default::default()
    };
    let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
    rescue.set_user_presence(true);
    rescue.set_pin_uv_authenticated(true);
    let mut scratch = [0xAAu8; 24];
    let report = crate::transport_lock::lock_on_transport_loss(
        &mut engine,
        &mut pin,
        &mut rescue,
        &mut [&mut scratch[..]],
        &mut fw_log,
        crate::transport_lock::TransportKind::UsbHid,
        5_000,
    );
    assert!(report.session_was_live);
    assert!(!engine.is_unlocked());
    assert!(report.secure_guard_locked_now);
    // PIN/verificador intactos (so RAM de sessao cai); bancada segue armada.
    assert_eq!(pin.pin_hash, Some([0x5A; 16]));
    assert!(engine.is_provisioned());
    assert!(super::policy::is_bench_active());
    bench_test_reset(&mut engine);
}

#[test]
#[cfg(feature = "test-mode")]
fn bancada_nao_persiste_nvs_nem_toca_keys() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut storage = crate::persistence::SecureStorage::new(
        crate::persistence::MockFlashBackend::new(),
        &[0x42; 32],
        &[0x99; 32],
    );
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);
    engine
        .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 1_000)
        .expect("provision ok");
    crate::secure_guard_storage::save_secure_guard_record(&mut storage, &engine).expect("save ok");
    assert!(super::policy::bench_enable(&mut engine, &mut fw_log, 2_000));
    assert_eq!(
        engine.policy().inactivity_timeout_ms,
        super::policy::BENCH_INACTIVITY_TIMEOUT_MS
    );
    assert!(super::policy::bench_disable(
        &mut engine,
        &mut fw_log,
        3_000
    ));
    // RAM restaurada e a NVS jamais recebeu a policy de bancada.
    assert_eq!(engine.policy().session_duration_ms, 300_000);
    assert_eq!(engine.policy().inactivity_timeout_ms, 300_000);
    let reloaded = crate::secure_guard_storage::load_secure_guard_record(&storage, 4_000);
    assert_eq!(reloaded.policy().session_duration_ms, 300_000);
    assert_eq!(reloaded.policy().inactivity_timeout_ms, 300_000);
    assert!(reloaded.is_provisioned());
    bench_test_reset(&mut engine);
}

#[test]
#[cfg(feature = "test-mode")]
fn dispatch_ack_marca_bench_e_fwlog() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);
    assert_eq!(
        super::dispatch::dispatch_serial_bench_line("ruido", &mut engine, &mut fw_log, 0),
        None
    );
    assert!(fw_log.is_empty());
    let ack_on = super::dispatch::dispatch_serial_bench_line(
        "TEST_BENCH_ON\n",
        &mut engine,
        &mut fw_log,
        1_000,
    )
    .expect("ack on");
    assert!(ack_on.contains("BENCH"), "log marcando BENCH");
    assert!(super::policy::is_bench_active());
    let ack_off = super::dispatch::dispatch_serial_bench_line(
        "TEST_BENCH_OFF",
        &mut engine,
        &mut fw_log,
        2_000,
    )
    .expect("ack off");
    assert!(ack_off.contains("BENCH"));
    assert!(!super::policy::is_bench_active());
    assert_eq!(fw_log.len(), 2);
    let rendered = fw_log.render_ascii(512);
    let text = std::string::String::from_utf8(rendered).expect("fwlog ascii");
    assert!(text.contains("EV=19 ARG=1"), "EV_BENCH on");
    assert!(text.contains("EV=19 ARG=0"), "EV_BENCH off");
    bench_test_reset(&mut engine);
}

#[test]
#[cfg(feature = "test-mode")]
fn quiescencia_estendida_e_borda_wifi_suprimida_com_bancada() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);
    assert!(super::policy::bench_enable(&mut engine, &mut fw_log, 1_000));
    // `poll` delega para a flag global: com bancada ativa o timeout de 30 s
    // nao trava (quiescencia estendida para 24 h).
    let mut mon = crate::transport_lock::TransportMonitor::new();
    assert_eq!(mon.observe_wifi(true, 2_000), None);
    mon.note_wifi_traffic(3_000);
    assert_eq!(
        mon.poll(3_000 + crate::transport_lock::WIFI_QUIESCENCE_TIMEOUT_MS),
        None
    );
    // Borda dura WiFi com bancada: suprimida (placa cai sozinha; bancada
    // usa USB/UART) — None, sem trava, sem EV_TRANSPORT_LOCK novo.
    let eventos_antes = fw_log.len();
    assert_eq!(mon.observe_wifi(false, 4_000), None);
    assert_eq!(fw_log.len(), eventos_antes);
    // USB segue travando com bancada (so o WiFi e suprimido).
    let mut mon_usb = crate::transport_lock::TransportMonitor::new();
    assert_eq!(mon_usb.observe_usb(true), None);
    assert_eq!(
        mon_usb.observe_usb(false),
        Some(crate::transport_lock::TransportKind::UsbHid)
    );
    // O disconnect lock em si segue valido: perda real (USB) trava.
    engine
        .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 4_000)
        .expect("provision ok");
    engine.unlock_with_pin(b"7391", 5_000).expect("unlock ok");
    let mut pin = aegis_fido_core::ctap::client_pin::ClientPinState::default();
    let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
    let mut empty: [&mut [u8]; 0] = [];
    let report = crate::transport_lock::lock_on_transport_loss(
        &mut engine,
        &mut pin,
        &mut rescue,
        &mut empty,
        &mut fw_log,
        crate::transport_lock::TransportKind::UsbHid,
        6_000,
    );
    assert!(report.session_was_live);
    assert!(!engine.is_unlocked());
    assert!(report.secure_guard_locked_now);
    assert!(super::policy::is_bench_active());
    bench_test_reset(&mut engine);
}

#[test]
#[cfg(not(feature = "test-mode"))]
fn release_nunca_ativa_bancada() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = aegis_fido_core::secure_guard::SecureGuardEngine::new(
        aegis_fido_core::secure_guard::SecureGuardPolicy::default(),
    );
    let mut fw_log = crate::fw_log::FwLog::new();
    assert!(!super::policy::bench_enable(&mut engine, &mut fw_log, 0));
    assert!(!super::policy::bench_disable(&mut engine, &mut fw_log, 0));
    assert!(!super::policy::is_bench_active());
    assert_eq!(
        super::dispatch::dispatch_serial_bench_line("TEST_BENCH_ON", &mut engine, &mut fw_log, 0),
        None
    );
}

/// Contrato 0x3A com o app (release): `bench_active` existe e é `false`.
#[test]
#[cfg(not(feature = "test-mode"))]
fn status_mapa_bench_active_false_no_release() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = aegis_fido_core::secure_guard::SecureGuardEngine::new(
        aegis_fido_core::secure_guard::SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..aegis_fido_core::secure_guard::SecureGuardPolicy::default()
        },
    );
    let (st, body) = crate::secure_guard_exec::status::handle_status(&mut engine, 1_000);
    assert_eq!(st, 0x00);
    let val: ciborium::value::Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let ciborium::value::Value::Map(entries) = val {
        let got = entries.iter().find_map(|(k, v)| {
            if matches!(k, ciborium::value::Value::Text(s) if s == "bench_active") {
                Some(v.clone())
            } else {
                None
            }
        });
        assert_eq!(
            got,
            Some(ciborium::value::Value::Bool(false)),
            "0x3A deve expor bench_active=false no release"
        );
    } else {
        panic!("expected cbor map");
    }
}

/// Contrato 0x3A com o app (bancada): `bench_active` reflete `is_bench_active()`.
#[test]
#[cfg(feature = "test-mode")]
fn status_mapa_bench_active_espelha_bancada() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine);

    // Bancada desligada (default): `false`, sem PII.
    let (st, body) = crate::secure_guard_exec::status::handle_status(&mut engine, 1_000);
    assert_eq!(st, 0x00);
    let val: ciborium::value::Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let ciborium::value::Value::Map(entries) = val {
        let got = entries.iter().find_map(|(k, v)| {
            if matches!(k, ciborium::value::Value::Text(s) if s == "bench_active") {
                Some(v.clone())
            } else {
                None
            }
        });
        assert_eq!(
            got,
            Some(ciborium::value::Value::Bool(false)),
            "0x3A deve expor bench_active=false com bancada off"
        );
    } else {
        panic!("expected cbor map");
    }

    // Bancada ligada: `true`.
    assert!(super::policy::bench_enable(&mut engine, &mut fw_log, 2_000));
    assert!(super::policy::is_bench_active());
    let (st, body) = crate::secure_guard_exec::status::handle_status(&mut engine, 3_000);
    assert_eq!(st, 0x00);
    let val: ciborium::value::Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let ciborium::value::Value::Map(entries) = val {
        let got = entries.iter().find_map(|(k, v)| {
            if matches!(k, ciborium::value::Value::Text(s) if s == "bench_active") {
                Some(v.clone())
            } else {
                None
            }
        });
        assert_eq!(
            got,
            Some(ciborium::value::Value::Bool(true)),
            "0x3A deve expor bench_active=true com bancada on"
        );
    } else {
        panic!("expected cbor map");
    }
    bench_test_reset(&mut engine);
}

/// #8: bancada vale no engine da rota CTAPHID serial (segunda instancia).
///
/// Falha antiga: `bench_enable` so estendia o primeiro engine (guardado por
/// `if !slot.active`); um engine criado ou recarregado da NVS depois (policy
/// padrao 300 s) carimbava a sessao curta no unlock via serial. Agora
/// `bench_enable` sempre reaplica no engine passado e
/// `apply_bench_policy_if_active` (chamado pelo executor antes de cada op SG)
/// estende qualquer engine enquanto a bancada esta ativa. Auditoria segue
/// idempotente (um unico `EV_BENCH` ON).
#[test]
#[cfg(feature = "test-mode")]
fn bancada_segundo_engine_serial_carimba_24h() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine_a = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine_a);
    assert_eq!(engine_a.policy().session_duration_ms, 300_000);
    assert!(super::policy::bench_enable(
        &mut engine_a,
        &mut fw_log,
        1_000
    ));
    assert_eq!(fw_log.len(), 1);
    // Segundo engine (rota serial): nasce com a policy padrao de 300 s...
    let mut engine_b = fast_engine();
    assert_eq!(engine_b.policy().session_duration_ms, 300_000);
    assert_eq!(engine_b.policy().inactivity_timeout_ms, 300_000);
    // ...mas `bench_enable` com a bancada ja ativa reaplica sem reaudit:
    assert!(super::policy::bench_enable(
        &mut engine_b,
        &mut fw_log,
        2_000
    ));
    assert_eq!(fw_log.len(), 1, "repetir nao duplica auditoria");
    assert_eq!(
        engine_b.policy().session_duration_ms,
        super::policy::BENCH_SESSION_DURATION_MS
    );
    assert_eq!(
        engine_b.policy().inactivity_timeout_ms,
        super::policy::BENCH_INACTIVITY_TIMEOUT_MS
    );
    // Unlock no engine B carimba 24 h: passa do idle padrao sem relock...
    engine_b
        .provision_pin(b"7391", [0x11; 16], &[0x22; 16], [0x33; 16], 3_000)
        .expect("provision ok");
    engine_b.unlock_with_pin(b"7391", 4_000).expect("unlock ok");
    let _ = engine_b.check_and_touch_session(4_000 + 300_001);
    assert!(
        engine_b.is_unlocked(),
        "engine serial nao pode relockar com 300 s de bancada ativa"
    );
    // ...e expira no prazo estendido (sessao finita, 24 h).
    let _ = engine_b.check_and_touch_session(4_000 + super::policy::BENCH_SESSION_DURATION_MS);
    assert!(!engine_b.is_unlocked());
    // Restaura A (desliga global) e higieniza B (local, descartado).
    bench_test_reset(&mut engine_a);
    engine_b.policy_mut().session_duration_ms = 300_000;
    engine_b.policy_mut().inactivity_timeout_ms = 300_000;
}

/// #8 (mecanismo do executor): engine fresco e estendido via `apply` sem
/// novo audit, cobrindo reload NVS pos-`TEST_BENCH_ON` na rota serial.
#[test]
#[cfg(feature = "test-mode")]
fn bancada_apply_estende_engine_fresco_sem_audit() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine_a = fast_engine();
    let mut fw_log = crate::fw_log::FwLog::new();
    bench_test_reset(&mut engine_a);
    assert!(super::policy::bench_enable(
        &mut engine_a,
        &mut fw_log,
        1_000
    ));
    assert_eq!(fw_log.len(), 1);
    // Engine recem-recarregado (ex.: NVS apos o ON): 300 s...
    let mut engine_novo = fast_engine();
    assert_eq!(engine_novo.policy().session_duration_ms, 300_000);
    // ...o executor reaplica antes do dispatch, sem tocar no fw_log.
    super::policy::apply_bench_policy_if_active(&mut engine_novo);
    assert_eq!(
        engine_novo.policy().session_duration_ms,
        super::policy::BENCH_SESSION_DURATION_MS
    );
    assert_eq!(
        engine_novo.policy().inactivity_timeout_ms,
        super::policy::BENCH_INACTIVITY_TIMEOUT_MS
    );
    assert_eq!(fw_log.len(), 1, "apply nao audita");
    bench_test_reset(&mut engine_a);
    engine_novo.policy_mut().session_duration_ms = 300_000;
    engine_novo.policy_mut().inactivity_timeout_ms = 300_000;
}

/// Release: `apply_bench_policy_if_active` e no-op (producao intacta).
#[test]
#[cfg(not(feature = "test-mode"))]
fn release_apply_bench_policy_e_noop() {
    let _guard = BENCH_TEST_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut engine = aegis_fido_core::secure_guard::SecureGuardEngine::new(
        aegis_fido_core::secure_guard::SecureGuardPolicy::default(),
    );
    super::policy::apply_bench_policy_if_active(&mut engine);
    assert_eq!(engine.policy().session_duration_ms, 300_000);
    assert_eq!(engine.policy().inactivity_timeout_ms, 300_000);
    assert!(!super::policy::is_bench_active());
}
