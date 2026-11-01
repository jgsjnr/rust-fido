//! FreeRTOS authenticator loop (D3 split from `run`, single owner).
//!
//! `run_authenticator_freertos`: USB + botao + housekeeping sobre fila
//! e event group. No host roda ~2 s e sai; no ESP-IDF o loop e infinito.
//!
//! Contract (R15/R16): move-only de `run/mod.rs`; `use super::*` mantem
//! o escopo do pai identico (helpers, FFI, cfgs); fio byte-a-byte.
//! Host+freertos nao usa itens do pai (ramos ESP-IDF): glob so no device
//! (R6: zero warnings em todas as configs).
#[cfg(target_os = "espidf")]
use super::*;

/// Entrada da variante FreeRTOS com feature freertos, T12 parte B.
///
/// Selecao sem quebrar o legado: com freertos cai aqui, sem a feature cai
/// em run_authenticator. O dispatcher BLE completo continua no legado.
/// Roteamento CTAPHID via route_ctaphid_event com origem preservada.
/// TrustFacade fiada no boot via sync_trust_claimed. sync_from_trust e
/// open_gaps seguem para a T8. Secmon segue ExternallyBlocked.
/// Gaps restantes: 7 FreertosTrustGap, todos ExternallyBlocked.
/// Sem burn ou secure boot, HW first, R6 zero, R7 gated.
///
/// Sobe USB mais botao mais housekeeping sobre fila mais event group.
/// No host roda cerca de 2 s e sai. No ESP-IDF o loop e infinito.
#[cfg(feature = "freertos")]
pub fn run_authenticator_freertos() {
    #[cfg(target_os = "espidf")]
    use crate::button::ButtonInput;
    #[cfg(target_os = "espidf")]
    use crate::freertos::route_ctaphid_event;
    #[cfg(target_os = "espidf")]
    use crate::freertos::SerialVendorCtx;
    use crate::freertos::{FirmwareEvent, FreeRtosScheduler, PacketOrigin, DEFAULT_QUEUE_DEPTH};
    kprintln!("[FREERTOS] AegisKey FreeRTOS variant booting (usb+button+housekeeping).");
    // Sem isto, `log::*` (incl. `log_boot_info`) cai no vazio no device:
    // nenhum caminho do firmware instala logger global.
    #[cfg(target_os = "espidf")]
    esp_idf_svc::log::EspLogger::initialize_default();
    // UART limpa p/ CTAPHID: driver WiFi em WARN (o INFO dele inunda o fio
    // a cada AP start com dezenas de linhas e afoga o resync do host).
    // Erros seguem visíveis; resto do IDF mantém INFO de boot.
    #[cfg(target_os = "espidf")]
    unsafe {
        esp_idf_sys::esp_log_level_set(
            b"wifi\0".as_ptr() as *const core::ffi::c_char,
            esp_idf_sys::esp_log_level_t_ESP_LOG_WARN,
        );
    }
    #[cfg(target_os = "espidf")]
    crate::freertos::log_boot_info();
    // USB-OTG nativo (TinyUSB) no PHY interno (GPIO19 D-/GPIO20 D+):
    // console primário no UART0 (`ESP_CONSOLE_UART_DEFAULT` +
    // `ESP_CONSOLE_SECONDARY_NONE` em sdkconfig.defaults.esp32s3) libera o
    // PHY p/ o TinyUSB como dono único — com o default S3 (console
    // USB_SERIAL_JTAG), o USJ reclama o mesmo PHY e o
    // `tinyusb_driver_install` falha (`LoadProhibited` no dump do
    // descritor). USB soma como transporte; a serial (UART0 115200)
    // segue intacta p/ CTAPHID + TEST_*.
    // Ordem funcional inalterada: USB primeiro, serial em seguida (a serial
    // é requisito do `aegis_serial_pop_packet`/`read_chunk`; ver abaixo).
    // Os anúncios saem SÓ depois da serial pronta, via `log::*` (mesmo lock
    // do `ESP_LOG` do C sob `EspLogger`): `kprintln!` (`esp_rom_printf`)
    // furava o lock e intercalava byte-a-byte com a task TinyUSB no UART0
    // (`AegisUSB: TinyUSB2…` truncado). Sem mutex novo, sem tocar no TinyUSB.
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let usb_init_rc: esp_idf_sys::esp_err_t = {
        // SAFETY: sem ponteiros; só instala o driver TinyUSB e lê o retorno.
        unsafe { aegis_usb_init() }
    };
    // Serial CTAPHID UART (UART0 115200, diagnóstico + TEST_*): sem ela,
    // `aegis_serial_pop_packet`/`read_chunk` devolvem 0 para sempre
    // (`s_serial_initialized` do C). Igual ao boot legado.
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let serial_init_rc: esp_idf_sys::esp_err_t = {
        // SAFETY: init idempotente do driver UART0; só lê o código de retorno.
        unsafe { aegis_serial_init() }
    };
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    {
        if usb_init_rc == esp_idf_sys::ESP_OK {
            log::info!("[INIT] TinyUSB FIDO2 HID online (USB-OTG D+/D- 19/20).");
        } else {
            log::warn!(
                "[WARN] TinyUSB init rc=0x{:04X}; CTAPHID segue na serial.",
                usb_init_rc as i32
            );
        }
        if serial_init_rc == esp_idf_sys::ESP_OK {
            log::info!("[INIT] Serial CTAPHID UART online (115200 8N1, framing = USB).");
        } else {
            log::warn!(
                "[WARN] Serial CTAPHID UART init failed (rc={}); USB segue primário.",
                serial_init_rc as i32
            );
        }
    }
    let sched = FreeRtosScheduler::new(DEFAULT_QUEUE_DEPTH);
    let poll_usb = || -> Option<([u8; 64], PacketOrigin)> {
        #[cfg(target_os = "espidf")]
        {
            let mut buf = [0u8; 64];
            // SAFETY: `buf` tem 64 B vivos na stack; o C escreve até 64 B e
            // devolve o total escrito; só aceitamos o pacote se completo (64 B).
            let n = unsafe { aegis_usb_pop_packet(buf.as_mut_ptr(), 64) };
            if n == 64 {
                return Some((buf, PacketOrigin::Usb));
            }
            #[cfg(not(feature = "board-ttgo-classic"))]
            {
                // SAFETY: mesmo `buf` válido por 64 B; drena o canal serial
                // (UART0 diagnóstico); parcial é descartado com `None`.
                let m = unsafe { aegis_serial_pop_packet(buf.as_mut_ptr(), 64) };
                if m == 64 {
                    return Some((buf, PacketOrigin::Serial));
                }
            }
            None
        }
        #[cfg(not(target_os = "espidf"))]
        {
            None
        }
    };
    #[cfg(target_os = "espidf")]
    let usb_h = sched
        .spawn_packet_task_native(poll_usb)
        .expect("spawn usb_ctaphid native");
    #[cfg(not(target_os = "espidf"))]
    let usb_h = sched.spawn_packet_task(poll_usb);
    // Botão sem bloqueio: amostragem direta `is_pressed_raw` (o helper
    // `DualButtonManager::is_boot_pressed` dorme ~1 ms e é proibido em task).
    #[cfg(target_os = "espidf")]
    let btn_h = {
        let boot_input = EspBootButtonInput::new();
        #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
        {
            let key_input = EspKeyButtonInput::new();
            sched
                .spawn_button_task_native(
                    move || boot_input.is_pressed_raw(),
                    move || key_input.is_pressed_raw(),
                )
                .expect("spawn ui_button native")
        }
        #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
        {
            sched
                .spawn_button_task_native(move || boot_input.is_pressed_raw(), {
                    let key_input = EspKeyButtonInput::new();
                    move || key_input.is_pressed_raw()
                })
                .expect("spawn ui_button native")
        }
    };
    #[cfg(not(target_os = "espidf"))]
    let btn_h = sched.spawn_button_task(|| false, || false);
    #[cfg(target_os = "espidf")]
    let hk_h = sched
        .spawn_housekeeping_task_native()
        .expect("spawn housekeeping native");
    #[cfg(not(target_os = "espidf"))]
    let hk_h = sched.spawn_housekeeping_task();
    #[cfg(feature = "proximity")]
    let mut prox = {
        let mut s = crate::proximity_sched::ProxSchedState::new();
        // Boot: `load` ou `rekey` SOMENTE se `bonded || claimed`. O
        // scheduler ainda não observa PairingManager/BindingManager nem
        // NVS (`prox_k`): sem vínculo, fail-closed até `note_paired`.
        s.note_boot(false);
        s
    };
    #[cfg(feature = "proximity")]
    let mut prox_now_ms: u64 = 0;
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Estado TEST_* do dispatcher FreeRTOS (device + test-mode; host inalterado).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut freertos_test = freertos_test_mode::FreertosTestState::new();
    // Linha de diagnóstico (`\n`; máx 48 B como o legado; sem JSON).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut freertos_serial_line: Vec<u8> = Vec::new();
    // Guarda do fio compartilhado UART: o dreno TEST nunca consome bytes
    // no meio de um reassemble CTAPHID (o evento do pacote 1 acorda o loop
    // bem no meio do pacote 2). Assembly pendente segura o dreno (teto
    // 2 s p/ nunca travar o inbox); janela quieta cobre o pacote 1.
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut serial_assembly_since_ms: Option<u64> = None;
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut serial_quiet_until_ms: u64 = 0;
    // Relógio monotónico do dispatcher p/ janelas/testes (atualizado no Tick).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut freertos_test_now_ms: u64 = 0;
    // Roteamento CTAPHID do dispatcher (device): 1 manager por transporte
    // (como `ctaphid_mgr`/`serial_router` no legado) + `CtapEngine` real com
    // a chave do provisionamento (fallback efêmero TRNG, como o legado).
    #[cfg(target_os = "espidf")]
    let mut ctaphid_usb = CtapHidManager::new();
    #[cfg(target_os = "espidf")]
    let mut ctaphid_serial = CtapHidManager::new();
    #[cfg(target_os = "espidf")]
    let (mut ctap_engine, dev_master_key, dev_salt) = {
        use rand_core::RngCore as _;
        let efuse_mgr = EfuseManager::new(RamEfuseStorage::new());
        match load_device_keys(&efuse_mgr) {
            Ok(keys) => {
                kprintln!("[INIT] Hardware Master Key carregada (FreeRTOS CTAPHID).");
                (
                    CtapEngine::new(keys.master_key, 0),
                    keys.master_key,
                    keys.device_salt,
                )
            }
            Err(_) => {
                let mut rng = rand_core::OsRng;
                let mut mk = [0u8; 32];
                let mut salt = [0u8; 32];
                rng.fill_bytes(&mut mk);
                rng.fill_bytes(&mut salt);
                // CI-GREP: TEST-HOOK (test-mode only; absent in release).
                // Sem burn de eFuse: a chave-dev mora em flash NVS
                // (namespace "aegisdev"), reutilizada entre boots.
                #[cfg(feature = "test-mode")]
                match crate::nvs_backend::load_or_create_dev_keys() {
                    Ok((m, s)) => {
                        kprintln!("[TEST] dev-key flash persistente ativa (test-mode only).");
                        mk = m;
                        salt = s;
                    }
                    Err(_) => {
                        kprintln!(
                            "[WARN] eFuse nao provisionado; chaves efemeras TRNG (sem persistencia)."
                        );
                    }
                }
                #[cfg(not(feature = "test-mode"))]
                kprintln!(
                    "[WARN] eFuse nao provisionado; chaves efemeras TRNG (sem persistencia)."
                );
                (CtapEngine::new(mk, 0), mk, salt)
            }
        }
    };
    // USB-OTG nativo (TinyUSB): ATIVO nesta variante (init acima, antes da
    // serial; dono único do PHY interno 19/20 com console no UART0).
    // CTAPHID soma USB + serial (UART0) + TEST_*; sem eFuse/secure/NVS tocados.
    // FreeRTOS: display/LED + BLE + NVS + WiFi + CCID (paridade com o loop
    // legado; o dispatcher CTAPHID acima segue intacto). Tudo `device-only`.
    // Marca d'água da stack da main a cada etapa (caça ao overflow da main).
    #[cfg(target_os = "espidf")]
    let stack_mark = |etapa: &str| {
        // SAFETY: NULL = tarefa corrente (main); só lê o high water mark.
        // `uxTaskGetStackHighWaterMark` retorna em words; ×4 p/ bytes
        // (convenção em freertos.rs:814-825; o rótulo antigo "words" mentia).
        let words = unsafe { esp_idf_sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) };
        let bytes = (words as usize).saturating_mul(4);
        kprintln!("[STACK] main livre após {}: {} bytes.", etapa, bytes);
    };
    #[cfg(target_os = "espidf")]
    let mut display_mgr = {
        kprintln!("[INIT] Display & LED (FreeRTOS).");
        #[cfg(feature = "board-devkitc")]
        let led_controller = {
            let mut led_output = EspWs2812Output::new(48);
            led_output.init_hardware();
            let mut ctrl = Ws2812Controller::new(led_output);
            ctrl.set_effect(LedEffect::Solid(crate::led::Color::SECURE_GUARD_UNPROVISIONED));
            let _ = ctrl.update(Duration::ZERO);
            Some(ctrl)
        };
        #[cfg(not(feature = "board-devkitc"))]
        let led_controller: Option<Ws2812Controller<EspWs2812Output>> = None;
        let mut dm = DisplayManager::new(led_controller);
        let _ = dm.init_hardware();
        dm.set_screen(UiScreen::IdleStandby {
            status_text: "Aguardando solicitação FIDO2...".into(),
        });
        kprintln!("[INIT] UI and visual engine online (FreeRTOS).");
        dm
    };
    #[cfg(target_os = "espidf")]
    stack_mark("display");
    #[cfg(target_os = "espidf")]
    let mut storage = {
        kprintln!("[INIT] Encrypted Storage (FreeRTOS)...");
        let flash_backend = PlatformFlashBackend::new();
        if flash_backend.is_persistent() {
            kprintln!("[INIT] Flash NVS backend online (persiste entre reboots).");
        } else {
            kprintln!("[WARN] Flash NVS indisponivel; RAM volatil (sem persistencia).");
        }
        // Boot health-check `boot_state` NÃO roda aqui: AES/NVS na main
        // pré-yield estourou a stack (~116 B livres → TWDT silencioso).
        // `SecureStorage::new` (HKDF) é barato e fica; o `store` foi
        // diferido p/ após o primeiro yield do loop (ver `boot_state_pending`
        // ao fim da iteração), onde a main já cedeu ao scheduler. 1x por boot.
        SecureStorage::new(flash_backend, &dev_master_key, &dev_salt)
    };
    #[cfg(target_os = "espidf")]
    stack_mark("storage");
    #[cfg(target_os = "espidf")]
    let mut binding_mgr = match crate::binding::BindingManager::load_from_storage(&storage) {
        Ok(m) => {
            kprintln!("[INIT] Binding loaded (claimed={}).", m.is_claimed());
            m
        }
        Err(e) => {
            kprintln!("[WARN] Binding store inconsistent ({e}); starting unclaimed.");
            crate::binding::BindingManager::new()
        }
    };
    #[cfg(target_os = "espidf")]
    let mut pairing_mgr = crate::pairing::PairingManager::new();
    #[cfg(target_os = "espidf")]
    let mut ble_server = crate::ble_gatt::BleGattServer::new();
    #[cfg(target_os = "espidf")]
    let mut ble_rx = [0u8; crate::ble_nimble::BLE_RX_FRAGMENT_MAX];
    #[cfg(target_os = "espidf")]
    let mut ble_start_gate = crate::ble_nimble::BleStartGate::new();
    #[cfg(target_os = "espidf")]
    let mut ble_adv_active = false;
    // Saúde BLE provada (`esp_ble_preinit rc=0` via TEST_BLE_PREINIT): sem
    // ela, o ramo de reconexão sem janela fica mudo (fail-closed). Sem esse
    // gate, o primeiro Tick pós-claim (`claimed` + `Idle`) chamava
    // `esp_ble_start → nimble_port_init` com heap/rádio nunca validado
    // neste HW → `LoadProhibited` determinístico.
    #[cfg(target_os = "espidf")]
    #[allow(unused_mut)]
    let mut ble_preinit_ok = false;
    #[cfg(target_os = "espidf")]
    let mut ble_bond_pending = false;
    #[cfg(target_os = "espidf")]
    let mut pairing_open_prev = false;
    #[cfg(target_os = "espidf")]
    let mut pairing_open_now = false;
    // B2 feedback do hold fisico (transicoes do Arming): mesmo cfg e
    // vizinhanca do bloco da janela (compila onde eles compilam).
    #[cfg(target_os = "espidf")]
    let mut pairing_arming_prev = false;
    #[cfg(target_os = "espidf")]
    let mut pairing_arming_sec: u64 = 0;
    #[cfg(target_os = "espidf")]
    let mut rescue_engine = RescueEngine::new();
    #[cfg(target_os = "espidf")]
    let mut wallet_store = WalletStore::new();
    #[cfg(target_os = "espidf")]
    let mut fw_log = crate::fw_log::FwLog::new();
    #[cfg(target_os = "espidf")]
    let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
    #[cfg(target_os = "espidf")]
    let mut oath_applet = OathApplet::new();
    #[cfg(target_os = "espidf")]
    {
        fw_log.record(crate::fw_log::EV_BOOT, 0, 0);
        if !crate::vendor_exec::load_states(&storage, &mut key_mgr, &mut oath_applet) {
            kprintln!("[WARN] vendor NVS inconsistente; começando vazio.");
        }
        if !crate::vendor_exec::load_pin_state(&storage, &mut ctap_engine.pin_state) {
            kprintln!("[WARN] PIN NVS inconsistente; sem PIN.");
        }
        let secure_guard = crate::secure_guard_storage::load_secure_guard_record(&storage, 0);
        kprintln!(
            "[INIT] Secure Guard online (state={:?}, provisioned={}).",
            secure_guard.state(),
            secure_guard.is_provisioned()
        );
    }
    #[cfg(target_os = "espidf")]
    let mut secure_guard = crate::secure_guard_storage::load_secure_guard_record(&storage, 0);
    #[cfg(target_os = "espidf")]
    {
        if let Some(ref mut led) = display_mgr.led_controller {
            led.set_effect(crate::pairing_led::effect_for_secure_guard_state(secure_guard.state()));
            let _ = led.update(Duration::ZERO);
        }
    }
    #[cfg(target_os = "espidf")]
    stack_mark("binding+managers");
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_mgr = crate::wifi_ap::WifiApManager::new();
    #[cfg(target_os = "espidf")]
    let mut mdns_mgr = crate::mdns::MdnsManager::new();
    #[cfg(target_os = "espidf")]
    let mut sta_mgr = crate::wifi_station::WifiStationManager::new();
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_active = false;
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_last_try_ms: u64 = 0;
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_fails: u32 = 0;
    #[cfg(target_os = "espidf")]
    let mut mdns_active = false;
    #[cfg(target_os = "espidf")]
    let mut wifi_radio_on = false;
    #[cfg(target_os = "espidf")]
    let mut last_sta_attempt_ms: Option<u64> = None;
    #[cfg(target_os = "espidf")]
    let mut ccid_transport = aegis_fido_usb::ccid::CcidTransport::new();
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Latch de cor solida p/ diagnostico LED (TEST_LED_*).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut led_test_hold: Option<LedEffect> = None;
    // Nível do BOOT p/ `PairingManager` (hold 5s abre pareamento) e TOTP.
    #[cfg(target_os = "espidf")]
    let mut boot_held_since_ms: Option<u64> = None;
    #[cfg(target_os = "espidf")]
    let mut totp_display_until: u64 = 0;
    #[cfg(target_os = "espidf")]
    let mut totp_account_idx: usize = 0;
    // Watchdog da main task (paridade legada: `Watchdog::new(300)` + feed
    // por poll). Sem ele, trechos lentos de init/loop matam a IDLE0 no TWDT.
    #[cfg(target_os = "espidf")]
    let mut freertos_watchdog = crate::watchdog::Watchdog::new(300);
    #[cfg(all(target_os = "espidf", feature = "proximity"))]
    {
        // Boot: K_prox em RAM se vínculo prévio (fail-closed caso contrário);
        // `note_paired` no bonding gera o próximo (ctr=0).
        // T12-parte-B: fia o vínculo TrustFacade no scheduler (BindingWire):
        // `sync_trust_claimed` espelha `binding_mgr.is_claimed()`; sem ela,
        // `trusted = bonded` (fail-closed). `sync_from_trust`/`open_gaps`
        // seguem para a T8; secmon (universal-device-sdk) segue ExternallyBlocked.
        let trusted = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
        prox.note_boot(trusted);
        prox.sync_trust_claimed(binding_mgr.is_claimed());
    }
    #[cfg(target_os = "espidf")]
    {
        kprintln!("[INIT] managers ok (FreeRTOS).");
        // BLE init é preguiçoso (lazy): `esp_ble_preinit` no boot trava
        // neste HW (LoadProhibited no `esp_intr_alloc` do controller — em
        // investigação). O adv liga via gate no loop (`esp_ble_start` →
        // `ensure_init`) e o diagnóstico sob demanda vem por TEST_BLE_PREINIT.
        // Boot segue sem BLE; CTAPHID/TEST/NVS/LED vivos.
        kprintln!("[INIT] BLE init lazy (sem preinit no boot; ver TEST_BLE_PREINIT).");
        kprintln!("============================================================");
        kprintln!("   AegisKey S3 Authenticator ONLINE & ACTIVE! (FreeRTOS)");
        kprintln!("   FIDO2 / WebAuthn ready on native USB (HID Usage Page 0xF1D0)");
        kprintln!("============================================================");
    }
    // Latch UP 1x (BOOT físico ou TEST_UP), com expiração de 1,5 s.
    #[cfg(target_os = "espidf")]
    let mut touch_latched = false;
    let mut pin_verified = false;
    #[cfg(target_os = "espidf")]
    let mut touch_expire_ms: u64 = 0;
    // Relógio do roteamento CTAPHID (atualizado a cada Tick10ms).
    #[cfg(target_os = "espidf")]
    let mut freertos_now_ms: u64 = 0;
    // Health-check de boot diferido: `true` até o primeiro `store` pós-yield.
    // O `receive` abaixo é o primeiro ponto onde a main cede ao scheduler;
    // só depois dele há stack folgada p/ AES/NVS. Executa 1x por boot.
    #[cfg(target_os = "espidf")]
    let mut boot_state_pending = true;
    #[cfg(not(target_os = "espidf"))]
    {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < std::time::Duration::from_secs(2) {
            match sched.queue.receive(Some(100)) {
                Some(FirmwareEvent::UsbPacket(pkt)) => {
                    kprintln!("[FREERTOS] usb packet ({} B).", pkt.len());
                }
                Some(FirmwareEvent::SerialPacket(pkt)) => {
                    kprintln!("[FREERTOS] serial packet ({} B).", pkt.len());
                }
                Some(FirmwareEvent::ButtonPress { boot, key }) => {
                    kprintln!("[FREERTOS] UP latch boot={} key={}.", boot, key);
                    #[cfg(feature = "proximity")]
                    if boot {
                        prox.note_presence(prox_now_ms);
                    }
                }
                Some(FirmwareEvent::Tick10ms(t)) => {
                    if t % 100 == 0 {
                        kprintln!("[FREERTOS] tick {}.", t);
                    }
                    #[cfg(feature = "proximity")]
                    {
                        prox_now_ms = t.saturating_mul(10);
                        // USB veta o beacon; no host, sem driver: inativo.
                        #[cfg(target_os = "espidf")]
                        // SAFETY: `aegis_usb_is_mounted` só lê o estado do
                        // driver TinyUSB; sem ponteiros, sem escrita.
                        let usb_active = unsafe { aegis_usb_is_mounted() };
                        #[cfg(not(target_os = "espidf"))]
                        let usb_active = false;
                        // Sem WiFi no dispatcher: intervalo sempre normal
                        // (gap: desacelerar quando o WiFi entrar na coex
                        // `USB > WiFi > BLE`). Sem PairingManager: `Idle`
                        // (gap: ligar à janela real de pareamento).
                        prox.tick(
                            prox_now_ms,
                            usb_active,
                            false,
                            crate::pairing::PairingState::Idle,
                        );
                    }
                }
                Some(FirmwareEvent::BleFragment(_, len)) => {
                    kprintln!("[FREERTOS] ble fragment ({} B).", len);
                    // Gap PROX: sem dispatch GATT no scheduler — `note_paired`
                    // (rekey + ctr=0 dos 2 `Paired`), `erase` (`BIND_RELEASE`/
                    // `RECOVERY_UNLOCK`) e RSSI vivem no loop legado; o tick
                    // ~1 s aqui segue fail-closed (sem chave, sem adv).
                }
                Some(FirmwareEvent::Shutdown) => {
                    kprintln!("[FREERTOS] shutdown.");
                    #[cfg(feature = "proximity")]
                    {
                        prox.erase();
                        kprintln!("[PROX] K_prox zerado no shutdown.");
                    }
                    break;
                }
                None => {}
            }
        }
        sched.request_stop();
    }
    #[cfg(target_os = "espidf")]
    loop {
        // CI-GREP: TEST-HOOK (test-mode only; absent in release).
        // Drena linhas de diagnóstico sem bloquear (o `receive` abaixo dá o
        // timeout; sem `sleep`). Fora da classic usa `aegis_serial_*`
        // (igual ao poll USB binário); na classic o canal já é o USB.
        // Binário 64 B segue na task USB; aqui só texto `\n`, nunca quebra
        // reassemble (uso idle, como o D1 legado).
        #[cfg(feature = "test-mode")]
        {
            // Fio compartilhado UART: o dreno TEST só lê com o CTAPHID
            // quieto. O evento do pacote 1 acorda o loop bem no meio do
            // pacote 2; sem a guarda, o dreno comia bytes do frame e o
            // reassemble multi-pacote morria (MC/GA mudos). Assembly
            // pendente segura o dreno (teto 2 s); janela quieta cobre a
            // chegada do pacote 1.
            let pending = ctaphid_serial.has_pending_assembly();
            if pending && serial_assembly_since_ms.is_none() {
                serial_assembly_since_ms = Some(freertos_now_ms);
            } else if !pending {
                serial_assembly_since_ms = None;
            }
            let assembly_hold = pending
                && serial_assembly_since_ms
                    .is_some_and(|since| freertos_now_ms.saturating_sub(since) < 2000);
            let wire_free = !assembly_hold && freertos_now_ms >= serial_quiet_until_ms;
            let mut chunk = [0u8; 32];
            // SAFETY: `chunk` tem 32 B vivos na stack; o C escreve até 32 B e
            // devolve o total; só lemos `chunk[..n]`. Com fio ocupado (n=0),
            // nada é consumido: o frame segue intacto p/ o reassemble.
            let n = if wire_free {
                serial_read_chunk(&mut chunk, 32)
            } else {
                0
            };
            for b in chunk.iter().take(n as usize) {
                if *b == b'\n' {
                    if let Ok(line) = core::str::from_utf8(&freertos_serial_line) {
                        // TEST_UP arma o latch SINCRONAMENTE aqui (o ack já
                        // sai com latch válido). UP momentaneo: latch +
                        // presença, SEM pairar. (Hold físico vem da borda
                        // do botão; TEST nunca abre janela sozinho —
                        // janelas de teste usam TEST_PAIRING_OPEN[_300].)
                        if line.trim() == "TEST_UP" {
                            touch_latched = true;
                            touch_expire_ms = freertos_now_ms.saturating_add(8000);
                            rescue_engine.set_user_presence(true);
                            #[cfg(feature = "proximity")]
                            prox.note_presence(prox_now_ms);
                        }
                        // CI-GREP: TEST-HOOK (test-mode only): preinit BLE sob
                        // demanda (diagnóstico do crash de boot; sem reboot).
                        #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                        if line.trim() == "TEST_BLE_PREINIT" {
                            kprintln!("[TEST] ble preinit on demand...");
                            // Prova de heap p/ o `Malloc failed` (emi.c:164): livre +
                            // maior bloco contíguo antes/depois (fragmentação, não
                            // vazamento). O C (`ensure_init`) também loga via ESP_LOGI.
                            // SAFETY: só lê estatísticas do heap; sem ponteiros, sem escrita.
                            let free_before = unsafe { esp_idf_sys::esp_get_free_heap_size() };
                            // SAFETY: `MALLOC_CAP_DEFAULT` só seleciona o heap; sem
                            // ponteiros, sem escrita; devolve o maior bloco livre.
                            let largest_before = unsafe {
                                esp_idf_sys::heap_caps_get_largest_free_block(
                                    esp_idf_sys::MALLOC_CAP_DEFAULT,
                                )
                            };
                            kprintln!(
                                "[BLE] heap antes livre={} maior={}.",
                                free_before,
                                largest_before
                            );
                            let rc = crate::ble_nimble::esp_ble_preinit();
                            // SAFETY: mesma leitura pós-preinit; sem ponteiros, sem escrita.
                            let free_after = unsafe { esp_idf_sys::esp_get_free_heap_size() };
                            // SAFETY: mesma leitura do maior bloco; sem ponteiros, sem escrita.
                            let largest_after = unsafe {
                                esp_idf_sys::heap_caps_get_largest_free_block(
                                    esp_idf_sys::MALLOC_CAP_DEFAULT,
                                )
                            };
                            kprintln!(
                                "[TEST] ble preinit rc={} heap depois livre={} maior={}.",
                                rc,
                                free_after,
                                largest_after
                            );
                            if rc == 0 {
                                ble_preinit_ok = true;
                                kprintln!("[BLE] preinit ok; reconexao sem janela liberada.");
                            }
                            let resp = format!("ble_preinit rc={}\n", rc);
                            serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            freertos_serial_line.clear();
                            continue;
                        }
                        // `touch=` expõe o flag do dispatcher (`touch_latched`)
                        // no `TEST_LED_STATE`/`TEST_LIFETIME_DUMP`: só metadado
                        // textual p/ observabilidade do harness; o latch real
                        // segue intocado (dreno TEST do device, sem cobertura
                        // host — ver teste `led_state_expoe_touch_do_dreno`).
                        let extra = format!(
                            "uptime_s={} up_latched={} touch={}",
                            freertos_test_now_ms / 1000,
                            freertos_test.up_pending() as u8,
                            touch_latched as u8
                        );
                        let outcome = freertos_test_mode::handle_freertos_test_line(
                            &mut freertos_test,
                            line,
                            freertos_test_now_ms,
                            &extra,
                        );
                        // TEST_PAIRING_CLOSE fecha também a janela host em
                        // `pairing_mgr` (placa não reseta entre sessões; uma
                        // janela de sonda anterior ainda vale aqui) e muda o
                        // radio: `shutdown_after_config` + `esp_ap_stop` se o
                        // AP estava on (sem isto o `WifiApManager` seguia
                        // `Active` ate expirar e o poll pedia Start sem heap).
                        if line.trim() == crate::pairing::TEST_PAIRING_CLOSE_CMD {
                            pairing_mgr.close_test_window();
                            wifi_ap_mgr.shutdown_after_config();
                            if wifi_ap_active {
                                let _ = crate::wifi_ap::esp_ap_stop();
                                wifi_ap_active = false;
                                kprintln!("[WIFI] AP off (pairing fechado).");
                            }
                        }
                        if let Some(resp) = outcome.response {
                            // `resp` viva até ao fim da chamada; o C só
                            // lê `len` bytes para TX serial.
                            serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                        }
                        if outcome.reboot_to_download {
                            kprintln!("[TEST] download via software (RTC_CNTL).");
                            // Reboot p/ download ROM via RTC_CNTL;
                            // nunca retorna; sem ponteiros.
                            // SAFETY: reboot via RTC_CNTL; nunca retorna.
                            unsafe {
                                aegis_reboot_to_download();
                            }
                        }
                        if outcome.usb_reconnect {
                            kprintln!("[TEST] usb reconnect via software.");
                            // SAFETY: drop + re-enumera o USB nativo; sem
                            // ponteiros, sem escrita em RAM partilhada.
                            unsafe {
                                aegis_usb_reconnect();
                            }
                        }
                        // CI-GREP: TEST-HOOK (test-mode only): espelha a cor
                        // pedida no LED físico (release devolve ao pipeline).
                        #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                        {
                            use crate::led::Color as LedColor;
                            let t = line.trim();
                            if t.starts_with("TEST_LED_RED") {
                                led_test_hold = Some(LedEffect::Solid(LedColor::RED));
                            } else if t.starts_with("TEST_LED_GREEN") {
                                led_test_hold = Some(LedEffect::Solid(LedColor::GREEN));
                            } else if t.starts_with("TEST_LED_BLUE") {
                                led_test_hold = Some(LedEffect::Solid(LedColor::BLUE));
                            } else if t.starts_with("TEST_LED_OFF") {
                                led_test_hold = Some(LedEffect::Off);
                            } else if t.starts_with("TEST_LED_RELEASE") {
                                led_test_hold = None;
                            }
                            if let Some(h) = led_test_hold {
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(h);
                                }
                            }
                        }
                    }
                    freertos_serial_line.clear();
                } else if freertos_serial_line.len() < 48 {
                    freertos_serial_line.push(*b);
                } else {
                    freertos_serial_line.clear();
                }
            }
        }
        // FreeRTOS: bomba BLE (GAP + FFF1->dispatch->FFF2) + CCID, por
        // iteração (FFI não-bloqueante; USB segue na task dedicada).
        #[cfg(target_os = "espidf")]
        {
            // Feed do TWDT da main a cada iteração (paridade legada).
            freertos_watchdog.feed(freertos_now_ms / 10);
            use crate::ble_nimble as ble;
            match ble::esp_ble_poll_event() {
                e if e == ble::BLE_EVT_SECURED => {
                    match ble::on_link_secured(&mut pairing_mgr, touch_latched, freertos_now_ms) {
                        ble::BondOutcome::Paired => {
                            touch_latched = false;
                            ble_bond_pending = false;
                            rescue_engine.set_user_presence(true);
                            let _ = ble::esp_ble_stop();
                            ble_adv_active = false;
                            display_mgr.set_screen(UiScreen::Success {
                                title: "DISPOSITIVO PAREADO".into(),
                                subtitle: "BLE seguro ativo".into(),
                            });
                            if let Some(ref mut led) = display_mgr.led_controller {
                                led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                            }
                            kprintln!("[BLE] bonding ok (FreeRTOS): advertising parado.");
                            fw_log.record(crate::fw_log::EV_BOND_OK, 0, freertos_now_ms);
                            #[cfg(feature = "proximity")]
                            prox.note_paired(freertos_now_ms);
                        }
                        ble::BondOutcome::DeniedNoPresence => {
                            ble_bond_pending = true;
                            kprintln!("[BLE] link seguro sem UP: toque no BOOT para confirmar.");
                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                rp_id: "Pareamento BLE".into(),
                                user_name: "App AegisKey".into(),
                                operation: "Confirmar pareamento".into(),
                                remaining_seconds: 25,
                            });
                        }
                        ble::BondOutcome::DeniedNoWindow => {
                            kprintln!("[BLE] link seguro fora da janela: ignorado.");
                        }
                    }
                }
                e if e == ble::BLE_EVT_DISCONNECTED => {
                    kprintln!("[BLE] central desconectou.");
                    ble_adv_active = false;
                    ble_bond_pending = false;
                }
                e if e == ble::BLE_EVT_CONNECTED => {
                    kprintln!("[BLE] central conectou (aguardando bonding).");
                }
                _ => {}
            }
            // Bonding pendente: conclui quando o usuario tocar no BOOT.
            #[allow(clippy::collapsible_if)]
            if ble_bond_pending
                && touch_latched
                && pairing_mgr.is_pairing_window_open(freertos_now_ms)
            {
                if ble::on_link_secured(&mut pairing_mgr, true, freertos_now_ms)
                    == ble::BondOutcome::Paired
                {
                    touch_latched = false;
                    ble_bond_pending = false;
                    rescue_engine.set_user_presence(true);
                    let _ = ble::esp_ble_stop();
                    ble_adv_active = false;
                    display_mgr.set_screen(UiScreen::Success {
                        title: "DISPOSITIVO PAREADO".into(),
                        subtitle: "BLE seguro ativo".into(),
                    });
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                    }
                    kprintln!("[BLE] bonding ok (apos UP): advertising parado.");
                    fw_log.record(crate::fw_log::EV_BOND_OK, 0, freertos_now_ms);
                    #[cfg(feature = "proximity")]
                    prox.note_paired(freertos_now_ms);
                }
            }
            // Fragmentos FFF1 -> reassemble -> dispatch -> notify FFF2.
            let rx_n = ble::esp_ble_fetch_rx(&mut ble_rx);
            if rx_n > 0 {
                let up = touch_latched;
                let frag = &ble_rx[..rx_n as usize];
                match ble::feed_control_write(&mut ble_server, frag, up) {
                    Ok(Some(msg)) => {
                        touch_latched = false;
                        ble::esp_ble_set_pending_len(ble::pending_len(&ble_server));
                        let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                        #[cfg(feature = "proximity")]
                        let prox_revoked_op = msg.opcode;
                        ble_dispatch::ble_dispatch_complete(
                            msg,
                            up,
                            pairing_open_now,
                            freertos_now_ms / 1000,
                            &mut ctap_engine,
                            &mut binding_mgr,
                            &mut storage,
                            &mut rescue_engine,
                            &mut wallet_store,
                            bonded,
                            freertos_now_ms,
                            &mut fw_log,
                            &mut key_mgr,
                            &mut oath_applet,
                        );
                        // Wave2: release/recovery apagou a NVS no dispatch;
                        // espelha no cache RAM (fail-closed até o rekey).
                        #[cfg(feature = "proximity")]
                        {
                            use crate::ble_gatt as g;
                            let revoked = prox_revoked_op == g::OP_BIND_RELEASE
                                || prox_revoked_op == g::OP_RECOVERY_UNLOCK;
                            if revoked && crate::proximity::load_proximity_key(&storage).is_err() {
                                prox.erase();
                            }
                        }
                    }
                    Ok(None) => {
                        ble::esp_ble_set_pending_len(ble::pending_len(&ble_server));
                    }
                    Err(e) => {
                        kprintln!("[BLE] fragmento rejeitado: {}", e);
                        let op = frag.first().copied().unwrap_or(0x83);
                        let frame = ble::notify_frame(op, e.to_vendor_status(), &[]);
                        let _ = ble::esp_ble_notify(&frame);
                    }
                }
            }
            // C2. Service CCID frames (F4 PIV; composite interface 2).
            #[cfg(not(feature = "board-ttgo-classic"))]
            {
                // SAFETY: só lê o estado do driver TinyUSB; sem ponteiros.
                let usb_mounted = unsafe { aegis_usb_is_mounted() };
                if usb_mounted {
                    const CCID_FRAME_MAX: usize = 2048;
                    let mut frame = [0u8; CCID_FRAME_MAX];
                    // SAFETY: `frame` tem 2048 B vivos; o C escreve até
                    // 2048 B e devolve o total; só lemos `frame[..n]`.
                    let n =
                        unsafe { aegis_ccid_pop_frame(frame.as_mut_ptr(), CCID_FRAME_MAX as u16) };
                    if n >= 10 {
                        if let Some(rpdu) = crate::ccid_dispatch::process_ccid_frame(
                            &mut ccid_transport,
                            &frame[..n as usize],
                            &mut storage,
                            &mut key_mgr,
                            freertos_now_ms / 1000,
                        ) {
                            if !unsafe { aegis_ccid_send(rpdu.as_ptr(), rpdu.len() as u16) } {
                                kprintln!("[CCID] bulk-IN send falhou ({} B).", rpdu.len());
                            }
                        }
                    }
                }
            }
        }
        match sched.queue.receive(Some(100)) {
            Some(ev @ (FirmwareEvent::UsbPacket(_) | FirmwareEvent::SerialPacket(_))) => {
                // CTAPHID com origem preservada (seção C legada, sem bloqueio):
                // acumula no manager do transporte de entrada, despacha ao
                // `CtapEngine` e responde 64 B pela MESMA origem. Vendor serial
                // (bind-mgmt/wallet/fw-log/rescue/pairing, seção D legada) vai
                // junto no contexto; U2F/OTA/desconhecido cai no engine.
                // Liveness lida NA HORA (não o cache do Tick, atualizado só
                // 1×/s): sem isto, janela recém-aberta (TEST_PAIRING_OPEN /
                // trigger 0x2F) era vista como fechada até o próximo Tick e
                // o gate devolvia 0x05 indevido no mesmo segundo da abertura.
                #[cfg(feature = "test-mode")]
                let pairing_live = pairing_mgr.is_pairing_window_open(freertos_now_ms)
                    || freertos_test.is_pairing_window_open(freertos_now_ms);
                #[cfg(not(feature = "test-mode"))]
                let pairing_live = pairing_mgr.is_pairing_window_open(freertos_now_ms);
                let pin_uv_session = pin_verified
                    || ctap_engine.pin_state.has_valid_pin_uv_session()
                    || (cfg!(feature = "test-mode") && (pairing_live || touch_latched));
                let mut vendor_ctx = SerialVendorCtx {
                    pairing_open: pairing_live,
                    up_latched: touch_latched,
                    now_ms: freertos_now_ms,
                    now_secs: freertos_now_ms / 1000,
                    arm_up: false,
                    pin_verified,
                    binding: &mut binding_mgr,
                    storage: &mut storage,
                    wallet: &mut wallet_store,
                    key_mgr: &mut key_mgr,
                    oath: &mut oath_applet,
                    fwlog: &mut fw_log,
                    rescue: &mut rescue_engine,
                    pairing: &mut pairing_mgr,
                    pin_uv_session,
                    secure_guard: Some(&mut secure_guard),
                };
                let out = route_ctaphid_event(
                    &mut ctaphid_usb,
                    &mut ctaphid_serial,
                    &mut ctap_engine,
                    &ev,
                    touch_latched,
                    freertos_now_ms,
                    freertos_now_ms / 1000,
                    Some(&mut vendor_ctx),
                );
                if out.pin_verified {
                    pin_verified = true;
                }
                if out.arm_up {
                    touch_latched = true;
                    touch_expire_ms = freertos_now_ms.saturating_add(10_000);
                    rescue_engine.set_user_presence(true);
                    #[cfg(feature = "proximity")]
                    prox.note_presence(prox_now_ms);
                } else if out.consumed_up {
                    touch_latched = false;
                }
                // Fio compartilhado UART: marca janela quieta em qualquer
                // pacote serial (recebido ou respondido) p/ o dreno TEST
                // não morder o próximo frame da rajada.
                #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                if matches!(ev, FirmwareEvent::SerialPacket(_))
                    || matches!(out.origin, Some(PacketOrigin::Serial))
                {
                    serial_quiet_until_ms = freertos_now_ms.saturating_add(40);
                }
                if let Some(ref mut led) = display_mgr.led_controller {
                    led.set_effect(crate::pairing_led::effect_for_secure_guard_state(secure_guard.state()));
                }
                if !out.responses.is_empty() {
                    kprintln!(
                        "[FREERTOS] ctaphid resp ({} pkt, origem={:?}).",
                        out.responses.len(),
                        out.origin
                    );
                }
                for pkt in &out.responses {
                    match out.origin {
                        Some(PacketOrigin::Usb) => {
                            // SAFETY: `pkt` vive até ao fim da chamada; o C só
                            // lê 64 B para o endpoint HID de entrada.
                            unsafe {
                                aegis_usb_send_report(pkt.as_ptr(), 64);
                            }
                        }
                        Some(PacketOrigin::Serial) => {
                            // `pkt` vivo até ao fim da chamada; o C só
                            // lê 64 B para TX serial enquadrada.
                            serial_send_bytes(pkt.as_ptr(), 64);
                        }
                        None => {}
                    }
                }
            }
            Some(FirmwareEvent::ButtonPress { boot, key }) => {
                kprintln!("[FREERTOS] UP latch boot={} key={}.", boot, key);
                // UP físico arma o latch 1x do CTAPHID (expira em 1,5 s).
                if boot {
                    touch_latched = true;
                    touch_expire_ms = freertos_now_ms.saturating_add(8000);
                    rescue_engine.set_user_presence(true);
                    pairing_mgr.on_button_level(true, freertos_now_ms);
                    boot_held_since_ms = Some(freertos_now_ms);
                } else {
                    // Borda de soltura: fecha o hold (sem timeout de parede;
                    // borda explicita sobrevive a rajadas de tick).
                    pairing_mgr.on_button_level(false, freertos_now_ms);
                    boot_held_since_ms = None;
                }
                // KEY (GPIO 14) alterna as contas TOTP reais do device.
                if key {
                    let tick10ms = freertos_now_ms / 10;
                    let entries =
                        collect_totp_codes(&mut oath_applet, freertos_now_ms / 1000, true);
                    if entries.is_empty() {
                        totp_display_until = tick10ms.saturating_add(TOTP_SHOW_TICKS);
                        display_mgr.set_screen(UiScreen::Error {
                            message: NO_ACCOUNTS_MSG.into(),
                        });
                    } else {
                        totp_account_idx = (totp_account_idx + 1) % entries.len();
                        let entry = &entries[totp_account_idx];
                        kprintln!("[KEY BUTTON] TOTP '{}' (FreeRTOS).", entry.account);
                        totp_display_until = tick10ms.saturating_add(TOTP_SHOW_TICKS);
                        display_mgr.set_screen(UiScreen::TotpCode {
                            label: entry.account.clone(),
                            code: entry.code.clone(),
                            remaining_seconds: entry.remaining_seconds,
                        });
                    }
                }
                #[cfg(feature = "proximity")]
                if boot {
                    prox.note_presence(prox_now_ms);
                }
            }
            Some(FirmwareEvent::Tick10ms(t)) => {
                if t % 100 == 0 {
                    kprintln!("[FREERTOS] tick {}.", t);
                }
                // Relógio do roteamento + expiração do latch UP (1,5 s).
                freertos_now_ms = t.saturating_mul(10);
                if touch_latched && freertos_now_ms >= touch_expire_ms {
                    touch_latched = false;
                    rescue_engine.set_user_presence(false);
                }
                // Hold fisico por borda: o Tick reavalia o 5s enquanto Arming
                // (a borda arma, o Tick completa). Sem timeout de parede:
                // rajadas de tick matavam o Arming antes dos 5s e a janela
                // nunca abria no hold fisico. Soltura e borda explicita
                // no ButtonPress (acima); sem evento, sem mudanca.
                if matches!(
                    pairing_mgr.state(),
                    crate::pairing::PairingState::Arming { .. }
                ) {
                    pairing_mgr.on_button_level(true, freertos_now_ms);
                }
                // Avança a janela TEST_PAIRING_OPEN[_300] (expira como o hold).
                #[cfg(feature = "test-mode")]
                {
                    freertos_test_now_ms = t.saturating_mul(10);
                    freertos_test.tick(freertos_test_now_ms);
                }
                // Pairing: alimenta nível + tick; borda da janela no fw-log.
                pairing_mgr.tick(freertos_now_ms);
                {
                    use crate::fw_log as fl;
                    #[cfg(feature = "test-mode")]
                    let test_open = freertos_test.is_pairing_window_open(freertos_now_ms);
                    #[cfg(not(feature = "test-mode"))]
                    let test_open = false;
                    pairing_open_now =
                        pairing_mgr.is_pairing_window_open(freertos_now_ms) || test_open;
                    if pairing_open_now && !pairing_open_prev {
                        fw_log.record(fl::EV_PAIR_OPEN, 0, freertos_now_ms);
                        kprintln!("[PAIRING] janela aberta 60s — pareando.");
                    } else if !pairing_open_now && pairing_open_prev {
                        fw_log.record(fl::EV_PAIR_CLOSE, 0, freertos_now_ms);
                        // Close/timeout (Locked): radio mudo no close. O
                        // `WifiApManager` so expira por tempo; sem isto ele
                        // seguia `Active` apos o close e, caido o veto BLE, o
                        // poll pedia Start sem heap -> OOM/abort do IDF.
                        wifi_ap_mgr.shutdown_after_config();
                        if wifi_ap_active {
                            let _ = crate::wifi_ap::esp_ap_stop();
                            wifi_ap_active = false;
                            kprintln!("[WIFI] AP off (pairing fechado).");
                        }
                    }
                    pairing_open_prev = pairing_open_now;
                    // B2: transicoes do hold fisico (visivel sem display/LCD).
                    {
                        use crate::pairing::PairingState;
                        match pairing_mgr.state() {
                            PairingState::Arming { start_ms } => {
                                if !pairing_arming_prev {
                                    kprintln!("[PAIRING] segurando BOOT... (mantenha 5s p/ abrir a janela).");
                                    pairing_arming_prev = true;
                                    pairing_arming_sec = 0;
                                }
                                let held = freertos_now_ms.saturating_sub(start_ms) / 1000;
                                if held > pairing_arming_sec && held < 60 {
                                    pairing_arming_sec = held;
                                    kprintln!("[PAIRING] segurando... {}s.", held);
                                }
                            }
                            _ => {
                                if pairing_arming_prev {
                                    pairing_arming_prev = false;
                                    // Saiu do Arming sem janela = soltou cedo (o
                                    // caso de sucesso passa pela borda da janela).
                                    if !pairing_open_now {
                                        kprintln!("[PAIRING] solto cedo, sem janela (segure 5s).");
                                    }
                                }
                            }
                        }
                    }
                }
                binding_mgr.tick(freertos_now_ms);
                let _ = binding_mgr.is_claimed();
                // WiFi (paridade legada): AP em pareamento, station fora dele
                // com backoff, mDNS com station up, radio off fora de uso.
                // Precedência: USB > WiFi > BLE (BLE desliga com WiFi ativo).
                wifi_ap_mgr.update(pairing_open_now, false, freertos_now_ms);
                let ap_want = wifi_ap_mgr.is_active(freertos_now_ms);
                if !ap_want {
                    wifi_ap_fails = 0;
                }
                {
                    use crate::ble_nimble as ble;
                    // Gate BLE ao vivo (Fix gate TEST): `TEST_PAIRING_OPEN`
                    // arma a janela em `freertos_test`, não em `pairing_mgr`.
                    // Sem o OR o adv nunca ligava em janela TEST (só o AP
                    // subia). Espelha o `pairing_live` do despacho vendor;
                    // `should_advertise` preserva o mute em `PairingAp`.
                    #[cfg(feature = "test-mode")]
                    let ble_pairing_now = ble::should_advertise(&pairing_mgr, freertos_now_ms)
                        || freertos_test.is_pairing_window_open(freertos_now_ms);
                    #[cfg(not(feature = "test-mode"))]
                    let ble_pairing_now = ble::should_advertise(&pairing_mgr, freertos_now_ms);
                    match crate::wifi_ap::ap_poll_action(ap_want, ble_pairing_now, wifi_ap_active) {
                        crate::wifi_ap::ApPollAction::Start => {
                            if wifi_ap_fails < 3
                                && (wifi_ap_last_try_ms == 0
                                    || freertos_now_ms.saturating_sub(wifi_ap_last_try_ms) >= 5000)
                            {
                                // Guarda de heap: sem bloco contiguo o driver
                                // aborta (OOM) em vez de retornar erro.
                                #[cfg(target_os = "espidf")]
                                // SAFETY: só lê o maior bloco livre do heap; sem ponteiros, sem escrita.
                                let largest: usize = unsafe {
                                    esp_idf_sys::heap_caps_get_largest_free_block(
                                        esp_idf_sys::MALLOC_CAP_DEFAULT,
                                    )
                                };
                                #[cfg(not(target_os = "espidf"))]
                                let largest: usize = usize::MAX;
                                if !crate::wifi_ap::wifi_ap_start_allowed(largest) {
                                    wifi_ap_last_try_ms = freertos_now_ms;
                                    kprintln!("[WIFI] AP skip (heap curto).");
                                } else {
                                    wifi_ap_last_try_ms = freertos_now_ms;
                                    let ssid = crate::wifi_ap::ap_ssid_for_serial(
                                        usb_descriptors::SERIAL_NUMBER_STRING,
                                    );
                                    let pass_bytes = storage
                                        .load(crate::wifi_ap::WIFI_PASS_NVS_KEY)
                                        .unwrap_or_default();
                                    let pass_opt = crate::wifi_ap::resolve_ap_password(
                                        if pass_bytes.is_empty() {
                                            None
                                        } else {
                                            Some(&pass_bytes)
                                        },
                                    );
                                    let pass_str = pass_opt.unwrap_or_default();
                                    let rc = crate::wifi_ap::esp_ap_start(&ssid, &pass_str);
                                    if rc == 0 {
                                        wifi_ap_active = true;
                                        wifi_ap_fails = 0;
                                        kprintln!("[WIFI] AP '{}' on (pareamento).", ssid);
                                    } else if rc == crate::wifi_ap::WIFI_AP_RC_NO_MEM {
                                        // NO_MEM terminal ate nova borda, sem retry.
                                        wifi_ap_fails = 3;
                                        kprintln!(
                                            "[WIFI] AP start rc=-4 NO_MEM (terminal ate nova borda)."
                                        );
                                    } else {
                                        wifi_ap_fails = wifi_ap_fails.saturating_add(1);
                                        if wifi_ap_fails == 1 {
                                            kprintln!("[WIFI] AP start rc={} (backoff 5s).", rc);
                                        }
                                    }
                                }
                            }
                        }
                        crate::wifi_ap::ApPollAction::Stop => {
                            let _ = crate::wifi_ap::esp_ap_stop();
                            wifi_ap_active = false;
                            kprintln!("[WIFI] AP off.");
                        }
                        crate::wifi_ap::ApPollAction::None => {}
                    }
                    let has_creds = crate::wifi_station::has_station_credentials(&storage);
                    sta_mgr.update(pairing_open_now, has_creds, freertos_now_ms);
                    let mut sta_radio = crate::wifi_station::esp_sta_state();
                    if sta_radio == crate::wifi_station::STA_CONNECTED {
                        if !sta_mgr.is_up() {
                            sta_mgr.on_connected();
                            let ip = crate::wifi_station::esp_sta_ip();
                            kprintln!(
                                "[WIFI] station conectada (DHCP {}.{}.{}.{}).",
                                ip[0],
                                ip[1],
                                ip[2],
                                ip[3]
                            );
                        }
                    } else if sta_radio == crate::wifi_station::STA_FAILED {
                        sta_mgr.on_failed();
                    }
                    if matches!(
                        sta_mgr.state(),
                        crate::wifi_station::WifiStationState::Connecting { .. }
                    ) && sta_radio == crate::wifi_station::STA_OFF
                        && !pairing_open_now
                        && !ble_pairing_now
                        && crate::wifi_station::sta_retry_due(freertos_now_ms, last_sta_attempt_ms)
                    {
                        let got = storage.load(crate::wifi_station::WIFI_STA_SSID_NVS_KEY);
                        let got_pass = storage.load(crate::wifi_station::WIFI_STA_PASS_NVS_KEY);
                        match (got, got_pass) {
                            (Ok(ssid_b), Ok(pass_b)) => {
                                match (core::str::from_utf8(&ssid_b), core::str::from_utf8(&pass_b))
                                {
                                    (Ok(ssid), Ok(pass)) => {
                                        let rc = crate::wifi_station::esp_sta_start(ssid, pass);
                                        last_sta_attempt_ms = Some(freertos_now_ms);
                                        if rc != 0 {
                                            kprintln!("[WIFI] station start rc={}.", rc);
                                            sta_mgr.on_failed();
                                        }
                                    }
                                    _ => sta_mgr.on_failed(),
                                }
                            }
                            _ => sta_mgr.on_failed(),
                        }
                    }
                    if (pairing_open_now || ble_pairing_now || !has_creds)
                        && sta_radio != crate::wifi_station::STA_OFF
                    {
                        let _ = crate::wifi_station::esp_sta_stop();
                        sta_mgr.disconnect();
                        #[allow(unused_assignments)]
                        {
                            sta_radio = crate::wifi_station::STA_OFF;
                        }
                    }
                    mdns_mgr.update(pairing_open_now || ble_pairing_now, sta_mgr.is_up());
                    let mdns_want = mdns_mgr.is_active();
                    if mdns_want != mdns_active {
                        if mdns_want {
                            let host = crate::mdns::mdns_hostname_for_serial(
                                usb_descriptors::SERIAL_NUMBER_STRING,
                            );
                            let bare = crate::mdns::mdns_bare_hostname(&host);
                            let rc = crate::mdns::esp_mdns_start(bare);
                            if rc == 0 {
                                mdns_active = true;
                                kprintln!("[WIFI] mDNS '{}' on.", host);
                            } else {
                                kprintln!("[WIFI] mDNS start rc={}.", rc);
                            }
                        } else {
                            let _ = crate::mdns::esp_mdns_stop();
                            mdns_active = false;
                        }
                    }
                    sta_radio = crate::wifi_station::esp_sta_state();
                    let radio_in_use = wifi_ap_active || sta_radio != crate::wifi_station::STA_OFF;
                    if !radio_in_use && wifi_radio_on {
                        let _ = crate::wifi_ap::esp_wifi_off();
                        wifi_radio_on = false;
                        kprintln!("[WIFI] radio off (bateria).");
                    } else if radio_in_use {
                        wifi_radio_on = true;
                    }
                    // BLE real: adv na janela de pareamento; reconexão de
                    // confiável sem janela SÓ com saúde BLE provada
                    // (`ble_preinit_ok` via TEST_BLE_PREINIT rc=0).
                    // Fail-closed: sem preinit saudável, o Tick pós-claim
                    // (claimed + Idle) fica mudo em vez de chamar
                    // `esp_ble_start → nimble_port_init` (LoadProhibited).
                    let trusted = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                    // Mesmo gate vivo do AP/BLE acima: janela TEST
                    // (`freertos_test`) também pede adv; sem isto o Tick
                    // pós-`TEST_PAIRING_OPEN` ficava mudo (sem EV_ADV_START).
                    let ble_want_adv = ble_pairing_now
                        || (ble_preinit_ok
                            && ble::should_advertise_reconnect(pairing_mgr.state(), trusted));
                    if ble_want_adv != ble_adv_active {
                        if ble_want_adv {
                            let wifi_active =
                                wifi_ap_mgr.is_active(freertos_now_ms) || sta_mgr.is_up();
                            if ble::BleStartGate::allow(&mut ble_start_gate, true, freertos_now_ms)
                            {
                                let rc = ble::esp_ble_start(pairing_open_now, wifi_active);
                                if rc == ble::BLE_ADV_RC_NOMEM {
                                    // 519 residual: registra e NAO consome retry.
                                    ble_start_gate.on_nomem();
                                    fw_log.record(crate::fw_log::EV_ADV_NOMEM, 0, freertos_now_ms);
                                    kprintln!(
                                        "[BLE] adv start rc=519 NOMEM (residual; sem gastar retry)."
                                    );
                                } else {
                                    ble_start_gate.on_result(rc == 0);
                                    if rc == 0 {
                                        ble_adv_active = true;
                                        fw_log.record(
                                            crate::fw_log::EV_ADV_START,
                                            0,
                                            freertos_now_ms,
                                        );
                                    } else {
                                        kprintln!("[BLE] adv start rc={} (backoff 5s).", rc);
                                    }
                                }
                            }
                        } else {
                            let _ = ble::esp_ble_stop();
                            ble_adv_active = false;
                            ble_bond_pending = false;
                            ble_start_gate.allow(false, freertos_now_ms);
                            fw_log.record(crate::fw_log::EV_ADV_STOP, 0, freertos_now_ms);
                        }
                    }
                }
                #[cfg(feature = "proximity")]
                {
                    prox_now_ms = freertos_now_ms;
                    // USB veta o beacon (controlador dedicado tem prioridade).
                    // SAFETY: `aegis_usb_is_mounted` só lê o estado do
                    // driver TinyUSB; sem ponteiros, sem escrita.
                    let usb_active = unsafe { aegis_usb_is_mounted() };
                    // TEST_UP (test-mode): 1 UP software, consumo único
                    // (latch 1,5 s + presença p/ BLE/rescue). SEM pairar:
                    // hold de teste nao abre janela (janelas de teste
                    // usam TEST_PAIRING_OPEN[_300]).
                    #[cfg(feature = "test-mode")]
                    if freertos_test.take_up() {
                        touch_latched = true;
                        touch_expire_ms = prox_now_ms.saturating_add(1500);
                        rescue_engine.set_user_presence(true);
                        prox.note_presence(prox_now_ms);
                        kprintln!("[TEST] UP via software CONFIRMED (latch 1x).");
                    }
                    let wifi_active = wifi_ap_mgr.is_active(freertos_now_ms) || sta_mgr.is_up();
                    prox.tick(prox_now_ms, usb_active, wifi_active, pairing_mgr.state());
                    // Proximidade acoplada diretamente ao Secure Guard:
                    let prox_is_away = matches!(prox.state(), crate::proximity::ProximityState::Away | crate::proximity::ProximityState::Locked);
                    let _ = secure_guard.on_ble_proximity_update(
                        secure_guard.paired_ble_mac(),
                        if prox_is_away { -90 } else { -40 },
                        prox_is_away,
                        freertos_now_ms,
                    );
                }
                // Display + LED (seção B legada): tick + efeito por estado.
                // TEST_LED_* (hold) vence o pipeline quando armado.
                display_mgr.tick(Duration::from_millis(freertos_now_ms));
                {
                    let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                    if matches!(display_mgr.current_screen, UiScreen::IdleStandby { .. }) {
                        if let Some(ref mut led) = display_mgr.led_controller {
                            if pairing_mgr.state() != crate::pairing::PairingState::Idle {
                                led.set_effect(crate::pairing_led::effect_for_pairing_state(
                                    pairing_mgr.state(),
                                    bonded,
                                ));
                            } else {
                                led.set_effect(crate::pairing_led::effect_for_secure_guard_state(
                                    secure_guard.state(),
                                ));
                            }
                        }
                    }
                }
                #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                if let Some(held) = led_test_hold {
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(held);
                    }
                }
                // Hold físico: 5s abre pareamento (via PairingManager), 2s
                // calcula TOTP no device (WAVE8, sem segredo no log).
                if let Some(since) = boot_held_since_ms {
                    use crate::pairing_flow as pf;
                    let held_ms = freertos_now_ms.saturating_sub(since);
                    let hold_action = pf::classify_hold(held_ms, pairing_open_now);
                    if hold_action == pf::HoldAction::Totp && totp_display_until <= t {
                        totp_display_until = t.saturating_add(TOTP_SHOW_TICKS);
                        let entries =
                            collect_totp_codes(&mut oath_applet, freertos_now_ms / 1000, true);
                        if entries.is_empty() {
                            display_mgr.set_screen(UiScreen::Error {
                                message: NO_ACCOUNTS_MSG.into(),
                            });
                        } else {
                            totp_account_idx %= entries.len();
                            let entry = &entries[totp_account_idx];
                            kprintln!(
                                "[TOTP] '{}' ({} conta(s), FreeRTOS).",
                                entry.account,
                                entries.len()
                            );
                            display_mgr.set_screen(UiScreen::TotpCode {
                                label: entry.account.clone(),
                                code: entry.code.clone(),
                                remaining_seconds: entry.remaining_seconds,
                            });
                        }
                    }
                }
                if totp_display_until > 0 && t >= totp_display_until {
                    totp_display_until = 0;
                    display_mgr.set_screen(UiScreen::IdleStandby {
                        status_text: "Aguardando solicitação FIDO2...".into(),
                    });
                } else if totp_display_until > t && t % 100 == 0 {
                    let entries =
                        collect_totp_codes(&mut oath_applet, freertos_now_ms / 1000, true);
                    if !entries.is_empty() {
                        totp_account_idx %= entries.len();
                        let entry = &entries[totp_account_idx];
                        display_mgr.set_screen(UiScreen::TotpCode {
                            label: entry.account.clone(),
                            code: entry.code.clone(),
                            remaining_seconds: entry.remaining_seconds,
                        });
                    }
                }
                // Sem proximidade o latch UP não tem onde ancorar: consome e
                // mantém só o ack já enviado (documentado; sem latch).
                #[cfg(all(feature = "test-mode", not(feature = "proximity")))]
                if freertos_test.take_up() {
                    kprintln!("[TEST] UP sem prox (ack já enviado, sem latch).");
                }
                // Tick periódico do Secure Guard (expiração por tempo e inatividade).
                let prev_sg_st = secure_guard.state();
                crate::secure_guard_sched::tick_secure_guard(&mut secure_guard, freertos_now_ms);
                if secure_guard.state() != prev_sg_st {
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(crate::pairing_led::effect_for_secure_guard_state(secure_guard.state()));
                    }
                }
            }
            Some(FirmwareEvent::BleFragment(_, len)) => {
                // Via task dedicada (nenhuma ativa hoje): o poll direto
                // `esp_ble_fetch_rx` + `ble_dispatch_complete` roda a cada
                // iteração do loop acima (bonding, BIND, vendor, OATH vivos).
                kprintln!("[FREERTOS] ble fragment ({} B, via task).", len);
            }
            Some(FirmwareEvent::Shutdown) => {
                kprintln!("[FREERTOS] shutdown.");
                let _ = secure_guard.on_transport_disconnect(freertos_now_ms);
                kprintln!("[SECURE_GUARD] Sessão do Secure Guard invalidada no shutdown.");
                #[cfg(feature = "proximity")]
                {
                    prox.erase();
                    kprintln!("[PROX] K_prox zerado no shutdown.");
                }
                break;
            }
            None => {}
        }
        // Health-check de boot (1x): roda SÓ após o primeiro yield (`receive`
        // acima cedeu ao scheduler), nunca na main pré-yield onde a stack tem
        // ~116 B. Log equivalente ao health-check original.
        #[cfg(target_os = "espidf")]
        if boot_state_pending {
            boot_state_pending = false;
            let init_nonce = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ];
            match storage.store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce) {
                Ok(()) => kprintln!("[INIT] boot_state ok (pos-yield, 1x/boot)."),
                Err(_) => kprintln!("[WARN] boot_state nao persistiu (segue sem NVS)."),
            }
        }
    }
    let _ = usb_h.join();
    let _ = btn_h.join();
    let _ = hk_h.join();
    kprintln!("[FREERTOS] scheduler stopped.");
}
