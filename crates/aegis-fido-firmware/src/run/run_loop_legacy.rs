//! Legacy authenticator loop (D4 split from `run`, single owner).
//!
//! `run_authenticator`: poll loop USB + serial + BLE + CCID (super-loop
//! legado; com feature `freertos` vira fallback via `allow(dead_code)`).
//!
//! Contract (R15/R16): move-only de `run/mod.rs`; `use super::*` mantem
//! o escopo do pai identico (helpers, FFI, cfgs); fio byte-a-byte.
use super::*;

#[cfg_attr(feature = "freertos", allow(dead_code))]
pub fn run_authenticator() {
    kprintln!("\r\n============================================================");
    kprintln!("   AegisKey S3 Authenticator - Firmware Booting up");
    kprintln!("   Target: ESP32-S3 (Dual-Core Xtensa LX7 @ 240MHz)");
    kprintln!(
        "   VID: 0x{:04X} | PID: 0x{:04X}",
        usb_descriptors::USB_VID,
        usb_descriptors::USB_PID
    );
    kprintln!("   Manufacturer: {}", usb_descriptors::MANUFACTURER_STRING);
    kprintln!("   Product:      {}", usb_descriptors::PRODUCT_STRING);
    kprintln!("   Serial:       {}", usb_descriptors::SERIAL_NUMBER_STRING);
    kprintln!("   AAGUID:       00010203-0405-0607-0809-0a0b0c0d0e0f");
    kprintln!("============================================================");

    // 0. Initialize Native Hardware USB-OTG Peripheral with TinyUSB HID (Usage Page 0xF1D0) FIRST
    kprintln!("[INIT] Initializing ESP32-S3 Native USB-OTG Controller as FIDO2 CTAPHID...");
    #[cfg(target_os = "espidf")]
    let usb_installed = unsafe {
        let err = aegis_usb_init();
        if err == esp_idf_sys::ESP_OK {
            kprintln!("[INIT] Native TinyUSB FIDO2 HID Driver installed successfully!");
            true
        } else {
            kprintln!("[WARN] USB driver returned code: 0x{:04X}", err);
            false
        }
    };
    #[cfg(not(target_os = "espidf"))]
    let usb_installed = true;
    #[cfg(not(target_os = "espidf"))]
    let _ = usb_installed;
    // Serial CTAPHID UART ready flag (classic reuses the UART transport above;
    // S3/S2 bring up UART0 as the diagnostic channel next to native USB).
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let serial_installed = unsafe {
        if aegis_serial_init() == esp_idf_sys::ESP_OK {
            kprintln!("[INIT] Serial CTAPHID UART online (115200 8N1, framing = USB).");
            true
        } else {
            kprintln!("[WARN] Serial CTAPHID UART init failed; USB stays primary.");
            false
        }
    };
    #[cfg(all(target_os = "espidf", feature = "board-ttgo-classic"))]
    let serial_installed = usb_installed;

    // 1. Initialize Display Subsystem (WS2812 RGB LED on DevKitC-1 + ST7789 IPS LCD on LilyGO T-Display)
    kprintln!("[INIT] Initializing Display & Visual Feedback Engine...");
    #[cfg(feature = "board-devkitc")]
    let led_controller = {
        let mut led_output = EspWs2812Output::new(48);
        led_output.init_hardware();
        Some(Ws2812Controller::new(led_output))
    };
    #[cfg(not(feature = "board-devkitc"))]
    let led_controller: Option<Ws2812Controller<EspWs2812Output>> = None;

    let mut display_mgr = DisplayManager::new(led_controller);
    let _ = display_mgr.init_hardware();

    // Boot visual self-test: Splash Screen + animation
    kprintln!("[INIT] Boot splash screen: AegisKey S3 Shield Logo...");
    #[cfg(feature = "board-ttgo-classic")]
    let chip_str = "ESP32 Classic (TTGO)".into();
    #[cfg(not(feature = "board-ttgo-classic"))]
    let chip_str = "ESP32-S3 Dual-Core".into();

    display_mgr.set_screen(UiScreen::BootSplash {
        version: "v1.0.0 (Rust)".into(),
        chip: chip_str,
    });
    for step in 0..30 {
        display_mgr.tick(Duration::from_millis(step * 33));
        std::thread::sleep(Duration::from_millis(33));
    }

    // Set to idle standby
    display_mgr.set_screen(UiScreen::IdleStandby {
        status_text: "Aguardando solicitação FIDO2...".into(),
    });
    kprintln!("[INIT] UI and visual engine online.");

    // 2. Initialize Hardware eFuse OTP (BLOCK7 Master Key, BLOCK8 Device Salt)
    // Wave3 P2: provision loader with fallback (no hardcoded 0x5A/0xA5 in prod).
    kprintln!("[INIT] Initializing eFuse OTP subsystem...");
    let efuse_storage = RamEfuseStorage::new();
    let efuse_mgr = EfuseManager::new(efuse_storage);

    let keys = match load_device_keys(&efuse_mgr) {
        Ok(keys) => {
            kprintln!("[INIT] Hardware Master Key & Salt loaded from eFuse OTP.");
            keys
        }
        Err(e) => {
            // Fail-operational: dispositivo sem provisionamento de fabrica.
            // Gera chaves efemeras via TRNG (RAM, zeradas no reboot) e segue o boot
            // com comportamento identico ao modo dev anterior. NUNCA panic no boot.
            kprintln!("[WARN] eFuse nao provisionado ({e:?}); usando chaves efemeras TRNG (modo DEV, sem persistencia entre reboots). Rode tools/factory_provision.py para provisionar.");
            use rand_core::Rng;
            let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
            let mut master_key = [0u8; 32];
            let mut salt = [0u8; 32];
            rng.fill_bytes(&mut master_key);
            rng.fill_bytes(&mut salt);
            // CI-GREP: TEST-HOOK (test-mode only; absent in release).
            // Sem burn de eFuse, com persistencia p/ teste: a chave-dev mora
            // em flash NVS (namespace "aegisdev"), reutilizada entre boots.
            // Release sem test-mode NEM COMPILA este ramo (efemero puro).
            #[cfg(all(target_os = "espidf", feature = "test-mode"))]
            if let Ok((m, s)) = crate::nvs_backend::load_or_create_dev_keys() {
                kprintln!("[TEST] dev-key flash persistente ativa (test-mode only).");
                master_key = m;
                salt = s;
            }
            crate::provision::DeviceKeys {
                master_key,
                device_salt: salt,
            }
        }
    };
    let master_key = keys.master_key;
    let salt = keys.device_salt;

    // 3. Initialize Encrypted Flash / NVS Persistence
    kprintln!("[INIT] Initializing AES-256-GCM Encrypted Storage...");
    let flash_backend = common::init_flash_backend();
    let mut storage = SecureStorage::new(flash_backend, &master_key, &salt);
    // AUDIT-PREP: wiring na Wave4

    let init_nonce = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];
    storage
        .store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce)
        .expect("Persist boot state");
    kprintln!("[INIT] Encrypted Flash / NVS storage ready.");

    // Binding: dono exclusivo de BLE vendor + WiFi mgmt (release exige vinculo
    // para CONFIGURAR; teste faz bypass com ltrace). USB/CTAP zero mudanca.
    // Carrega da NVS (par ausente = Unclaimed; parcial = Corrupted e exige reset).
    let mut binding_mgr = match crate::binding::BindingManager::load_from_storage(&storage) {
        Ok(m) => {
            kprintln!("[INIT] Binding loaded (claimed={}).", m.is_claimed());
            m
        }
        Err(e) => {
            kprintln!("[WARN] Binding store inconsistent ({e}); starting unclaimed (factory_reset recovers).");
            crate::binding::BindingManager::new()
        }
    };

    // 4. Initialize Hardware Buttons: BOOT (GPIO 0) + Optional KEY (GPIO 14 / GPIO 35)
    kprintln!("[INIT] Initializing Hardware Buttons...");
    let boot_input = EspBootButtonInput::new();
    #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
    let key_input = Some(EspKeyButtonInput::new());
    #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
    let key_input: Option<EspKeyButtonInput> = None;

    let button_mgr = DualButtonManager::new(boot_input, key_input);
    kprintln!("[INIT] User Presence (UP) sensor online.");

    // 5. Initialize Rust CTAPHID Manager and CTAP2 Core Engine
    #[allow(unused_mut)]
    let mut ctaphid_mgr = CtapHidManager::new();
    #[allow(unused_mut)]
    let mut ctap_engine = CtapEngine::new(master_key, 0);
    // WAVE8: OATH real no device (contas do NVS via PUT; display calcula CALCULATE no long-press).
    let mut oath_applet = OathApplet::new();
    // F2: chaves vendor on-device (NVS persistente).
    let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
    if !crate::vendor_exec::load_states(&storage, &mut key_mgr, &mut oath_applet) {
        kprintln!("[WARN] vendor NVS inconsistente; começando vazio.");
    }
    // F3: PIN persistente (hash+retries; sessão pinUvAuth morre no reboot).
    if !crate::vendor_exec::load_pin_state(&storage, &mut ctap_engine.pin_state) {
        kprintln!("[WARN] PIN NVS inconsistente; sem PIN.");
    }
    #[cfg(not(target_os = "espidf"))]
    let _ = (&ctaphid_mgr, &ctap_engine);
    // Classic serves CTAPHID through the serial section D (ctaphid_mgr stays
    // as the S3-USB manager only).
    #[cfg(all(target_os = "espidf", feature = "board-ttgo-classic"))]
    let _ = &ctaphid_mgr;
    let mut rescue_engine = RescueEngine::new();
    // Wave1: latch uso unico; PIN para RESC so apos verify_token_permission Ok.
    // Carteira Fase7: WalletStore de sessão (RAM; NVS = follow-up).
    let mut wallet_store = WalletStore::new();
    // DEV-only boot resilience (test-mode ONLY): single-attempt auto-recovery
    // from the on-device code cache on ErrorLocked; release keeps the plain
    // load (fail-closed, no auto path). No eFuse operation on either path.
    #[cfg(feature = "test-mode")]
    let mut secure_guard =
        crate::secure_guard_storage::load_secure_guard_record_with_dev_auto_recovery(
            &mut storage,
            0,
        );
    #[cfg(not(feature = "test-mode"))]
    let mut secure_guard = crate::secure_guard_storage::load_secure_guard_record(&storage, 0);
    // Log real do device p/ o app (op 0x38; RAM, sem PII/segredos).
    let mut fw_log = crate::fw_log::FwLog::new();
    fw_log.record(crate::fw_log::EV_BOOT, 0, 0);

    kprintln!("============================================================");
    kprintln!("   AegisKey S3 Authenticator ONLINE & ACTIVE!");
    kprintln!("   FIDO2 / WebAuthn ready on native USB (HID Usage Page 0xF1D0)");
    kprintln!("   Dual-Board Ready: DevKitC-1 (WS2812) / LilyGO T-Display-S3");
    kprintln!("============================================================");
    // F5: pré-init BLE no boot (heap fresco). Sem anunciar; o adv liga só
    // na janela (gate com backoff no loop).
    // Saúde BLE provada (`rc=0`): libera a reconexão de confiável sem
    // janela no loop (fail-closed, mesmo gate do FreeRTOS).
    #[allow(unused_mut)]
    let mut ble_preinit_ok = false;
    #[cfg(target_os = "espidf")]
    {
        let rc = crate::ble_nimble::esp_ble_preinit();
        if rc != 0 {
            kprintln!("[BLE] preinit rc={} (retry com backoff na janela).", rc);
        } else {
            kprintln!("[BLE] nimble preinit ok.");
            ble_preinit_ok = true;
        }
    }

    // Main Event Loop
    let mut tick: u64 = 0;
    let mut touch_latched = false;
    let mut touch_expire_tick: u64 = 0;
    // OTA staged verify-before-swap session (R-04/R-06; USB section C only).
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let mut ota_state = OtaState::new(FIRMWARE_VERSION);
    // F4: transporte CCID (framing) com applet PIV persistente entre polls
    // (seleção/PIN sobrevivem a frames; NVS+chaves emprestados por frame).
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    #[allow(unused_mut)]
    let mut ccid_transport = aegis_fido_usb::ccid::CcidTransport::new();

    let mut press_start_tick: Option<u64> = None;
    let mut totp_display_until: u64 = 0;
    let mut totp_account_idx: usize = 0;
    // Phase8 UX-conex: PairingManager orfao agora alimentado no loop (hold 5s vence TOTP 2s).
    let mut pairing_mgr = crate::pairing::PairingManager::new();
    // Etapa B (BLE NimBLE real): servidor GATT 0xFFFD + estado do radio.
    let mut ble_server = crate::ble_gatt::BleGattServer::new();
    let mut ble_adv_active = false;
    let mut ble_bond_pending = false;
    // Wave2 proximidade (feature proximity): beacon rolling-code 0xFFFE.
    // fob_id de 6 B derivado do serial USB (placeholder estavel p/ host e
    // testes). Follow-up: ler o MAC BLE real via FFI (ble_hs_id_copy_addr /
    // esp_read_mac) e usar os 6 B publicos como fob_short_id; nunca inventar
    // MAC aqui. Cache RAM do K_prox + flag de presenca (fail-closed sem chave).
    // Nunca auto-unlock: beacon/RSSI so sinalizam ausencia (ver proximity.rs).
    // Vetor de interop (py == rs): K=0x42*16, fob=AA:BB:CC:DD:EE:FF, ctr=7,
    // VER=0x01 => tag=660d4941 (ver proximity_tag; agents host espelham).
    #[cfg(feature = "proximity")]
    let mut prox_beacon = crate::proximity::ProximityBeacon::new();
    #[cfg(feature = "proximity")]
    let mut prox_last_ms: u64 = 0;
    #[cfg(feature = "proximity")]
    let mut prox_key: [u8; 16] = [0u8; 16];
    #[cfg(feature = "proximity")]
    let mut prox_key_present: bool = false;
    // fob_short_id = MAC BLE publico real via own_addr(), resolvido a cada
    // tick no loop (beacon_fob_id); None (stack down) => sem adv (fail-closed).
    #[cfg(feature = "proximity")]
    let mut prox_adv_active: bool = false;
    // F5: gate de tentativas do BLE start (backoff 5s, 3 por borda).
    // Sem isso, um `nimble_port_init` falho repetia a CADA poll, vazava
    // heap do controlador até `Malloc failed` e panic (Interrupt WDT).
    let mut ble_start_gate = crate::ble_nimble::BleStartGate::new();
    let mut ble_rx = [0u8; crate::ble_nimble::BLE_RX_FRAGMENT_MAX];
    // Borda da janela de pareamento p/ o fw-log (0x38).
    let mut pairing_open_prev = false;
    // B2 feedback do hold fisico: borda do Arming + progresso por segundo +
    // solto-cedo. Console e a prova remota; LED segue pairing_led.rs
    // (PromptTouch no hold, azul respirando na janela).
    let mut pairing_arming_prev = false;
    let mut pairing_arming_sec: u64 = 0;
    // Phase8 UX-conex: mDNS+station so fora de pareamento, com fallback AP.
    let mut wifi_ap_mgr = crate::wifi_ap::WifiApManager::new();
    let mut mdns_mgr = crate::mdns::MdnsManager::new();
    let mut sta_mgr = crate::wifi_station::WifiStationManager::new();
    // Etapa B (WiFi real): espelhos do radio p/ edge-trigger + backoff.
    let mut wifi_ap_active = false;
    // Backoff do AP start: sem isso, uma falha (ex. radio com BLE) repete
    // o start a CADA poll (~10ms) com NVS load + deinit + log — inunda o
    // UART, esfomeia o loop e desgasta flash. Tenta no max 1x/5s e desiste
    // apos 3 falhas ate a proxima borda de want.
    let mut wifi_ap_last_try_ms: u64 = 0;
    let mut wifi_ap_fails: u32 = 0;
    let mut mdns_active = false;
    let mut wifi_radio_on = false;
    let mut last_sta_attempt_ms: Option<u64> = None;
    // TOTP sem bateria (ver `time_sync`): ancora NVS + SNTP quando a station up.
    #[cfg(any(
        feature = "cap-fido-totp",
        not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
    ))]
    let mut time_state = crate::time_sync::TimeSyncState::load(&storage);
    #[cfg(any(
        feature = "cap-fido-totp",
        not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
    ))]
    let mut last_time_sync_attempt_ms: Option<u64> = None;
    // WAVE8: sem TOTP literal — o display mostra SO codigos calculados no device
    // via `OathApplet::device_code` (contas do NVS via PUT). Sem contas -> "sem contas".

    #[cfg(target_os = "espidf")]
    let mut rx_buf = [0u8; PACKET_SIZE];
    // Serial CTAPHID (UART 115200, framing identical to USB): text-tolerant
    // router plus pairing-mode + UP gates (simulator parity).
    #[cfg(target_os = "espidf")]
    let mut serial_router = crate::serial_ctaphid::SerialRouter::new();
    // Diagnostic text-line buffer (TEST_LIFETIME_DUMP with test-mode).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut serial_line: Vec<u8> = Vec::new();
    // Latch de cor solida p/ diagnostico LED (TEST_LED_*, test-mode only).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut led_test_hold: Option<crate::led::LedEffect> = None;
    // UP por software (TEST_UP, test-mode only): injeta UM toque BOOT.
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut test_up_latch = false;

    let mut watchdog = Watchdog::new(300); // L5: feed sem mudar timing USB
                                           // Wave2 proximidade (feature proximity): carrega o K_prox da NVS cifrada.
                                           // So gera+persiste via rekey se ja houver vinculo (bonded/trusted); sem
                                           // vinculo deixa ausente fail-closed (sem adv ate o pareamento).
    #[cfg(feature = "proximity")]
    {
        match crate::proximity::load_proximity_key(&storage) {
            Ok(k) => {
                prox_key = k;
                prox_key_present = true;
                kprintln!("[PROX] K_prox carregado da NVS.");
            }
            Err(_) => {
                let bonded_now = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                if bonded_now {
                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                    match crate::proximity::rekey_proximity(&mut storage, &mut rng) {
                        Ok(k) => {
                            prox_key = k;
                            prox_key_present = true;
                            kprintln!("[PROX] K_prox gerado no boot (vinculo previo).");
                        }
                        Err(e) => {
                            prox_key = [0u8; 16];
                            prox_key_present = false;
                            kprintln!("[PROX] rekey falhou no boot ({e:?}); sem adv.");
                        }
                    }
                } else {
                    kprintln!("[PROX] sem K_prox (fail-closed ate parear).");
                }
            }
        }
    }

    // Wave7 test-mode: serial diagnostic inbox (host stdio; on ESP-IDF wire UART RX to dispatch_test_command).
    #[cfg(all(feature = "test-mode", not(target_os = "espidf")))]
    let diag_rx = {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let _ = std::thread::Builder::new()
            .name("aegis_diag".into())
            .spawn(move || {
                use std::io::BufRead as _;
                let stdin = std::io::stdin();
                let mut line = String::new();
                loop {
                    line.clear();
                    match stdin.lock().read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if tx.send(line.clone()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        rx
    };

    loop {
        watchdog.feed(tick); // L5: feed no hot path, sem sleep
        let elapsed = Duration::from_millis(tick * 10);
        let now_ms = tick * 10;
        let now_secs = now_ms / 1000;
        #[cfg(not(target_os = "espidf"))]
        let _ = now_secs;

        // A. Check physical buttons
        // Button 1: BOOT (GPIO 0) - Confirm / UP / Long press (2s)
        // Button 2: KEY (GPIO 14 on LilyGO T-Display) - Cycle accounts / Cancel
        // TEST_UP (test-mode): UM toque via software, mesma semantica do tap
        // fisico (latch 1.5s, pairing/UP/rescue); consumo unico por comando.
        #[cfg(all(target_os = "espidf", feature = "test-mode"))]
        let test_up_once = core::mem::replace(&mut test_up_latch, false);
        #[cfg(not(all(target_os = "espidf", feature = "test-mode")))]
        let test_up_once = false;
        let is_boot_pressed = button_mgr.is_boot_pressed(std::thread::sleep) || test_up_once;
        let is_key_pressed = button_mgr.is_key_pressed(std::thread::sleep);

        // Phase8 UX-conex: alimenta PairingManager todo poll (corrige orfao).
        pairing_mgr.on_button_level(is_boot_pressed, now_ms);
        pairing_mgr.tick(now_ms);
        // Bond BLE expira em 30d (`pairing::BLE_BOND_MAX_AGE_MS`): esquece
        // em RAM + apaga o LTK do NimBLE; re-parear exige janela + UP + MITM.
        if pairing_mgr.forget_stale_bond(now_ms) {
            let _ = crate::ble_nimble::esp_ble_forget_bonds();
            kprintln!("[BLE] bond expirado (>30d): removido; re-pareamento exigido.");
        }
        let pairing_open_now = pairing_mgr.is_pairing_window_open(now_ms);
        // Borda da janela -> fw-log (0x38) do app.
        {
            use crate::fw_log as fl;
            if pairing_open_now && !pairing_open_prev {
                fw_log.record(fl::EV_PAIR_OPEN, 0, now_ms);
                kprintln!("[PAIRING] janela aberta 60s — pareando.");
            } else if !pairing_open_now && pairing_open_prev {
                fw_log.record(fl::EV_PAIR_CLOSE, 0, now_ms);
                // Close/timeout (Locked): radio mudo no close (mesmo fix do
                // FreeRTOS; sem isto o AP seguia `Active` e o poll pedia
                // Start sem heap -> OOM/abort).
                wifi_ap_mgr.shutdown_after_config();
                if wifi_ap_active {
                    let _ = crate::wifi_ap::esp_ap_stop();
                    wifi_ap_active = false;
                    kprintln!("[WIFI] AP off (pairing fechado).");
                }
            }
            pairing_open_prev = pairing_open_now;
        }
        common::poll_pairing_hold_transitions(
            &mut pairing_mgr,
            &mut pairing_arming_prev,
            &mut pairing_arming_sec,
            pairing_open_now,
            now_ms,
        );
        // Exclusao mutua de radio (OOM BT+WiFi): BLE anuncia SOMENTE em
        // PairingBle; WiFi (AP/station/mDNS) fica desligado nesse estado.
        let ble_pairing_now = crate::ble_nimble::should_advertise(&pairing_mgr, now_ms);
        // Binding + recovery: fiação transporte GATT/main (tick todo poll; USB intacto).
        binding_mgr.tick(now_ms);
        let _ = binding_mgr.is_claimed();
        // Etapa B (WiFi real via `aegis_wifi`): AP em pareamento (SSID do
        // serial + senha da NVS, aberta no bootstrap), station fora dele com
        // backoff (bateria), mDNS com station up, power-down fora de uso.
        // Precedencia de radio: USB (controlador dedicado, intacto) > WiFi >
        // BLE. BLE e WiFi sao mutuamente exclusivos (heap do S3 nao suporta
        // os dois juntos); PairingBle desliga todo WiFi, PairingAp desliga BLE.
        wifi_ap_mgr.update(pairing_open_now, false, now_ms);
        let ap_want = wifi_ap_mgr.is_active(now_ms);
        if !ap_want {
            wifi_ap_fails = 0;
        }
        // Decisao edge-triggered (wifi_ap::ap_poll_action): cada acao
        // executa no maximo uma vez por transicao. O `else` anterior
        // chamava esp_ap_stop() a CADA poll com BLE pareando (spam de
        // close/wifi-ap no log e churn no radio durante o bonding).
        match crate::wifi_ap::ap_poll_action(ap_want, ble_pairing_now, wifi_ap_active) {
            crate::wifi_ap::ApPollAction::Start => {
                if wifi_ap_fails >= 3 {
                    // Desistiu ate a proxima borda: sem spam, sem churn.
                } else if now_ms.saturating_sub(wifi_ap_last_try_ms) < 5000
                    && wifi_ap_last_try_ms != 0
                {
                    // Backoff: aguarda 5s entre tentativas.
                } else {
                    // Guarda de heap: sem bloco contiguo o driver aborta (OOM).
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
                        wifi_ap_last_try_ms = now_ms;
                        kprintln!("[WIFI] AP skip (heap curto).");
                    } else {
                        wifi_ap_last_try_ms = now_ms;
                        let ssid = crate::wifi_ap::ap_ssid_for_serial(
                            usb_descriptors::SERIAL_NUMBER_STRING,
                        );
                        let pass_bytes = storage
                            .load(crate::wifi_ap::WIFI_PASS_NVS_KEY)
                            .unwrap_or_default();
                        let pass_opt =
                            crate::wifi_ap::resolve_ap_password(if pass_bytes.is_empty() {
                                None
                            } else {
                                Some(&pass_bytes)
                            });
                        let pass_str = pass_opt.unwrap_or_default();
                        // Nunca loga a senha.
                        let rc = crate::wifi_ap::esp_ap_start(&ssid, &pass_str);
                        if rc == 0 {
                            wifi_ap_active = true;
                            wifi_ap_fails = 0;
                            kprintln!("[WIFI] AP '{}' on (pareamento).", ssid);
                        } else if rc == crate::wifi_ap::WIFI_AP_RC_NO_MEM {
                            // NO_MEM terminal ate nova borda, sem retry.
                            wifi_ap_fails = 3;
                            kprintln!("[WIFI] AP start rc=-4 NO_MEM (terminal ate nova borda).");
                        } else {
                            wifi_ap_fails = wifi_ap_fails.saturating_add(1);
                            // Loga só a 1ª falha (as seguintes seriam spam a cada 5s);
                            // apos 3, desiste ate a proxima borda de want.
                            if wifi_ap_fails == 1 {
                                kprintln!(
                                    "[WIFI] AP start rc={} (backoff 5s, desiste apos 3).",
                                    rc
                                );
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
        // Station: so fora de pareamento, com credenciais e backoff 60s.
        let has_creds = crate::wifi_station::has_station_credentials(&storage);
        common::poll_wifi_station_radio(
            &storage,
            &mut sta_mgr,
            &mut mdns_mgr,
            &mut mdns_active,
            wifi_ap_active,
            &mut wifi_radio_on,
            &mut last_sta_attempt_ms,
            pairing_open_now,
            ble_pairing_now,
            has_creds,
            now_ms,
        );
        // TOTP sem bateria: SNTP quando a station esta up; ancora NVS
        // sobrevive ao reboot (max() + fail-closed). Ver `time_sync`.
        #[cfg(any(
            feature = "cap-fido-totp",
            not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
        ))]
        crate::time_sync::poll_time_sync(
            &mut storage,
            &mut time_state,
            sta_mgr.is_up(),
            now_ms,
            &mut last_time_sync_attempt_ms,
        );
        // Etapa B (BLE NimBLE real): advertising na janela de pareamento
        // (flag ligada) + reconexão de confiável sem janela SÓ com saúde
        // BLE provada (`ble_preinit_ok` do preinit de boot `rc=0`).
        // Fail-closed: sem preinit saudável, claimed + Idle fica mudo em
        // vez de chamar `esp_ble_start → nimble_port_init` (LoadProhibited).
        // Coexistencia USB > WiFi > BLE: com WiFi ativo o intervalo e lento.
        let trusted = pairing_mgr.is_bond_fresh(now_ms) || binding_mgr.is_claimed();
        let ble_want_adv = crate::ble_nimble::should_advertise(&pairing_mgr, now_ms)
            || (ble_preinit_ok
                && crate::ble_nimble::should_advertise_reconnect(pairing_mgr.state(), trusted));
        if ble_want_adv != ble_adv_active {
            if ble_want_adv {
                let wifi_active = wifi_ap_mgr.is_active(now_ms) || sta_mgr.is_up();
                // Gate: borda tenta já; falha entra em backoff 5s e desiste
                // após 3 (nunca martela `nimble_port_init` — vaza heap e
                // derruba o controlador em panic).
                if crate::ble_nimble::BleStartGate::allow(&mut ble_start_gate, true, now_ms) {
                    let rc = crate::ble_nimble::esp_ble_start(pairing_open_now, wifi_active);
                    if rc == crate::ble_nimble::BLE_ADV_RC_NOMEM {
                        // 519 residual: registra e NAO consome retry.
                        ble_start_gate.on_nomem();
                        fw_log.record(crate::fw_log::EV_ADV_NOMEM, 0, now_ms);
                        kprintln!("[BLE] adv start rc=519 NOMEM (residual; sem gastar retry).");
                    } else {
                        ble_start_gate.on_result(rc == 0);
                        if rc == 0 {
                            ble_adv_active = true;
                            fw_log.record(crate::fw_log::EV_ADV_START, 0, now_ms);
                        } else {
                            kprintln!("[BLE] adv start rc={} (backoff 5s, desiste apos 3).", rc);
                        }
                    }
                }
            } else {
                let _ = crate::ble_nimble::esp_ble_stop();
                ble_adv_active = false;
                ble_bond_pending = false;
                // Janela fechou: o gate zera na próxima borda.
                ble_start_gate.allow(false, now_ms);
                fw_log.record(crate::fw_log::EV_ADV_STOP, 0, now_ms);
            }
        }
        // Wave2 proximidade (feature proximity): adv 0xFFFE ~1 s quando Idle +
        // bonded + trusted + USB inativo + K_prox presente. USB veta o adv;
        // WiFi ativo so desacelera o intervalo (coex). Nunca auto-unlock:
        // aceitar beacon nunca destrava (unlock exige presenca + PIN).
        #[cfg(feature = "proximity")]
        {
            use crate::ble_nimble as prox_ble;
            use crate::proximity as prox_mod;
            let bonded = pairing_mgr.is_bonded();
            let trusted = bonded || binding_mgr.is_claimed();
            #[cfg(target_os = "espidf")]
            let usb_active = unsafe { aegis_usb_is_mounted() };
            #[cfg(not(target_os = "espidf"))]
            let usb_active = false;
            let wifi_active = wifi_ap_mgr.is_active(now_ms) || sta_mgr.is_up();
            // Revogado via release/recovery (dispatch apagou a NVS): limpa o
            // cache RAM na borda (fail-closed ate o proximo rekey).
            if prox_key_present && prox_mod::load_proximity_key(&storage).is_err() {
                prox_key = [0u8; 16];
                prox_key_present = false;
                if prox_adv_active {
                    let _ = prox_ble::esp_ble_stop();
                    prox_adv_active = false;
                }
                kprintln!("[PROX] K_prox revogado; adv parado.");
            }
            // Rollover (ctr travou no MAX): rekey + ctr=0; sem rekey, mudo.
            if prox_beacon.is_rollover() && prox_key_present {
                let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                match prox_mod::rekey_proximity(&mut storage, &mut rng) {
                    Ok(k) => {
                        prox_key = k;
                        prox_beacon = prox_mod::ProximityBeacon::new();
                        prox_last_ms = now_ms;
                        kprintln!("[PROX] rekey pos-rollover (ctr=0).");
                    }
                    Err(e) => {
                        prox_key = [0u8; 16];
                        prox_key_present = false;
                        kprintln!("[PROX] rekey pos-rollover falhou ({e:?}).");
                    }
                }
            }
            // fob_short_id real (MAC BLE publico); None => sem adv (fail-closed).
            let prox_fob = prox_mod::beacon_fob_id();
            let want_prox = prox_ble::should_adv_proximity(
                pairing_mgr.state(),
                bonded,
                trusted,
                usb_active,
                prox_key_present,
            ) && prox_fob.is_some();
            if want_prox {
                // Radio unico: presenca 0xFFFE vence a reconexao 0xFFFD em Idle.
                if ble_adv_active {
                    let _ = prox_ble::esp_ble_stop();
                    ble_adv_active = false;
                    ble_start_gate.allow(false, now_ms);
                    fw_log.record(crate::fw_log::EV_ADV_STOP, 0, now_ms);
                }
                // So (re)anuncia no tick de ~1 s (throttle natural + backoff de
                // falha); o C e idempotente, entao para antes p/ reaplicar o
                // svc_data novo (ctr++) e o intervalo atual.
                if prox_beacon.tick_if_due(prox_last_ms, now_ms) {
                    prox_last_ms = now_ms;
                    if prox_adv_active {
                        let _ = prox_ble::esp_ble_stop();
                        prox_adv_active = false;
                    }
                    let ctr = prox_beacon.counter();
                    // Gate want_prox garante Some; o default abaixo nunca e
                    // transmitido (fail-closed sem MAC real).
                    let fob = prox_fob.unwrap_or([0u8; 6]);
                    let tag = prox_mod::proximity_tag(
                        &prox_key,
                        prox_mod::PROXIMITY_BEACON_VERSION,
                        ctr,
                        &fob,
                    );
                    let svc = prox_mod::encode_proximity_svc_data(ctr, &tag);
                    let rc = prox_ble::esp_ble_proximity_start(&svc, wifi_active);
                    if rc == 0 {
                        prox_adv_active = true;
                        fw_log.record(crate::fw_log::EV_ADV_START, 0, now_ms);
                    } else {
                        kprintln!("[PROX] adv start rc={} (retry ~1 s).", rc);
                    }
                }
            } else if prox_adv_active {
                let _ = prox_ble::esp_ble_stop();
                prox_adv_active = false;
                fw_log.record(crate::fw_log::EV_ADV_STOP, 0, now_ms);
            }
        }
        // Etapa B: bomba BLE (eventos GAP + fragmentos FFF1). USB intacto.
        {
            use crate::ble_nimble as ble;
            match ble::esp_ble_poll_event() {
                e if e == ble::BLE_EVT_SECURED => {
                    match ble::on_link_secured(&mut pairing_mgr, touch_latched, now_ms) {
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
                            #[cfg(target_os = "espidf")]
                            if let Some(ref mut led) = display_mgr.led_controller {
                                led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                            }
                            kprintln!(
                                "[BLE] bonding ok: advertising parado, pareamento encerrado."
                            );
                            fw_log.record(crate::fw_log::EV_BOND_OK, 0, now_ms);
                            // Wave2 proximidade: rekey do K_prox no pareamento +
                            // zera o contador do beacon (ctr=0 no proximo adv).
                            #[cfg(feature = "proximity")]
                            {
                                let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                match crate::proximity::rekey_proximity(&mut storage, &mut rng) {
                                    Ok(k) => {
                                        prox_key = k;
                                        prox_key_present = true;
                                        prox_beacon = crate::proximity::ProximityBeacon::new();
                                        prox_last_ms = now_ms;
                                        kprintln!("[PROX] rekey pos-pareamento (ctr=0).");
                                    }
                                    Err(e) => {
                                        prox_key = [0u8; 16];
                                        prox_key_present = false;
                                        kprintln!("[PROX] rekey falhou ({e:?}); sem adv.");
                                    }
                                }
                            }
                        }
                        ble::BondOutcome::DeniedNoPresence => {
                            common::note_bond_denied_no_presence(
                                &mut ble_bond_pending,
                                &mut display_mgr,
                            );
                        }
                        ble::BondOutcome::DeniedNoWindow => {
                            kprintln!("[BLE] link seguro fora da janela: ignorado.");
                        }
                    }
                }
                e if e == ble::BLE_EVT_DISCONNECTED => {
                    common::note_ble_disconnected(&mut ble_adv_active, &mut ble_bond_pending);
                }
                e if e == ble::BLE_EVT_CONNECTED => {
                    kprintln!("[BLE] central conectou (aguardando bonding).");
                }
                _ => {}
            }
            // Bonding pendente: conclui quando o usuario tocar no BOOT.
            // Nested to avoid simultaneous &mut/& borrows of pairing_mgr in one condition; readability intentional.
            #[allow(clippy::collapsible_if)]
            if ble_bond_pending && touch_latched && pairing_mgr.is_pairing_window_open(now_ms) {
                if ble::on_link_secured(&mut pairing_mgr, true, now_ms) == ble::BondOutcome::Paired
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
                    #[cfg(target_os = "espidf")]
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                    }
                    kprintln!("[BLE] bonding ok (apos UP): advertising parado.");
                    fw_log.record(crate::fw_log::EV_BOND_OK, 0, now_ms);
                    // Wave2 proximidade: rekey do K_prox no pareamento +
                    // zera o contador do beacon (ctr=0 no proximo adv).
                    #[cfg(feature = "proximity")]
                    {
                        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                        match crate::proximity::rekey_proximity(&mut storage, &mut rng) {
                            Ok(k) => {
                                prox_key = k;
                                prox_key_present = true;
                                prox_beacon = crate::proximity::ProximityBeacon::new();
                                prox_last_ms = now_ms;
                                kprintln!("[PROX] rekey pos-pareamento (ctr=0).");
                            }
                            Err(e) => {
                                prox_key = [0u8; 16];
                                prox_key_present = false;
                                kprintln!("[PROX] rekey falhou ({e:?}); sem adv.");
                            }
                        }
                    }
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
                            now_secs,
                            &mut ctap_engine,
                            &mut binding_mgr,
                            &mut storage,
                            &mut rescue_engine,
                            &mut wallet_store,
                            bonded,
                            now_ms,
                            &mut fw_log,
                            &mut key_mgr,
                            &mut oath_applet,
                            &mut secure_guard,
                        );
                        // Wave2 proximidade: release/recovery apagou a NVS
                        // no dispatch (so no Ok); espelha no cache RAM.
                        #[cfg(feature = "proximity")]
                        {
                            let revoked = prox_revoked_op == crate::ble_gatt::OP_BIND_RELEASE
                                || prox_revoked_op == crate::ble_gatt::OP_RECOVERY_UNLOCK;
                            if revoked && crate::proximity::load_proximity_key(&storage).is_err() {
                                prox_key = [0u8; 16];
                                prox_key_present = false;
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
        }
        if is_boot_pressed {
            if press_start_tick.is_none() {
                press_start_tick = Some(tick);
                touch_latched = true;
                rescue_engine.set_user_presence(true);
                touch_expire_tick = tick + 150; // Keep touch valid for 1.5 seconds
                                                // Distingue software (TEST_UP) do dedo para nao poluir auditoria:
                                                // latch valido sem nivel fisico agora => veio de software.
                #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                let via_software = !button_mgr.is_boot_pressed(|_| {}) && touch_latched;
                #[cfg(not(all(target_os = "espidf", feature = "test-mode")))]
                let via_software = false;
                if via_software {
                    kprintln!("[TEST] UP via software CONFIRMED (latch 1x).");
                } else {
                    kprintln!(
                        "[BUTTON] Physical touch detected on BOOT (GPIO 0)! User Presence CONFIRMED."
                    );
                }
            } else if let Some(start) = press_start_tick {
                // Phase8 UX-conex: hold>=5000 PairingReady vence; TOTP so em [2s,5s) sem pairing.
                let held_ms = tick.saturating_sub(start).saturating_mul(10);
                let hold_action = crate::pairing_flow::classify_hold(held_ms, pairing_open_now);
                if hold_action == crate::pairing_flow::HoldAction::PairingReady {
                    kprintln!("[PAIRING] 5s hold detected! Pairing window open (60s).");
                }
                // WAVE8: long-press 2s -> CALCULATE no device (UP confirmado pelo hold).
                if hold_action == crate::pairing_flow::HoldAction::Totp
                    && totp_display_until <= tick
                {
                    kprintln!(
                        "[LONG PRESS] 2-second hold detected! Calculating OATH TOTP on device..."
                    );
                    totp_display_until = tick + TOTP_SHOW_TICKS; // 15s (igual Vault auto-clear)
                    let entries = collect_totp_codes(&mut oath_applet, now_secs, true);
                    if entries.is_empty() {
                        display_mgr.set_screen(UiScreen::Error {
                            message: NO_ACCOUNTS_MSG.into(),
                        });
                    } else {
                        totp_account_idx %= entries.len();
                        let entry = &entries[totp_account_idx];
                        // Log so rotulo/contagem — codigo e segredo nunca vao para o log.
                        kprintln!(
                            "[TOTP] account '{}' ({} conta(s))",
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
        } else {
            press_start_tick = None;
            if tick > touch_expire_tick && touch_latched {
                touch_latched = false;
                rescue_engine.set_user_presence(false);
            }
            if totp_display_until > 0 && tick >= totp_display_until {
                totp_display_until = 0;
                display_mgr.set_screen(UiScreen::IdleStandby {
                    status_text: "Aguardando solicitação FIDO2...".into(),
                });
            }
        }

        // WAVE8: KEY (GPIO 14) alterna entre as contas reais do device.
        if is_key_pressed {
            let entries = collect_totp_codes(&mut oath_applet, now_secs, true);
            if entries.is_empty() {
                totp_display_until = tick + TOTP_SHOW_TICKS;
                display_mgr.set_screen(UiScreen::Error {
                    message: NO_ACCOUNTS_MSG.into(),
                });
            } else {
                totp_account_idx = (totp_account_idx + 1) % entries.len();
                let entry = &entries[totp_account_idx];
                kprintln!("[KEY BUTTON] Cycled TOTP Account -> {}", entry.account);
                totp_display_until = tick + TOTP_SHOW_TICKS; // 15s (igual Vault auto-clear)
                display_mgr.set_screen(UiScreen::TotpCode {
                    label: entry.account.clone(),
                    code: entry.code.clone(),
                    remaining_seconds: entry.remaining_seconds,
                });
            }
        }

        // WAVE8: enquanto o TOTP esta visivel, atualiza o countdown a cada 1s
        // (codigo recalculado no device — trata a virada da janela de 30s).
        if totp_display_until > tick && tick.is_multiple_of(100) {
            let entries = collect_totp_codes(&mut oath_applet, now_secs, true);
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

        // Wave7 test-mode: TEST_PAIRING_OPEN (mesma janela 60s do hold 5s,
        // source=software; UP/bonding seguem exigidos) + TEST_PAIRING_CLOSE
        // (fecha p/ determinismo entre sessões) + TEST_LIFETIME_DUMP.
        #[cfg(all(feature = "test-mode", not(target_os = "espidf")))]
        while let Ok(cmd) = diag_rx.try_recv() {
            if cmd.trim() == crate::pairing::TEST_PAIRING_OPEN_CMD {
                pairing_mgr.open_test_window(now_ms);
                std::println!("pairing_open window_s=60 source=software");
                continue;
            }
            if cmd.trim() == crate::pairing::TEST_PAIRING_CLOSE_CMD {
                pairing_mgr.close_test_window();
                std::println!("pairing_closed source=software");
                continue;
            }
            let extra = format!("uptime_s={} up_latched={}", tick * 10 / 1000, touch_latched);
            if let Some(resp) = crate::lifetime_trace::dispatch_test_command(&cmd, &extra) {
                std::println!("{}", resp);
            }
        }

        // B. Update Display Animation & LED
        display_mgr.tick(elapsed);
        // Pairing journey drives the LED from Idle screens (headless parity):
        // arming = rapid touch prompt, pairing window = blue breathing,
        // bonded idle = solid green, locked = solid red. Any other screen
        // (UP prompt, TOTP, success/error) keeps its own LED effect.
        {
            let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
            if matches!(display_mgr.current_screen, UiScreen::IdleStandby { .. })
                && (pairing_mgr.state() != crate::pairing::PairingState::Idle || bonded)
            {
                if let Some(ref mut led) = display_mgr.led_controller {
                    led.set_effect(crate::pairing_led::effect_for_pairing_state(
                        pairing_mgr.state(),
                        bonded,
                    ));
                }
            }
        }

        // C. Service USB CTAPHID Packets (native USB-OTG; classic serves
        // the same UART through the serial section D below instead).
        #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
        if usb_installed {
            let bytes_read =
                unsafe { aegis_usb_pop_packet(rx_buf.as_mut_ptr(), PACKET_SIZE as u16) };

            if bytes_read == PACKET_SIZE as u16 {
                match ctaphid_mgr.process_packet(&rx_buf, now_ms) {
                    Ok(Some(msg)) => {
                        kprintln!(
                            "[CTAPHID] Message received! CID: 0x{:08X}, CMD: 0x{:02X}, Len: {}",
                            msg.cid,
                            msg.cmd,
                            msg.payload.len()
                        );

                        match msg.cmd {
                            CMD_INIT => {
                                if msg.payload.len() >= 8 {
                                    let mut nonce = [0u8; 8];
                                    nonce.copy_from_slice(&msg.payload[0..8]);
                                    let new_cid = ctaphid_mgr.allocate_cid();
                                    let resp_pkt = CtapHidFramer::frame_init_response(
                                        msg.cid,
                                        &nonce,
                                        new_cid,
                                        1,
                                        0,
                                        0,
                                        CAPABILITY_WINK | CAPABILITY_CBOR,
                                    );
                                    unsafe {
                                        aegis_usb_send_report(
                                            resp_pkt.as_ptr(),
                                            PACKET_SIZE as u16,
                                        );
                                    }
                                    kprintln!("[CTAPHID] Allocated CID: 0x{:08X}", new_cid);
                                }
                            }
                            CMD_PING => {
                                let pkts = CtapHidFramer::frame_ping(msg.cid, &msg.payload);
                                for p in pkts {
                                    unsafe {
                                        aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                }
                            }
                            CMD_WINK => {
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(LedEffect::Wink);
                                }
                                let pkts = CtapHidFramer::frame_message(msg.cid, CMD_WINK, &[]);
                                for p in pkts {
                                    unsafe {
                                        aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                }
                            }
                            CMD_CBOR | CMD_MSG => {
                                // OTA vendor 0x30-0x34 over CMD_MSG (R-04/R-06):
                                // staged verify-before-swap; COMMIT consumes the UP latch.
                                // Any OtaError rolls back (NVS intact); real esp-ota
                                // partition swap = factory follow-up.
                                let ota_op = if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && is_ota_op(msg.payload[0])
                                {
                                    Some(msg.payload[0])
                                } else {
                                    None
                                };
                                if let Some(op) = ota_op {
                                    let ota_ctx = OtaRequestCtx {
                                        provisioned: ota_provisioned(&efuse_mgr),
                                        up: touch_latched,
                                        ota_pubkey: ota_active_pubkey(),
                                        current_version: FIRMWARE_VERSION,
                                    };
                                    let mut ota_sink = FlashOtaSink::new(storage.backend_mut());
                                    let (ota_consumed_up, ota_resp) = match dispatch_ota_request(
                                        &mut ota_state,
                                        &mut ota_sink,
                                        op,
                                        &msg.payload[1..],
                                        &ota_ctx,
                                    ) {
                                        Some((st, body)) => {
                                            if st == OTA_STATUS_OK {
                                                kprintln!(
                                                    "[OTA] op 0x{:02X} ok (phase {:?}).",
                                                    op,
                                                    ota_state.phase()
                                                );
                                            } else {
                                                kprintln!(
                                                    "[OTA] op 0x{:02X} denied (status 0x{:02X}, phase {:?}).",
                                                    op,
                                                    st,
                                                    ota_state.phase()
                                                );
                                            }
                                            let mut out = Vec::with_capacity(1 + body.len());
                                            out.push(st);
                                            out.extend_from_slice(&body);
                                            (st == OTA_STATUS_OK && op == OP_OTA_COMMIT, out)
                                        }
                                        // Unreachable (pre-filtered by is_ota_op): fail-closed.
                                        None => (false, vec![OTA_STATUS_FAIL]),
                                    };
                                    if ota_consumed_up {
                                        touch_latched = false;
                                        rescue_engine.set_user_presence(true);
                                    }
                                    let ota_pkts =
                                        CtapHidFramer::frame_message(msg.cid, msg.cmd, &ota_resp);
                                    for p in ota_pkts {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                    kprintln!(
                                        "[CTAPHID] Sent OTA response ({} bytes)",
                                        ota_resp.len()
                                    );
                                } else if msg.cmd == CMD_MSG
                                    && crate::serial_ctaphid::is_rescue_msg(msg.cmd, &msg.payload)
                                {
                                    // Rescue Wave2 Step3 (0x2E): UP do latch (uso unico),
                                    // PIN via plumbing ClientPIN (sessão viva = PIN
                                    // verificado; sem ela o remoto nega fail-closed).
                                    // Resposta status-first.
                                    rescue_engine.set_user_presence(touch_latched);
                                    rescue_engine.set_pin_uv_authenticated(
                                        ctap_engine.pin_state.has_valid_pin_uv_session(),
                                    );
                                    touch_latched = false;
                                    let (st, body) = crate::serial_ctaphid::dispatch_serial_rescue(
                                        &mut rescue_engine,
                                        &msg.payload[1..],
                                    );
                                    kprintln!("[RESCUE] op 0x2E via USB (status 0x{:02X}).", st);
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::pairing::is_host_pairing_msg(
                                        msg.payload[0],
                                        msg.payload.len() - 1,
                                    )
                                {
                                    // Pareamento por software (produto 0x2F): abre a
                                    // mesma janela do hold; UP/bonding seguem
                                    // exigidos. Só existe no USB físico.
                                    pairing_mgr.open_host_window(now_ms);
                                    touch_latched = true;
                                    touch_expire_tick = now_ms.saturating_add(10_000);
                                    rescue_engine.set_user_presence(true);
                                    kprintln!("[PAIRING] 0x2F via USB: janela 60s aberta (UP/bond seguem).");
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x00])
                                    {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && legacy_sg_dispatch::is_legacy_sg_op(msg.payload[0])
                                {
                                    // Secure Guard 0x3A-0x3E over USB-HID: parity
                                    // with the serial section D branch and the freertos
                                    // USB path (`dispatch_serial_vendor_msg` SG branch):
                                    // same `exec_secure_guard_op`, same responses, same
                                    // gates (none at the dispatcher; auth is enforced
                                    // inside the executor). USB is remote-facing: no
                                    // weaker gates invented.
                                    let op = msg.payload[0];
                                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                    let (st, body, effects) =
                                        legacy_sg_dispatch::dispatch_legacy_secure_guard_op(
                                            &mut secure_guard,
                                            &mut storage,
                                            &mut wallet_store,
                                            &mut key_mgr,
                                            &mut oath_applet,
                                            op,
                                            &msg.payload[1..],
                                            now_ms,
                                            &mut rng,
                                        );
                                    if effects.did_unlock {
                                        pairing_mgr.open_host_window(now_ms);
                                        touch_latched = true;
                                        touch_expire_tick = now_ms.saturating_add(10_000);
                                        rescue_engine.set_user_presence(true);
                                        if let Some(pin_bytes) = effects.verified_pin {
                                            ctap_engine.pin_state.pin_hash =
                                                Some(aegis_fido_core::crypto::pin_hash(&pin_bytes));
                                            ctap_engine.pin_state.pin_retries = 8;
                                            ctap_engine.pin_state.power_cycle_state = false;
                                            let _ = crate::vendor_exec::save_pin_state(
                                                &mut storage,
                                                &ctap_engine.pin_state,
                                            );
                                            kprintln!("[USB][SG] PIN synced to CTAP2 ClientPIN.");
                                        }
                                    } else if effects.did_lock {
                                        pairing_mgr.lock();
                                        touch_latched = false;
                                    }
                                    // LED: SG error class (0x36/0x04) -> existing
                                    // ErrorFlash (no new effects, no WS2812 timing
                                    // changes; `None` keeps the state pipeline).
                                    match crate::pairing_led::effect_for_sg_status(st) {
                                        Some(fx) => {
                                            if let Some(ref mut led) = display_mgr.led_controller {
                                                led.set_effect(fx);
                                            }
                                            kprintln!("[USB][SG] op 0x{:02X} error (status 0x{:02X}): ErrorFlash.", op, st);
                                        }
                                        None => {
                                            kprintln!(
                                                "[USB][SG] op 0x{:02X} (status 0x{:02X}).",
                                                op,
                                                st
                                            );
                                        }
                                    }
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                    kprintln!("[CTAPHID] Sent SG response ({} bytes)", resp.len());
                                } else {
                                    // 1. Determine if this command requires User Presence (UP)
                                    let ctap_subcmd = if !msg.payload.is_empty() {
                                        msg.payload[0]
                                    } else {
                                        0
                                    };
                                    let is_up_required = match msg.cmd {
                                        CMD_CBOR => {
                                            ctap_subcmd == CTAP_CMD_MAKE_CREDENTIAL
                                                || ctap_subcmd == CTAP_CMD_GET_ASSERTION
                                                || ctap_subcmd == CTAP_CMD_RESET
                                        }
                                        CMD_MSG => {
                                            // U2F APDU: INS=0x01 (Register) or INS=0x02 (Authenticate with check/sign)
                                            if msg.payload.len() >= 4 {
                                                let ins = msg.payload[1];
                                                let p1 = msg.payload[2];
                                                ins == 0x01 || (ins == 0x02 && p1 == 0x03)
                                            } else {
                                                false
                                            }
                                        }
                                        _ => false,
                                    };

                                    let (rp_id, user_name, op_name) =
                                        ble_dispatch::extract_rp_and_user(
                                            ctap_subcmd,
                                            &msg.payload,
                                        );

                                    let mut up_confirmed = false;
                                    if is_up_required {
                                        if touch_latched {
                                            up_confirmed = true;
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            kprintln!("[UP] Touch already latched on GPIO 0! Confirming User Presence for: {}", rp_id);
                                        } else {
                                            kprintln!(
                                            "[UP] Touch required for {} ({})! Waiting up to 25s...",
                                            rp_id,
                                            op_name
                                        );

                                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                                rp_id: rp_id.clone(),
                                                user_name: user_name.clone(),
                                                operation: op_name.into(),
                                                remaining_seconds: 25,
                                            });

                                            // Wait up to 25s (1250 * 20ms)
                                            for wait_step in 0..1250 {
                                                // Send CTAPHID Keepalive STATUS_UPNEEDED every 100ms (every 5 steps)
                                                if wait_step % 5 == 0 {
                                                    let keepalive = CtapHidFramer::frame_keepalive(
                                                        msg.cid,
                                                        STATUS_UPNEEDED,
                                                    );
                                                    unsafe {
                                                        aegis_usb_send_report(
                                                            keepalive.as_ptr(),
                                                            PACKET_SIZE as u16,
                                                        );
                                                    }
                                                }

                                                // Advance Display animation & countdown bar
                                                if wait_step % 25 == 0 {
                                                    let rem_s = 25u32.saturating_sub(
                                                        (wait_step * 20 / 1000) as u32,
                                                    );
                                                    display_mgr.set_screen(
                                                        UiScreen::UserPresencePrompt {
                                                            rp_id: rp_id.clone(),
                                                            user_name: user_name.clone(),
                                                            operation: op_name.into(),
                                                            remaining_seconds: rem_s,
                                                        },
                                                    );
                                                }
                                                display_mgr
                                                    .tick(Duration::from_millis(wait_step * 20));

                                                // Check physical buttons:
                                                // BOOT (GPIO 0) -> Confirm User Presence
                                                // KEY (GPIO 14) -> Cancel / Reject Transaction
                                                if button_mgr.is_boot_pressed(std::thread::sleep) {
                                                    up_confirmed = true;
                                                    rescue_engine.set_user_presence(true);
                                                    kprintln!("[BUTTON] Physical touch confirmed on BOOT (GPIO 0)! (t={}ms)", wait_step * 20);
                                                    break;
                                                }
                                                if button_mgr.is_key_pressed(std::thread::sleep) {
                                                    up_confirmed = false;
                                                    kprintln!("[BUTTON] User cancelled transaction via KEY (GPIO 14)! (t={}ms)", wait_step * 20);
                                                    break;
                                                }

                                                // Check if host sent CANCEL
                                                #[cfg(target_os = "espidf")]
                                                {
                                                    let mut check_buf = [0u8; PACKET_SIZE];
                                                    let n = unsafe {
                                                        aegis_usb_pop_packet(
                                                            check_buf.as_mut_ptr(),
                                                            PACKET_SIZE as u16,
                                                        )
                                                    };
                                                    if n == PACKET_SIZE as u16 {
                                                        if let Ok(raw_pkt) =
                                                            CtapHidManager::parse_raw_packet(
                                                                &check_buf,
                                                            )
                                                        {
                                                            if let RawPacket::Init {
                                                                cid,
                                                                cmd,
                                                                ..
                                                            } = raw_pkt
                                                            {
                                                                if cid == msg.cid
                                                                    && cmd == CMD_CANCEL
                                                                {
                                                                    kprintln!("[UP] Host cancelled transaction (CMD_CANCEL received).");
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                std::thread::sleep(Duration::from_millis(20));
                                            }
                                        }

                                        if up_confirmed {
                                            display_mgr.set_screen(UiScreen::Success {
                                                title: "ACESSO AUTORIZADO".into(),
                                                subtitle: {
                                                    let mut sbuf: [u8; 64] = [0u8; 64];
                                                    let pre = b"Dominio: ";
                                                    sbuf[..pre.len()].copy_from_slice(pre);
                                                    let mut slen = pre.len();
                                                    let idb = rp_id.as_bytes();
                                                    let mut take =
                                                        (sbuf.len() - slen).min(idb.len().min(48));
                                                    while take > 0 && !rp_id.is_char_boundary(take)
                                                    {
                                                        take -= 1;
                                                    }
                                                    sbuf[slen..slen + take]
                                                        .copy_from_slice(&idb[..take]);
                                                    slen += take;
                                                    core::str::from_utf8(&sbuf[..slen])
                                                        .unwrap_or("Dominio: ?")
                                                        .into()
                                                },
                                            });
                                        } else {
                                            display_mgr.set_screen(UiScreen::Error {
                                                message: "Tempo esgotado ou cancelado".into(),
                                            });
                                            kprintln!("[UP] User Presence denied or timed out!");
                                        }
                                    } else {
                                        // Command does not require user presence (GetInfo, ClientPIN, etc.)
                                        up_confirmed = true;
                                    }

                                    ctap_engine.set_user_presence(up_confirmed);

                                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                    let ctap_res = ctap_engine.process_packet(
                                        &msg.payload,
                                        now_secs,
                                        &mut rng,
                                    );

                                    // F3: ClientPIN (0x06) mudou estado? Persiste.
                                    if msg.payload.first() == Some(&0x06)
                                        && !crate::vendor_exec::save_pin_state(
                                            &mut storage,
                                            &ctap_engine.pin_state,
                                        )
                                    {
                                        kprintln!("[WARN] NVS pin save falhou (USB).");
                                    }

                                    kprintln!(
                                        "[CTAP2] Response status: 0x{:02X}, length: {} bytes",
                                        ctap_res.get(0).unwrap_or(&0xFF),
                                        ctap_res.len()
                                    );

                                    let pkts =
                                        CtapHidFramer::frame_message(msg.cid, msg.cmd, &ctap_res);
                                    for (p_idx, p) in pkts.iter().enumerate() {
                                        let sent = unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16)
                                        };
                                        if !sent {
                                            kprintln!(
                                                "[USB] Error: packet {}/{} failed to send!",
                                                p_idx + 1,
                                                pkts.len()
                                            );
                                            crate::ltrace!(LtCat::Transport, LtEvt::TpError, "usb");
                                        }
                                    }
                                    kprintln!(
                                        "[CTAPHID] Sent CTAP response ({} bytes in {} USB packets)",
                                        ctap_res.len(),
                                        pkts.len()
                                    );

                                    // Return display back to idle standby after brief celebration
                                    if is_up_required && up_confirmed {
                                        std::thread::sleep(Duration::from_millis(800));
                                        display_mgr.set_screen(UiScreen::IdleStandby {
                                            status_text: "Aguardando solicitação FIDO2...".into(),
                                        });
                                    }
                                } // end OTA else (non-OTA CTAP routing above untouched)
                            }
                            _ => {
                                let err_pkt = CtapHidFramer::frame_error(msg.cid, 0x01); // ERR_INVALID_CMD
                                unsafe {
                                    aegis_usb_send_report(err_pkt.as_ptr(), PACKET_SIZE as u16);
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // Multi-packet message continuing reassembly
                    }
                    Err(err) => {
                        kprintln!("[CTAPHID] Protocol error: {}", err);
                        crate::ltrace!(LtCat::Transport, LtEvt::TpError, "usb");
                        let err_pkt = err.to_packet();
                        unsafe {
                            aegis_usb_send_report(err_pkt.as_ptr(), PACKET_SIZE as u16);
                        }
                    }
                }
            }
            // C2. Service CCID frames (F4 PIV; composite interface 2).
            // O driver C remonta frames bulk completos; o applet Rust
            // (em `ccid_transport`) sobrevive entre polls; NVS+chaves
            // são emprestados por frame.
            #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
            if usb_installed {
                const CCID_FRAME_MAX: usize = 2048;
                let mut frame = [0u8; CCID_FRAME_MAX];
                let n = unsafe { aegis_ccid_pop_frame(frame.as_mut_ptr(), CCID_FRAME_MAX as u16) };
                if n >= 10 {
                    if let Some(rpdu) = crate::ccid_dispatch::process_ccid_frame(
                        &mut ccid_transport,
                        &frame[..n as usize],
                        &mut storage,
                        &mut key_mgr,
                        now_secs,
                    ) {
                        if !unsafe { aegis_ccid_send(rpdu.as_ptr(), rpdu.len() as u16) } {
                            kprintln!("[CCID] bulk-IN send falhou ({} B).", rpdu.len());
                        }
                    }
                }
            }
        }

        // D. Service serial CTAPHID (UART 115200, framing identical to USB).
        //
        // Classic: this IS the transport (single serial port). S3/S2: UART0
        // diagnostic channel alongside native USB (section C untouched).
        // Heartbeat text stays outside the framing (the router ignores it);
        // test-mode answers TEST_LIFETIME_DUMP text lines on the same wire.
        // Vendor keys/OATH (0x20-0x27) use the BLE-identical gates with a
        // status-only answer (on-device executor = follow-up, status 0x04).
        // Binding mgmt over serial (0x28-0x2D) reuses the BLE dispatch_*
        // helpers (same binding -> UP -> PIN gates), status-first answer.
        #[cfg(target_os = "espidf")]
        if serial_installed {
            use crate::ble_gatt::{
                is_bind_mgmt_op, is_piv_enroll_op, is_vendor_keys_oath_op, is_wallet_op,
            };
            #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
            use crate::ble_gatt::{OP_WALLET_ADDR, OP_WALLET_GEN, OP_WALLET_LIST};
            use crate::serial_ctaphid::{
                authorize_serial, deny_response, dispatch_serial_bind_mgmt, dispatch_serial_rescue,
                is_rescue_msg, serial_bind_mgmt_consumes_up, serial_is_up_required, SerialFeed,
                SerialGate,
            };
            #[cfg(feature = "test-mode")]
            use crate::serial_ctaphid::{dispatch_serial_pairing_line, dispatch_serial_text_line};

            // D1. Diagnostic text lines (test-mode only; idle use only).
            // CI-GREP: TEST-HOOK (test-mode only; absent in release).
            // TEST_PAIRING_OPEN abre a mesma janela 60s do hold (software);
            // TEST_PAIRING_CLOSE fecha (determinismo entre sessões);
            // TEST_LIFETIME_DUMP responde o dump. Release: linhas desconhecidas.
            // D1b. LED ground-truth + primarias (test-mode only).
            // TEST_LED_STATE devolve tela + pairing + efeito ativo (diz o que o
            // firmware MANDA mostrar). TEST_LED_{RED,GREEN,BLUE,OFF} trava uma
            // cor solida (latch reaplicado todo poll, vence o override da
            // jornada); TEST_LED_RELEASE devolve o controle a jornada.
            #[cfg(feature = "test-mode")]
            {
                let mut chunk = [0u8; 32];
                let n = serial_read_chunk(&mut chunk, 32);
                for b in chunk.iter().take(n as usize) {
                    if *b == b'\n' {
                        if let Ok(line) = core::str::from_utf8(&serial_line) {
                            let t = line.trim();
                            if t == "TEST_UP" {
                                // UM toque BOOT via software (vale no proximo
                                // poll, mesma semantica do tap fisico).
                                test_up_latch = true;
                                kprintln!("[TEST] UP via software (latch 1x).");
                                let resp = "up_latched source=software\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if t == "TEST_DOWNLOAD" {
                                // CI-GREP: TEST-HOOK (test-mode only).
                                // Reboot p/ download ROM via RTC_CNTL
                                // (dispensa BOOT/DTR/RTS). Nunca retorna.
                                kprintln!("[TEST] download via software (RTC_CNTL).");
                                let resp = "download_mode source=software\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                                unsafe { aegis_reboot_to_download() };
                            } else if t == "TEST_USB_RECONNECT" {
                                // CI-GREP: TEST-HOOK (test-mode only).
                                // Drop + re-enumera o USB nativo via software
                                // (dispensa replug físico; Windows rebinda).
                                kprintln!("[TEST] usb reconnect via software.");
                                let resp = "usb_reconnect source=software\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                                unsafe { aegis_usb_reconnect() };
                            } else if t == "TEST_LED_STATE" {
                                let screen = match &display_mgr.current_screen {
                                    UiScreen::BootSplash { .. } => "BootSplash",
                                    UiScreen::IdleStandby { .. } => "IdleStandby",
                                    UiScreen::UserPresencePrompt { .. } => "UP-Prompt",
                                    UiScreen::Success { .. } => "Success",
                                    UiScreen::Error { .. } => "Error",
                                    UiScreen::TotpCode { .. } => "TotpCode",
                                };
                                let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                                let effect = display_mgr
                                    .led_controller
                                    .as_ref()
                                    .map(|l| format!("{:?}", l.current_effect()));
                                let resp = format!(
                                    "led_state screen={} pairing={:?} bonded={} claimed={} effect={} tick_ms={}\n",
                                    screen,
                                    pairing_mgr.state(),
                                    bonded as u8,
                                    binding_mgr.is_claimed() as u8,
                                    effect.as_deref().unwrap_or("no-led"),
                                    now_ms
                                );
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if t == "TEST_LED_RELEASE" {
                                led_test_hold = None;
                                let resp = "led_set released\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if let Some(held) = match t {
                                "TEST_LED_RED" => Some(LedEffect::Solid(crate::led::Color::RED)),
                                "TEST_LED_GREEN" => {
                                    Some(LedEffect::Solid(crate::led::Color::GREEN))
                                }
                                "TEST_LED_BLUE" => Some(LedEffect::Solid(crate::led::Color::BLUE)),
                                "TEST_LED_OFF" => Some(LedEffect::Off),
                                _ => None,
                            } {
                                led_test_hold = Some(held);
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(held);
                                }
                                let resp = format!("led_set {}\n", t);
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if let Some(resp) =
                                dispatch_serial_pairing_line(line, &mut pairing_mgr, now_ms)
                            {
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else {
                                let extra = format!(
                                    "uptime_s={} up_latched={}",
                                    tick * 10 / 1000,
                                    touch_latched
                                );
                                if let Some(resp) = dispatch_serial_text_line(line, &extra) {
                                    serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                                }
                            }
                        }
                        serial_line.clear();
                    } else if serial_line.len() < 48 {
                        serial_line.push(*b);
                    } else {
                        serial_line.clear();
                    }
                }
                // Reaplica o latch de cor solida todo poll: vence o override
                // da jornada (B-block) sem altera-lo.
                if let Some(held) = led_test_hold {
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(held);
                    }
                }
            }

            // D2. 64-byte packets (INIT/CONT, CID, keepalive — same as USB).
            let serial_n = serial_pop_packet(&mut rx_buf);
            if serial_n == PACKET_SIZE as u16 {
                match serial_router.feed(&rx_buf, now_ms) {
                    SerialFeed::IgnoredText | SerialFeed::NeedMore => {}
                    SerialFeed::Error(err) => {
                        kprintln!("[SERIAL] Protocol error: {}", err);
                        let pkt = err.to_packet();
                        serial_send_bytes(pkt.as_ptr(), PACKET_SIZE as u16);
                    }
                    SerialFeed::Message(msg) => {
                        kprintln!(
                            "[SERIAL] Message! CID: 0x{:08X}, CMD: 0x{:02X}, Len: {}",
                            msg.cid,
                            msg.cmd,
                            msg.payload.len()
                        );
                        match msg.cmd {
                            CMD_INIT => {
                                if msg.payload.len() >= 8 {
                                    let mut nonce = [0u8; 8];
                                    nonce.copy_from_slice(&msg.payload[0..8]);
                                    let new_cid = serial_router.allocate_cid();
                                    let pkt = CtapHidFramer::frame_init_response(
                                        msg.cid,
                                        &nonce,
                                        new_cid,
                                        1,
                                        0,
                                        0,
                                        CAPABILITY_WINK | CAPABILITY_CBOR,
                                    );
                                    serial_send_bytes(pkt.as_ptr(), PACKET_SIZE as u16);
                                    kprintln!("[SERIAL] Allocated CID: 0x{:08X}", new_cid);
                                }
                            }
                            CMD_PING => {
                                for p in CtapHidFramer::frame_ping(msg.cid, &msg.payload) {
                                    serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                }
                            }
                            CMD_WINK => {
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(LedEffect::Wink);
                                }
                                for p in CtapHidFramer::frame_message(msg.cid, CMD_WINK, &[]) {
                                    serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                }
                            }
                            CMD_CBOR | CMD_MSG => {
                                if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && is_bind_mgmt_op(msg.payload[0])
                                {
                                    // Binding mgmt 0x28-0x2D: same gates as BLE
                                    // (shared dispatch_* helpers); status-first
                                    // answer, framing untouched.
                                    let op = msg.payload[0];
                                    let (st, body) = dispatch_serial_bind_mgmt(
                                        op,
                                        &msg.payload[1..],
                                        pairing_open_now,
                                        touch_latched,
                                        &mut binding_mgr,
                                        &mut storage,
                                        &mut rand_core::UnwrapErr(getrandom::SysRng),
                                    );
                                    if st == 0x00 && serial_bind_mgmt_consumes_up(op) {
                                        touch_latched = false;
                                        rescue_engine.set_user_presence(true);
                                    }
                                    if st != 0x00 {
                                        kprintln!(
                                            "[SERIAL] Bind-mgmt 0x{:02X} denied (status 0x{:02X}).",
                                            op,
                                            st
                                        );
                                    }
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && msg.payload[0] == crate::fw_log::OP_FW_LOG
                                {
                                    // Log da firmware over serial: posse física
                                    // = livre (sem pairing, sem UP, sem latch).
                                    use crate::fw_log as fl;
                                    fw_log.record(fl::EV_OP_RX, fl::OP_FW_LOG, now_ms);
                                    let body = fw_log.render_ascii(1024);
                                    fw_log.record(fl::EV_OP_RESP, 0x00, now_ms);
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(0x00);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::ble::oob::is_ble_oob_op(msg.payload[0])
                                {
                                    // BLE OOB ARM 0x42 over serial (USB; o BLE
                                    // rejeita no reassembler, ver `ble::oob`):
                                    // classe CONFIG (janela + binding -> UP ->
                                    // sessao, sem bypass de presenca). Sucesso
                                    // arma o latch de radio e consome o latch
                                    // UP; negacoes nao tocam estado (fail-closed:
                                    // 0x05 sem janela/vinculo, 0x01 sem UP,
                                    // 0x02 travado, 0x04 forma ou radio sem latch).
                                    let op = msg.payload[0];
                                    let pin_live = ctap_engine.pin_state.has_valid_pin_uv_session()
                                        || (cfg!(feature = "test-mode")
                                            && (pairing_mgr.is_pairing_window_open(now_ms)
                                                || touch_latched));
                                    let (st, body) = if !pairing_mgr.is_pairing_window_open(now_ms)
                                    {
                                        (0x05, Vec::new())
                                    } else {
                                        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                        crate::vendor_exec::exec_vendor_op(
                                            &mut key_mgr,
                                            &mut oath_applet,
                                            &mut storage,
                                            op,
                                            &msg.payload[1..],
                                            binding_mgr.is_claimed(),
                                            pin_live,
                                            touch_latched,
                                            now_secs,
                                            &mut rng,
                                        )
                                    };
                                    if st == 0x00 {
                                        // `exec` validou 16 B; re-fatia
                                        // defensivo antes do radio.
                                        let tk = &msg.payload[1..];
                                        if tk.len() == crate::ble::oob::OOB_TK_LEN
                                            && crate::ble::nimble_backend::esp_ble_arm_oob(tk) == 0
                                        {
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            kprintln!(
                                                "[SERIAL] BLE OOB 0x42 armado (latch radio ok)."
                                            );
                                            let mut resp = Vec::with_capacity(1 + body.len());
                                            resp.push(st);
                                            resp.extend_from_slice(&body);
                                            for p in CtapHidFramer::frame_message(
                                                msg.cid, msg.cmd, &resp,
                                            ) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        } else {
                                            // Radio nao latchou: fail-closed.
                                            for p in CtapHidFramer::frame_message(
                                                msg.cid,
                                                msg.cmd,
                                                &[0x04],
                                            ) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                    } else {
                                        kprintln!(
                                            "[SERIAL] BLE OOB 0x42 negado (status 0x{:02X}).",
                                            st
                                        );
                                        let mut resp = Vec::with_capacity(1 + body.len());
                                        resp.push(st);
                                        resp.extend_from_slice(&body);
                                        for p in
                                            CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp)
                                        {
                                            serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && legacy_sg_dispatch::is_legacy_sg_op(msg.payload[0])
                                {
                                    // Secure Guard 0x3A-0x3E over serial: parity
                                    // with the freertos dispatcher (same
                                    // exec_secure_guard_op, same responses,
                                    // same gates). Move-only reuse, no protocol.
                                    let op = msg.payload[0];
                                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                    let (st, body, effects) =
                                        legacy_sg_dispatch::dispatch_legacy_secure_guard_op(
                                            &mut secure_guard,
                                            &mut storage,
                                            &mut wallet_store,
                                            &mut key_mgr,
                                            &mut oath_applet,
                                            op,
                                            &msg.payload[1..],
                                            now_ms,
                                            &mut rng,
                                        );
                                    if effects.did_unlock {
                                        pairing_mgr.open_host_window(now_ms);
                                        touch_latched = true;
                                        touch_expire_tick = now_ms.saturating_add(10_000);
                                        rescue_engine.set_user_presence(true);
                                        if let Some(pin_bytes) = effects.verified_pin {
                                            ctap_engine.pin_state.pin_hash =
                                                Some(aegis_fido_core::crypto::pin_hash(&pin_bytes));
                                            ctap_engine.pin_state.pin_retries = 8;
                                            ctap_engine.pin_state.power_cycle_state = false;
                                            let _ = crate::vendor_exec::save_pin_state(
                                                &mut storage,
                                                &ctap_engine.pin_state,
                                            );
                                            kprintln!(
                                                "[SERIAL][SG] PIN synced to CTAP2 ClientPIN."
                                            );
                                        }
                                    } else if effects.did_lock {
                                        pairing_mgr.lock();
                                        touch_latched = false;
                                    }
                                    kprintln!(
                                        "[SERIAL][SG] op 0x{:02X} (status 0x{:02X}).",
                                        op,
                                        st
                                    );
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::vendor_exec::is_get_caps_op(msg.payload[0])
                                {
                                    // GET_CAPS 0x3F: advertisement read-only, sem auth
                                    // (como o 0x38): posse fisica = livre; execucao
                                    // direta sem gates pairing/UP/PIN e sem latch.
                                    let op = msg.payload[0];
                                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                    let (st, body) = crate::vendor_exec::exec_vendor_op(
                                        &mut key_mgr,
                                        &mut oath_applet,
                                        &mut storage,
                                        op,
                                        &msg.payload[1..],
                                        false,
                                        false,
                                        false,
                                        now_secs,
                                        &mut rng,
                                    );
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::ctap_cmd::is_set_up_policy_op(msg.payload[0])
                                {
                                    // SET_UP_POLICY 0x40: management gated
                                    // (sem latch UP, sem pairing). Serial =
                                    // posse fisica + sessao PIN viva
                                    // (fail-closed); forma 0x04, travado
                                    // 0x02, ausente 0x03, ok 0x00 (+
                                    // auditoria EV_UP_POLICY_SET). Sem
                                    // latch: `touch_latched` intacto.
                                    let op = msg.payload[0];
                                    let pin_live = ctap_engine.pin_state.has_valid_pin_uv_session()
                                        || (cfg!(feature = "test-mode")
                                            && (pairing_mgr.is_pairing_window_open(now_ms)
                                                || touch_latched));
                                    let (st, body) = crate::ctap_cmd::exec_set_up_policy_wire(
                                        &mut storage,
                                        &mut fw_log,
                                        pin_live,
                                        &msg.payload[1..],
                                        now_ms,
                                    );
                                    kprintln!(
                                        "[SERIAL][UP-POLICY] op 0x{:02X} (status 0x{:02X}).",
                                        op,
                                        st
                                    );
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && (is_vendor_keys_oath_op(msg.payload[0])
                                        || is_wallet_op(msg.payload[0])
                                        || is_piv_enroll_op(msg.payload[0]))
                                {
                                    // Vendor keys/OATH + carteira + PIV enroll:
                                    // app-driven UP (latch, like BLE); denial
                                    // carries the BLE wire status.
                                    let op = msg.payload[0];
                                    match authorize_serial(
                                        msg.cmd,
                                        &msg.payload,
                                        pairing_open_now,
                                        touch_latched,
                                    ) {
                                        SerialGate::NeedPairing => {
                                            kprintln!(
                                                "[SERIAL] Pairing-mode required (hold BOOT 5s)."
                                            );
                                            for p in deny_response(&msg) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                        SerialGate::NeedUp => {
                                            // NEED_UP (0x01); the app re-sends after
                                            // the user taps BOOT (BLE parity).
                                            for p in CtapHidFramer::frame_message(
                                                msg.cid,
                                                msg.cmd,
                                                &[0x01],
                                            ) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                        SerialGate::Ok => {
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            let (st, body) = if is_wallet_op(op) {
                                                #[cfg(not(any(
                                                    feature = "cap-fido-only",
                                                    feature = "cap-fido-totp"
                                                )))]
                                                {
                                                    // Carteira Fase7: executa de verdade
                                                    // (gate pairing+UP já passou acima).
                                                    let mut rng =
                                                        rand_core::UnwrapErr(getrandom::SysRng);
                                                    use crate::wallet_exec as w;
                                                    match op {
                                                        OP_WALLET_GEN => w::wallet_gen(
                                                            &mut wallet_store,
                                                            &msg.payload[1..],
                                                            now_secs,
                                                            true,
                                                            &mut rng,
                                                        ),
                                                        OP_WALLET_LIST => {
                                                            w::wallet_list(&wallet_store, true)
                                                        }
                                                        OP_WALLET_ADDR => w::wallet_addr(
                                                            &wallet_store,
                                                            &msg.payload[1..],
                                                            true,
                                                        ),
                                                        _ => (0x04, Vec::new()),
                                                    }
                                                }
                                                // Diet: carteira fora da capability (fail-closed, 0x06).
                                                #[cfg(any(
                                                    feature = "cap-fido-only",
                                                    feature = "cap-fido-totp"
                                                ))]
                                                {
                                                    (crate::UNSUPPORTED_FEATURE, Vec::new())
                                                }
                                            } else {
                                                // F2: executor real on-device
                                                // (gate pairing+UP já passou;
                                                // PIN via plumbing ClientPIN).
                                                let mut rng =
                                                    rand_core::UnwrapErr(getrandom::SysRng);
                                                let (st, body) = crate::vendor_exec::exec_vendor_op(
                                                    &mut key_mgr,
                                                    &mut oath_applet,
                                                    &mut storage,
                                                    op,
                                                    &msg.payload[1..],
                                                    binding_mgr.is_claimed(),
                                                    ctap_engine
                                                        .pin_state
                                                        .has_valid_pin_uv_session()
                                                        || (cfg!(feature = "test-mode")
                                                            && (pairing_mgr
                                                                .is_pairing_window_open(now_ms)
                                                                || touch_latched)),
                                                    true,
                                                    now_secs,
                                                    &mut rng,
                                                );
                                                (st, body)
                                            };
                                            let mut resp = Vec::with_capacity(1 + body.len());
                                            resp.push(st);
                                            resp.extend_from_slice(&body);
                                            for p in CtapHidFramer::frame_message(
                                                msg.cid, msg.cmd, &resp,
                                            ) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::ota_store::is_ota_op(msg.payload[0])
                                {
                                    // F5: OTA over serial (mesmos gates do USB:
                                    // provisionado-lab + UP só no COMMIT).
                                    // Sem swap real (partição única): COMMIT
                                    // grava só o marker NVS (zero risco brick).
                                    #[cfg(all(
                                        target_os = "espidf",
                                        not(feature = "board-ttgo-classic")
                                    ))]
                                    {
                                        use crate::ota::OP_OTA_COMMIT;
                                        use crate::ota_store::{
                                            dispatch_ota_request, FlashOtaSink, OtaRequestCtx,
                                            OTA_STATUS_OK,
                                        };
                                        let ota_ctx = OtaRequestCtx {
                                            provisioned: ota_provisioned(&efuse_mgr),
                                            up: touch_latched,
                                            ota_pubkey: ota_active_pubkey(),
                                            current_version: FIRMWARE_VERSION,
                                        };
                                        let mut ota_sink = FlashOtaSink::new(storage.backend_mut());
                                        let op = msg.payload[0];
                                        let (st, body) = match dispatch_ota_request(
                                            &mut ota_state,
                                            &mut ota_sink,
                                            op,
                                            &msg.payload[1..],
                                            &ota_ctx,
                                        ) {
                                            Some((st, body)) => {
                                                kprintln!(
                                                    "[SERIAL][OTA] op 0x{:02X} (status 0x{:02X}).",
                                                    op,
                                                    st
                                                );
                                                (st, body)
                                            }
                                            None => (0x04, Vec::new()),
                                        };
                                        if st == OTA_STATUS_OK && op == OP_OTA_COMMIT {
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                        }
                                        let mut resp = Vec::with_capacity(1 + body.len());
                                        resp.push(st);
                                        resp.extend_from_slice(&body);
                                        for p in
                                            CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp)
                                        {
                                            serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                    // Classic (sem OTA): nega genérico, nunca silencia.
                                    #[cfg(not(all(
                                        target_os = "espidf",
                                        not(feature = "board-ttgo-classic")
                                    )))]
                                    {
                                        for p in
                                            CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x04])
                                        {
                                            serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG && is_rescue_msg(msg.cmd, &msg.payload)
                                {
                                    // Rescue Wave2 Step3 (0x2E) over serial: mesmo gate do
                                    // USB (UP do latch + plumbing ClientPIN).
                                    rescue_engine.set_user_presence(touch_latched);
                                    rescue_engine.set_pin_uv_authenticated(
                                        ctap_engine.pin_state.has_valid_pin_uv_session(),
                                    );
                                    touch_latched = false;
                                    let (st, body) = dispatch_serial_rescue(
                                        &mut rescue_engine,
                                        &msg.payload[1..],
                                    );
                                    kprintln!("[SERIAL][RESCUE] op 0x2E (status 0x{:02X}).", st);
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::pairing::is_host_pairing_msg(
                                        msg.payload[0],
                                        msg.payload.len() - 1,
                                    )
                                {
                                    // Pareamento por software (produto 0x2F) over
                                    // serial: mesma janela do hold; UP/bonding
                                    // seguem exigidos. UART = posse física.
                                    pairing_mgr.open_host_window(now_ms);
                                    touch_latched = true;
                                    touch_expire_tick = now_ms.saturating_add(10_000);
                                    rescue_engine.set_user_presence(true);
                                    kprintln!("[SERIAL][PAIRING] 0x2F: janela 60s aberta.");
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x00])
                                    {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if authorize_serial(
                                    msg.cmd,
                                    &msg.payload,
                                    pairing_open_now,
                                    touch_latched,
                                ) == SerialGate::NeedPairing
                                {
                                    kprintln!("[SERIAL] Pairing-mode required (hold BOOT 5s).");
                                    for p in deny_response(&msg) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else {
                                    // CTAP/U2F path: latch fast-path, else a
                                    // bounded 25s UP wait with serial keepalive
                                    // (same UX contract as the USB section).
                                    let ctap_subcmd = msg.payload.first().copied().unwrap_or(0);
                                    let up_needed = serial_is_up_required(msg.cmd, &msg.payload);
                                    let (rp_id, user_name, op_name) =
                                        ble_dispatch::extract_rp_and_user(
                                            ctap_subcmd,
                                            &msg.payload,
                                        );
                                    let mut up_ok = false;
                                    if up_needed {
                                        if touch_latched {
                                            up_ok = true;
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            kprintln!(
                                                "[SERIAL][UP] Latched touch confirms {}.",
                                                rp_id
                                            );
                                        } else {
                                            kprintln!(
                                                "[SERIAL][UP] Touch BOOT for {} ({}), 25s...",
                                                rp_id,
                                                op_name
                                            );
                                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                                rp_id: rp_id.clone(),
                                                user_name: user_name.clone(),
                                                operation: op_name.into(),
                                                remaining_seconds: 25,
                                            });
                                            for wait_step in 0..1250u32 {
                                                if wait_step % 5 == 0 {
                                                    let ka = CtapHidFramer::frame_keepalive(
                                                        msg.cid,
                                                        STATUS_UPNEEDED,
                                                    );
                                                    serial_send_bytes(
                                                        ka.as_ptr(),
                                                        PACKET_SIZE as u16,
                                                    );
                                                }
                                                if button_mgr.is_boot_pressed(std::thread::sleep) {
                                                    up_ok = true;
                                                    rescue_engine.set_user_presence(true);
                                                    kprintln!(
                                                        "[SERIAL][BUTTON] UP confirmed on BOOT."
                                                    );
                                                    break;
                                                }
                                                if button_mgr.is_key_pressed(std::thread::sleep) {
                                                    kprintln!(
                                                        "[SERIAL][BUTTON] Cancelled via KEY."
                                                    );
                                                    break;
                                                }
                                                std::thread::sleep(Duration::from_millis(20));
                                            }
                                            if up_ok {
                                                display_mgr.set_screen(UiScreen::Success {
                                                    title: "ACESSO AUTORIZADO".into(),
                                                    subtitle: rp_id.clone(),
                                                });
                                            } else {
                                                display_mgr.set_screen(UiScreen::Error {
                                                    message: "Tempo esgotado ou cancelado".into(),
                                                });
                                            }
                                        }
                                    } else {
                                        up_ok = true;
                                    }
                                    ctap_engine.set_user_presence(up_ok);
                                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                                    let res = ctap_engine.process_packet(
                                        &msg.payload,
                                        now_secs,
                                        &mut rng,
                                    );
                                    // F3: ClientPIN (0x06) mudou estado? Persiste.
                                    if msg.payload.first() == Some(&0x06)
                                        && !crate::vendor_exec::save_pin_state(
                                            &mut storage,
                                            &ctap_engine.pin_state,
                                        )
                                    {
                                        kprintln!("[WARN] NVS pin save falhou (serial).");
                                    }
                                    kprintln!(
                                        "[SERIAL][CTAP2] status 0x{:02X}, {} bytes",
                                        res.first().copied().unwrap_or(0xFF),
                                        res.len()
                                    );
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &res) {
                                        if !serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16) {
                                            kprintln!("[SERIAL] TX failed (packet dropped).");
                                        }
                                    }
                                    if up_needed && up_ok {
                                        std::thread::sleep(Duration::from_millis(800));
                                        display_mgr.set_screen(UiScreen::IdleStandby {
                                            status_text: "Aguardando solicitação FIDO2...".into(),
                                        });
                                    }
                                }
                            }
                            _ => {
                                let pkt = CtapHidFramer::frame_error(msg.cid, 0x01);
                                serial_send_bytes(pkt.as_ptr(), PACKET_SIZE as u16);
                            }
                        }
                    }
                }
            }
        }

        // Heartbeat log every 3 seconds (300 ticks * 10ms = 3000ms).
        // Silent mid-transaction on the shared serial wire so heartbeat text
        // never interleaves a 64-byte CTAPHID exchange (framing stays clean).
        #[cfg(target_os = "espidf")]
        let serial_busy = serial_router.has_pending();
        #[cfg(not(target_os = "espidf"))]
        let serial_busy = false;
        if tick.is_multiple_of(300) && !serial_busy {
            #[cfg(target_os = "espidf")]
            let usb_mounted = if usb_installed {
                unsafe { aegis_usb_is_mounted() }
            } else {
                false
            };
            #[cfg(not(target_os = "espidf"))]
            let usb_mounted = false;

            kprintln!(
                "[HEARTBEAT] AegisKey S3 alive | uptime: {}s | USB Mounted: {}",
                tick * 10 / 1000,
                usb_mounted
            );
        }

        tick = tick.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(10));
    }
}
