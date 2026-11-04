# Variante FreeRTOS em Rust

Decomposição do super-loop único (`run_authenticator`) em três tarefas FreeRTOS explícitas, 100% em Rust.

## Tarefas

| Tarefa | Nome | Prio | Stack | Núcleo |
|---|---|---|---|---|
| USB CTAPHID | `usb_ctaphid` | 5 | 8 KiB | Some(1) |
| UI / botão | `ui_button` | 4 | 4 KiB | None |
| Housekeeping | `housekeeping` | 2 | 4 KiB | None |

- Tick base `TICK_MS = 10`, pacote `CTAPHID_PACKET_SIZE = 64`, fila `DEFAULT_QUEUE_DEPTH = 32`.
- `TaskConfig::new` valida prio `1..=24`, stack >= 2048, core 0/1.

## Fila + EventGroup

- `FreeRtosQueue<T>`: FIFO limitada, `send` não-bloqueante fail-closed, `receive(timeout)` com `Condvar`.
- Bits: `EVT_USB_RX=1<<0`, `EVT_BUTTON_UP=1<<1`, `EVT_BLE_RX=1<<2`, `EVT_TICK_10MS=1<<3`, `EVT_SHUTDOWN=1<<31`.
- `FirmwareEvent::{UsbPacket, ButtonPress, BleFragment, Tick10ms, Shutdown}` — sem segredos.
- `request_stop()`: flag + `EVT_SHUTDOWN` + evento `Shutdown`.

## Device vs host

- `task_delay_ms`: `vTaskDelay` no ESP-IDF, `sleep` no host.
- `tick_count_ms`: `xTaskGetTickCount*10` no device, `Instant` no host.
- Criação: no host `std::thread::Builder` com nome/stack; no device
  `spawn_*_native` via `xTaskCreatePinnedToCore` com `TaskConfig` real
  (`NativeTaskHandle::join` cooperativo / `delete` via `vTaskDelete`).

## Habilitar

```toml
[features]
freertos = []
```

```sh
cargo test -p aegis-fido-firmware --features freertos
cargo build --features freertos   # device ESP-IDF
```

`app_main` desvia para `run_authenticator_freertos()` (USB + botão + housekeeping sobre fila/event-group). `app_main_freertos_demo()` drena 3 pacotes sintéticos + 1 UP em ~50 ms.

## Fluxo

```text
poll_64 -> UsbPacket -> EVT_USB_RX -> queue[32] -> dispatcher
poll_boot/key -> ButtonPress -> EVT_BUTTON_UP -> queue
housekeeping 10ms -> feed TWDT + Tick10ms a cada 100 ticks
request_stop -> flag + EVT_SHUTDOWN + Shutdown
```

## Pinos

- `GPIO0` BOOT (UP), `GPIO48` WS2812. Nada novo.

## Segurança

- Fila cheia descarta sem panic; host reenvia; nunca autoriza presença.
- Sem chaves/seeds na fila; TWDT via `Watchdog::new(300)`; parada cooperativa sem deadlock.

## Prioridades e núcleos efetivos (implementado)

Fonte: `crates/aegis-fido-firmware/src/freertos.rs` (`USB_TASK_PRIO`, `UI_TASK_PRIO`,
`HOUSEKEEPING_TASK_PRIO`, `TaskConfig::usb/button/housekeeping`).

| Tarefa | Prio efetiva | Stack efetivo | Afinidade declarada | Afinidade forçada |
|---|---|---|---|---|
| `usb_ctaphid` | 5 | 8 KiB | `Some(1)` | Host não (`spawn_usb_task` std); device sim (`spawn_usb_task_native` via `xTaskCreatePinnedToCore`) |
| `ui_button` | 4 | 4 KiB | `None` | Não (sem afinidade) |
| `housekeeping` | 2 | 4 KiB | `None` | Não (sem afinidade) |

- Ordem efetiva: USB (5) > botão (4) > housekeeping (2); idle = 0.
- `TaskConfig::new` rejeita prio fora de `1..=24`, stack < 2048 e `pinned_core > 1`.
- Estado atual: `spawn_usb_task_native` / `spawn_button_task_native` /
  `spawn_housekeeping_task_native` chamam `xTaskCreatePinnedToCore` com o
  `TaskConfig` real (nome NUL 16 B, stack em words, prio e afinidade;
  `tskNO_AFFINITY` quando `None`); `freertos_task_create` valida o mesmo
  caminho via sonda. No host, `spawn_*` std continua sem pinagem explícita.

## TWDT (estado real)

Fonte: `src/freertos.rs` (`spawn_housekeeping_task`, `housekeeping_step`) +
`src/watchdog.rs` (`Watchdog::new/feed`).

- Implementado: TWDT por task via `PerTaskWatchdog`. Cada `spawn_*` (std e
  nativo) faz `subscribe_current_task` no início (`esp_task_wdt_add(NULL)`
  no device, no-op no host) e `feed_current_task` por iteração
  (`esp_task_wdt_reset()` no device, contador `feed_count()` no host).
  O housekeeping acumula ainda `Watchdog::new(300)` (300 ticks de 10 ms =
  ~3 s) com `feed(tick)` a cada 10 ms via `housekeeping_step`; no host só
  registra `last_feed_tick`.

## High-water (estado real)

- Implementado: nome de cada task (`usb_ctaphid`, `ui_button`, `housekeeping`)
  via `std::thread::Builder::name` (host) e entry nativa (device), visível em
  `vTaskList`; leitura real via `stack_high_water_mark()`
  (`uxTaskGetStackHighWaterMark(NULL)` no device, 4096 no host),
  `task_count()` (`uxTaskGetNumberOfTasks` no device, 3 no host),
  `current_core_id()` (`xTaskGetCoreID` no device, -1 no host) e
  `log_boot_info()` (`boot tasks/high-water/core`). Stacks configurados:
  8 KiB USB, 4 KiB botão, 4 KiB housekeeping.

## Dispatcher (estado real, mínimo)

Fonte: `src/main.rs` (`run_authenticator_freertos`, feature `freertos`).

- Não existe função `dispatcher()` dedicada em `freertos.rs`. O despacho é o
  loop `sched.queue.receive(...)` dentro de `run_authenticator_freertos`:
  fila limitada de 32 (`DEFAULT_QUEUE_DEPTH`) + `EventGroup`.
- Roteamento: `usb_task_step` (5 ms, `poll_64`) -> `Evt USB_RX` + `UsbPacket`;
  `button_task_step` (10 ms, `poll_boot/poll_key`) -> `EVT_BUTTON_UP` +
  `ButtonPress`; housekeeping (10 ms) -> `EVT_TICK_10MS` + `Tick10ms` a cada
  100 ticks; `request_stop` -> flag + `EVT_SHUTDOWN` + `Shutdown`.
- Host (`not(espidf)`): roda ~2 s drenando a fila com `kprintln!`
  (`[FREERTOS] usb packet (N B).` / `[FREERTOS] UP latch boot=.. key=..` /
  `[FREERTOS] tick N.` a cada 100 ticks), depois `request_stop` e `join`.
- Device (`espidf`): loop infinito; cada variante gera `kprintln!` (`usb packet`,
  `UP latch` + `note_presence` no BOOT, `tick` + `prox.tick(~1 s)` com gate
  coex/USB, `ble fragment` anotado sem dispatch GATT); `Shutdown` faz
  `prox.erase()` (zeroize K_prox) e sai.
- USB real: no device `poll_64` chama `aegis_usb_pop_packet(buf, 64)` e só
  aceita `n == 64`; fora do classic ainda drena `aegis_serial_pop_packet`
  (UART0) com a mesma regra 64 B; no host retorna `None`.
- Botão real: no device fiado em `EspBootButtonInput::is_pressed_raw()`
  (BOOT = GPIO0) mais `EspKeyButtonInput::is_pressed_raw()` nas boards com
  KEY (t-display/ttgo-classic), sem `DualButtonManager` (dorme ~1 ms,
  proibido em task); no host segue stub `|| false, || false`.
- Serial: no device não-classic `run_authenticator_freertos` drena UART0
  115200 8N1 via `aegis_serial_pop_packet` dentro do `poll_64` (parcial
  descartado com `None`); classic reusa `aegis_usb_*` via `serial_pop_packet`.

## Como habilitar `--features freertos`

Definição: `crates/aegis-fido-firmware/Cargo.toml` -> `freertos = []`
(default é só `board-devkitc`; `freertos` é opt-in).

```sh
cargo test -p aegis-fido-firmware --features freertos
cargo build -p aegis-fido-firmware --features freertos   # device ESP-IDF
```

`src/main.rs::app_main` desvia com `#[cfg(feature = "freertos")]` para
`run_authenticator_freertos()`; sem a feature, sobe o super-loop legado
`run_authenticator()` numa thread `aegis_auth` de 96 KiB.

## Gates

- Host: `cargo test -p aegis-fido-firmware --features freertos` (18 testes em
  `src/freertos.rs`: configs, bits, fila FIFO + descarte fail-closed, receive
  com timeout, event-group set/wait/clear + timeout, passos puros, scheduler
  USB/botão/housekeeping, demo end-to-end 3 pacotes + 1 UP, delay/tick,
  `request_stop` triplo, clamp de depth 0, `request_stop` com fila cheia,
  watchdog por task, bindings host, core_id + boot info).
- Device: `cargo build -p aegis-fido-firmware --features freertos` sob ESP-IDF
  (`target_os = "espidf"`); `task_delay_ms` usa `vTaskDelay`, `tick_count_ms`
  usa `xTaskGetTickCount * 10`.
- Demonstração sem hardware: `app_main_freertos_demo()` drena 3 pacotes
  sintéticos + 1 UP em ~50 ms; cobre-se no teste `demo_freertos_end_to_end`.

## Limitações conhecidas (dispatcher mínimo)

- `FirmwareEvent::BleFragment` + `EVT_BLE_RX` existem mas nenhum `spawn_*`
  produz/consome BLE; `ble_nimble.rs` (NimBLE GATT) não está fiado no scheduler.
- WiFi/mDNS fora: features `wifi`/`ble` do `Cargo.toml` e componentes C
  (`aegis_ble`, `aegis_wifi`) não participam do caminho freertos.
- Serial CTAPHID no caminho freertos: no device fora de `board-ttgo-classic`,
  `poll_64` drena `aegis_serial_pop_packet` (UART0) além de
  `aegis_usb_pop_packet`, ambos só com 64 B completos (`None` se parcial);
  no host retorna `None`.
- Botão real no device via `EspBootButtonInput::is_pressed_raw()` (BOOT = GPIO0)
  mais `EspKeyButtonInput::is_pressed_raw()` nas boards com KEY
  (`board-t-display`/`board-ttgo-classic`); sem `DualButtonManager` (dorme
  ~1 ms, proibido em task); no host segue stub `|| false, || false`.
- TWDT por task via `PerTaskWatchdog` nos 3 `spawn_*` (std e nativos);
  high-water via `stack_high_water_mark()` + `task_count()` + `log_boot_info`;
  pinagem via `xTaskCreatePinnedToCore` com `TaskConfig` real (USB `Some(1)`,
  demais `None`).
- Fila cheia descarta (fail-closed, host reenvia) — correto para segurança,
  mas sem contador de descarte observável.

## Loop 1 (2026-10-20, verificado)

- TWDT por task: `PerTaskWatchdog` com subscribe no inicio e feed por
  iteracao nos 3 `spawn_*` (host com contador testavel).
- High-water: `stack_high_water_mark` e `task_count` com FFI real no device
  e stubs no host; criacao via `xTaskCreatePinnedToCore` com sonda.
- `request_stop` sem perda: fila cheia drena 1 item e retenta 1x.
- `main.rs`: USB real (USB mais serial 64 B no device) e botao GPIO0 e KEY
  reais sem bloqueio via `is_pressed_raw`.
- Verde: 269 lib mais 2 integracao mais 3 migracao; clippy limpo nas 2 configs.
  Resta: dispatcher BLE e WiFi com mDNS, build ESP-IDF, hardware COM7 e COM8.

## Proximity BLE no scheduler (loop 2)

Origem de referência (somente leitura): `E:/projetos/fido/docs/piv-ble-proximity.md`
e `docs/proximity-worktree-handoff.md` (sessão origem 2026-10-20). O que segue
separa estado implementado nesta lane, contrato herdado da origem e plano.

### Estado implementado nesta lane (verificado no código desta worktree)

- `src/proximity.rs` existe com Wave 1 apenas:
  `ProximityState::{Near, Away, Locked}`, `ProximityConfig::default()` com
  `lock_rssi_dbm = -75`, `lock_secs = 10`, `hysteresis_db = 5`
  (`PROXIMITY_LOCK_RSSI_DBM = -75`, `PROXIMITY_LOCK_SECS = 10`,
  `PROXIMITY_HYSTERESIS_DB = 5`).
- Semântica presente: `None` conta como fraco, clamp de 60 s por amostra
  (`MAX_ELAPSED_SECS_PER_UPDATE`), banda de histerese congela estado,
  `Away` só via acúmulo, `Locked` só via `confirm_lock()`, `update` nunca
  sai de `Locked` sozinho, `unlock(presença+PIN)` volta a `Near`.
- Coex e bonding presentes: `coex_proximity_allowed(usb_active) = !usb_active`,
  `bonding_required() = true`,
  `authorize_proximity_sample(bonded, usb_active) = bonded && !usb_active`;
  amostra negada deve ser alimentada como `None`/fraco (fail-closed).
- `src/freertos.rs` nesta lane tem 3 tarefas e nenhum caminho proximity:
  `usb_ctaphid` prio 5 stack 8 KiB, `ui_button` prio 4 stack 4 KiB,
  `housekeeping` prio 2 stack 4 KiB; `FirmwareEvent::BleFragment` e
  `EVT_BLE_RX` existem mas nenhum `spawn_*` produz ou consome.
- `src/ble_nimble.rs` nesta lane tem Wave 2 proximity (`#[cfg(feature =
  "proximity")]`): `encode_proximity_adv_payload` (30 B, `0xFFFE`),
  `should_adv_proximity`, `proximity_adv_intervals`, `esp_ble_proximity_start`
  (FFI no device, shim 0 no host) e `own_addr_or_placeholder` (FFI
  `aegis_ble_own_addr` com fallback XOR-fold do serial); GATT `0xFFFD` intacto.
- `src/main.rs::run_authenticator_freertos` nesta lane sobe USB + botão +
  housekeeping (nativos no device, std no host) e, com `proximity`, um
  `prox_sched::ProxSchedState` (`note_boot(false)` fail-closed, `tick(~1 s)`
  com gates `Idle`+bonded+trusted+USB-idle+KEY, `note_presence` no BOOT,
  `erase` no `Shutdown`); sem task BLE dedicada nem dispatch GATT.

### Contrato herdado da origem (não reimplementado nesta lane, referência)

- Política RSSI: `Near` perto, `Away` após `< -75 dBm` por 10 s,
  retorno a `Near` só acima de `-70 dBm` (hist 5 dB), `Locked` só via
  `confirm_lock`, `unlock` exige presença física + PIN, sem auto-unlock.
- Beacon Wave 2: service-data `0xFFFE` com `[VER|CTR|TAG]`,
  `VER = 0x01`, `CTR = u32LE`, `TAG = 4 B`;
  `TAG = AES-CCM-128(K_prox, nonce = VER||CTR||fob_id[6B], AAD = VER||CTR)`
  truncado a 4 B; `ProximityBeacon` com tick de cerca de 1 s e saturação de CTR;
  `ProximityVerifier` com anti-replay e salto `> 1000` com reverify.
- Gates do tick/anúncio na origem: `Idle` + bonded + trusted + não-USB
  (`aegis_usb_is_mounted`, `false` no host) + com KEY (`K_prox` provisionada);
  `USB` veta, `WiFi` desacelera; nunca auto-unlock.
- Coex: prioridade `USB > BLE`; `proximity_coex_allow` e
  `proximity_adv_allowed` negam com USB ativo; GATT `0xFFFD` intacto, rev `0x01`.
- Bonding obrigatório para amostra e anúncio; `ble_nimble.rs` da origem com
  `encode_proximity_adv_payload` 30 B (limite 31 B), `should_adv_proximity`
  Idle-only, `esp_ble_proximity_start`; C `aegis_ble_proximity_start`
  fail-closed reusando coex.
- Chave: `K_prox` em NVS `prox_k` + `zeroize`; boot faz `load` ou `rekey` só
  se `bonded||claimed`; `rekey + ctr = 0` nos 2 `Paired`; `delete` em
  `BIND_RELEASE`/`RECOVERY_UNLOCK`; tudo `#[cfg(feature = "proximity")]`.
- `fob_id`: placeholder `XOR-fold` de `SERIAL_NUMBER_STRING` na origem,
  documentado como provisório; FFI MAC real futuro (`aegis_ble_own_addr`
  via `ble_hs_id_copy_addr`/`esp_read_mac`, `extern C` em `ble_nimble.rs`).
- Hosts `tools/host/{win,linux,macos}/proximity_agent.py`: `ProximityDecider`
  idêntico, `_fob_id_bytes` do MAC bonded, `_ccm_tag` réplica do firmware,
  `RollingCodeVerifier`, `make_polling_source` exige `0xFFFE` válido,
  `ProximityBeacon`/`ProximityVerifier` espelhados; trava por OS
  (`LockWorkStation`/`loginctl`/`CGSession`), lock-only, fail-closed.
- Vetor de interop da origem: `K = 0x42 * 16`, `fob = AA:BB:CC:DD:EE:FF`,
  `ctr = 7`, `VER = 0x01` resulta `TAG = 660d4941` (`py-tag == rs-tag`).

### Scheduler: task dedicada prio 1 vs hook no housekeeping (plano, sem código novo)

- O código desta lane não criou task proximity dedicada; o hook é
  `prox_sched::ProxSchedState::tick` (~1 s, throttle `PROX_TICK_MS`) chamado
  do ramo `Tick10ms` do dispatcher, além de `housekeeping_step` (feed +
  `Tick10ms` a cada 100 ticks) e 3 `spawn_*` com `PerTaskWatchdog` próprio.
- Opção A (task dedicada): 4a task `proximity` prio 1 stack 4 KiB, abaixo de
  housekeeping (2), USB (5) e botão (4); poll de cerca de 1 s, aplica gates
  e publica beacon/verifier sem bloquear USB/botão; parada cooperativa via
  `stop` + `EVT_SHUTDOWN`.
- Opção B (hook housekeeping): reaproveitar `spawn_housekeeping_task`
  (10 ms) com contador para tick de cerca de 1 s; menor custo de task,
  mas acopla watchdog/tick com beacon e exige cuidado para não atrasar feed.
- Estado nesta lane: hook no dispatcher (opção B, via `prox_sched::tick` no
  ramo `Tick10ms`); task dedicada (opção A) segue alternativa não implementada.
  Qualquer port mantém `default-off` (`proximity` + `freertos` opt-in), sem
  tocar `CTAP`/`USB`/`CBOR`.

### Gates de teste (plano, sem alegação de verde nesta lane)

- `cargo test -p aegis-fido-firmware --features proximity proximity`
  (origem: 34 testes; nesta lane 27 testes em `proximity.rs` + 11 em
  `prox_sched` no `main.rs`).
- `cargo test -p aegis-fido-firmware --features freertos,proximity`
  (unidade proximity + scheduler + integração).
- `cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity -- -D warnings`
  e baseline `cargo clippy --all-targets -- -D warnings`.
- Hosts: `python tools/host/win/test_proximity_agent.py`,
  `python tools/host/linux/test_proximity_agent.py`,
  `python tools/host/macos/test_proximity_agent.py` e `--self-test` nos 3.

### Limitações conhecidas

- `fob_id` real pendente: placeholder `XOR-fold` documentado; falta FFI
  `aegis_ble_own_addr` no `.c` + `extern C` + uso no `main.rs`.
- Fluxo fábrica `K_prox` pendente: hoje `rekey` no `Paired` + chave via
  argumento host; falta troca dentro de link cifrado+bonded, nunca em claro.
- Build embarcado pendente: targets `xtensa`/`riscv32imc-esp-espidf` + `idf.py`
  + `ESP_IDF_VERSION`, `idf.py build --features proximity`, checar `.bss`/flash.
- Medição aérea pendente: flash + parear/bond + agente
  (`--fob-id`, `--k-prox-hex`, `--lock-secs 10`, `--poll-secs 2`),
  walk-away até 15 s trava, volta não destrava, USB ativo silencia BLE,
  calibrar `-75`/`5 dB` no ambiente.
- Opcional fora do escopo: `scan-response` para nome cheio, `IRK`/privacidade,
  `Dynamic Lock` como fallback, nunca decisor.

## Hardware S3 — flash + boot + suite (2026-10-21, evidencias colhidas)

- Binario S3: `C:\t\aegis-app-freertos-s3.bin`, SHA256
  `E569658AE5808AD2A24CC5498E18F9707A40921DC9C6FF5FC9374A6D674DE064`,
  828752 bytes (factory max 3145728).
- Flash: COM13 (ESP32-S3 MAC 3c:84:27:c7:17:78) via
  `esptool write_flash 0x10000` (hash verificado, hard reset).
- Enumeracao USB: VID 0x303A PID 0xAE61 (CCID + HID FIDO + composite OK).
- Suite `tools/test_aegiskey_rust.py`: 8/8 PASS no hardware.
- Boot log real capturado: `main_task Started on CPU0`,
  `[FREERTOS] AegisKey FreeRTOS variant booting`,
  `boot tasks=6 stack_high_water=8272B core=0`,
  `[PROX] fob_id via placeholder (FFI rc=-1)` x2,
  `[PROX] sem K_prox fail-closed`, ticks.
- Portas: COM13 = console UART0; COM11/COM12 pertencem a outra placa
  (nao tocar); COM7 ocupada.
- PENDENTE (nao afirmado): distribuicao das 3 tasks por nucleo
  (linhas `na core N` adicionadas mas ainda nao capturadas no boot);
  walk-away aereo.
