# STATE.md — fido / fido-auditoria
- stage: fd-execute in_progress (Wave3)
- skippedStages: none
- topic: fido-auditoria
- gates: rewrite-sem-mudanca, worktree-antes-do-real, testes-verdes-antes-do-merge
- waves done: wave0 (5d6c716), wave1 (83c0135+80537db), wave2 (a6837b5), wave2.5 SIZE+FLASH COM7 OK
- next: fd-execute Wave3 (config.rs + migracao + fabrica) na worktree wave3-3
plan_file: C:\Users\junior\.fd-plan\fido\sistema-ota\plan.md
topic: "sistema-ota"

---
# fd-execute validacao-usb-telas (2026-10-19)
- topic: validacao-usb-telas
- plan_confirmed: true (CONFIRM fd-review)
- research_execute: reused fd-task session research (USB paths, simulator, 22 screens, monitor points, COM7/COM8 states)
status: in_progress
last_action: "Step 4 complete: web assisted tab, docs reconciled, store rollback fix, 87/87 crate tests"

## Session History
- 2026-10-19T20:09:48.125Z — Step 4 complete: web assisted tab, docs reconciled, store rollback fix, 87/87 crate tests
- 2026-10-19T20:09:21.826Z — Wave 1 complete (Steps 1+2 + M1/M2/m1 fixup): 191 tests green, clippy clean
- 2026-10-19T20:08:09.967Z — piv-ble-proximity Wave 1 verified — all checks passed
- 2026-10-19T20:04:05.230Z — Wave 1 gate PASS: reviewer no-majors, workspace 291/291, clippy clean
- 2026-10-19T20:02:27.364Z — Wave 1 complete: wallet module (17 tests green, clippy clean) + docs DRAFT; B1 dedicated-KeyManager, B3 4 no_std deps
- 2026-10-19T20:01:57.158Z — Wave 1 complete Steps 1-4 (PIV skeleton + proximity + win agent + docs), verified
- 2026-10-19T20:01:33.939Z — Step 1 complete: integration worktree fd-fido-integracao-unificada-phase-0 created at baseline 4b28aa4, verified MATCH + clean
- 2026-10-19T19:59:51.982Z — Wave 1 Steps 1-2 complete + fixes verified (284+182 tests, clippy clean, re-review PASS)
- 2026-10-19T19:59:01.199Z — Review complete — artifacts confirmed
- 2026-10-19T19:56:56.597Z — Task artifacts confirmed and saved (validation loop-guard noted)
- 2026-10-19T19:42:39.959Z — Review complete — artifacts confirmed
- 2026-10-19T19:42:19.655Z — Review complete — artifacts confirmed
- 2026-10-19T19:37:40.781Z — Review complete — artifacts confirmed
- 2026-10-19T19:35:05.381Z — Task artifacts confirmed and saved
- 2026-10-19T19:35:04.049Z — Review complete — artifacts confirmed
- 2026-10-19T19:34:54.432Z — Task artifacts confirmed and saved
- 2026-10-19T19:32:22.328Z — Task artifacts confirmed and saved
next_action: "Step 5 final gate + merge"
plan_confirmed: true
design_approved: false
steps_complete: [2, 3, 4]
steps_pending: [3, 4, 5]

## FreeRTOS Rust (feat/freertos-rust) — loop 1 verificado 2026-10-20

- escopo: variante FreeRTOS em Rust com 3 tarefas explícitas (`usb_ctaphid` prio 5 stack 8 KiB, `ui_button` prio 4 stack 4 KiB, `housekeeping` prio 2 stack 4 KiB) sobre fila limitada (`DEFAULT_QUEUE_DEPTH = 32`, `send` não-bloqueante fail-closed) + EventGroup (`EVT_USB_RX/BUTTON_UP/BLE_RX/TICK_10MS/SHUTDOWN`). Detalhe em `docs/freertos-rust.md`.
- arquivos: `crates/aegis-fido-firmware/src/freertos.rs` (queue, EventGroup, TaskConfig, xTaskCreatePinnedToCore/sonda, PerTaskWatchdog, high-water, request_stop sem perda), `src/main.rs` (`app_main`, `run_authenticator_freertos`: USB+serial 64 B reais no device, botão GPIO0/KEY real sem bloqueio, dispatcher Shutdown-break), `src/lib.rs`, `Cargo.toml` (`freertos = []`), `tests/freertos_tasks.rs` (novo, 2 testes), `docs/freertos-rust.md`.
- como testar: `cargo test -p aegis-fido-firmware --features freertos` (269 lib + 2 integração + 3 migração, 0 falhas); `cargo clippy -p aegis-fido-firmware --all-targets [--features freertos] -- -D warnings` (ambos Finished limpos); `cargo test --workspace` verde.
- próximos passos: (1) dispatcher BLE/WiFi (`BleFragment`/`EVT_BLE_RX`, `ble_nimble.rs`, depois WiFi/mDNS; prioridade USB > WiFi > BLE); (2) build ESP-IDF + log high-water no boot; (3) hardware COM7/COM8: CTAPHID 64 B + UP, regressão serial 115200 8N1.

## Proximity BLE no FreeRTOS (port do handoff, loop 2)

- origem: `docs/proximity-worktree-handoff.md` (trazido do checkout main; sessão origem 2026-10-20). Firmware `proximity.rs` (Near/Away/Locked, lock < -75 dBm/10 s/hist 5 dB, `Locked` só via `confirm_lock`, `unlock` com presença+PIN, `None`=fraco, clamp 60 s, coex USB>BLE, bonding obrigatório) + beacon Wave2 (service-data `0xFFFE [VER|CTR|TAG]`, TAG=AES-CCM-128 trunc 4 B, tick ~1 s, anti-replay, `K_prox` em NVS `prox_k` + zeroize) + `ble_nimble.rs` (payload 30 B, `should_adv_proximity` Idle-only, `esp_ble_proximity_start`) + C `aegis_ble_proximity_start` + `main.rs` (+241, tudo `#[cfg(feature="proximity")]`) + hosts `tools/host/{win,linux,macos}/proximity_agent.py` (vetor interop `K=0x42*16, fob=AA:BB:CC:DD:EE:FF, ctr=7 => TAG=660d4941`). Origem verde no host (34 proximity + agents 34/33/33 + self-tests).
- estado nesta lane: `src/proximity.rs` existe mas `src/ble_nimble.rs` tem 0 refs proximity e `run_authenticator_freertos` em `src/main.rs` não fia beacon/tick; `freertos.rs` sem task/hook proximity. Port = trazer beacon+verifier+tick ~1 s com gates (Idle/bonded/trusted/não-USB/com KEY) para o scheduler FreeRTOS (4ª task `proximity` prio 1/stack 4 KiB ou hook no housekeeping), `fob_id` placeholder XOR-fold documentado (FFI MAC real fica para o passo HW), `K_prox` via `rekey` no `Paired`, tudo `#[cfg(feature="proximity")]`, default-off, sem tocar CTAP/USB/CBOR, secure-boot off, CRLF em `.rs`/`.py` e LF no `.c`.
- como testar: `cargo test -p aegis-fido-firmware --features freertos,proximity` (unit proximity + scheduler + integração); `cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity -- -D warnings`; `cargo test -p aegis-fido-firmware --features proximity proximity` (34 origem); `python tools/host/win|linux|macos/test_proximity_agent.py` + `--self-test` nos 3 hosts.
- próximos passos cumpridos no loop 2 (2026-10-20, verificado): beacon/verifier (`proximity.rs` Wave2 + `ble_nimble.rs` + C `aegis_ble_proximity_start`) e fiação no scheduler (`mod prox_sched` em `main.rs`: boot fail-closed, rekey+ctr=0, tick ~1 s com gates, USB veta, erase no Shutdown, 11 testes bin); hosts `tools/host/{win,linux,macos}` portados (self-tests ok 34/33/33) + `tests/proximity_freertos.rs` (11 passed, inclui interop `TAG=660d4941` por oráculo independente). Verde: 301 lib + 11 bin + 2 + 3 + 11 integração; clippy limpo em default, freertos, proximity e freertos+proximity; workspace verde.
- próximos passos (loop 3): (1) pinagem dual-core (`xPortGetCoreID` no boot; USB fixo core 1, housekeeping no 0); (2) `fob_id` real via FFI `aegis_ble_own_addr`; (3) fluxo fábrica `K_prox` em link cifrado+bonded; (4) build `idf.py` + flash + medição aérea (walk-away ≤15 s trava, volta não destrava, USB silencia BLE, calibrar -75/5 dB).

## Fase A — 100% FreeRTOS nativo (loop 3, código pronto; device build rodando)
- `freertos.rs`: `spawn_*_native` via `xTaskCreatePinnedToCore` real (USB prio 5/8K/core 1, botão prio 4/4K/sem afinidade, housekeeping prio 2/4K/sem afinidade), `NativeTaskHandle` com join via `ulTaskNotifyTake`, TWDT por task, `current_core_id` (`xPortGetCoreID`), `log_boot_info` (task_count + high-water + core). Host `std::thread` inalterado.
- `main.rs` `run_authenticator_freertos`: device usa nativas + `log_boot_info()` no boot; host mantém 2 s + `request_stop`. Verde host: 302 lib + 11 bin + 2 + 3 + 11 integração; clippy limpo nas 4 configs.
- Device build S3 release (`board-devkitc,freertos,proximity`) via `scripts/build-freertos-s3.ps1`: PASS (11,98 s) — ELF ok, `C:\t\aegis-app-freertos-s3.bin`, SHA256 `13B9A3C20D0495F7A85F37E421BD93FB435FAD93A76131F147DBC7A08D86267B`, 483936 bytes (factory max 3145728). Corrige 5 erros de bindings (`xPortGetCoreID`→`xTaskGetCoreID(NULL)`; join por notify→flag `done` + `vTaskDelay`). Restam só warnings preexistentes de drift de toolchain (provision `RngCore`, `dispatch_serial_wallet`, `unsafe` do `kprintln`), sem relação com freertos.
- Scripts novos: `sync-master.ps1/.sh` (fetch + ahead/behind + hotspots + gate), `build-matrix.ps1` (4 variantes em paralelo, 4 PASS ~84 s), `build-freertos-s3.ps1`, `bench-freertos.ps1` (lado-host da bancada, sintaxe validada).

## Fase C item 2 — FFI MAC real (loop 4, código pronto; device build rodando)

- `aegis_ble_nimble.c`: `aegis_ble_own_addr()` fail-closed (`ble_hs_id_copy_addr`, NULL/não-sync → -1 sem lixo).
- `ble_nimble.rs`: `own_addr_or_placeholder()` (FFI no device com log da fonte, placeholder XOR-fold no host); `prox_sched::note_boot` usa a função (host idêntico).
- Verde host: 303 lib + 11 bin + 2 + 3 + 11 integração; clippy limpo; `fmt --check` ok.
- Device build S3 release com FFI: PASS (2m33s) — `C:\t\aegis-app-freertos-s3.bin`, SHA256 `15868719343897AABC2B5BD95F03B94052105301502DC85B4B4D32212111D7DB`, 821808 bytes (factory max 3145728; cresceu vs 483936 do build anterior pelo link do C + proximity, ainda com folga). Só warnings preexistentes de drift.
- Pacote de bancada pronto: `docs/bench-freertos-s3.md` (8 seções, aceite por etapa) + `scripts/bench-freertos.ps1`.
- Hardware S3 colhido (bin E569658A): flash COM13 (MAC 3c:84:27:c7:17:78) via `esptool write_flash 0x10000` (hash verificado); USB VID 0x303A PID 0xAE61 (CCID + HID FIDO + composite OK); suite `tools/test_aegiskey_rust.py` 8/8 PASS no hardware (2x, em bins diferentes); boot real (`main_task Started on CPU0`, `[FREERTOS] AegisKey FreeRTOS variant booting`, `boot tasks=6 stack_high_water=8272B core=0`, `[PROX] fob_id via placeholder (FFI rc=-1)` x2, `[PROX] sem K_prox fail-closed`, ticks); COM13 = console UART0; COM11/COM12 de outra placa (não tocar); COM7 ocupada.
- PENDENTE (não afirmado): distribuição das 3 tasks por núcleo (linhas `na core N` no ar, captura com janela de reset a fazer); walk-away aéreo.
## Sync master (scripts, 2026-10-20)

- `scripts/sync-master.ps1` (win) e `scripts/sync-master.sh` (linux/mac): fetch origin (somente leitura) + ahead/behind vs `origin/main` e `main` + lista commits novos + hotspots (firmware/host/docs/plans/tools/android) + `-Gate` (test+clippy freertos,proximity) + `-SaveJson`. Exit 0 em dia, 2 se a master tiver commits novos. Nunca faz merge/rebase/reset/push.
- Última avaliação: `feat/freertos-rust` ahead 57 / behind 0 vs `origin/main`, ahead 56 / behind 0 vs `main` local; `main` é ancestral do HEAD. Nada a puxar; relatório em JSON validado.

- PER-NUCLEO PROVADO no boot real (reset deterministico COM13, bin 62FEB1F2 com fixes da auditoria): usb_ctaphid na core 1 (prio 5); ui_button sem afinidade (flutuante, como projetado); boot tasks=6 stack_high_water=8272B core=0; suite 8/8 revalidada 3x no HW sem reset TWDT. Resta: walk-away aereo.

- Bateria HW COM14 (2026-10-20, bin 62FEB1F2 release): gate chip_id PASS (ESP32-S3 MAC 3c:84:27:c7:17:78); bench-freertos 7/7 PASS (bundle bench-freertos-20261020-232037); killswitch dry-run + 13 unit PASS; factory --dry-run PASS (sem burn); self-tests 3x PASS. BLOCKED: e2e base/all-safe (device sem test-mode; exige inbox TEST_* + flash test-mode); simulate walk-away (loop infinito por desenho, SKIP seguro); fisico: UP/botao, RF bonded, burn eFuse.

- Fixes pos-restart (loop final): (1) lifetime_trace.rs remove import Write nao usado sob test-mode (clippy -D warnings); (2) testes de gate binding->UP viraram bypass-aware (test-mode pula vinculo por desig; release segue NeedBinding primeiro); (3) mod freertos_test_mode ja tinha allow(dead_code) p/ host. Matriz test-mode verde: 309 lib + 17 bin + 2 + 3 + 11 integracao; clippy limpo default e test-mode. Sem regressao (303+11+2+3 sem test-mode). Device build test-mode (board-devkitc,freertos,proximity,test-mode) rodando; proximo: flash + e2e full + wipe.

- Inbox TEST_* vivo no HW (bin F030D989 test-mode): TEST_LIFETIME_DUMP responde lt_dump v=1 + contadores + lt_end via serial; fix era aegis_serial_init() ausente no caminho freertos. e2e base rodando em background.

- Vigilia (2026-10-21, teto 2h): aguardando sessao 'entendendo o projeto*' terminar versao com novidades p/ portar p/ esta lane. Verificado: sem branch/worktree/lane/arquivo com esse nome (branches: fd-integracao-unificada, fd/finalizacao-linux, main + origin; lanes: so freertos-rust; fd-worktrees vazio; fetch origin sem novidades). Se surgir: avaliar diff, portar se verde e relevante; senao ignorar e seguir. Deteccao via scripts/sync-master.ps1.

- REGRA DE LOOP (2026-10-21): etapa travada = max 3 a 5 tentativas, depois parar e reportar (sem retry infinito). Vale para HW (flash/e2e/monitor) e agentes.

- REGRA DE LOOP (2026-10-21): etapa travada = max 3 a 5 tentativas, depois parar e reportar (sem retry infinito). Vale para HW (flash/e2e/monitor) e agentes.

- Vigilia (2026-10-21, teto 2h): aguardando sessao 'entendendo o projeto*' terminar versao com novidades p/ portar p/ esta lane. Verificado: sem branch/worktree/lane/arquivo com esse nome (branches: fd-integracao-unificada, fd/finalizacao-linux, main + origin; lanes: so freertos-rust; fd-worktrees vazio; fetch origin sem novidades). Se surgir: avaliar diff, portar se verde e relevante; senao ignorar e seguir. Deteccao via scripts/sync-master.ps1.
- LOOP: e2e base rodando em background na COM14 (job vivo, porta ocupada por ele); TEST inbox ok no HW (lt_dump v=1); regra 3-5 tentativas ativa; outra placa intocada.
