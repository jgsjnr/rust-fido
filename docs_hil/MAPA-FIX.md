# MAPA-FIX — HIL USB/BLE/WiFi/SIM (lane fd/hil-usb-tests, base 2c3dcad)

> Escopo de escrita: worktree inteira (`E:\projetos\fido-hil`). Principal
> `E:\projetos\fido` intocado. Fixes seguros apenas: test-mode only,
> feature-gated, sem OTA-COMMIT/wipe/killswitch, sem segredo em log.
> Estado desta rodada: fixes aplicados abaixo + `cargo test`/`clippy`/pytest
> (ver §7). Sem alegar HW ausente.

## 0. Convenção SIM-COVERED vs HW-ONLY

- `SIM-COVERED`: o sim respondeu tudo (boot-check `ONLINE&ACTIVE` + INIT→CID
  + PING eco + `TEST_LIFETIME_DUMP` + `TEST_UP`) via `python_hil/sim_pilot.py`
  (`--tcp`/`--uart`/`--self-test`). Só o loopback `--self-test` prova a
  camada TCP/CTAPHID local — nunca é evidência de HW.
- `HW-ONLY`: falha documentada pedindo HW/sim real (skip elegante nos testes,
  nunca aprova sem evidência). Nenhum build, tráfego simulado, screenshot,
  emulador ou handshake substitui aceite físico.
- Regra da lane: sem test-doubles em `python_hil/*.py` fora de `tests/`;
  sem HW = skip com falha documentada (`docs_hil/falha-*.md`).

## 1. L2 `test_mode_gates` — LED_STATE sem resposta (FALHA REAL de firmware)

- Sintoma: `TEST_PAIRING_OPEN_300` OK, `TEST_UP` OK (`paring=Arming`),
  `LIFETIME_DUMP` OK, mas `test_led_state("ON")` sem eco (só `tick NNN`).
  Ver `docs_hil/falha-L2-uart-acesso-negado-2026-10-24.md` §7–§8.
- Causa raiz: o harness envia `TEST_LED_ON` (`link_serial.SerialLink.test_led_state("ON")`),
  mas o classificador FreeRTOS só conhecia `RED/GREEN/BLUE/OFF`
  (caía em `UnknownTest` → sem resposta, por desenho).
- Onde consertar (exato):
  - `crates/aegis-fido-firmware/src/run/mod.rs`
    `freertos_test_mode::classify_freertos_test_line()` — incluir
    `"TEST_LED_ON"` no braço `LedSet` (alias de `TEST_LED_RED`).
  - `crates/aegis-fido-firmware/src/run/run_loop_freertos.rs`
    bloco `#[cfg(all(target_os = "espidf", feature = "test-mode"))]`
    do dreno TEST (latch `led_test_hold`): tratar `TEST_LED_ON` como
    `LedEffect::Solid(Color::RED)`.
  - Harness (espelho, sem mudança de semântica):
    `python_hil/link_serial.py` `SerialLink.test_led_state()`.
- Fix aplicado nesta rodada: alias `TEST_LED_ON` → `LedSet` + latch
  `RED`, **só sob `feature = "test-mode"`** (módulo `freertos_test_mode`
  nem compila em release; release ignora a linha). Teste
  `led_responde_status_sem_segredo_e_sem_latch` estendido com `"TEST_LED_ON"`.
- Referências:
  - `tools/host_sdk/gates.py` (`check_up`, ordem binding→UP→PIN — LED não é gate).
  - `crates/universal-device-sdk/src/capabilities.rs` (`TEST_MODE` bit; lab only)
    + `src/test_hooks.rs` (superfície de hooks de lab).
  - Legado (paridade): `crates/aegis-fido-firmware/src/run/run_loop_legacy.rs`
    `TEST_LED_{RED,GREEN,BLUE,OFF}` + `TEST_LED_RELEASE`.

## 2. L3/L4/L5 transiente — INIT+PING ok, 2º CBOR/MSG mudo 0/64 bytes, retry PASS

- Sintoma (3 ocorrências, mesma assinatura): `USB_SENT cmd=86` → `USB_RESPONSE bytes=17`
  (`CID_ALLOCATED`) → `USB_SENT cmd=90/83` sem resposta (`0/64 bytes`, ~10 s);
  retry imediato após re-enumerar 1x PASS (0.07–0.14 s).
  Ver `falha-L3-getinfo-usb-timeout-2026-10-24.md`,
  `falha-L4-fwlog-usb-timeout-2026-10-24.md` §7, `falha-L5-*.md` (persistente §3).
- Causa provável: sessão USB back-to-back deixa assembly órfã multi-pacote no
  `CtapHidManager` do firmware; o próximo INIT (CID novo) batia em
  `ERR_CHANNEL_BUSY` em vez de recomeçar. Harness sem retry amplificava.
- Onde consertar (exato):
  - `crates/aegis-fido-usb/src/ctaphid.rs`
    `CtapHidManager::process_packet()` braço `RawPacket::Init`:
    broadcast `INIT` (`cid == BROADCAST_CID && cmd == CMD_INIT`) limpa
    `active_assembly` antes do check `BUSY` (INIT carrega só nonce; seguro).
    Timeout `MSG_TIMEOUT_MS` (3000 ms) e `ERR_MSG_TIMEOUT`/`ERR_CHANNEL_BUSY`
    inalterados.
  - `python_hil/link_usb.py` `HidLink.exchange_read_retry()` (novo):
    leituras idempotentes (`get_info`, `fw_log`, `rescue`) com 1 retry
    (re-enumerar + `cmd_init` novo + timeout maior 20 s no retry).
    `MC/GA` e escritas NUNCA usam retry (não-idempotentes).
    `HidLink.reconnect()` / `_timeout_hint()` (re-plug hint AEGIS-S3-0002).
- Fix aplicado nesta rodada: firmware + harness acima + teste
  `test_broadcast_init_clears_stale_assembly` (novo, em `ctaphid.rs`).
- Referências:
  - `tools/host_sdk/transport.py` + `ops.py` (builders; sem I/O).
  - `crates/universal-device-sdk/src/providers/audit.rs` (fw-log `0x38`),
    `src/capabilities.rs` (`AUDIT`), `src/status.rs`/`response.rs` (tipos).

## 3. L2 framing `[FREERTOS]` multiplex (CURADO no harness; spam residual no firmware)

- Sintoma curado: firmware multiplexa logs `[FREERTOS] ...` sem alinhamento a
  64 B antes de cada resposta CTAPHID (`[FREERTOS] ctaphid resp…` + pacote INIT
  na mesma janela; `tick NNN` a cada ~1 s). `exchange()` lia janelas fixas de
  64 B e quebrava (`ValueError: unexpected continuation`).
  Ver `falha-L2-*.md` §7–§8 (`3 passed, 1 failed` pós-resync; framing 100% curado).
- Onde consertar (exato):
  - Harness (já na base): `python_hil/link_serial.py`
    `SerialLink._read_framed_packet()` (`_looks_like_init/_looks_like_cont`,
    `is_text_chunk/is_text_line`, `Reassembler`) — drena linhas `\r\n` texto
    antes de cada janela 64 B; resync 1 B em janela mista.
  - Firmware (fix desta rodada, feature-gated): 
    `crates/aegis-fido-firmware/src/run/run_loop_freertos.rs`
    `run_authenticator_freertos()` — `kprintln!("[FREERTOS] ctaphid resp…")`
    e `kprintln!("[FREERTOS] tick …")` (ramo `Tick10ms` device) agora sob
    `#[cfg(feature = "debug-terminal")]`. Boot `ONLINE & ACTIVE!`, erros
    (`[CCID]`, `[BLE]`, `[WIFI]`), `UP latch` e acks TEST seguem sempre.
- Referências:
  - `tools/host_sdk/tlv.py` (canônico byte-identico) — framing 64 B espelha o USB.
  - `crates/universal-device-sdk/src/test_hooks.rs` (dreno TEST textual `k=v`).

## 4. L1 live — QEMU mudo + Renode travado (SKIP HONESTO, sem fix de firmware)

- Sintoma: QEMU `:5678` aceita TCP mas 0 bytes (sem banner/`ONLINE&ACTIVE`);
  Renode trava em `System bus created` + monitor 1234 em uso; `.resc` com
  `LoadBIN` comentados. Ver `falha-L1-live-sim-sem-boot-2026-10-24.md`.
- Onde consertar (fora do firmware; lane do sim, sem código tocado aqui):
  - Imagem QEMU: regenerar com `-BuildImage` (bootloader + PT 16 MB + app
    test-mode) em `C:\t\qemu-flash-16m.bin`.
  - Renode: depurar `sim/boards/fido-s3-v3.repl` (uart0 terminal,
    `sysbus LoadBIN $BIN 0x0`), resolver porta 1234 ocupada (processo alheio).
  - Harness (já pronto): `python_hil/sim_pilot.py`
    `tcp_pilot()` (`boot_check` ONLINE&ACTIVE), `uart_pilot()`, `--self-test`.
- Nenhum fix aplicado nesta rodada (externally blocked: QEMU/Renode na bancada).

## 5. COM7 disputa intermitente (WinError 5)

- Sintoma: `SerialException: PermissionError(13, 'Acesso negado')`, `mode COM7`
  indisponível; `handle.exe` sem holder; libera sozinho (poller de outro
  processo). Ver `falha-L2-*.md` §§1–7.
- Onde consertar (harness; sem firmware):
  - `python_hil/link_serial.py` `SerialLink.open()` — hint no `HwMissingError`
    (fechar monitor serial/Renode/outro poller; re-plugar cabo dados; retry 1x).
    Abertura segue sem DTR/RTS (`_open_win` DCB `Flags=0x1`; `_open_posix`
    `CLOCAL|CREAD` sem `HUPCL`) — abrir nunca reseta o device.
- Fix aplicado: hint acima. Sem `thread::sleep` polling no harness além do
  backoff curto de leitura existente.

## 6. Arquivos tocados nesta rodada (diff resumido)

| Arquivo | Função/símbolo | Mudança |
|---|---|---|
| `crates/aegis-fido-firmware/src/run/mod.rs` | `classify_freertos_test_line` + teste `classifica_todas_do_manifesto_sem_json` | `TEST_LED_ON` → `LedSet` (+ teste) |
| `crates/aegis-fido-firmware/src/run/run_loop_freertos.rs` | dreno TEST `led_test_hold`; `kprintln!` tick/ctaphid-resp | `TEST_LED_ON` → latch RED; logs verbosos sob `debug-terminal` |
| `crates/aegis-fido-usb/src/ctaphid.rs` | `CtapHidManager::process_packet` + teste novo | broadcast INIT limpa assembly órfã |
| `python_hil/link_usb.py` | `HidLink.reconnect/exchange_read_retry/get_info/fw_log/rescue` | retry idempotente + re-plug hint |
| `python_hil/link_serial.py` | `SerialLink.open` | hint COM7 (holder/re-plug/retry) |
| `docs_hil/MAPA-FIX.md` | (este arquivo) | mapa exigido pela lane |

Nada destrutivo: sem `OTA-COMMIT`/wipe/killswitch; `TEST_DOWNLOAD`/`TEST_USB_RECONNECT`
inalterados; nenhum segredo em log (só nomes + contagens).

## 7. Build/test desta rodada (resultados reais, 2026-10-24)

- `cargo fmt -- --check`: PASS (1 ajuste auto: quebra de linha no braco LED).
- `cargo check --workspace --all-targets`: PASS (9.9 s).
- `cargo clippy --all-targets -- -D warnings`: PASS (12.4 s, zero warnings).
- `cargo test --workspace`: PASS — 810 totais (476 firmware + 108 + 93 + 51
  + 18 + 16 + 14 + 12 + 10 usb + 9 + 8 + 3 + 2 + 1), 0 failed.
  Inclui os novos: `test_broadcast_init_clears_stale_assembly` (usb) e
  `TEST_LED_ON` em `classifica_todas_do_manifesto_sem_json` (firmware).
- `pytest python_hil/tests --tb=line -q` (com HW USB AEGIS-S3-0002 enumerado
  303A:AE61, sem flags): **47 passed, 16 skipped, 0 failed** — baseline anterior
  era `7 failed, 40 passed, 16 skipped` com a mesma assinatura
  (INIT+PING ok, 2o comando mudo). L3+L4 focados: 10 passed.
  L5 mgmt focado: 10 passed, 2 skipped (os 3 FAIL persistentes viraram PASS;
  device saudável no momento + retry idempotente disponível).
  Evidência: HW real (enumerate=1), não simulação.
- `pytest --uart COM7` (COM7 com HW): `3 passed, 1 failed` no retry
  (1a passada flaky `2 failed, 2 passed` com init_ping TimeoutError —
  COM7 disputa). Residual: só o passo LED de `test_mode_gates` FAIL, porque
  o **device gravado é pré-fix** (fix provado no host, falta reflash).
  Ver `docs_hil/falha-L2-led-residual-pos-mapafix-2026-10-24.md`.
- `python -m python_hil.sim_pilot --self-test`: PASS (loopback; camada, não HW).
- L1 `--tcp` / Renode / QEMU: não re-sondados (externally blocked, ver falha-L1;
  sem mudança desde o SKIP honesto).
- Multiprocesso `-n auto`: N/A (xdist não instalado — externo).
- Nenhum destrutivo executado (sem `--confirm`; sem COMMIT/wipe/killswitch).

## 8. Re-rodada pos-210e980 (HEAD da983da, 2026-10-24 — device AINDA pre-fix)

> Resultado: device degradou com o uso (USB + UART wedged); fixes da
> worktree continuam provados so no host. Reflash + power-cycle pendentes
> (fora do escopo `python_hil/`+`docs_hil/`; sem DTR-toggle sem maos:
> risco de download-mode no CP210x).

- L0: clippy PASS zero warnings; `host_sdk/cli --self-test` PASS (0 failed);
  `app_simulator --self-test` 24/24 PASS; `emulate_app_session.py` 29/29 PASS
  (UP simulado — referencia offline, nao evidencia HW);
  `usb_ctap_probe.py` sem flag `--help` (default = self-test fake
  `USB_INIT_OK/PING_OK/PROBE_OK`; `--live` nao executado).
  `cargo test --workspace`: FLAKE de timing em
  `freertos_sched::demo_freertos_end_to_end` (`presses>=1`/`drained==3` sob
  carga paralela; PASS isolado; com `--no-fail-fast`: firmware-lib 481 passed,
  soma ~818 passed, 0 failed vs baseline 810 — +8 testes novos).
- L1-L5 (`pytest --collect-only`: 63 itens): suite sem flags em T0 (device
  saudavel) = **47 passed, 16 skipped, 0 failed** (baseline §7 reproduzida;
  L3+L4 focados 10 passed). Apos sequencia L2 COM7 + sessoes USB acumuladas,
  suite = **7 failed, 40 passed, 16 skipped** — os 7 com a assinatura
  INIT-ok + 2o comando CBOR/MSG mudo (retry+reenumerar NAO recupera desta vez).
  L2 `--uart COM7` = 1 failed, 3 passed, com assinatura NOVA no device
  pre-fix: INIT UART -> CTAPHID ERROR `0xBF/0x0B` persistente (7/7, mesmo com
  purge + 12 s idle) + TEST_* mudo (so ticks `[FREERTOS]`).
  Ver `falha-L2-uart-wedge-invalid-channel-2026-10-24.md` (novo) e
  `falha-L5-usb-mudo-pos-init-2026-10-24.md` §7 (re-ocorrencia).
- L1 `--tcp`: 5 passed, 1 skipped (sem sim em :5678; QEMU/Renode seguem
  externally blocked). BLE scan 5 s: 0 dispositivos (SKIP). WiFi AP:
  `HwMissingError` (fora do SSID; SKIP). Multiprocesso `-n auto
  --test-threads=1`: N/A (xdist nao instalado).
- Gaps do HEAD sem contraparte HIL (documentar, nao implementar sem HW):
  1. BLE parse `[op,status,pay]` no WRITE_NOTIFY (44702f0, `tools/`) —
     `python_hil/link_ble_wifi.py` so sonda descritores FFF1-FFF4 + frag/defrag
     offline; sem radio 0xFFFD nao ha como validar parser live.
  2. Mapa F2/F3 (`plans/F2-F3-HIL-MAP`, `usb_ctap_probe --live`): exige rota
     USB-Linux/WSL2+usbipd ou 2o PC (WUDF bloqueado aqui) + reflash; HIL fica
     no fake/skip honesto.
  3. `emulate_app_session.py` incorporado como referencia offline no
     `docs_hil/README` (matriz L0); paridade de menus com `app_usb_sim.py`
     (0-18) nao verificada contra HW (UART wedged) — gap aberto.
  4. Harness gap (proposto, nao aplicado — nao curaria wedge de device):
     `SerialLink.exchange()` sem `flush_input()` previo (so `send_text_line`
     purga); propor purge-RX no `open()` + retry-INIT idempotente a lane dona.
- Prescricao: power-cycle/re-plug do AEGIS-S3-0002 (canario:
  `test_l3_usb_get_info` isolado), depois reflash com HEAD (leva §2+§3 ao
  device) e repetir suite (alvo: 47 passed, 16 skipped, 0 failed + L2 4 passed).

## 9. Rodada desta lane (2026-10-24 — fixes host-prováveis aplicados, HW segue wedged)

> Fixes de firmware + harness aplicados e provados no host. Device físico
> segue pré-fix (USB mudo pós-INIT + UART `0x0B` persistentes mesmo após
> purge/retry) — reflash + power-cycle pendentes (passo físico, sem forçar
> flash sem confirmação).

- Firmware (`crates/`, test-mode/feature-gated, sem destrutivos):
  - `serial_ctaphid.rs`: `SerialStreamDecoder` (descarta prefixo texto até
    `\n`, realinha em `>IBH` via `starts_with_init_header`, delega ao
    `CtapHidManager` que já limpa assembly órfã em INIT broadcast) +
    `purge()` (purge-RX) + 3 testes novos (prefixo 22 B + INIT, órfã +
    purge, `cid==0`/teto/broadcast).
  - `ctaphid.rs`: teste `test_timeout_then_broadcast_init_recovers`
    (ERR_MSG_TIMEOUT 3000 ms + INIT seguinte recupera — robustez
    timeout/retransmit do lado device).
  - `run_loop_legacy.rs`: alias `TEST_LED_ON` → RED (paridade com freertos;
    sob `test-mode`).
  - `freertos_sched.rs`: `app_main_freertos_demo()` determinístico (dreno da
    fila com `receive` bloqueante até `drained>=3 && presses>=1 && ticks`,
    teto 5 s; sem `sleep` de parede fixa — flake `demo_freertos_end_to_end`
    curado) — sem `thread::sleep` polling novo, sem `unsafe` novo.
  - `aegis_serial.c`: `uart_flush_input()` no `aegis_serial_init()`
    (purge-RX no open; abrir nunca reseta o device).
- Harness (`python_hil/`, sem test-doubles, só stdlib):
  - `link_serial.py`: purge-RX no `open()` + purge pré-`exchange()` +
    `reconnect()` + `exchange_read_retry()` (reopen + INIT novo + timeout
    20 s no retry, só leituras idempotentes; MC/GA/escritas nunca usam) +
    `get_info()` via retry.
  - `sim_pilot.py`: `list_port_holder()` (netstat/ss, só leitura) +
    `free_own_holder()` (só PIDs próprios rastreados; nunca mata alheio sem
    listar) + hint `:5678` + monitor `:1234` no `tcp_pilot`.
- Builds (reais, nesta worktree):
  - `cargo fmt --check`: PASS (após `cargo fmt`).
  - `cargo check --workspace --all-targets`: PASS.
  - `cargo clippy -p aegis-fido-firmware -p aegis-fido-usb --all-targets -- -D warnings`: PASS zero warnings.
  - `cargo clippy --workspace`: FALHA pré-existente em `uniffi-bridge`
    (gerado `aegis_bridge.uniffi.rs`: `OtpAuthParsed`/`otpauth_*` ausentes;
    crate intocada por esta lane — externally blocked, fora do escopo).
  - `cargo test -p aegis-fido-core -p aegis-fido-usb -p aegis-fido-firmware -p universal-device-sdk`: PASS
    (core 108+9+1, firmware-lib 484, usb 94, sdk 51 + integração; inclui os
    5 testes novos desta rodada). `cargo test --workspace`: bloqueado pelo
    `uniffi-bridge` acima (mesma causa).
  - `pytest offline` (`-k offline/selftest/loopback/...`): **33 passed**.
    `sim_pilot --self-test`: PASS (loopback; camada, não HW).
    Suite com HW (USB 303A:AE61 `AEGIS-S3-0002` enumerado + COM7): **5 failed,
    42 passed, 16 skipped** — os 5 com a assinatura INIT-ok + 2º comando
    CBOR/MSG mudo `0/64 bytes` (retry+reenumerar NÃO recupera; device wedged).
    L2 `--uart COM7`: **3 failed, 1 passed** (INIT → `0xBF/0x0B` persistente).
    L1 `--tcp 127.0.0.1:5678`: 5 passed, 1 skipped (porta livre; QEMU mudo +
    Renode travado seguem externally blocked, ver falha-L1; holder listado,
    nenhum kill executado).
- Prescrição física exata (sem executar sem confirmação):
  1. Power-cycle / re-plug do AEGIS-S3-0002 (USB + CP210x COM7).
  2. Canário: `python -m pytest python_hil/tests/test_l3_usb.py::test_l3_usb_get_info -v`.
  3. Reflash com o bin test-mode desta worktree (comando pronto, NÃO executado):
     `.\scripts\build-esp32s3-devkitc.ps1 -Test` (build; bin em `C:\t\`)
     + flash manual confirmado: `.\scripts\build-esp32s3-devkitc.ps1 -Flash -Port COM7`
     (ou `-OnlyFlash -Port COM7` com o bin test-mode; sem `--confirm` não há
     COMMIT/wipe/killswitch; sem DTR-toggle por software nesta bancada).
  4. Repetir: suite completa (alvo 47 passed, 16 skipped, 0 failed) + L2
     `--uart COM7` (alvo 4 passed).
## 10. Rodada reflash autorizado (2026-10-24 — subagente pos-power-cycle do usuario)

> Build test-mode ordenado = `.\scripts\build-esp32s3-devkitc.ps1 -Test`
> (cargo test + build `board-devkitc`); flash = `-Flash -Port COM7`.
> Executado literalmente; desvio unico documentado abaixo (reset padrao).

- Build `-Test`: `cargo test -p firmware --lib` **484 passed**; cargo build
  release `xtensa-esp32s3-espidf`/`board-devkitc` em 5m19s; bin
  `C:\t\aegis-app-esp32s3-devkitc.bin` **2.013.888 B** SHA256
  `6573736B5840811FC3245A8C1A10F51A0E573E839F9753548064BEBC488B2CC9`
  (factory max 3.145.728; `.sha256` sidecar). Toolchain presente
  (esp active + IDF v5.3.1): sem EXTERNAL_BLOCKED. Pre-flash: USB
  303A:AE61 enumerado + UART INIT→CID `0x2`/PING/GetInfo `0x00` 479 B PASS
  (power-cycle do usuario limpou o wedge; COM7 livre, sem WinError 5).
- Flash tentativa 1 (script): **FALHOU** — `TEST_DOWNLOAD` sem ack (8 s) +
  esptool `--before no_reset` sem sync (2 bauds, `Invalid head of packet
  (0x5B)`). Causa: app rodando, chip fora de download, sem entrada soft
  neste firmware. Log: `C:\t\logs\flash-devkitc-COM7-20261024.log`.
- Tentativa DTR/RTS manual (sequencia `dlmode_test.py`): probe travou em
  loop de dreno (bug do probe, sem saida; processo morto por timeout) e o
  chip rebootou (POWERON). Aprendizado: open/close com transicao de linhas
  pulsa EN e reboota este HW (observado 2x, `rst:0x1`); harness segue sem
  DTR/RTS por desenho.
- Retry 1x (esptool reset padrao, mesmos args do script menos `no_reset`):
  **FLASH OK** — 2.013.888 B em `0x10000`, 17,8 s, hash verificado, hard
  reset. Log: `C:\t\logs\flash-devkitc-COM7-retry1-20261024.log`.
- Pos-flash: boot banner `Compile time: Oct 24 2026 16:50:16` (bin novo);
  canario `test_l3_usb_get_info` PASS 0,16 s; L0
  `cargo test -p core+usb+firmware+sdk` **802 passed, 0 failed** (1 ignored);
  `--workspace` segue bloqueado por `uniffi-bridge` pre-existente (intocado).
- Suites (device com bin novo): sem flags `3 failed, 46 passed, 14 skipped`
  (repetido: `6/43/14` sob mais trafego; pos-reboot `3/46/14`); `--uart
  COM7` `4 failed, 49 passed, 10 skipped` (degradado: `9/44/10`). Vitimas
  USB estaveis: `oath_challenge`, `wallet_list`, `wallet_addr` (INIT ou
  MSG/VENDOR mudos 5–10 s, ponto de falha alterna; `wallet_list` isolado
  SKIP `0x01` em 0,06 s; loop 6x INIT 6/6 OK). L2 gates FAIL por desenho
  (sem test-mode no bin). Wedge total recorre sob trafego (USB+UART) e
  limpa por reboot — ver falha-L5 §9 e falha-L2 §8.
- Nao executado (sem autorizacao/escopo): build+flash da variante
  `freertos+test-mode` (`.\scripts\build-freertos-s3-testmode.ps1` +
  `-OnlyFlash`), necessario p/ validar §1/§3 no HW; comandos destrutivos;
  kills de holder (nenhum kill executado; holders listados, nenhum conflito).
- Prescricao: (1) power-cycle antes de cada rodada HIL ate fix device-side;
  (2) reflash `freertos+test-mode` com autorizacao (leva §1+§2+§3 ao device;
  alvo: 47 passed + L2 4 passed); (3) retry em `HidLink.cmd_init`
  idempotente (lane dona); (4) investigar stalls do loop legado + estado
  `0x0B` sticky (dona do firmware). Estado final: device Wedged-parcial
  (UART `0x0B`; USB flaky) — proxima rodada comeca por power-cycle.

## 11. Rodada LED (2026-10-24 — regressão ON→RED + latch FreeRTOS; fix host-provádo)

> Escopo da tarefa: `led*`, `run/*`, `button*`, `pairing*`, `bluetooth/ble*`,
> `heartbeat`, `docs led-diagnostico`. `python_hil/` intocado (salvo testes —
> nenhum teste alterado nesta rodada). Sem destrutivos; sem flash/sondagem HW
> (sem aprovação: status físico = REAL_IMPLEMENTED_NOT_RUN, ver prescrição).

### 11.1 O que mudou no path do LED (`210e980..HEAD` + worktree)

| Arquivo | Mudança no path do LED |
|---|---|
| `run/mod.rs` (commitado) | `classify_freertos_test_line`: `TEST_LED_ON` → `LedSet` (alias de RED) + teste |
| `run_loop_freertos.rs` (commitado) | `TEST_LED_ON` → latch `Solid RED`; `kprintln!` tick/ctaphid-resp sob `debug-terminal` |
| `run_loop_legacy.rs` (worktree) | `TEST_LED_RED \| TEST_LED_ON` → `Solid RED` (paridade, não-commitado) |
| `serial_ctaphid.rs` / `ctaphid.rs` / `aegis_serial.c` (worktree) | fora do path LED: `SerialStreamDecoder`+purge-RX, INIT broadcast limpa órfã (framing; reduzem spam UART, sem efeito em cor) |
| `freertos_sched.rs` (worktree) | fora do path LED: dreno determinístico do demo (timing de teste) |

### 11.2 Causa raiz (qual diff quebrou qual estado)

1. **Alias `TEST_LED_ON`→RED nos dois loops.** O harness envia
   `test_led_state("ON")` após `PAIRING_OPEN+UP` sem `RELEASE`
   (`test_l2_uart_test_mode_gates`): latch RED residual cobria o **azul
   respirando do pairing/BLE** e o **âmbar pulsante do UP/arming** nas
   sessões seguintes (boot amarelo/pareamento piores).
2. **Latch device-side no FreeRTOS** (`led_test_hold` + `starts_with` +
   reaplicação a cada `Tick10ms`), contrariando o contrato documentado
   ("FreeRTOS só ack, latch vive no legado" — `run/mod.rs` § + `docs/test-hooks.md`
   + teste `led_responde_status_sem_segredo_e_sem_latch`). RED sólido cobria
   **boot rainbow, UP-Prompt âmbar, sucesso verde, erro, TOTP azul** — cores
   "mudadas" + flicker entre escritores (jornada B-block vs hold).
3. **Latch legado incondicional + sem expiração**: reaplicado todo poll sobre
   qualquer tela/estado, sem timeout — máscara persistente da jornada.

### 11.3 Correção (nesta worktree, test-mode only)

- `pairing_led.rs`: classificador puro `classify_test_led_line` (comparação
  EXATA, sem `starts_with`) + `TestLedLine::{Hold,PingAck,Ignored}` +
  `TEST_LED_HOLD_TIMEOUT_MS = 60 s` (= `PAIRING_WINDOW_MS`); 4 testes host
  (cores exatas, ON ping, anti-prefixo, timeout).
- `run_loop_freertos.rs`: latch **removido** (decl + RX + reaplicação Tick);
  só ack `led_set <CMD>` via `handle_freertos_test_line` — jornada manda sempre.
- `run_loop_legacy.rs`: `TEST_LED_ON` = **só ack** (`led_set TEST_LED_ON`,
  sem cor, sem residual); cores explícitas armam `(efeito, expira_ms)`;
  reaplicação **só no idle livre** (`IdleStandby` + pairing `Idle` + sem bond),
  expira em 60 s, libera em `TEST_PAIRING_CLOSE` (Locked volta a mandar).
- Docs: `docs/test-hooks.md` (linha ON), `docs/led-diagnostico.md` (Achado 24/10),
  `run/mod.rs` (doc `LedSet` + assert ON sem-latch) — ver também
  `docs_hil/falha-LED-regressao-on-red-latch-2026-10-24.md`.

### 11.4 Build/test desta rodada (reais, 2026-10-24)

- `cargo fmt -p aegis-fido-firmware -- --check`: PASS.
- `cargo check -p aegis-fido-firmware --features test-mode`: PASS.
- `cargo check -p aegis-fido-firmware --features test-mode,freertos`: PASS.
- `cargo check -p aegis-fido-firmware` (default, path release): PASS.
- `cargo test -p aegis-fido-firmware --features test-mode --lib`: **504 passed, 0 failed**
  (inclui 4 novos `pairing_led::test_led_line_*` + ON em `led_responde_*_sem_latch`).
- `cargo test -p aegis-fido-firmware --lib` (default): **484 passed, 0 failed** (baseline intacta).
- `cargo clippy -p aegis-fido-firmware --features test-mode --all-targets -- -D warnings`: PASS.
- Build embarcado (`xtensa-esp32s3-espidf`): **EXTERNAL_BLOCKED** — target
  `xtensa-esp32s3-espidf` NÃO instalado (`rustup target list` sem xtensa);
  IDF_PATH existe (`C:\esp\v6.0.3\esp-idf`) mas sem toolchain `esp` ativa
  nesta sessão. Comando pronto (NÃO executado):
  `scripts\build-freertos-s3-testmode.ps1` (build) + `-OnlyFlash -Port COM7`.
- HW (UART/COM7, flash, `led_probe.py` visual): **não executado** — sem hardware
  + sem aprovação explícita (regra: status REAL_IMPLEMENTED_NOT_RUN).

### 11.5 Matriz LED esperado vs obtido

| Estado | Efeito esperado (política) | Obtido pré-fix (bug) | Obtido pós-fix (host) | HW |
|---|---|---|---|---|
| Boot splash | RainbowCycle 1000 ms | RED sólido (latch) | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| Idle sem bond | Breathing CYAN 2000 ms | RED residual | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| Arming (hold 5 s) | PromptTouch (âmbar) | RED sólido | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| Pairing BLE/AP | Breathing BLUE 1600 ms | RED sólido | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| Bond ok idle | Solid GREEN | RED residual | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| Locked/timeout | Solid RED (headless) / ErrorFlash (tela) | RED sólido (máscara) | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| UP prompt | PromptTouch âmbar | RED sólido | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| Sucesso | AuthSuccessPulse verde | RED sólido | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| TOTP/Vault | Solid BLUE | RED sólido | jornada manda | REAL_IMPLEMENTED_NOT_RUN |
| `TEST_LED_ON` | ack `led_set TEST_LED_ON`, sem cor | Solid RED + residual | ack-only, sem latch | host PASS |
| `TEST_LED_{R,G,B,OFF}` | latch 2 s + RELEASE (olhos) | latch sem teto, qualquer tela | latch só idle livre, 60 s, CLOSE libera | host PASS + `led_probe.py` pendente |

Prioridade aplicada: **pairing > UP > BLE > heartbeat** (jornada/telas vencem o
hold; um escritor por vez, sem flicker). Gating `debug-terminal` do spam
`[FREERTOS]` mantido (menos UART contention no trem WS2812).

### 11.6 Prescrição física exata (sem executar sem confirmação)

1. Power-cycle / re-plug do AEGIS-S3-0002 (USB + CP210x COM7).
2. Canário: `python -m pytest python_hil/tests/test_l3_usb.py::test_l3_usb_get_info -v`.
3. Reflash com o bin `freertos+test-mode` desta worktree (comando pronto, NÃO executado):
   `.\scripts\build-freertos-s3-testmode.ps1` (build; bin em `C:\t\`)
   + flash manual confirmado com `-OnlyFlash -Port COM7`
   (sem `--confirm` não há COMMIT/wipe/killswitch; sem DTR-toggle por software).
4. Repetir: suite completa (alvo 47 passed, 16 skipped, 0 failed) + L2
   `--uart COM7` (alvo 4 passed) + `led_probe.py` visual (cores sólidas + RELEASE).
## 12. Rodada reflash `freertos+test-mode` autorizado (2026-10-24 - subagente pos-power-cycle)

> Build+flash+sonda executados com aprovacao do usuario. Device AEGIS-S3-0002
> com power-cycle presumido; COM7 sem disputa (open exclusivo ok, sem holder).

### 12.1 Build (`scripts\build-freertos-s3-testmode.ps1`, variante do fix LED p.11)

- Host previo: `cargo test -p aegis-fido-firmware --features test-mode --lib`
  **504 passed, 0 failed** (inclui 4 `test_led_line_*`).
- Toolchain presente (env-check 13/13 PASS; `esp` + IDF v5.3.1; COM7 CP210x):
  sem EXTERNAL_BLOCKED.
- ELF release `xtensa-esp32s3-espidf` / `board-devkitc,freertos,proximity,test-mode`
  em 51,6 s; bin `C:\t\aegis-app-freertos-s3-testmode.bin` **2.011.696 B**
  SHA256 `E9ACDA958D579A6EB4661E55C0CE222DDFBA381D526FC57808D65F5B84924622`
  (factory max 3.145.728; `.sha256` sidecar ok).
- Proveniencia: `C:\t\aegis-app-da983da1.bin` (git short da worktree).

### 12.2 Flash (COM7, 921600)

- Desvio documentado: o script testmode so aceita `-Clean` (sem `-OnlyFlash`);
  e o device rodava bin **sem** test-mode, logo `TEST_DOWNLOAD` sem ack, e o fluxo
  `Invoke-FirmwareFlash` (`--before no_reset` + `Read-Host` manual) travaria.
  Precedente p.10: flash direto esptool com **reset padrao** (mesmos args menos
  `no_reset`), nao-interativo, com log.
- `esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset
  --after hard_reset write_flash 0x10000 <bin>`: **FLASH OK** - 2.011.696 B
  em 18,0 s, hash verificado, hard reset. Log:
  `C:\t\logs\flash-freertos-testmode-COM7-20261024.log`. Sem WinError 5
  (COM7 livre; nenhum holder; retry nao precisou).
- Pos-flash: boot captura banner IDF v5.3.1 (16 MB flash); app `screen=freertos`
  (via `TEST_LED_STATE`); `uptime_s` coerente; sem destrutivos, sem segredo em log.

### 12.3 Sondagem LED/UART (aprovada; cores = ack textual, olhos = pendente)

| Comando | Resposta do device | Interpretacao |
|---|---|---|
| `TEST_LED_RED/GREEN/BLUE/OFF` | `led_set TEST_LED_<COR>` cada | latch arma (so idle livre, expira 60 s) |
| `TEST_LED_ON` | `led_set TEST_LED_ON` (so ack) | **fix p.11 confirmado no HW: sem cor, sem residual RED** |
| `TEST_PAIRING_OPEN_300` | `pairing_open window_s=300` + `[PAIRING] janela aberta` + BLE adv on (`aegis_ble: adv on pairing=1`, MAC `3c:84:27:c7:17:7a`) | pairing/BLE azul respira (jornada manda) |
| `TEST_UP` | `up_latched` + `UP via software CONFIRMED` | UP ambar prompt (jornada manda) |
| `LIFETIME_DUMP` | `lt_dump v=1 ... lt_end` (354 B, todos `lt.*=0`) | contadores integros |
| `TEST_LED_STATE` | `led_state screen=freertos pairing=PairingBle { expires_ms } up_pending=0 touch=0` | estado coerente |
| `TEST_PAIRING_CLOSE` | `pairing_closed` + NimBLE stop adv | libera hold legado |

Cores fisicas por estado (boot rainbow->idle, heartbeat, BLE, pairing, UP):
**REAL_IMPLEMENTED_NOT_RUN** - sem observador diante do device nesta sessao
(`tools/led_probe.py` exige confirmacao visual do usuario; nao executado).
Acks textuais + `TEST_LED_STATE` provam a politica; a matriz p.11.5 coluna HW
segue pendente de olhos.

### 12.4 Pytest finais

| Suite | Resultado | Detalhe |
|---|---|---|
| L2 `--uart COM7` (`test_l2_uart.py`) | **4 passed** OK | alvo atingido (era 1F/3P pre-fix) - INIT/PING/GetInfo/gates |
| L3+L4 focados (pos-flash, device saudavel) | **10 passed** OK | INIT->CID, PING eco, GetInfo, probes, fw-log, wallet LIST |
| Suite sem flags | **47 passed, 16 skipped, 0 failed** OK | alvo exato do p.7 reproduzido com bin novo |
| Suite `--uart COM7` | **3 failed, 49 passed, 11 skipped** | ver p.12.5 |
| 3 L5-mgmt isolados pos-reboot | **3 passed** | fwlog/backup-envelope/proximity passam fora do trafego acumulado |

### 12.5 Residual: wedge MSG sob trafego acumulado (falha real, reboot limpa)

- Apos as suites acumuladas: `get_info` (e fwlog/backup/proximity live_usb)
  caem em **INIT ok (CID alocado, 17 B) + MSG `0x90` mudo `0/64 bytes`**,
  persistindo a retry+re-enumerar+timeout 20 s; `TEST_USB_RECONNECT`
  (re-enumera: `USB Device mounted by Host`) **nao** recupera; UART segue
  100% viva (`TEST_LED_STATE`/`LIFETIME_DUMP` ok; `lt.transport.erro=0`;
  sem reboot - `uptime_s` continuo). PING/INIT USB seguem ok (4/5 L3 passam).
- Recuperacao aprovada executada 2x: `esptool --port COM7 --after hard_reset
  chip_id` (reset via RTS, sem flash) -> canario `get_info` PASS; suite sem
  flags volta a **47/16/0**; os 3 L5-mgmt passam isolados em 0,29 s.
- Causa: camada CBOR/MSG do loop FreeRTOS trava sob trafego USB+UART
  acumulado (INIT/PING, servidos antes do dispatch, seguem ok). Distinto do
  wedge p.8/p.10 (la: INIT-mudo total / `0x0B` UART; aqui UART limpa).
  **Nao curado nesta rodada** - documentado como residual; prescrito a dona
  do firmware (investigar stalls do dispatch MSG no loop FreeRTOS + estado
  pos-janela pairing/BLE sob carga). Workaround HIL: reboot (RTS/esptool)
  antes de cada rodada ate fix device-side.
- Nenhum destrutivo (sem `--confirm`; sem COMMIT/wipe/killswitch; PUT/GEN
  nunca live); nenhum segredo em log (so nomes + contagens + bytes de erro).

### 12.6 Rodada 2026-10-24 18:20 — bin 923FCC86 (stall-TX-nonblock + LED-ON-ack, proveniencia da983da1)

- Build: scripts\build-freertos-s3-testmode.ps1 EXIT 0 (1m46s) — SHA256 923FCC8634AAA94E94E90D711B5A84A23F4EC2D498A48EFF62128C7BF56540E4, 2011968 B (factory max 3145728), copia C:\t\aegis-app-da983da1.bin.
- Flash: esptool direto --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 (precedente reset padrao) EXIT 0, 18.0 s, Hash verified. Log C:\t\logs\flash-freertos-testmode-COM7-20261024-1820.log. Sem WinError 5.
- Host previo: cargo check test-mode OK; cargo test -p aegis-fido-firmware --lib 484 passed; -p aegis-fido-usb 99 passed. (cargo test com features board-devkitc,freertos,proximity,test-mode falha pre-existente em proximity.rs:451 campo ctr privado — nao bloqueia build embarcado.)
- Pos-flash (reboot+5 s workaround wedge): UART INIT cid=00000001 PING a5:5a:00:ff GETINFO len 479 OK; TEST_LED_ON -> `led` (ack, sem latch por contrato PingAck); TEST_PAIRING_OPEN_300 -> `pairing_open`; BLE scan 10 s HIT 3C:84:27:C7:17:7A name AegisKey uuid fffd RSSI -28.
- L2 --uart COM7: 4 passed (alvo 4/4 OK). L6 --ble-addr 3C:84:27:C7:17:7A: 9 passed, 2 skipped (ping_live SKIP gate 0x01 presence-required fisico; windows_enum SKIP sem bonding).
- Suite completa --uart COM7: 54 passed, 13 skipped, 7 failed em 85 s (log C:\t\logs\pytest-hil-COM7-20261024-1830.log). 7 falhas todas USB multi-pacote GETINFO/fw-log (INIT+PING USB ok, 2o comando mudo 0/64 bytes, retry+reenumerar nao recupera) — mesmo transiente L5-usb-mudo-pos-init, agora sob bin com TX nao-bloqueante (fail-closed por pacote). UART 100% viva. Nenhum destrutivo (--confirm ausente).
- Cores fisicas: REAL_IMPLEMENTED_NOT_RUN — sem observador diante do device; acks provam politica (ON=ack, prioridade pairing>UP>BLE>heartbeat no codigo), matriz HW segue pendente de olhos.
### 12.7 Rodada 2026-10-24 19:48-19:54 UTC - build 3F6528EB (fix TX multi-pacote) + flash BLOQUEADO COM7 ocupada
- Host previo (verde exigido): `cargo check -p aegis-fido-usb` PASS; `cargo test -p aegis-fido-usb` 100 passed; `cargo test -p aegis-fido-firmware --lib` 484 passed (default/board-devkitc); `cargo check -p aegis-fido-firmware --features board-devkitc,freertos,proximity,test-mode` PASS; `cargo test` com `proximity` falha pre-existente `proximity.rs:451 campo ctr privado` (sem edicao de codigo nesta lane).
- Build: `scripts/build-freertos-s3-testmode.ps1` EXIT 0 (4m28s) - SHA256 3F6528EB6400DCC31A8DF13213AF1663D2CEACE71B92C74D98908C6CA57B6190, 2013168 B (anterior 923FCC86 2011968 B; delta +1200 B compativel com fix TX), copia `C:\t\aegis-app-da983da1.bin`. Log `C:\t\logs\build-freertos-testmode-20261024-1948.log`. Esperado diferente de 923FCC86: OK.
- Flash: BLOQUEADO - COM7 `PermissionError(13, Acesso negado, WinError 5)` em open serial, `mode COM7` indisponivel, `esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000` => `Could not open COM7, the port is busy` EXIT 2. Log `C:\t\logs\flash-freertos-testmode-COM7-20261024-1954.log`. Holder: `handle.exe COM7`/`CP210x` sem match; `handle -p python` sem COM7; processo suspeito `host_hardware_android_bridge.py` (E:\projetos\fido) sem handle COM7 confirmado; retry 5 s + 20 s (2x) sem liberar - poller transiente documentado. Script `Invoke-FirmwareFlash` NAO tentado (travaria em `Read-Host TEST_DOWNLOAD`); precedente reset-padrao aplicado direto.
- Pos-flash: NAO executado (sem flash, sem power-cycle nesta lane). Device segue bin anterior wedged no path USB CBOR/MSG.
- Canarios USB (pre-flash, device wedged): INIT ok CID 0x0B; PING 4 B PASS (`test_l3_usb_init_ping`); PING-200B (4 pkts) FAIL `0/64 bytes`; `get_info` FAIL `0/64 bytes` com retry+reenumerar (mesma assinatura falha-L5). Prova que o fix TX ainda nao esta no device.
- Suites: sem flags `7 failed, 46 passed, 21 skipped` (71 s); L2 `--uart COM7` `4 failed` (HwMissingError COM7 inacessivel, holder listado sem match); L6 BLE `6 passed, 5 skipped` (scan live SKIP sem radio 0xFFFD). Alvos 47+/16/0 e L2 4/4 NAO atingidos - gated no flash+replug.
- Prescricao fisica: liberar COM7 (fechar poller/monitor), reflash bin 3F6528EB via esptool reset-padrao, power-cycle/re-plug, canario PING-200B + get_info, repetir suites. Nenhum destrutivo (sem --confirm); nenhum segredo em log.

### 12.8 Rodada 2026-10-24 20:01 UTC - flash 3F6528EB BLOQUEADO (COM7 ocupada, retry 20s)

- Bin integro: SHA256 3F6528EB6400DCC31A8DF13213AF1663D2CEACE71B92C74D98908C6CA57B6190 2013168 B (confere .sha256). Sem edicao de codigo.
- Flash: BLOQUEADO - pyserial open + `esptool chip-id` + `write_flash 0x10000` => `Could not open COM7, the port is busy / PermissionError(13, WinError 5)` em T0 e retry +20s. Log `C:\t\logs\flash-freertos-testmode-COM7-20261024-200153.log`. Holder: `handle.exe COM7` sem match; PnP CP210x COM7 Status OK.
- Canarios USB (device segue bin anterior wedged): INIT ok CID 0x3C + PING-4B PASS `a55a00ff`; PING-200B FAIL `0/64 bytes`; get_info FAIL `0/64 bytes` retry+reenumerar. Logs `C:\t\logs\canario-usb-20261024-200507.log` + `canario-getinfo-20261024-200514.log`.
- Suites: sem flags `7 failed, 46 passed, 21 skipped` (mesmos 7 USB multi-pacote 0/64); L2 `--uart COM7` `4 failed` (HwMissingError); L6 scan `6 passed, 5 skipped` (fora de janela). Logs `pytest-hil-COM7-20261024-200158.log`, `pytest-hil-L2-COM7-20261024-200325.log`, `pytest-hil-L6-20261024-200417.log`.
- Alvos NAO atingidos (gated no flash): PING-200B PASS / GetInfo PASS / 47+/16/0 / L2 4/4. Doc: `docs_hil/falha-flash-COM7-ocupada-2026-10-24-2001.md`.
- Prescricao: liberar COM7, reflash 3F6528EB reset-padrao, power-cycle, canarios, suites. Nenhum destrutivo (sem --confirm); nenhum segredo em log.
