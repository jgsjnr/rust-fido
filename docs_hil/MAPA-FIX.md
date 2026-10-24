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
