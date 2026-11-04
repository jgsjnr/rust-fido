# Finalização — variante FreeRTOS em Rust + proximity (lane `feat/freertos-rust`)

Data-base: 2026-10-21. Worktree: `.slim/worktrees/freertos-rust`.

## 1. Objetivo

Decompor o super-loop do firmware em tarefas FreeRTOS explícitas 100% em
Rust, portar a trava de presença BLE (proximity) para o scheduler e validar
no silício (ESP32-S3 DevKitC-1, COM14).

## 2. Finalizado (com evidência)

- **Scheduler FreeRTOS** (`src/freertos.rs`): fila limitada (32, fail-closed),
  EventGroup, 3 tasks nativas (`usb_ctaphid` prio 5/core 1, `ui_button`
  prio 4/sem afinidade, `housekeeping` prio 2/sem afinidade), TWDT por task,
  high-water, `log_boot_info`. Stacks em 8K (4K estourava no Xtensa —
  crash `LoadProhibited` diagnosticado e corrigido no HW).
- **Prova dual-core no silício**: `usb_ctaphid na core 1`, `ui_button` sem
  afinidade, `boot tasks=6 stack_high_water=8272B core=0`, ticks fluindo sem
  reset TWDT.
- **Proximity portada**: beacon Wave2 (`0xFFFE`), verifier anti-replay,
  FFI `aegis_ble_own_addr` com fallback XOR-fold logado
  (`FFI rc=-1` → placeholder), fail-closed sem `K_prox`
  (`PROX sem K_prox (fail-closed ate parear)`).
- **Inbox `TEST_*`** (test-mode): `TEST_UP`, `TEST_PAIRING_OPEN[_300]`,
  `TEST_DOWNLOAD`, `TEST_USB_RECONNECT`, `TEST_LED_*`,
  `TEST_LIFETIME_DUMP` — `lt_dump v=1` respondido no HW.
- **Bins validados**: `aegis-app-freertos-s3.bin`
  SHA256 `8A73509D…` (828944 B); test-mode `F030D989…` (854640 B);
  com audit-fixes `62FEB1F2`; ambos flasheados e bootados na COM14
  (ESP32-S3 MAC `3c:84:27:c7:17:78`).
- **Gates host verdes**: test-mode 309 lib + 17 bin + 2 + 3 + 11 integração;
  default 270 lib; clippy `-D warnings` limpo nas 4 configs; workspace 5/5.
- **Bateria lado-host 7/7** (`scripts/bench-freertos.ps1`): env, USB,
  suite 8/8, self-tests win/linux/mac. Nota honesta: a suite 8/8 de
  `test_aegiskey_rust.py` é **host-side** (sem I/O USB) — prova de HW é
  enumeração AE61 + boot + e2e CTAPHID.
- **Infra**: `scripts/sync-master.ps1/.sh`, `scripts/build-matrix.ps1`
  (4 variantes em paralelo, 4 PASS ~84 s), `scripts/build-freertos-s3.ps1`,
  `scripts/build-freertos-s3-testmode.ps1`, `scripts/bench-freertos.ps1`
  (fix PS5.1 `ArgumentList`), `docs/bench-freertos-s3.md`,
  `docs/bench-destructive.md` (plano), inventário trigger→função,
  `docs/proximity-worktree-handoff.md` (trazido da origem).

## 3. Em voo / pendente

- e2e `base` na COM14 (background); na sequência `pairing`, `all-safe`,
  `destructive`, `wipe` (com `--confirm`, autorizado).
- Consistência docs vs código (agente).
- Walk-away aéreo com fob real + `K_prox` (precisa de humano na bancada).
- Burn eFuse (`factory --confirm`): **não executar sem ordem explícita**
  (one-way).
- Wipe via `authenticatorReset` (exige UP; com test-mode, via `TEST_UP`).
- Outra placa conectada (COM7/COM11/COM12): **não tocar**.

## 4. Reajustes aplicados no caminho

- `aegis_serial_init()` faltava no boot freertos → serial nascia morta
  (inbox surdo). Corrigido espelhando o legado.
- Cópia IDF de `ccid_device.c` rasgada (`}u`) quebrava o build device —
  recópia forçada + hash conferido (`E8EC9AA8…`).
- `erase_flash` total exige regravar bootloader (0x0) + partições (0x8000).
- Testes de gate viraram bypass-aware sob test-mode (documentam as duas
  semânticas sem enfraquecer o release).
- `main.rs` do legado intocado; fmt churn de agentes deixado como está
  (cosmético, não quebra gates).

## 6. Status e2e (atualizado em loop)

- Cadeia na COM14 com build test-mode: `base` → `pairing` → `all-safe`
  → `destructive --confirm` → `wipe` (SIM via stdin). Harness:
  `tools/e2e_user_test.py --port COM14 --phase <f>`.
- Killswitch: só `--dry-run` + unitário (sem `--confirm`).
- eFuse: NUNCA queimar sem ordem explícita (one-way); factory só `--dry-run`.
- Outra placa (COM7/COM11/COM12): intocável.
- Jobs obsoletos devem ser mortos antes de nova rodada
  (`Get-CimInstance Win32_Process` filtrando `e2e_user_test`, `Stop-Process`);
  job velho valida bin velho e segura a COM.

## 7. Reproduzir

```powershell
cargo test -p aegis-fido-firmware --features freertos,proximity,test-mode
cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity,test-mode -- -D warnings
powershell -ExecutionPolicy Bypass -File scripts/build-freertos-s3.ps1
powershell -ExecutionPolicy Bypass -File scripts/bench-freertos.ps1
```

- Robustez host: next_frame com deadline 30s; parse_dump filtra tick-split + 1 retry; T11 executa em pairing/all-safe. Self-test app_simulator 15/15.
- Roteamento CTAPHID no freertos: PacketOrigin Usb/Serial, 1 CtapHidManager por transporte, resposta volta pela mesma origem, UP latch 1x (BOOT ou TEST_UP), fail-closed sem espera. Host: 314 lib + 17+2+3+11; clippy limpo.

## 8. USB + LED (COM14, 21/10/2026)

- SIM, há erro USB, e é esperado neste estado: o app nunca boota, então nunca enumera.
  Bootloader registrou `Image length 2092592 does not fit in partition length 1048576`
  + `Factory app partition is not bootable` (bin test-mode 2 MB maior que factory 1 MB
  da PT antiga gravada no chip). Após flash da PT 3M do repo: `partition 2 invalid`
  + `Failed to verify partition table` (PT de 16 MB inválida para o chip físico de 2 MB).
- LED apagado é sintoma do mesmo boot-loop: o app não chega ao init de LED/USB;
  o bootloader ROM não acende LED. Nenhum defeito de LED/USB provado.
- Correção: `crates/aegis-fido-firmware/partitions-2m.csv` (factory 1M em 0x10000,
  storage 960K em 0x110000, fim exato 0x200000) gerando `C:/t/partition-table-2m.bin`
  validado (factory 1M). O `partitions.csv` de 16 MB do repo foi mantido.
- Bloat: test-mode foi de 810 KB para 2044 KB (fiat p521/p384 duplicados plain +
  sufixo llvm, monomorfizacao sem LTO). Fix: `[profile.release]` com
  `lto=true, codegen-units=1, strip=true` no Cargo.toml raiz, opt default mantido.
  Rebuild test-mode em curso; meta abaixo de 1 MB da factory.
