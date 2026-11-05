# PM SIM Report — 2026-11-05 (fluxo completo NO SIMULADOR, sem hardware)

**Escopo desta sessão:** simular o fluxo PM completo SEM hardware
(sem COM7/USB/adb, sem PIN real, sem placa/celular): viewer → unlock →
abrir item → olho (biometria simulada) → wipe-on-close → reabrir
(prova que zerou) + `release_roundtrip_and_wipe` + census/search.
**Nenhum flash/erase/eFuse/Secure Boot tocado; nenhuma escrita serial/COM7;
nenhum push** (somente working tree local).

**Branch:** `fd/finalizacao-linux`.
**Artefato novo desta sessão:** 1 teste host em
`crates/aegis-pm-vault/src/store.rs`
(`simulated_viewer_unlock_eye_wipe_reopen_proves_zeroed`) + este relatório.
Nenhum Mock/Fake/Stub em código de produção (o único doble,
`TestStore`, já vivia em `#[cfg(test)]`).

> Builds, mocked traffic, ports, screenshots, emulators e handshakes
> **NÃO** são aceitação em dispositivo físico. Nenhum veredito abaixo
> afirma HIL L3/device; o fluxo foi simulado no host.

## 1. Gap do simulador (achado) + cobertura adicionada no host

- `python tools/app_simulator.py --self-test` (offline, sem hardware):
  **23/24** — cobre framing CTAPHID, pairing gate, AEGN, OATH, wifi, OTA,
  PIV, killswitch; **NÃO cobre PM** (nenhum opcode `0x43..=0x47`).
  1 FAIL pré-existente e fora do escopo PM: `stream cid resync poisoned`
  (resync serial CTAPHID; `tools/app_simulator.py` **não modificado**
  nesta sessão).
- `python tools/e2e_harness.py session` (offline, UP-SIMULATED, sem HW):
  **29/29 PASS** (S1..S5); **NÃO cobre PM** (S3 cobre OATH/wallet/fwlog,
  sem vault PM).
- Cobertura adicionada **no host (não no device)**, conforme autorizado:
  `store::tests::simulated_viewer_unlock_eye_wipe_reopen_proves_zeroed`
  espelha `PasswordManagerScreen`/`PasswordManagerViewModel`
  (viewer → unlock → `openRelease` → olho `BiometricPrompt` → `closeRelease`
  wipe → reabrir vazio) contra `PmVault` + `TestStore` (RAM+NVS simulada).

## 2. Fluxo simulado — tabela PASS/FAIL por etapa

| Etapa (SIM, sem hardware) | Como foi simulada | Resultado |
|---|---|---|
| viewer (tela bloqueada, fail-closed) | gates `binding/UP/PIN` negados → `list/search/get/release` = `NeedBinding` | **PASS** |
| unlock (binding+UP+PIN; olho=`BiometricPrompt` simulada pelos bits presence+PIN) | `PmGateState::authorized()` | **PASS** |
| abrir item (lista só ids opacos, sem labels) | `list_ids` = 2 ids opacos; `Debug` sem `bank/mail/alice/s3cr3t` | **PASS** |
| census (contagem vs quota, forma do status `0x47`) | `len()==2 <= max_entries`; `status_response_roundtrip` (host+Android) | **PASS** |
| search (substring device-side, resposta opaca) | `search_ids("ban")`=1 id; `"zzz"`=vazio; `""`=2 ids | **PASS** |
| olho → release pontual 1 frame | `release_password` = `s3cr3t-bank`; `Debug` redigido (`Zeroizing`) | **PASS** |
| wipe-on-close (`closeRelease`) | `drop(Zeroizing)` + `store.wipe()` escopado | **PASS** |
| reabrir prova que zerou | `restore_from_store` = `NotFound`; vault vazio; janela expirada = `BindingWindowExpired`; walk-away nega release | **PASS** |
| `release_roundtrip_and_wipe` | `PasswordManagerViewerTest.release_roundtrip_and_wipe` (focado) | **PASS** |
| erros sem segredo | `errors_carry_no_secret_payload` (firmware) + `debug_never_logs_*` (vault/SDK) | **PASS** |

## 3. Resultados exatos (`--test-threads=1`)

| Suíte | Comando | Resultado exato |
|---|---|---|
| `aegis-pm-vault` (focado novo) | `cargo test -p aegis-pm-vault simulated_viewer -- --test-threads=1` | `1 passed; 0 failed; 17 filtered out` |
| `aegis-pm-vault` (cheia) | `cargo test -p aegis-pm-vault -- --test-threads=1` | `18 passed; 0 failed` (era 17/17 + 1 novo) |
| `universal-device-sdk --features pm` (filtro `pm`) | `cargo test -p universal-device-sdk --features pm pm -- --test-threads=1` | `9 passed; 0 failed; 64 filtered out` |
| `uniffi-bridge` | `cargo test -p uniffi-bridge -- --test-threads=1` | `46 passed; 0 failed` |
| `aegis-fido-firmware --lib pm_store` | `cargo test -p aegis-fido-firmware --lib pm_store -- --test-threads=1` | `10 passed; 0 failed; 596 filtered out` |
| `PasswordManagerViewerTest` (Android unit, focado) | `:app:testDebugUnitTest --tests dev.aegiskey.app.PasswordManagerViewerTest` | `tests=8 skipped=0 failures=0 errors=0` (incl. `release_roundtrip_and_wipe`, `opaque_handles_carry_no_invented_labels`, `status_response_roundtrip`, `list_request_response_roundtrip`) |
| `e2e_harness session` (SIM offline) | `python tools/e2e_harness.py session` | `total=29 pass=29 fail=0` (S1..S5; PM fora do harness — coberto pelo teste host novo) |
| `app_simulator --self-test` (offline) | `python tools/app_simulator.py --self-test` | `23/24` — FAIL pré-existente `stream cid resync poisoned`, fora do escopo PM, arquivo não tocado |
| clippy (crate tocado) | `cargo clippy -p aegis-pm-vault --all-targets -- -D warnings` | limpo |

**L1 reconfirmado nesta sessão: 18+9+46+10 = 83/83 + 8/8 Android.**

## 4. Contratos observáveis / presets / erros / Boundaries / evidências

- **Contrato observável:** viewer exibe só ids opacos; segredo aparece 1 frame
  pós-biometria e zera ao fechar; reabrir mostra vazio (provado por
  `NotFound` pós-`wipe`, não por asserção de UI).
- **Feature preset:** `pm` (SDK off por default; `require_pm` → `NotCompiled`
  sem a feature — coberto por `request_carrier_checks_compiled_gate`).
- **Semântica de erro:** ordem canônica binding→UP→PIN→janela 60 s preservada
  nos 3 layers (vault `PmError`, firmware `BleGattError` 0x05/0x01/0x02,
  app `PmGate`→`VaultGate`); wire bytes congelados (`0x43..=0x47`,
  primeiro range livre após OOB `0x42`).
- **Extension boundaries:** envelope AEGN v1 intocado; `PmStore` trait é o
  único acoplamento firmware↔vault (DIP); phone = blind transport; wipe
  escopado (`vault-pm/`; FIDO2/OATH preservados — `wipe_scoped_preserves_fido2_and_oath`).
- **Estados de evidência:** `PmStatusDto{entry_count,max_entries}` (census, sem
  segredos); `PmReleaseResponseDto` transitório (nunca persistir); dump do
  blob selado não contém label/username/secret (`seal_open_roundtrip_and_dump_reveals_nothing`).

## 5. Bloqueadores / pendências (não re-executados aqui)

- Device E2E (popup/olho/digital/wipe no hardware) segue
  **PENDENTE_INTERAÇÃO** (exige key + sessão + digital — ver
  `PM_E2E_REPORT_2026-11-05.md`); nada desta sessão afirma HIL L3.
- 2 falhas firmware testmode pré-existentes (`oob_arm_funil_serial…`,
  `sign_gates_mirror…`) continuam fora do escopo host (não re-executadas).
- `app_simulator --self-test`: `stream cid resync poisoned` FAIL
  pré-existente, fora do escopo PM, sem alteração no arquivo.

## 6. Próximos passos (HIL L3, só com `--confirm` explícito)

Repetir o fluxo do §2 no device físico com hardware key + Secure Guard
desbloqueado + digital cadastrada, e re-checar `find`/prefs pós-fechamento.

---
*Sessão SIM-only: 1 teste host novo + cargo `--test-threads=1` (83/83 +
8/8 Android) + `e2e_harness session` 29/29 + `app_simulator --self-test`
23/24 (1 FAIL pré-existente fora de escopo). Nenhum eFuse/Secure Boot/COM7.
Sem push.*
