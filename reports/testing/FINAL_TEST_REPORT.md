# Final Test Report -- BASELINE ONLY (full gate pending later phases)

Status: BASELINE ONLY. This file records the clean-tree regression baseline at HEAD 30680ff on 2026-11-02.
It is not a full PR gate verdict. The full gate (fmt clean, workspace clippy, workspace check, minimal plus full plus external-consumer presets) remains pending for later phases.

- Worktree: `E:\projetos\standalone-architecture-worktree`, HEAD `30680ff`, clean, no code changes.
- Toolchain: `cargo 1.99.1` / `rustc 1.99.1`.
- Scope: host-only Windows x86_64. No ESP-IDF target, no NDK .so matrix, no hardware.

## Section verdicts (evidence-backed only)

## Post-fix full validation (2026-11-02 UTC, HEAD `e683979`)

Scheduler fix `e683979` ("stabilize freertos_sched demo end-to-end tick
assertion", 2026-11-01) resolved the sole pre-existing failure without
weakening any assertion: the demo now waits for the `EVT_TICK_10MS` bit
(non-destructive) before `request_stop`, guaranteeing `ticks >= 1`
(`crates/aegis-fido-firmware/src/freertos_sched.rs`, +11/-1).

### `cargo test --workspace` — PASS (exit 0, VERIFIED)

- Toolchain: `cargo 1.99.1` / `rustc 1.99.1` (unchanged from baseline).
- Full log: host-local `$env:TEMP\postfix-workspace-test.log`.
- Prior baseline: 648 passed / 1 failed. Now: **927 passed, 0 failed**,
  1 ignored (firmware doc-test, pre-existing ignore).
- Per-crate results (all `ok`):
  - `aegis-fido-core` lib: 124 passed, 0 failed (VERIFIED).
  - `ctap_tests` integration: 9 passed, 0 failed (VERIFIED).
  - `e2e_vectors` integration: 1 passed, 0 failed (VERIFIED).
  - `aegis-fido-firmware` lib: **515 passed, 0 failed (VERIFIED, FIXED)** —
    includes `freertos_sched demo_freertos_end_to_end` now passing.
  - firmware bins/integration: `applets_t9` 12, `freertos_tasks` 2,
    `migration_tests` 3, `namespaced_store_t5` 14, `netwifi_t10` 16,
    `otakey_provider_t6` 8, `proximity_freertos` 0, `secure_guard_integration` 2.
  - `aegis-fido-usb` lib: 92 passed, 0 failed (VERIFIED).
  - `aegis-secure-guard` lib: 39 passed, 0 failed (VERIFIED).
  - `aegis-bridge` lib (`aegis_bridge`): 26 passed, 0 failed (VERIFIED).
  - `universal-device-sdk` lib: 64 passed, 0 failed (VERIFIED).
  - Doc-tests: all `ok` (1 ignored, pre-existing).
- Scope: host-only Windows x86_64. No ESP-IDF target, no NDK matrix,
  no physical-device acceptance. Mocked traffic/ports/screenshots/emulators/
  handshakes are not device acceptance.

### `cargo clippy --workspace --all-targets -- -D warnings` — PASS (exit 0, VERIFIED)

- Full log: host-local `$env:TEMP\postfix-workspace-clippy.log`.
- Output: `Finished dev profile [unoptimized + debuginfo]` in 3.86s.

### Standalone consumer reuse — VERIFIED desktop-only (`$env:TEMP` consumer, 4/4)

- External crate `standalone-consumer` (host-local `$env:TEMP`, NOT part of
  this repo) depends on `universal-device-sdk`, `aegis-secure-guard`, and
  `aegis-fido-usb` via path dependencies: `cargo test -- --test-threads=1`
  exit 0, **4 passed / 0 failed** (log: `$env:TEMP\standalone-consumer-test.log`).
  Tests: SDK envelope seal→open roundtrip; SecureGuard provision→unlock
  roundtrip; wrong-PIN denied fail-closed; USB CTAPHID frame via crate-root
  re-export (`CtapHidFramer::frame_message`, `CtapHidError::to_packet`).
- Findings (gaps/caveats, still open):
  - SDK `auth`/`envelope` modules are private (`mod auth; mod envelope;`);
    external consumers MUST use root re-exports
    (`universal_device_sdk::AuthContext`, `::seal_envelope`, ...). Works, but
    module paths do not resolve — documented, not changed (out of lane).
  - USB root re-export gap: `CtapHidMessage` has no `to_packet`; framing goes
    through `CtapHidFramer`. Root re-exports exist but the message type is not
    directly frameable — noted for the standalone-reuse lane.
  - `no_std` caveat: SDK (`cfg_attr(not(test), no_std)` + `alloc`) and
    SecureGuard (`#![no_std]` + `alloc`) declare `no_std`, but `aegis-fido-usb`
    has no `no_std` attribute (std-only). All reuse evidence here is
    desktop std host-only; no embedded/ESP target build was run in this lane —
    bare-metal reuse remains UNVALIDATED.

### License / `cargo deny` evidence — PASS (exit 0, pos-migracao `33df2ea`)

- `cargo deny` binary: PRESENT on host (`cargo-deny 0.20.2` em `$env:USERPROFILE\.cargo\bin`).
  No `cargo deny check` run exists in this lane: SUPERSEDED — deny agora PASS (exit 0).
- Per repo `deny.toml` `[licenses]`: allow-list is MIT, Apache-2.0,
  BSD-2-Clause, BSD-3-Clause, ISC, Zlib (+ per-crate GPL-3.0-only exceptions).
  CC0-1.0 / MPL-2.0 / Unlicense: policy atualizada cobre explicitamente via
  `deny.toml` (0.20 schema migration); deny PASS com exit 0 nesta lane.
- First-party crates are all `GPL-3.0-only` (covered by exceptions).
  `cargo deny check licenses advisories bans sources`: exit 0 (so warnings
  de duplicate versions), verificado nesta lane. RUSTSEC-2026-0387 RESOLVIDO
  via migracao p256/k256/p384/p521 0.13->0.14 (+ecdsa 0.17, elliptic-curve
  0.14, signature 3.0, ed25519-dalek 3.0, crypto-bigint 0.7.10), commit
  `33df2ea`. Wire-preserving (Sec1Point alias, mesmos bytes, try_sign
  propaga erro). Evidencia completa em `reports/compliance/cargo-deny-output.log`
  (dono anterior, NAO modificado) + snapshot `reports/compliance/cargo-deny-final.log`.
  Revisao juridica humana (23 crates) segue pendente — nao se declara PASS legal.

### Updated verdict (pos-migracao `33df2ea`)

- `cargo check --workspace` (+ `--all-targets`): PASS (exit 0).
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS (exit 0).
- `cargo test --workspace`: **PASS (exit 0, 927 passed / 0 failed)** — pre-existing fail FIXED by `e683979`; suite verde mantida apos migracao `33df2ea`.
- Standalone consumer (SDK/secure-guard/usb): VERIFIED desktop-only, 4/4.
- `cargo deny check licenses advisories bans sources`: PASS (exit 0, so warnings de duplicate versions). RUSTSEC-2026-0387 RESOLVIDO.
- Revisao juridica humana (23 crates): PENDENTE — sem PASS legal.
- `cargo fmt --check`: ainda BLOCKED (28 arquivos, pre-existente).
- ESP-IDF: v5.3.1 pinado; v6.1/v6.0.3-compat nao validados; 2 instalacoes host mantidas.
- Physical-device acceptance: nao realizado (fora de escopo, todas as lanes). Builds, mocked traffic, ports, screenshots, emuladores e handshakes nao sao aceitacao de dispositivo fisico.

### Pos-migracao RUSTSEC-2026-0387 (HEAD `33df2ea`, 2026-11-02 UTC)

- `git log --oneline -6`: `33df2ea` / `ab1dfcd` / `c48038b` / `d33cf41` / `e683979` / `6a3fd53`.
- Migracao: p256/k256/p384/p521 0.13->0.14 (+ecdsa 0.17, elliptic-curve 0.14, signature 3.0, ed25519-dalek 3.0, crypto-bigint 0.7.10). Wire-preserving (Sec1Point alias, mesmos bytes, try_sign propaga erro).
- Escopo desta lane: somente `cargo deny check licenses advisories bans sources` (exit 0) + `git log --oneline -6` para SHAs; demais gates usados verbatim do dono do codigo, sem re-validacao.

## Pos-JNI (HEAD `915ebf3`, 2026-11-02 UTC) — UniFFI removido, zero MPL

- Commit: `915ebf3` "refactor(ffi): drop UniFFI runtime for manual JNI (zero MPL)".
  `crates/uniffi-bridge` sem `uniffi` (deps + build-dep + `build.rs` removidos);
  22 funcoes de dominio byte-identicas + nova ABI `extern "C"` estavel (`aegis_*`,
  two-call buffer protocol, JSON so na borda JNI). UDL congelada como referencia
  (`reports/refactoring/UNIFFI_REMOVAL_PLAN.md`). Lock: 34 pacotes podados, 0
  adicionados. `deny.toml` sem entrada MPL-2.0; notices/inventory/SBOM 273->239.
- Toolchain: `cargo 1.99.1` / `rustc 1.99.1` (inalterada).
- Escopo: host-only Windows x86_64. Sem ESP-IDF target, sem matriz NDK .so,
  sem aceite em dispositivo fisico. Builds, mocked traffic, ports, screenshots,
  emuladores e handshakes NAO sao aceitacao de dispositivo fisico.
- Sem Mock/Fake/Stub em codigo de producao (somente testes/`cfg(test)`).

### `cargo test --workspace` — PASS (exit 0, VERIFIED)

- Log host-local: `$env:TEMP\postjni-workspace-test.log`.
- Total: **937 passed, 0 failed, 1 ignored** (firmware doc-test, ignore
  pre-existente). Delta pos-JNI vs `33df2ea`: 927 -> 937 (+10 na bridge).
- Per-crate (todos `ok`):
  - `aegis-fido-core` lib: 124 passed, 0 failed.
  - `ctap_tests` integration: 9 passed, 0 failed.
  - `e2e_vectors` integration: 1 passed, 0 failed.
  - `aegis-fido-firmware` lib: 515 passed, 0 failed (demo
    `freertos_sched` segue passando pos-`e683979`); bin `main`: 0 tests.
  - firmware bins/integration: `applets_t9` 12, `freertos_tasks` 2,
    `migration_tests` 3, `namespaced_store_t5` 14, `netwifi_t10` 16,
    `otakey_provider_t6` 8, `proximity_freertos` 0, `secure_guard_integration` 2.
  - `aegis-fido-usb` lib: 92 passed, 0 failed.
  - `aegis-secure-guard` lib: 39 passed, 0 failed.
  - `aegis-bridge` lib (`uniffi-bridge` crate): **36 passed, 0 failed** —
    27 de dominio preservadas + 9 FFI novas (`ffi_c_abi`, NULL-reject,
    length-query, mapeamento de codigos de erro).
  - `universal-device-sdk` lib: **64 passed, 0 failed**.
  - Doc-tests: todos `ok` (1 ignored pre-existente).

### Focado single-thread (`--test-threads=1`) — PASS exato

- `cargo test -p uniffi-bridge -- --test-threads=1`: **36 passed, 0 failed,
  0 ignored** (exit 0) — resultado focado exato, multiprocess-safe.
- `cargo test -p universal-device-sdk`: **64 passed, 0 failed** (exit 0).

### `cargo clippy --workspace --all-targets -- -D warnings` — PASS (exit 0, VERIFIED)

- `Finished dev profile [unoptimized + debuginfo]` sem warnings (10.49s).

### `cargo deny check licenses advisories bans sources` — PASS (exit 0, VERIFIED)

- Log host-local: `$env:TEMP\postjni-deny.log`.
  `advisories ok, bans ok, licenses ok, sources ok`.
- MPL eliminado: `cargo tree -i uniffi` nao casa nenhum pacote (zero `uniffi*`
  no grafo); unicas ocorrencias de "mpl" no log sao substrings
  (`thiserror-impl`, `windows-implement`), nao licenca MPL-2.0.
- Notices/inventory 273->239 entradas (SBOM 280->246 pacotes/relacoes),
  conforme commit `915ebf3` (dono da lane FFI).

### Veredito pos-JNI (`915ebf3`)

- `cargo test --workspace`: PASS (exit 0, 937/0/1). Bridge 36/36, SDK 64/64.
- Focado `--test-threads=1` (bridge): PASS exato 36/0.
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS (exit 0).
- `cargo deny check licenses advisories bans sources`: PASS (exit 0, MPL gone).
- `cargo fmt --check`: segue BLOCKED (28 arquivos, pre-existente, nao revalidado).
- ESP-IDF/on-device: nao validados nesta lane (fora de escopo host-only).

## Heavy battery (HEAD `b1a10b3`, 2026-11-02 UTC) — detalhe em `HEAVY_TEST_REPORT.md`

- `cargo test --workspace`: PASS (exit 0, **941 passed / 0 failed / 1 ignored**).
- Feature matrix: `check --workspace --all-features` FAIL exit 101 **by design**
  (GAP-04 `compile_error!` bloqueia `test-mode`+`prod-strict` juntos);
  `test -p aegis-fido-firmware --features freertos,proximity` PASS (lib 562/0,
  integration 68/0); `check --features prod-strict` PASS; `check --features
  test-mode` PASS (somente leitura, nada commitado).
- Stress: `freertos_sched` 5/5 (18/18 cada), `proximity_freertos` 3/3 default
  (0 testes, feature-gated) + 3/3 com features (11/11) — **zero flakes**.
- `cargo test --workspace --release`: PASS (exit 0, 941/0/1, identico ao debug).
- Probes (somente leitura, sem flash/dispositivo): sem target xtensa instalado;
  `check --target xtensa-esp32s3-espidf` BLOCKED (E0463 `can't find crate for
  core`); `IDF_PATH\tools\idf.py` existe; Android SDK dirs setadas, adb
  presente mas nunca invocado; sdkmanager NOT VERIFIED.
- Testes novos: nenhum (sem gap genuino encontrado). Sem Mock/Fake/Stub
  adicionados; `MockFlashBackend` revisado (cfg-gated, documentado).
- Veredito: bateria host-only verde; pernas de dispositivo/ESP seguem
  BLOCKED/NOT VERIFIED por ambiente. Sem aceite em dispositivo fisico.

## Consolidated full run (2026-11-02 UTC, HEAD `354d46c`, `python tools/run_all.py --release`, exit 1) — BLOCKED on dep-track + docs (no code fixed in this lane)

- Veredito final consolidado (host-only Windows x86_64, sem aceite em dispositivo fisico): `test-debug` PASS (exit 0, 20.4s), `test-firmware-features` (`-p aegis-fido-firmware --features freertos,proximity`) PASS (exit 0, 24.3s), `clippy --workspace --all-targets -- -D warnings` PASS (exit 0, 26.5s), `fmt --check` FAIL exit 1 ADVISORY-ONLY (ex.: diff em `crates/universal-device-sdk/src/shamir.rs:82`, sem efeito no exit), `cargo deny check licenses advisories bans sources` PASS (exit 0, 35.9s, `advisories/bans/licenses/sources ok`), `dep-track --check` FAIL exit 2 (gate: NEW god-file `crates/aegis-fido-firmware/src/secure_guard_exec/mod.rs` score 25.45, dono da lane godfiles), `docs` FAIL exit 1 (gate: `docs-lint --root docs` com 5 BROKEN — 4x `MANUAL-CONEXAO-E-USO.md -> file:///e:/projetos/fido/...` + `PROJECT.md -> docs/project/ARCHITECTURE-MAP.html`; `--root reports` exit 0, `reports/**` scan 0 broken; dono da lane docs), `scripts` PASS (exit 0, 14.6s, todos os `scripts/*.ps1` SYNTAX-OK via `Parser::ParseFile`, sem execucao), `test-release --workspace` PASS (exit 0, 91.6s); totais 6 passed / 2 failed (dep-track, docs) / 1 advisory (fmt) / 0 skipped, evidencias em `reports/testing/consolidated-result.json` (parse OK) + secao `Run 2026-11-02T15:57:30Z` em `CONSOLIDATED_RUN.md` (real, nao PENDING); sem Mock/Fake/Stub em producao; builds, mocked traffic, ports, screenshots, emuladores e handshakes nao sao aceitacao de dispositivo fisico.

## Consolidated re-run (2026-11-02 UTC, HEAD `52826bb`, `python tools/run_all.py --release`, exit 0) — ALL GREEN

- Veredito final consolidado (host-only Windows x86_64, sem aceite em dispositivo fisico): ALL GREEN — `test-debug` PASS (exit 0, 22.8s), `test-firmware-features` (`-p aegis-fido-firmware --features freertos,proximity`) PASS (exit 0, 8.5s), `clippy --workspace --all-targets -- -D warnings` PASS (exit 0, 4.1s), `fmt --check` FAIL exit 1 ADVISORY-ONLY (sem efeito no exit), `cargo deny check licenses advisories bans sources` PASS (exit 0, 12.9s, `advisories/bans/licenses/sources ok`), `dep-track --check` PASS (exit 0, 0.3s, 230 files, god-split `secure_guard_exec` resolvido pos-`52826bb` slim), `docs` PASS (exit 0, 0.2s, `--root reports` + `--root docs` + `reports/**` scan 0 broken, 5 links corrigidos pos-`6c732f2`), `scripts` PASS (exit 0, 9.8s, todos os `scripts/*.ps1` SYNTAX-OK via `Parser::ParseFile`, sem execucao), `test-release --workspace` PASS (exit 0, 37.0s); totais 8 passed / 0 failed / 1 advisory (fmt) / 0 skipped, evidencias em `reports/testing/consolidated-result.json` (parse OK, `timestamp_utc 2026-11-02T16:09:32Z`) + secao `Run 2026-11-02T16:09:32Z` em `CONSOLIDATED_RUN.md` (real, nao PENDING); sem Mock/Fake/Stub em producao; builds, mocked traffic, ports, screenshots, emuladores e handshakes nao sao aceitacao de dispositivo fisico.

## Final validation on fd/finalizacao-linux (2026-11-03 UTC, HEAD `c393b3c`, `python tools/run_all.py --release`, exit 1) — post-merge + diet, CLOSING VERDICT

- Estado: HEAD `c393b3c` "feat(firmware): capability presets fido-only/totp (2MB diet)" sobre merge `f3b9cfe` (standalone architecture, zero-MPL, RUSTSEC fix, audits + product updates). Sem alteracoes de codigo nesta lane (somente `reports/testing/*`).
- Veredito de fechamento (host-only Windows x86_64, sem aceite em dispositivo fisico): **RED nos gates dep-track + docs; verde em todos os gates de codigo/teste**. `test-debug` PASS (exit 0, 26.4s), `test-firmware-features` (`-p aegis-fido-firmware --features freertos,proximity`) PASS (exit 0, 22.2s), `clippy --workspace --all-targets -- -D warnings` PASS (exit 0, 4.1s), `fmt --check` FAIL exit 1 ADVISORY-ONLY (pre-existente `crates/universal-device-sdk/src/shamir.rs:82`, sem efeito no exit), `cargo deny check licenses advisories bans sources` PASS (exit 0, 33.8s), `dep-track --check` FAIL exit 2 (gate: 232 files, 26 gods; 4 NEW god-files — `crates/aegis-fido-firmware/src/run/legacy_sg_dispatch.rs` 38.11, `src/vendor_exec.rs` 27.85, `src/pairing.rs` 27.54, `src/ble_gatt.rs` 25.16; dono da lane godfiles), `docs` FAIL exit 1 (gate: `docs-lint --root reports` exit 0 + `--root docs` exit 0, STYLE-HINTs apenas; `reports/**` scan checked=1 broken=1 — `reports/refactoring/CLOSED_MODEL_PLAN.md -> LICENSE`; dono da lane docs), `scripts` PASS (exit 0, 9.2s, SYNTAX-OK via `Parser::ParseFile`, sem execucao), `test-release --workspace` PASS (exit 0, 56.2s); totais 6 passed / 2 failed (dep-track, docs) / 1 advisory (fmt) / 0 skipped.
- Evidencias: `reports/testing/consolidated-result.json` parse OK (`timestamp_utc 2026-11-03T00:48:10Z`, `selector all`, `include_release true`) + secao `Run 2026-11-03T00:48:10Z` em `CONSOLIDATED_RUN.md` (real, nao PENDING).
- Diet presets (citado da diet lane, NAO re-executado aqui — este `run_all` cobre o default): totais de preset 589/526/476 conhecidos da diet lane.
- Test doubles: nenhum Mock/Fake/Stub adicionado nesta lane (`reports/testing/*` apenas; sem codigo de producao tocado).
- Builds, mocked traffic, ports, screenshots, emuladores e handshakes nao sao aceitacao de dispositivo fisico. Sem flash/hardware/destructive.

## Sealing full run on fd/finalizacao-linux (2026-11-03 UTC, HEAD `62c1f9b`, `python tools/run_all.py --release`, exit 0) — ALL GREEN, CLOSING VERDICT

- Estado: HEAD `62c1f9bae73a5a9b05f5df803a1dadd1409701fb` "refactor(god): slim legacy_sg_dispatch, vendor_exec, pairing, ble_gatt below threshold" sobre `37e38cf` (docs: fix CLOSED_MODEL_PLAN link). Branch `fd/finalizacao-linux`. Sem alteracoes de codigo nesta lane (somente `reports/testing/*`).
- Veredito de fechamento (host-only Windows x86_64, sem aceite em dispositivo fisico): **ALL GREEN** — `test-debug` PASS (exit 0, 19.8s), `test-firmware-features` (`-p aegis-fido-firmware --features freertos,proximity`) PASS (exit 0, 6.3s), `clippy --workspace --all-targets -- -D warnings` PASS (exit 0, 0.7s), `fmt --check` FAIL exit 1 ADVISORY-ONLY (pre-existente `crates/universal-device-sdk/src/shamir.rs:82`, sem efeito no exit), `cargo deny check licenses advisories bans sources` PASS (exit 0, 12.6s), `dep-track --check` PASS (exit 0, 0.3s, 245 files, 22 gods, no new god-files beyond 24 allowlisted — god-split `legacy_sg_dispatch`/`vendor_exec`/`pairing`/`ble_gatt` resolvido pos-`62c1f9b` slim), `docs` PASS (exit 0, 0.4s, `--root reports` + `--root docs` + `reports/**` scan checked=1 broken=0 — link `CLOSED_MODEL_PLAN.md -> LICENSE` corrigido pos-`37e38cf`), `scripts` PASS (exit 0, 9.0s, todos os `scripts/*.ps1` SYNTAX-OK via `Parser::ParseFile`, sem execucao), `test-release --workspace` PASS (exit 0, 32.8s); totais 8 passed / 0 failed / 1 advisory (fmt) / 0 skipped.
- Focado single-thread (`--test-threads=1`) — resultado exato: `cargo test -p aegis-secure-guard -- --test-threads=1` exit 0, lib **43 passed, 0 failed, 0 ignored** + doc-tests 0 passed (multiprocess-safe).
- Evidencias: `reports/testing/consolidated-result.json` parse OK (`timestamp_utc 2026-11-03T01:06:10Z`, `selector all`, `include_release true`) + secao `Run 2026-11-03T01:06:10Z` em `CONSOLIDATED_RUN.md` (real, nao PENDING).
- Test doubles: nenhum Mock/Fake/Stub adicionado nesta lane (`reports/testing/*` apenas; sem codigo de producao tocado). Side effect fora da lane deixado intacto e NAO commitado: `reports/refactoring/dep-track.json` (reescrito pelo proprio `dep-track --check`, dono da lane godfiles).
- Builds, mocked traffic, ports, screenshots, emuladores e handshakes nao sao aceitacao de dispositivo fisico. Sem flash/hardware/destructive. Sem push/merge.
