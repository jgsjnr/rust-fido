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
