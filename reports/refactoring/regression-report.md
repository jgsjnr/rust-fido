# Regression Report -- preservation-first baseline (zero moves)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `915ebf3`
- Date (UTC): 2026-11-02
- Mode: preservation-first, zero file moves executed. Scheduler fix `e683979`
  (crates-only, sibling lane) re-validated here; seguranca `33df2ea`
  (migracao elliptic 0.13->0.14, RUSTSEC-2026-0387) e remocao UniFFI `915ebf3`
  (manual JNI, zero MPL) incorporadas e re-validadas nesta lane
  (`cargo test` + `clippy` + `deny` executados em HEAD `915ebf3`); sem alteracoes de
  test-file ou report-scope alem dos owned report files.
- Scope: host-only Windows x86_64 (`cargo check` / `cargo clippy` / `cargo test`).
  No ESP-IDF target build, no hardware acceptance.

## Baseline (from reports/testing/BASELINE.md, HEAD 30680ff)

| Gate | Result | Evidence |
| ---- | ------ | -------- |
| `cargo check --workspace` | PASS | exit 0, VERIFIED |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | exit 0, VERIFIED |
| `cargo test --workspace` | BLOCKED (pre-existing fail) | 648 passed / 1 failed, 0 ignored |
| `cargo fmt --check` | BLOCKED (pre-existing fail) | 28 files, parent-noted, not re-run in this lane |
| `tools/architecture-analyzer` `cargo check` | PASS | exit 0, re-verified in final integration |

Sole test failure (pre-existing, not introduced here):

- `aegis-fido-firmware` lib: 514 passed, 1 failed.
- Failing test: `freertos_sched demo_freertos_end_to_end`,
  assertion `ticks >= 1` at `freertos_sched.rs:924`.
- `aegis-fido-core` lib: 124 passed, 0 failed (VERIFIED).
- `ctap_tests` integration: 9 passed, 0 failed (VERIFIED).
- `e2e_vectors` integration: 1 passed, 0 failed (VERIFIED).

## Why zero new regressions

- `reports/refactoring/moved-files.md`: NONE, zero moves executed.
- `reports/refactoring/dependency-graph-after.json` is identical to
  `dependency-graph-before.json` (zero moves, no dependency changed).
- `reports/refactoring/migration-plan.json`: `moves_executed: 0`,
  KEEP verdicts plus 3 PROPOSED items only, nothing executed.
- No files under `crates/`, `tools/`, or `app-*` were modified in this lane.
  Untracked additions are reports, `deny.toml`, `THIRD_PARTY_NOTICES.md`,
  and `tools/architecture-analyzer/` only.
- With no code delta, no new regression is possible by construction.
  The one failing test and the fmt failures pre-date this lane.

## Verdict

- **PASS at HEAD `915ebf3` — RUSTSEC-2026-0387 RESOLVIDO via migracao
  p256/k256/p384/p521 0.13->0.14 (+ecdsa 0.17, elliptic-curve 0.14,
  signature 3.0, ed25519-dalek 3.0, crypto-bigint 0.7.10). Wire-preserving
  (Sec1Point alias, mesmos bytes, try_sign propaga erro) + UniFFI REMOVIDO
  (ABI `extern "C"` manual `aegis_*`, zero MPL-2.0, lock -34/+0).**
- `cargo check` (workspace e `--all-targets`): PASS (exit 0, herdado da lane FFI).
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS (exit 0, VERIFIED).
- `cargo test --workspace`: PASS (exit 0; **937 passed / 0 failed** / 1 pre-existing
  doc-test ignore). Bridge 36/36 (27 dominio + 9 FFI novas), SDK 64/64.
  Focado `cargo test -p uniffi-bridge -- --test-threads=1`: 36/0 exato (exit 0).
  O fail `freertos_sched demo_freertos_end_to_end` (`ticks >= 1`) segue FIXADO
  por `e683979` (sem assercao enfraquecida).
- `cargo deny check licenses advisories bans sources`: PASS (exit 0, VERIFIED;
  `advisories ok, bans ok, licenses ok, sources ok`). MPL-2.0 ELIMINADO:
  `cargo tree -i uniffi` vazio; notices/inventory 273->239 (SBOM 280->246).
- Ressalvas (nao bloqueiam o PASS tecnico, seguem abertas):
  - Evidencia anterior preservada em `reports/compliance/cargo-deny-output.log`
    (outro dono, NAO modificado); snapshots em
    `reports/compliance/cargo-deny-final.log` (pos-migracao + pos-JNI).
  - `cargo fmt --check`: ainda BLOCKED (28 arquivos, pre-existente).
  - ESP-IDF: v5.3.1 pinado; v6.1/v6.0.3-compat nao validados; 2 instalacoes
    host mantidas; sem validacao fisica/on-device.
  - Revisao juridica humana: sem MPL-2.0 restante (9 uniffi removidos por
    `915ebf3`); demais licencas com aceite tecnico do dono 2026-11-02
    (APPROVED-by-owner) — nao se declara PASS legal.
- External standalone consumer (`$env:TEMP`, SDK + secure-guard + usb path
  deps): 4/4 PASS desktop-only (evidencia herdada `d33cf41`, nao revalidada
  nesta lane); usb root re-export gap + `no_std` caveat noted.
- Zero moves, portanto zero novas regressoes introduzidas por esta lane; os
  unicos deltas de codigo desde `30680ff` sao o scheduler fix do sibling lane
  (`e683979`), a migracao de seguranca `33df2ea` do dono do codigo e a
  remocao UniFFI `915ebf3` (dono FFI, re-validada aqui: 937/0 + deny exit 0).
- Remediation owner: firmware scheduler test owner — closed by `e683979`.
  Security owner: elliptic migration — closed by `33df2ea`.
  FFI owner: UniFFI removal — closed by `915ebf3` (re-validado nesta lane).
  Do NOT weaken any gate to make a red build pass.
