# Regression Report -- preservation-first baseline (zero moves)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `33df2ea`
- Date (UTC): 2026-11-02
- Mode: preservation-first, zero file moves executed. Scheduler fix `e683979`
  (crates-only, sibling lane) re-validated here; seguranca `33df2ea`
  (migracao elliptic 0.13->0.14, RUSTSEC-2026-0387) incorporada sem
  re-validacao de codigo alem de `cargo deny` + SHAs; sem alteracoes de
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

- **PASS at HEAD `33df2ea` — RUSTSEC-2026-0387 RESOLVIDO via migracao
  p256/k256/p384/p521 0.13->0.14 (+ecdsa 0.17, elliptic-curve 0.14,
  signature 3.0, ed25519-dalek 3.0, crypto-bigint 0.7.10). Wire-preserving
  (Sec1Point alias, mesmos bytes, try_sign propaga erro).**
- `cargo check` (workspace e `--all-targets`): PASS (exit 0).
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS (exit 0).
- `cargo test --workspace`: PASS (exit 0; 927 passed / 0 failed / 1 pre-existing
  doc-test ignore). O fail `freertos_sched demo_freertos_end_to_end`
  (`ticks >= 1`) segue FIXADO por `e683979` (sem assercao enfraquecida).
- `cargo deny check licenses advisories bans sources`: PASS (exit 0, so
  warnings de duplicate versions). Evidencia anterior preservada em
  `reports/compliance/cargo-deny-output.log` (outro dono, NAO modificado);
  snapshot pos-migracao em `reports/compliance/cargo-deny-final.log` (novo).
- Ressalvas (nao bloqueiam o PASS tecnico, seguem abertas):
  - `cargo fmt --check`: ainda BLOCKED (28 arquivos, pre-existente).
  - ESP-IDF: v5.3.1 pinado; v6.1/v6.0.3-compat nao validados; 2 instalacoes
    host mantidas; sem validacao fisica/on-device.
  - Revisao juridica humana (23 crates): PENDENTE — nao se declara PASS legal.
- External standalone consumer (`$env:TEMP`, SDK + secure-guard + usb path
  deps): 4/4 PASS desktop-only; usb root re-export gap + `no_std` caveat noted.
- Zero moves, portanto zero novas regressoes introduzidas por esta lane; o
  unico delta de codigo desde `30680ff` e o scheduler fix do sibling lane +
  a migracao de seguranca `33df2ea` do dono do codigo.
- Remediation owner: firmware scheduler test owner — closed by `e683979`.
  Security owner: elliptic migration — closed by `33df2ea`.
  Do NOT weaken any gate to make a red build pass.
