# Plan: vault-cofre-flash-seguro

## Wave 1 (paralelo, worktree `fd-vault-migracao` nova a partir de `main@4b28aa4`)
- [ ] Step 1: Criar `vault_store.rs` + cotas em `config.rs` + testes roundtrip/tamper/quota (traces: R-01,R-02,R-06) — files: [vault_store.rs, config.rs]
- [ ] Step 2: Criar `migrations/vault_v7.rs` idempotente + testes legacy→A/B/backup + power-loss injetado (traces: R-03,R-05) — files: [migrations/vault_v7.rs, migrations/mod.rs]

## Wave 2 (sequencial, depende Wave 1)
- [ ] Step 3: Fiar `persistence.rs`+`lib.rs`+`main.rs` (migra 1x no boot) + `provision.rs`+`factory_provision.py` (dry-run/`--confirm`/sha256, sem auto-burn) + testes host (traces: R-04,R-07) — files: [persistence.rs, lib.rs, main.rs, provision.rs, factory_provision.py]

## Wave 3 (verificação + rastreio do original)
- [ ] Step 4: Prova de paridade — `cargo test --workspace` + `clippy -D warnings` + grep mocks zerado + roundtrip placa COM7/COM8 + relatório rebase contra `main` final (traces: R-07,R-08) — files: [snapshots/parity-report.md]
- [ ] Step 5: Rastreio do original — `git fetch origin`, `git log --oneline 4b28aa4..main-final`, `git diff --stat`, registra baseline/main-final/decisão rebase no parity-report (traces: R-08) — files: [snapshots/parity-report.md]
