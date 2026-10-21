# Plan: Unificacao worktrees ativas

## Wave 0 — base (executa agora)
- [ ] Step 1: Criar worktree/branch `fd-integracao-unificada` de `main@4b28aa4`, travar baseline, registrar `git log`/`diff --stat` das 4 origens (traces: R-01, R-06) — files: [nova worktree, baseline `4b28aa4`]

## Wave 1 — sob demanda (uma por "finalizada", sequencial)
- [ ] Step 2: Integrar carteira-cripto-store quando finalizada + reconciliar `wallet_slot_*` x `vault/` + paridade parcial (traces: R-02, R-03, R-04, R-05) — files: [docs/carteira-cripto.md, docs/nvs_schema.md]
- [ ] Step 3: Integrar vault-cofre-flash-seguro quando finalizada + reconciliar `migrations/mod.rs` + paridade storage (traces: R-02, R-03, R-04, R-05) — files: [migrations/vault_v7.rs, migrations/mod.rs]
- [ ] Step 4: Integrar piv-ble-proximity quando finalizada + reconciliar `ccid.rs`/`lib.rs`/`proximity` + paridade USB (traces: R-02, R-03, R-04, R-05) — files: [usb/piv.rs, usb/ccid.rs, usb/lib.rs, firmware/proximity.rs, firmware/lib.rs, firmware/Cargo.toml]
- [ ] Step 5: Integrar sistema-ota quando finalizada + reconciliar wiring `ota` em `lib.rs`/`main.rs` (opcodes `0x30+`) + paridade OTA/negativos (traces: R-02, R-03, R-04, R-05) — files: [firmware/ota.rs, firmware/lib.rs, OtaApi.kt, OtaTransfer.kt, tools/ota_server.py]

## Wave 2 — consolidacao (apos as 4 unidas)
- [ ] Step 6: Paridade final consolidada + relatorio por origem (baseline, commits `4b28aa4..HEAD`, decisao rebase) + `cargo test --workspace`, `clippy -D warnings`, AEGN byte-identico, suite Python (traces: R-05, R-06) — files: [relatorio-paridade.md]
