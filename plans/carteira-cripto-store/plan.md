# Plan: Carteira cripto — armazenamento

## Wave 1
- [ ] Step 1: Criar worktree `fd-carteira-cripto-store-w1` da main e provar isolamento (traces: R-03) — files: [docs/carteira-cripto.md]
- [ ] Step 2: Implementar `wallet/types+address` + testes de endereço BTC/ETH/SOL (traces: R-01, R-02) — files: [crates/aegis-fido-core/src/wallet/types.rs, crates/aegis-fido-core/src/wallet/address.rs]
- [ ] Step 3: Implementar `wallet/store` delegando a KeyManager/Vault (sem OTP, sem lock) + testes generate/import/sign/list/delete (traces: R-02, R-04, R-05) — files: [crates/aegis-fido-core/src/wallet/store.rs, crates/aegis-fido-core/src/wallet/mod.rs]

## Wave 2
- [ ] Step 4: Fiar `pub mod wallet`, docs + NVS schema aditivo, aba web assistida sem OTP (traces: R-06) — files: [crates/aegis-fido-core/src/lib.rs, docs/carteira-cripto.md, docs/nvs_schema.md, web/app.js, web/index.html]
- [ ] Step 5: Validação junto ao sistema (cargo test + clippy + suite Python) e reconciliação final com vaults paralelos, envelope byte-idêntico (traces: R-03, R-04) — files: [crates/aegis-fido-core/src/wallet/store.rs, docs/carteira-cripto.md]
