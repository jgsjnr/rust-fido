# Affect Analysis
Generated: 2026-10-19T19:30:00Z

## Affected Files
- create crates/aegis-fido-core/src/wallet/mod.rs
- create crates/aegis-fido-core/src/wallet/types.rs
- create crates/aegis-fido-core/src/wallet/store.rs
- create crates/aegis-fido-core/src/wallet/address.rs
- modify crates/aegis-fido-core/src/lib.rs
- create docs/carteira-cripto.md
- modify docs/nvs_schema.md
- modify web/app.js
- modify web/index.html
- modify crates/aegis-fido-core/Cargo.toml
- modify Cargo.lock

## Notes
`lib.rs`: adição de 1 linha (`pub mod wallet;`). `nvs_schema.md`: tabela
`wallet_slot_*` aditiva. Web: aba assistida, sem OTP. `Cargo.toml`/`Cargo.lock`:
somente se a codificação de endereço exigir crates novos (B3); provar no_std.

## Affected Systems
- Vault/KeyManager (read/reuse, sem reescrita): risco de merge com agentes paralelos — mitigado por worktree + reconciliação final.
- NVS schema (só documentação de chaves novas, envelope intacto).
- Web RP (aba nova isolada).

## Risk Level
medium

## Parallel Safety
### Can Parallel
- Task A (módulo wallet + testes unitários): [crates/aegis-fido-core/src/wallet/mod.rs, crates/aegis-fido-core/src/wallet/types.rs, crates/aegis-fido-core/src/wallet/store.rs, crates/aegis-fido-core/src/wallet/address.rs]
- Task B (docs + NVS schema doc): [docs/carteira-cripto.md, docs/nvs_schema.md]
### Must Sequential
- Task C (fiação `lib.rs` + aba web + validação E2E, depende de A): [crates/aegis-fido-core/src/lib.rs, web/app.js, web/index.html]
