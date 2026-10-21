---
# Affect Analysis
Generated: 2026-10-19T21:30:00Z

## Affected Files
- create crates/aegis-fido-firmware/src/vault_store.rs
- create crates/aegis-fido-firmware/src/migrations/vault_v7.rs
- modify crates/aegis-fido-firmware/src/migrations/mod.rs
- modify crates/aegis-fido-firmware/src/persistence.rs
- modify crates/aegis-fido-firmware/src/config.rs
- modify crates/aegis-fido-firmware/src/lib.rs
- modify crates/aegis-fido-firmware/src/main.rs
- modify crates/aegis-fido-firmware/src/provision.rs
- modify tools/factory_provision.py

## Affected Systems
- crypto/persistência: envelope AES-256-GCM + HKDF(eFuse) — reuso, sem nova cripto.
- migração/boot: idempotência + dual-slot + rollback.
- fábrica/provisionamento: dry-run + burn irreversível guardado.
- CTAP/OATH/Vault: só fiação de leitura, bytes idênticos.
- partições: partitions.csv verify-only, sem resize (storage 896KB reutilizada por namespace).

## Risk Level
high

## Risk Rationale
security-sensitive + eFuse irreversível + schema/migração; mesmo com reuso, erro trava placa.

## Parallel Safety
### Can Parallel
- Task A: [vault_store.rs, config.rs] (novo store + cotas)
- Task B: [migrations/vault_v7.rs, migrations/mod.rs] (migração isolada, mock backend nos testes)
### Must Sequential
- Task C (depends on A+B): [persistence.rs, lib.rs, main.rs, provision.rs, factory_provision.py] (fiação boot + fábrica, integra A e B)
---