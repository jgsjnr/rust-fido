---
# Architecture: vault-cofre-flash-seguro

## Approach
Reusar `SecureStorage` + `AegisVault::seal_to_blob/open_blob` sem nova cripto: novo `vault_store.rs` liga os dois via namespace `vault/` na partição `storage` existente, com migração `vault_v7` idempotente (dual-slot A/B + `vault_backup/`, verify-after-write) seguindo o padrão já provado de `aegn_v1_to_v2` e `keys_oath_v6`. Chave sempre de eFuse via `provision::load_device_keys` (nunca hardcoded); `DeviceConfig` ganha cotas do cofre.

## Components
- `vault_store.rs` (novo): `vault_put/get/delete` sobre `SecureStorage`, cotas + verify-after-write + zeroize.
- `migrations/vault_v7.rs` (novo): `migrate_to_vault_v7` idempotente, preserva legacy até verificado.
- `persistence.rs` (estende): reexporta `VAULT_PREFIX`, sem mudar envelope `AEGN v1`.
- `config.rs` (estende): `max_vault_slots`, `max_vault_bytes` com bounds.
- `provision.rs` + `tools/factory_provision.py` (verifica/estende): dry-run + `--confirm` + sha256 audit, sem auto-burn.
- `lib.rs` + `main.rs` (fiação mínima): registra módulos e roda migração 1x no boot, fora do hot path USB.

## Data Flow
boot → `load_device_keys` (eFuse BLOCK7/8) → `SecureStorage::new` → `migrate_to_vault_v7` (legacy→`vault_a/`+`vault_b/`+`vault_backup/`, verify) → `vault_store` serve CTAP/OATH/Vault com `seal_blob/open_blob` (AES-256-GCM, nonce TRNG, AAD `Aegis-Vault-Storage-v1`).

## Alternatives Considered
- Nova partição `vault` dedicada — rejected because resize de `partitions.csv` invalida OTA/factory atual; reuso de `storage` 896KB já isola por namespace.
- XChaCha20-Poly1305 ou chave em software — rejected because AES-256-GCM+HMD eFuse já é padrão NIST do projeto e auditado (vetor NIST em `aead.rs`); troca quebraria paridade.
- Migração destrutiva (apaga legacy) — rejected because viola rollback e risco (a)/(b); dual-slot + backup preserva prova de paridade.
- Reused existing `SecureStorage`, `AegisVault`, `oath_store` pattern, `aegn_v1_to_v2` idempotence instead of building new.
---