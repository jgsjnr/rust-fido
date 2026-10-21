# Auditoria mocks + AEGN v1→v2 (20/10, sem COM8/sem subagentes)

Método: grep `Mock|mock!|0x5A|0xA5|unimplemented!|todo!` em `crates/`
fora de arquivos de teste + inspeção dos hits + suíte verde.

## Veredito: uso de mock contido, zero segredo hardcoded em prod

| Achado | Arquivo:linha | Veredito |
|---|---|---|
| `MockEfuseStorage` / `MockFlashBackend` (structs + trait impls) | `efuse.rs:119`, `persistence.rs:451` | Infra de teste compilada junto (sem `cfg` no tipo), mas **inocente**: prod usa `RamEfuseStorage::new()` zerado + `load_device_keys` com fallback (`main.rs:461-466`). Por isso a placa real boota `Unprovisioned` — comportamento correto, não mock. |
| `[0x5A; …]` / `[0xA5; …]` | `efuse.rs:153` | Só em `#[cfg(test)] with_default_keys` (fixture). Fora de teste: zero ocorrências em código de produção. |
| `Mock*` em testes | `binding.rs:520`, `ble_gatt.rs:839,895`, `oath_store.rs:166`, `migration_tests.rs:7`, `persistence.rs:507+` | Todos dentro de `mod tests` ou teste de integração. OK. |
| `[0x5A; 32]` em `wallet/store.rs:385,419` | Testes (`AegisVault::new` com chave fake). OK. |
| `[0x5Au8; 32]` etc. em `recovery.rs:379`, `provision.rs:117` | Fixtures de teste (`from_slice` em teste / salt exemplo). OK. |
| `todo!/unimplemented!` | — | Zero ocorrências em `crates/`. |

Comentários `CI-GREP: MOCK-ONLY-IN-TEST` (`binding.rs:21`,
`efuse.rs:116`) confirmam a política; um `ci-grep-mocks.ps1` existe em
`scripts/` para travar em CI.

## AEGN v1→v2

Migração em `migrations/aegn_v1_to_v2.rs` com 4 testes
(`migrates_and_verifies_slots` e cia) + `migration_tests.rs` (3 testes)
— ida/volta coberta e verde no `cargo test` (224 firmware + 3 migration).

## Prova

`cargo test -p aegis-fido-firmware --lib` 224 passed +
`cargo clippy -p aegis-fido-firmware --all-targets -- -D warnings` zero
(rodados em 20/10 nesta branch).
