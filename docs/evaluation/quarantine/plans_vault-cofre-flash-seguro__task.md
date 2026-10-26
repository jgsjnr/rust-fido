---
# Task: vault-cofre-flash-seguro

**Created:** 2026-10-19T21:30:00Z

## Requirements
- R-01: Cofre dedicado em lugar específico da flash 16MB S3 (partição `storage` 896KB, namespace `vault/`), sem tocar `nvs` do sistema nem `factory`.
- R-02: Criptografia melhor padrão de mercado S3: eFuse BLOCK7/BLOCK8 → HKDF-SHA256 → AES-256-GCM (envelope `AEGN|0x01|NONCE12|CT+TAG`), nonce TRNG, AAD estrito, Zeroize.
- R-03: Migração COMPLETA idempotente (legacy `credential_*`/`pin_hash` + `cred_slot_a/b` + `keys6/`/`oath6/`) → `vault/` dual-slot A/B + backup, com verify-after-write e rollback preservando legacy.
- R-04: Risco (a) ELIMINADO: migração NUNCA queima eFuse sozinha; burn só via `tools/factory_provision.py --confirm --port`, dry-run primeiro, verify-after-readback.
- R-05: Risco (b) mitigado: power-loss mid-write não corrompe cofre (dual-slot + backup + re-run idempotente retoma do legacy intacto).
- R-06: Risco (c) mitigado: cotas `DeviceConfig` (max_keys/max_oath/label 32B/TLV 512B) + contador monotônico anti-rollback.
- R-07: Trabalho 100% em worktree `fd-vault-*` nova; `main` intacto; rebase/ajuste contra versão final do sistema depois; sem quebrar lógicas (bytes CTAP/USB/CBOR/APDU idênticos).
- R-08: Rastreio do original preservado: baseline `main@4b28aa4` travado; toda mudança do `main` final monitorada via `git fetch + git log baseline..main + diff-stat` antes do rebase, sem perder histórico.

## Out of Scope
- Troca de curva/AEAD (mantém AES-256-GCM, sem XChaCha/Kyber nesta v1).
- Nova partição física ou resize de `factory` (reusa `storage` existente).
- App Android/Kotlin e BLE GATT (só preserva gates `binding+UP+PIN`).

## Acceptance Criteria
- [ ] `cargo test --workspace` verde + `clippy -- -D warnings` limpo na worktree.
- [ ] Prova de paridade: mesmo input → mesmo output (seal/load roundtrip, export/import vault, CTAP vetores NIST inalterados); `grep Mock*/0x5A/0xA5` zerado fora de `#[cfg(test)]`.
- [ ] Boot + seal/load roundtrip validado em placa real (COM7/COM8) ou simulador com `storage` real, com power-loss injetado (slot B corrompido → slot A + legacy intactos).
- [ ] `factory_provision.py --dry-run` mostra plano + sha256 sem tocar hardware; burn real só com `--confirm`.
- [ ] Relatório de rastreio: `baseline`, `main-final`, lista de commits do original desde o baseline e decisão rebase (fast-forward vs ajuste manual) registrada.

## Constraints
- eFuse OTP irreversível: nenhum auto-burn; `AlreadyProgrammed`/`WriteProtected` = erro fatal, nunca overwrite (OR-only).
- Envelope 512B/envelope total 545B; TLV total ≤512B; label 1..32B utf8.
- Lógicas NÃO mudam: reescrita só com bytes idênticos; `ble/wifi/menu` default-off; binário com features off = baseline.
- Baseline rastreio: `main@4b28aa4` (18-19/out/2026); tópicos ativos `fido-auditoria` (fd-verify) e `validacao-usb-telas` não podem ser perturbados.
- Note: criado COM pesquisa de codebase (Step 2Y) — vault/, persistence.rs, partitions.csv, migrations/, provision.rs lidos.

## Open Questions
- none (riscos a/b/c fechados nesta sessão).

## Suppressed Questions
- "Constraints?" → answered by: descrição inicial (worktree, 16MB, criptografado, melhor mercado) + partitions.csv + provision.rs.
---