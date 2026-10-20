# Task: Carteira cripto — armazenamento de chaves junto aos demais protocolos

**Created:** 2026-10-19T19:30:00Z

## Requirements
- R-01: Armazenar chaves das principais criptos (Bitcoin + EVM/Ethereum via secp256k1, Solana via Ed25519) — SOMENTE armazenamento + assinatura de hash/mensagem, sem construir/enviar transação.
- R-02: Reutilizar o que existe — `KeyManager` (GEN/IMPORT/SIGN/LIST/DELETE), `AegisVault` envelope AEGN v1, `Mnemonic24`/seed, `KeyPair` 5 curvas. Nada de novo motor cripto.
- R-03: Trabalhar isolado em worktree dedicada `fd-carteira-cripto-store-*`, nunca direto na main; no final reconciliar/merge com os vaults dos outros agentes mantendo AEGN v1 byte-idêntico.
- R-04: Módulo novo + testes + validações junto ao sistema: `cargo test --workspace` + `tools/test_aegiskey_rust.py` + `clippy -D warnings` verdes, sem quebrar teste existente.
- R-05: Sem OTP e sem travar/bloquear o sistema na gravação inicial (generate/import não exigem OTP, sem lock global).
- R-06: Superfície completa aditiva: docs em `docs/` + aba/painel na web (assistida, sem OTP) + chaves NVS `wallet_*` formais documentadas.

## Out of Scope
- Construção, broadcast ou decoding de transações on-chain.
- Mudança no envelope AEGN v1, em `KeyManager`/gates existentes ou em curvas/BIP-39.
- OTP como gate; wipe/reset físico.

## Acceptance Criteria
- [ ] Worktree dedicada criada a partir da main; main intacta até o merge reconciliado.
- [ ] Chaves BTC/ETH/SOL geradas, importadas (envelope AEGN + PIN token), listadas (só metadados) e assinando mensagem de teste via `KeyManager` reutilizado.
- [ ] `cargo test --workspace`, clippy `-D warnings` e suite Python verdes; nenhum teste anterior quebrado.
- [ ] Nenhum caminho de gravação inicial exige OTP ou adquire lock global do sistema.
- [ ] `docs/carteira-cripto.md` + NVS schema atualizado + aba web funcional (sem OTP).
- [ ] Merge final reconciliado com vaults paralelos; envelope AEGN byte-idêntico (prova: mesmo input → mesmo output).

## Constraints
- Envelope AEGN v1 imutável (`41 45 47 4E`|0x01|NONCE12|CT+TAG); só adição.
- `KeyManager`: 32 slots, label 1–32B utf8, gates UP (GEN/LIST/SIGN) e UP+PIN (IMPORT/DELETE); chave privada nunca sai em LIST.
- ZeroizeOnDrop em todo material privado; sem log de segredo.
- Sem prazo; cobrir as principais (BTC, EVM, SOL).
- Note: planejado COM pesquisa do codebase (Y) — risco de deriva com vaults paralelos mitigado via worktree + reconciliação final.

## Open Questions
- none

## Suppressed Questions
- "Qual stack de persistência?" → answered by: `docs/nvs_schema.md` + `vault/mod.rs` (AEGN v1, HKDF eFuse).
- "Novo motor cripto?" → answered by: `crypto/curves.rs` + `credential/key_manager.rs` (5 curvas, secp256k1/Ed25519 já cobertos — reusar).
- "Onde validar?" → answered by: README + sessão (cargo test workspace, `tools/test_aegiskey_rust.py`, clippy).
