# Task: Unificacao worktrees ativas em branch propria

**Created:** 2026-10-19T22:00:00Z

## Requirements
- R-01: Criar worktree/branch propria `fd-integracao-unificada` a partir de `main@4b28aa4` como base unica de uniao.
- R-02: Unir SOMENTE as 4 worktrees ativas em `E:\projetos\fd-worktrees` (carteira-cripto-store, piv-ble-proximity, sistema-ota, vault-cofre-flash-seguro), nunca tocar nos arquivos delas (read-only).
- R-03: Integracao incremental sob demanda — so agir numa worktree quando o usuario disser "finalizada".
- R-04: Reconciliar conflitos DENTRO da branch propria (ex.: `firmware/lib.rs` PIV x OTA, `migrations/mod.rs`, namespaces NVS `wallet_*` x `vault/`), sem reescrever logica (bytes CTAP/USB/CBOR/APDU identicos).
- R-05: Prova de paridade obrigatoria a cada integracao: merge limpo + `cargo test --workspace` + `clippy -D warnings` + AEGN v1 byte-identico + suite Python verde.
- R-06: `main` intacta ate o merge final reconciliado; historico das origens preservado (baseline `4b28aa4` + log `baseline..HEAD` por origem).

## Out of Scope
- Topicos sem worktree ativa (`fido-auditoria`, `validacao-usb-telas`, `fido-ux-conex`).
- Commits, edits ou rebase dentro das 4 worktrees alheias.
- Nova crypto, troca de envelope AEGN v1, resize de particao `factory`, flash eFuse real.
- Transporte BLE/WiFi OTA nesta fase; enrollment AD real; RF calibrado.

## Acceptance Criteria
- [ ] Branch/worktree `fd-integracao-unificada` criada de `main@4b28aa4`, `main` intacta.
- [ ] Cada worktree finalizada integrada sob demanda com merge limpo + reconciliacao documentada.
- [ ] Paridade por integracao: `cargo test --workspace` verde, `clippy -D warnings` zero, AEGN `41 45 47 4E|0x01|NONCE12|CT+TAG` byte-identico (seal/load roundtrip), suite Python verde.
- [ ] Nenhum byte CTAP/USB/CBOR/APDU existente alterado fora do previsto em cada `task.md` de origem.
- [ ] Relatorio de rastreio por origem: baseline, commits `4b28aa4..HEAD`, decisao de reconciliacao.

## Constraints
- Somente-leitura nas 4 worktrees; escrita so na branch propria (resposta Constraints).
- Incremental: sem acao antecipada em worktree nao-finalizada (resposta Risks).
- Envelope AEGN v1 imutavel; `ble/wifi/menu/proximity` default-off; binario com tudo off = baseline.
- eFuse OTP irreversivel: nenhum auto-burn; `AlreadyProgrammed` = erro fatal.
- Note: criado COM pesquisa do codebase (Y) — diffs `main...HEAD` + status das 4 worktrees + 4 `task.md`/`plan.md` lidos.

## Open Questions
- none

## Suppressed Questions
- "Qual stack de persistencia?" → answered by: `persistence.rs` (AEGN v1, SecureStorage) + `docs/nvs_schema.md` lidos na pesquisa.
- "Novo motor cripto?" → answered by: `task.md` origens (reuso KeyManager/AEGN/Ed25519, sem nova crypto).
- "Onde validar?" → answered by: gates das origens (cargo test workspace, clippy -D warnings, suite Python, COM7/COM8).
