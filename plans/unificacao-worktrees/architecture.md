# Architecture: Unificacao worktrees ativas

## Approach
Branch de integracao `fd-integracao-unificada` a partir de `main@4b28aa4` (ancestral comum das 4 worktrees) recebe merges ordenados por demanda ("finalizada"), cada um seguido de reconciliacao local (fiação `mod` em `lib.rs`/`mod.rs`, namespaces NVS) e prova de paridade. Nenhuma edicao nas origens; todo conflito resolve na branch propria com commits atomicos por origem + relatorio de rastreio. Ordem sugerida por dependencia quando duas finalizarem juntas: docs (carteira) → vault (migracao base) → piv (usb/firmware aditivo) → ota (wiring `main.rs`/opcodes `0x30+` por ultimo, maior superficie).

## Components
- `integracao-base`: worktree/branch propria + baseline travado `4b28aa4` + script de rastreio (`log baseline..HEAD`, `diff --stat`).
- `merge-vault-first`: migracao `migrations/vault_v7.rs` + `mod.rs` (base de storage; sem re-encode AEGN).
- `merge-carteira-docs`: `docs/carteira-cripto.md` + `nvs_schema.md` (`wallet_slot_*` aditivo) + futuro `wallet/` em `aegis-fido-core`.
- `merge-piv`: `usb/piv.rs` + hook `handle_piv_apdu` em `ccid.rs` (default `6D00`) + `firmware/proximity.rs` feature-gated.
- `merge-ota`: `firmware/ota.rs` + wiring `lib.rs`/`main.rs` + `OtaApi.kt`/`OtaTransfer.kt` + `tools/ota_server.py`.
- `paridade`: `cargo test --workspace`, `clippy -D warnings`, roundtrip AEGN, suite Python, relatorio por origem.

## Data Flow
Origem finalizada (read-only) → `git merge`/`cherry-pick` na `fd-integracao-unificada` → reconciliacao local (fiação `mod`, NVS, opcodes) → paridade (test+clippy+AEGN+Python) → relatorio `baseline/commits/decisao` → aguarda proxima "finalizada". Repete ate as 4 unidas; `main` so recebe o resultado final reconciliado.

## Alternatives Considered
- Merge direto na `main` — rejeitado porque quebraria isolamento e topicos ativos (constraint vault R-07/R-08).
- Rebase das origens antes de unir — rejeitado porque viola read-only nas worktrees alheias (resposta Constraints).
- Branch por origem + octopus merge — rejeitado porque dificulta reconciliacao incremental e rastreio por demanda; merge sequencial na branch unica e mais auditavel.
- Reusar `SecureStorage`/AEGN/`KeyManager` existentes em vez de novo motor — reusar (ladder rung 2), sem nova abstracao.
