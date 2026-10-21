# Base record — Wave 0 (fd-execute Step 1)

- Worktree: `E:\projetos\fd-worktrees\fido-integracao-unificada-0`
- Branch: `fd-fido-integracao-unificada-phase-0`
- Baseline: `main@4b28aa4` (4b28aa4d7253fcca4a77c896efc21c44c3025fdd)
- Verified: `rev-parse main == rev-parse HEAD` → MATCH; `status` limpo.
- Created: 2026-10-19 (fd-execute, sob instrucao explicita do usuario: partir do main atual)
- Pre-flight notes:
  - `fdx-graph` indisponivel (HOME unset) — impacto via git diffs do fd-task reusado.
  - `fdx-validate artifacts` bloqueado pelo loop-guard (formato alinhado manualmente ao `carteira-cripto-store/affect.md` aprovado).
  - `fdx-validate pre-execute` falhou em `docs/carteira-cripto.md not found` — falso-positivo esperado: arquivo vive na branch de origem, é alvo de merge, não pré-requisito do Wave 0. Override com motivo registrado aqui.
- Pendente (sob demanda): Steps 2–5 aguardam sinal "finalizada" por worktree; Step 6 após as 4 unidas.
- Origens observadas (read-only): carteira avançou sozinha para `6ed2719` na própria branch; piv/ota/vault seguem no baseline (piv e ota com mudanças não-commitadas, ota com `ota.rs` untracked extra).
