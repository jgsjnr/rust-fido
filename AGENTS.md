# AGENTS.md

## Commands

- `cargo test` — run the full test suite.
- `cargo clippy --all-targets -- -D warnings` — run the lint task.

## Code Map

- `crates` — crates.
- `docs` — project documentation.

## Conventions

- Declare modules with `mod` and re-export with `pub use`.
- Import items with `use` paths rooted at the crate.
- Put unit tests in an inline `mod tests` module inside the source file.

<!-- OPENCODE-TOKEN-OPTIMIZER -->
## OpenCode: regras de economia de contexto

- Antes de agir, identifique a tarefa e consulte somente os arquivos relevantes.
- Nao delegue tarefas simples que possam ser resolvidas diretamente.
- Delegue apenas quando houver uma especialidade necessaria ou trabalho realmente independente.
- Use no maximo um especialista por padrao; use dois somente quando forem tarefas independentes e justificadas.
- Nao chame varios agentes para analisar a mesma pergunta sem uma razao concreta.
- Nao solicite uma exploracao completa do repositorio para uma alteracao localizada.
- Prefira buscas por simbolos, funcoes, erros e arquivos relevantes em vez de ler arquivos grandes integralmente.
- Passe aos especialistas um resumo curto, caminhos exatos e uma pergunta delimitada.
- Solicite resultados objetivos: conclusao, arquivos envolvidos, riscos e verificacoes.
- Nao repita testes que ja passaram sem alteracao relevante no codigo.
- Nao reproduza logs extensos; extraia somente erros e trechos necessarios.
- Mantenha um resumo atualizado das descobertas importantes para evitar reanalisar o mesmo problema.
- Para firmware FIDO, nao reduza verificacoes de seguranca, criptografia, persistencia, provisionamento ou testes de regressao apenas para economizar tokens.
- Antes de finalizar, informe as alteracoes feitas e os testes realmente executados.
<!-- /OPENCODE-TOKEN-OPTIMIZER -->
