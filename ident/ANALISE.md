# Fundamentação / AegisKey

## Escopo e método

Base: commit `cc50473`, worktree `codex/aegis-ident`. O checkout original tinha modificação em `reports/testing/HW_MATRIX.md`; ela não foi copiada ou alterada. Todas as entregas novas ficam em `ident/`, conforme solicitado, inclusive esta documentação específica da identidade.

Foi feito um inventário de todos os Markdown rastreados, com títulos, tamanho e temas, salvo em `documentation-inventory.json`. A leitura aprofundada foi direcionada aos documentos canônicos, jornadas de uso, identidade existente e relatórios relevantes. Isso não é uma auditoria linha a linha de todo o código ou uma nova avaliação de segurança.

Fontes principais consultadas:

- `AGENTS.md`, `AGENT_MAP.md`, `README.md`: escopo, convenções, produto e mapa do repositório.
- `docs/project/PROJECT.md`: arquitetura em camadas, transportes, presença física e semântica de LED.
- `MASTER_EXECUTION_PLAN.md`, `docs/plans/PLANS.md`, `docs/tasks/TASKS.md`: famílias de capacidades e distinção entre planejamento e operação.
- `docs/manual/MANUAL_USUARIO.md`: bloqueio, desbloqueio, cofre, TOTP, dispositivo e recuperação.
- `docs/plans/PASSWORD_MANAGER_PLAN.md` e `reports/testing/PM_E2E_REPORT_2026-11-05.md`: viewer device-only, IDs opacos, zero persistência e limites do E2E.
- `app-tray/README.md`, `tools/web_dashboard/index.html`, `app-android/.../ui/theme/ColorTokens.kt`, estrutura e trecho inicial de `PasswordManagerScreen.kt`: linguagens visuais existentes, navegação e famílias de componentes.
- `reports/release/GO_NOGO.md` e `reports/compliance/trademark-audit.md`: capacidades condicionais, limitações e ausência de certificação.

## Síntese do sistema

AegisKey é um ecossistema de autenticação com chave ESP32-S3, núcleo Rust, Secure Guard e companions web, desktop e Android. A marca precisa representar tanto a chave física quanto o controle humano. Os recursos incluem passkeys/WebAuthn, SSH, OATH/TOTP, PIV, carteiras, senha device-only e integrações de proximidade. O suporte real varia conforme dispositivo e build.

A documentação contém estados históricos e planos. Listar uma capacidade não comprova sua disponibilidade atual. O protótipo apresenta essas famílias como linguagem de produto e usa exemplos explícitos; não reproduz contagens de testes, status de produção ou selos de certificação como evidência nova.

## Direção visual

**Conceito:** um guardião que mantém o usuário no comando.

**Assinatura:** Seu acesso. Sob sua guarda.

**Símbolo:** escudo de seis lados com A geométrico e núcleo central. O contorno representa limite; o A, acesso; o núcleo, autorização humana. Desenhado em SVG, escalável e monocromático. Não usa marcas de terceiros.

**Paleta:** tema Google Material 3 existente, espelhando os valores de AegisColors em ColorTokens.kt: azul primário, esmeralda secundário, âmbar terciário e erro. Os pares on/container também são preservados. Os estados sempre têm texto; nenhuma informação depende só da cor. Não se usa a paleta elétrica escurecida do WS2812 como cor de texto.

**Tipografia:** Roboto quando instalada, com Segoe UI/Arial como fallback local; monoespaçada apenas para IDs, códigos e metadados. A assinatura vetorial tem lettering geométrico original, independente de fontes instaladas.

**Formas:** componentes alinhados a Material 3: botões preenchidos, tonais e contornados com shape full; cartões de 12 px; hero e diálogos de 28 px; seleção de navegação tonal; ícones lineares em grade de 24 px; espaçamento de 8 px. A ilustração conceitual da chave relaciona o produto físico ao companion.

**Voz:** pessoal, direta e calma. Ações descrevem intenção e resultado; estados indicam o próximo passo. Não se apresentam hashes e opcodes no fluxo principal de uso.

## Mapa de telas

| Tela | Papel | Origem conceitual |
|---|---|---|
| Visão geral | Estado da sessão e atalhos | Cofre + cockpit |
| Minhas chaves | Catálogo, busca, filtros e detalhes | Hub Android, passkeys, SSH, wallet, PIV |
| Códigos temporários | Janela temporal e cópia de amostra | OATH/TOTP |
| Senhas | IDs opacos, visualização temporária | PasswordManagerScreen / viewer |
| Dispositivos | Conexão, presença e proximidade | ConnectedKeysRepositoryScreen + tray |
| Integrações | Famílias de capacidades | SDK, WebAuthn, SSH, PIV, OTA, carteiras |
| Recuperação | Orientação, sem coleta de código | Secure Guard / manual |
| Preferências | Ajustes da demonstração | Companion |
| Identidade visual | Marca, cores, tipografia, ícones e estados | Proposta original |

## Limites de integração

A interface começa bloqueada e exige uma ação explicitamente simulada para entrar no estado ativo. Desconexão e expiração voltam ao estado bloqueado. WebAuthn padrão tem política distinta das operações administrativas; esconder o catálogo no companion não significa bloquear a autenticação WebAuthn no firmware. Recuperação de sessão e backup Shamir são tratados como conceitos distintos.

O protótipo abstrai os dez estados Secure Guard em cenários visuais comuns; não é a implementação integral da máquina de estados. Não recebe PIN, recuperação ou senha real. Todos os dados de exemplo vivem na memória da página. Não há assinatura criptográfica, geração de TOTP, biometria, acesso a hardware, mudança de segurança ou alteração de firmware.

## Alinhamento ao Material 3

A correção do usuário estabelece o Google Material como linguagem visual do sistema. A proposta usa os 24 papéis de cores do esquema escuro definido em `app-android/app/src/main/java/dev/aegiskey/app/ui/theme/ColorTokens.kt`, incluindo cores de conteúdo e containers. `material.css` aplica hierarquia tonal, shapes e estados aos controles HTML nativos. Não foi adicionada biblioteca de componentes nem alterado o tema Android. Os três níveis de superfície web são derivados por mistura tonal e estão identificados como derivados em `tokens.css`. A marca original ocupa os espaços de marca dentro desse sistema.
