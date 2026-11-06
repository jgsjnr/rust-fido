# AegisKey / ident

Identidade visual e protótipo navegável alinhados ao Google Material 3 já usado no projeto, isolados da aplicação real.

Para abrir pela forma validada, sirva esta pasta por HTTP:

```powershell
python -m http.server 8769 --bind 127.0.0.1
```

Depois acesse http://127.0.0.1:8769. Nenhuma instalação ou build é necessário. O site funciona offline e não importa fontes nem bibliotecas externas.

## Manuais

- [Manual de uso](MANUAL_USO.md): abrir na worktree principal, explorar as telas, encerrar e resolver problemas.
- [Manual de identidade](MANUAL_IDENTIDADE.md): logos, ícones, cores Material 3, tipografia e regras de aplicação.
- [Análise do conceito](ANALISE.md) e [verificações executadas](VALIDACAO.md).

## Entregas

- Interface responsiva: visão geral, chaves, TOTP, senhas, dispositivos, integrações, recuperação e preferências.
- Painel de identidade em `index.html#identity`.
- `assets/`: símbolo, assinaturas horizontais em curvas vetoriais, versões claras/escuras/monocromáticas, app icon, tray, ilustração de produto e ícones SVG individuais + sprite.
- `tokens.css`: papéis de cores do AegisColors Android e dimensões reutilizáveis.
- `material.css`: formas, navegação, estados e componentes web alinhados ao Material 3, usando HTML nativo.
- `ANALISE.md`: fundamentos, fontes e limites da análise.
- `documentation-inventory.json`: inventário estrutural da documentação rastreada no commit-base.
- `VALIDACAO.md`: verificações realmente realizadas.

`python build_assets.py` recompõe os vetores e o inventário sem dependências. Os símbolos e o lettering vetorial são originais desta proposta. Roboto/Segoe UI/Arial/Consolas são fontes do sistema quando disponíveis; não são redistribuídas. O lettering geométrico em SVG é a assinatura oficial da proposta; o texto tipográfico da barra lateral é uma adaptação para a interface.

## Explorar

1. A interface começa bloqueada. Clique em **Explorar desbloqueio** e **Simular sessão ativa**. Não informe PIN real.
2. Visite as páginas pela barra lateral. Em Chaves, busque, filtre, abra detalhes e adicione um exemplo em memória.
3. Em Senhas, explore o diálogo de visualização com conteúdo fictício. Fechar ou trocar de página remove o conteúdo do diálogo.
4. Em Dispositivos, simule desconexão: a sessão fecha e as listas protegidas desaparecem. Reconectar mantém o bloqueio.
5. Visite **Universo AegisKey** para ver e baixar a identidade. Atualizar a página restaura os exemplos.

Nenhum acesso a bridge, USB, BLE, serial, firmware ou credenciais reais. Sem banco, localStorage, cookies ou telemetria. O desbloqueio é uma transição visual; não implementa autenticação. Os códigos TOTP são números fixos fictícios com um indicador de tempo. A ilustração do produto é conceitual, sem valor de CAD, fabricação ou comprovação física. Não há alegação de certificação FIDO.

## Adoção futura

Este pacote é um ponto de partida para aplicar a marca ao cockpit web, Compose Android e tray. Integração real precisa preservar a autoridade da chave, capacidades negociadas, canal protegido, vínculo, PIN, biometria quando exigida, toque físico, expiração e tratamento dos dez estados Secure Guard. Esse trabalho não está implementado aqui.
