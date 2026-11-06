# Manual de identidade / AegisKey

## Princípio

**Seu acesso. Sob sua guarda.**

A marca representa uma chave física e a autorização humana. O símbolo combina escudo, letra A e núcleo central. A interface segue o Google Material 3 já adotado pelo projeto.

## Arquivos da marca

| Uso | Arquivo em `assets/` |
|---|---|
| Assinatura horizontal em fundo escuro | `logo-horizontal.svg` |
| Assinatura horizontal em fundo claro | `logo-horizontal-dark.svg` |
| Assinatura monocromática clara | `logo-horizontal-mono.svg` |
| Símbolo em fundo escuro | `symbol.svg` |
| Símbolo em fundo claro | `symbol-dark.svg` |
| Símbolo monocromático claro | `symbol-mono.svg` |
| Ícone de aplicativo | `app-icon.svg` |
| Símbolo claro para tray escuro | `tray.svg` |
| Ícones de interface | `icon-*.svg` e `icons.svg` |
| Ilustração conceitual de produto | `device-concept.svg` |

As assinaturas horizontais usam curvas vetoriais originais. Não dependem de uma fonte instalada. A barra lateral usa uma adaptação tipográfica para interface. Preserve as proporções, a posição do núcleo e os traços. Não estique, incline, recorte ou acrescente efeitos ao logo. Reserve ao redor um espaço livre de pelo menos um quarto da largura do escudo.

Como referência de aplicação, use o símbolo a partir de 24 px e a assinatura horizontal a partir de 160 px de largura. Confira legibilidade em tamanho real. A conversão para PNG, ICO, recursos Android ou ícones de tray de plataformas específicas deve ser validada em cada destino; os SVGs entregues não substituem automaticamente esses recursos.

## Cores e Material 3

A fonte do tema é `app-android/app/src/main/java/dev/aegiskey/app/ui/theme/ColorTokens.kt`. `tokens.css` espelha os 24 papéis do esquema escuro, incluindo pares de conteúdo e containers.

| Papel escuro | Cor | Conteúdo sobre a cor |
|---|---|---|
| Primary | `#9ECAFF` | `#003258` |
| Primary container | `#00497D` | `#D1E4FF` |
| Secondary | `#53DBC9` | `#003731` |
| Secondary container | `#005048` | `#73F8E5` |
| Tertiary | `#F0BE3B` | `#3F2E00` |
| Tertiary container | `#5A4300` | `#FFDF9E` |
| Error | `#FFB4AB` | `#690005` |
| Surface | `#101418` | `#E2E2E6` |

Use o azul primário para ações principais, o secundário para realces e estados ativos, o terciário para atenção e o papel de erro para falhas. Um estado precisa de texto e, quando útil, ícone; a cor não deve ser sua única indicação. Os tons de interface não representam valores elétricos do LED.

`material.css` aplica superfícies tonais, navegação selecionada, botões preenchidos/tonais/contornados, cartões de 12 px e diálogos de 28 px. Os níveis de superfície web são derivados por mistura tonal, identificados nos tokens. O pacote não inclui a biblioteca Google de componentes web, nem um tema claro completo de interface.

## Tipografia e ícones

Use Roboto quando disponível, com Segoe UI e Arial como fallback local. IDs e códigos usam Cascadia Code ou Consolas. Nenhuma fonte é baixada ou redistribuída pelo pacote.

Os 18 ícones usam grade de 24 × 24, traço de 1,6 px, terminais e junções arredondados. O sprite expõe os nomes dos arquivos individuais como IDs. Prefira cor herdada do componente (`currentColor`). Preserve um nome acessível no controle; o desenho isolado não deve carregar toda a informação.

## Voz e estados

Use português direto, com ação e resultado claros: **Bloquear sessão**, **Conecte sua AegisKey**, **Confirme na sua chave**. Separe estado da conexão, estado da sessão e solicitação de presença. Não apresente uma conexão USB como prova de sessão autorizada.

Nesta entrega, qualquer transição funcional é explicitamente simulada. Em integração futura, a chave deve continuar sendo a autoridade para capacidades e autorizações. Preserve as exigências reais de vínculo, PIN, presença, biometria quando aplicável e expiração. WebAuthn padrão e operações administrativas têm políticas distintas. Não use a identidade para alegar certificação, segurança auditada ou fabricação validada.

## Manutenção

Edite os vetores pelo gerador `build_assets.py`; ele recompõe os assets e atualiza o inventário documental do checkout atual. Execute na pasta `ident`:

```powershell
python build_assets.py
node --check app.js
```

Depois confira visualmente as aplicações e as dimensões responsivas. Se o tema Android mudar, sincronize os papéis em `tokens.css`, as amostras em `app.js` e as cores geradas em `build_assets.py`. A integração no cockpit, Android e tray é um trabalho separado deste pacote visual.
