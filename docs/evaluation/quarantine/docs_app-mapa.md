# Mapa do app — rotas, botões e logs

Barra inferior (5 itens): Início(`onboarding`) · Chaves(`accounts`) ·
Auth(`auth`) · Cofre(`vault`) · Conectar(`connect`). Telas fora da barra
(`scan/control/usb/wifi/settings/log/binding/foreign/transfer/unbind/
recovery/wallet`) contam como **Conectar** no destaque.

| Rota | Tela | Chega por |
|---|---|---|
| `onboarding` | Início (status + ações) | Início (barra) |
| `scan` | Scan/Pair (0xFFFD) | Conectar → BLE; Início → Conectar |
| `control` | Controle pós-pareamento + menus | Scan → Abrir controle |
| `accounts` | Chaves (GEN/LIST/DELETE) | Chaves (barra); Controle → Chaves; Início → Gerar chave |
| `wallet` | Carteira (BTC/ETH/SOL + endereço) | Controle → Carteira |
| `auth` | Auth (GetAssertion) | Auth (barra); Controle → Entrar |
| `vault` | Cofre (OATH) | Cofre (barra); Controle → Cofre; Início → Ver código |
| `usb` | USB via cabo | Conectar → USB |
| `wifi` | WiFi/AP | Conectar → WiFi |
| `connect` | Hub Conectar | Conectar (barra) |
| `log` | Registros (filtro por categoria) | Controle/Log; Início → Ver registros; Conectar → Log |
| `settings` | Ajustes | Conectar → Ajustes |
| `binding`/`foreign`/`transfer`/`unbind`/`recovery` | Posse e recuperação | Conectar → seção Dono |

## Logs (duas fontes, sem PII/segredos)

**Fonte (a) — tráfego observado pelo app** (ao vivo na tela Log):
- `SYSTEM tela=<rota>`: toda troca de tela (prova de navegação).
- `BLE`: scan started/achou/parou(N) · connect · GATT connected/
  disconnected/erro · revisão · SUB FFF2 · bond · key gen/list ·
  assertion · wallet gen/preview · re-assinar/cancel/desconectar.
- `PAIRING`: bond solicitado/estadual; `WIFI`/`LOCK`: fluxos próprios.

**Fonte (b) — LOG REAL DA FIRMWARE (op `0x38`)**: anel de 64 eventos
em RAM no device — boot, advertising start/stop, janela abre/fecha,
bond ok, cada op recebida + status respondido, UP. Linhas
`SEQ EV=cc ARG=aa T=ms`. Na tela Log, seção "Log da firmware (0x38)"
com botão "Puxar log da firmware" (exige link READY + vínculo no BLE;
sem vínculo a firmware nega `0x05`; firmware antiga sem a op dá
"sem resposta"). Serial/USB físico lê livre (posse do cabo).

Se um botão "não vai": abra o Log e veja o último `tela=` — diz
exatamente onde o app está.
