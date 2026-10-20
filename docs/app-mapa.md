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

## Logs (tela Log do dispositivo, sem PII/segredos)

- `SYSTEM tela=<rota>`: toda troca de tela (prova de navegação).
- `BLE`: scan started/achou/parou(N) · connect · GATT connected/
  disconnected/erro · revisão · SUB FFF2 · bond · key gen/list ·
  assertion · wallet gen/preview · re-assinar/cancel/desconectar.
- `PAIRING`: bond solicitado/estadual; `WIFI`/`LOCK`: fluxos próprios.

Se um botão "não vai": abra o Log e veja o último `tela=` — diz
exatamente onde o app está.
