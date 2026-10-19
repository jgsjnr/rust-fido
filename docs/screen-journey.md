# Screen Journey — LCD + Headless (Wave4, sec 4.2)

Menu NUNCA decide auth: so chama `UpPolicy`/`CtapEngine`. Telas sao espelho LCD <-> LED.

## 1. Maquinas

- Pareamento: `firmware/src/pairing.rs` (`PairingManager`): `Idle / Arming(hold progressivo) / PairingBLE / PairingAP / Locked`.
- Telas: `firmware/src/ui_journey.rs` (`UiJourney`): `Boot / Home / PairingBLE / PairingAP / Vault / Locked / Busy`.
- LED headless: `firmware/src/pairing_led.rs` (`effect_for_pairing_state`) + `led_for_journey`.

## 2. Tabela tela x LED

| Tela (`JourneyScreen`) | LCD mostra | LED headless | Sai por |
|------------------------|------------|--------------|---------|
| `Boot` | Splash AegisKey + versao/chip | `RainbowCycle{1000}` | init ok -> `Home` |
| `Home` | "DISPOSITIVO ATIVO" + status | `Breathing{CYAN,2000}` | hold 5s -> `PairingBLE` |
| `PairingBLE{code}` | Codigo 6 digitos (ex `483920`) + " confirme no app" | `Breathing{BLUE,1600}` | timeout 60s -> `Locked`; codigo ok -> `Home`(bonded) |
| `PairingAP{ssid}` | SSID `AegisKey-XXXX` + "conecte e configure" | `Breathing{BLUE,1600}` | mesmo que BLE; `enter_ap/ble_mode` alterna preservando expiracao |
| `Vault{account,code}` | Rotulo + codigo TOTP + barra 30s | `Solid(BLUE)` | auto-limpa 15s (`VAULT_AUTO_CLEAR_SECS`) -> `Home`; `tick(now)` faz a transicao |
| `Locked` | "BLOQUEADO — novo hold 5s" | `ErrorFlash` (vermelho) | novo hold 5s -> `Arming` |
| `Busy` | Spinner "processando..." | `PromptTouch` (pisca rapido) | fim CTAP -> `Home`/`Vault` |

Arming (hold progressivo, sem tela dedicada): LCD reusa `Busy`/barra; LED `PromptTouch` (pisca rapido). `arming_progress_pct(now)` 0..100.

## 3. Vault (OATH apos UP)

- Chamador valida `UpPolicy` ANTES de `show_vault(account, code, now)`.
- `code` 6-8 digitos; secret nunca entra na UI.
- `is_vault_visible(now)` checa expiracao; `tick(now)` auto-limpa para `Home`.

## 4. Headless (sem LCD)

Mesmos estados via LED:

- pisca rapido (`PromptTouch`) = arming
- respiracao azul (`Breathing{BLUE,1600}`) = pairing (BLE/AP)
- verde solido (`Solid(GREEN)`) = pareado (`Idle+bonded`)
- vermelho (`ErrorFlash`) = erro/timeout (`Locked`)
- ciano respirando (`Breathing{CYAN,2000}`) = idle sem bond

## 5. Proibicoes

- Menu/UI nao chamam `set_user_presence(true)` sozinhas; UP vem do botao (`BootButton`/`DualButtonManager`) com latch uso unico.
- Troca de senha WiFi e `GET /oath/code` exigem UP (+PIN para senha); UI so exibe resultado.
- SSID `AegisKey-XXXX` deriva do serial (`ap_ssid_for_serial`); codigo 6 digitos via TRNG no chamador.

## 6. WAVE8 — TOTP real no display (sem literais)

- `main.rs` NAO contem mais codigos TOTP literais (`482 915` etc removidos).
- Long-press BOOT 2s (`TOTP_LONG_PRESS_TICKS`) -> `totp_view::collect_totp_codes`
  (`OathApplet::device_list` + `device_code`, UP confirmado pelo hold) -> `UiScreen::TotpCode`
  com codigo real + countdown 30s (`T = unix/30`, `remaining = 30 - unix%30`).
- Sem contas no NVS -> `UiScreen::Error{"Sem contas OATH — adicione via app"}` (nunca codigo falso).
- KEY (GPIO 14) alterna entre as contas reais; countdown recalculado a cada 1s (virada da janela).
- Visivel por 15s (`TOTP_SHOW_TICKS` = `VAULT_AUTO_CLEAR_SECS`); depois volta a `Home`.
- Log so rotulo/contagem — codigo e segredo nunca vao para tela/log.
- `UiJourney::to_ui_screen_at(now)` espelha cada estado na LilyGO ST7789 135x240;
  `Vault` repassa o codigo do device sem tocar.

## 7. Telas de erro (WAVE8)

| Situacao | Tela LCD | LED headless |
|----------|----------|--------------|
| sem UP (toque nao confirmado) | `Error{"Sem toque UP - pressione BOOT"}` | `ErrorFlash` |
| sem PIN (operacao exige PIN) | `Error{"PIN exigido - desbloqueie no app"}` | `ErrorFlash` |
| timeout (pareamento 60s, UP 25s, CTAP 30s) | `Error{"Tempo esgotado - tente de novo"}` | `ErrorFlash` |
| sem contas OATH (long-press) | `Error{"Sem contas OATH — adicione via app"}` | `ErrorFlash` |
| bloqueado | `Error{"BLOQUEADO - novo hold 5s"}` | `ErrorFlash` |

Transicoes: `Boot -> Home -> PairingBLE/AP <-> Home -> Vault -> Home` (auto-limpa 15s);
qualquer timeout/erro -> `Locked`; `Busy` (CTAP em curso) -> `Home`/`Vault` ao fim ou `Locked` em 30s.
