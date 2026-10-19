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
