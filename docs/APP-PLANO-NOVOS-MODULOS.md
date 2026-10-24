# APP Android — plano p/ tudo que e novo (pos-modulos-novos)
Lane: `.slim/worktrees/android-totp` (branch `omos/android-totp`).
Base pronta: onboarding + TOTP + telas (BLE/USB/Wallet/Vault/PIV/Wifi/
Recovery/Logs) + smoke no emulador. Regras: R3 facade-first (app so via
`universal-device-sdk` -> `uniffi-bridge`, nenhum import de crate
interna), R4 7 estados (NotCompiled so p/ feature off; sem `todo!()`),
R15/R16 (fakes so em teste), ASCII puro, sem segredo em log.
Rollback por item: `git checkout -- <write-scope>`.

## 0. O que ja existe (nao refazer)

- BLE GATT 0xFFFD FFF1-FFF4 (`BleContract`, `AegisBleClient`),
  bind 0x28-0x2D (`BindingWizardScreen`, `BindingOps`), vendor
  0x20-0x27 (`VendorOps`: KEY_GEN/LIST/DELETE, OATH PUT/LIST/CODE/DELETE),
  wallet 0x35-0x37 (`WalletScreen`), fw-log 0x38 (`LogScreen`),
  PIV enroll 0x39 (`PivScreen`), WiFi AP/STA (`WifiApi`, `WifiScreen`),
  OTA builders 0x30-0x34 (`OtaApi`), rescue/killswitch builder,
  `TestModeBanner`, `GateBanner` (gates), `RecoveryUnlockScreen`.
- O que falta e FIAR tudo isso no SDK novo + telas p/ o que nao tem UI.

## 1. Novo desde a base (dono = SDK/firmware; app so consome)

- SDK: `providers/*` (audit/backup/oath/ota/otp/piv/policy/proximity/
  rescue/wallet), `envelope.rs` (AEGN backup/export, binding->UP->PIN),
  `capabilities.rs` (`require_*` por dominio), `error.rs` (`SdkError`),
  `request/response/status` (contrato + `TooLarge`/0x04).
- Firmware: `oath_cmd` (contador atomico + power-loss), TOTP RFC6238/4226,
  `kbd_gate` (teclado so digita apos UP, so digitos 6-8), `hd_wallet`
  (BIP32/SLIP-0010), `dkek` (n-de-m), `backup_envelope`, `piv_cmd` /
  `openpgp_cmd` (`apdu` dono unico), `ctap_ext` (hmac-secret/minPinLength/
  credProtect/credBlob/largeBlob), P-384 real, `anti_rollback`,
  `efuse_plan`, `up_policy`/`led_policy`, `vault_aead`, `trust_facade`.
- Bridge: `MAX_PLAINTEXT_BYTES=4096` com paridade cruzada (nao duplicar
  numero no app — ler do SDK).

## 2. Lanes de app (1 writer por vez; UI via @designer se mexer layout)

- A1 SDK wiring | scope: `bridge/AegisBridge.kt` + `security/FeatureFlags.kt`
  | ligar `capabilities()`/`require_*` por tela (sem capability =
  `NotCompiled` honesto no `GateBanner`, nunca crash) + mapear `SdkError`
  p/ R4 (Success/Unsupported/Unavailable/PermissionDenied/NotCompiled/
  ExternalBlocked/RealVerified). Gate: unit c/ fakes + `./gradlew :app:testDebugUnitTest`.
- A2 OATH pleno | scope: `ui/AccountsScreen.kt` + `ui/CodeCard.kt` |
  PUT (UP+PIN, erro 0x02 sem PIN), LIST sem segredo (so codigo),
  CODE com janela ±1, DELETE com confirmacao, contador HOTP persistente
  (prova: power-loss não perde contador). Gate: unit + emulador.
- A3 Wallet+HD | scope: `ui/WalletScreen.kt` + `ui/VaultScreen.kt` |
  GEN/LIST/ADDR, endereco por curva, display HD (caminho BIP32), aviso
  RAM-only onde aplicar, validacao de rede invalida (0x04). Gate: idem.
- A4 PIV/OpenPGP | scope: `ui/PivScreen.kt` | enroll 0x39 (binding->UP),
  slots 24-27, RSA=BadAlg honesto, strip-FF (helpers F4), VERIFY/PIN
  com contadores. Gate: idem + roteiro OpenSC documentado.
- A5 Backup/restore (envelope) | scope: `security/RecoveryBackup.kt` +
  `ui/TransferOwnershipScreen.kt` | export/import via AEGN (app gera,
  device guarda blob; segredo nunca em claro fora do envelope), frase
  24 palavras (entropia+checksum), DKEK n-de-m UI. Gate: vetores AEGN
  cruzados com firmware.
- A6 OTA | scope: `net/OtaApi.kt` | stage/verify no app; COMMIT SÓ via
  USB + chave release + UP (regra travada na UI: sem caminho BLE/serial
  p/ COMMIT); manifesto 104 B validado antes do stage. Gate: lab-mocks
  off por defeito (`ExternalBlocked`, nunca `Success`).
- A7 Proximidade | scope: `ui/ScanPairScreen.kt` + BLE scan | peer
  bonded, adv 0xFFFE, walkaway (lock <= -75 dBm/10 s, volta NAO
  destrava), USB veta BLE por desenho. Sem peer = ExternalBlocked.
- A8 Teclado OTP + politicas + auditoria | scope: `ui/*` (digitos 6-8
  apos UP), telas UP/LED policy (comando autenticado), `LogScreen`
  (fw-log 0x38: metadados/contagens, nunca segredo). Gate: idem.
- A9 Bateria app | scope: `tools/` + emulador | self-tests + smoke no
  AVD (Telemetry_AVD_S24 24/10: install ok, MainActivity displayed,
  pid vivo, zero FATAL/AndroidRuntime) + HIL BLE fim-a-fim (H5:
  scan+janela+bond+wallet, com celular pareado; sem celular =
  ExternalBlocked, nao finge).

## 3. Ordem e gates

Ordem: A1 -> (A2..A8 em qualquer ordem, 1 por vez) -> A9. Nenhuma tela
nova sem `require_*` + estado R4 + teste com fake. HIL BLE só com
device + par real; QEMU/emulador nunca conta como RealVerified.
Doc do implementado por tela (sem alegar FIDO sem teste oficial).

## 4. Fora desta lane

Burn eFuse/secure-boot (R13), COMMIT OTA fora do rito, mocks de
comportamento, wrappers fora do SDK facade, `t_display` sem placa
(ExternalBlocked), conformidade FIDO sem suite oficial.
