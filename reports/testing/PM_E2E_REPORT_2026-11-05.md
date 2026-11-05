# PM E2E Report — 2026-11-05 (subagente device+E2E)

**Escopo desta sessão:** rebuild + reinstall APK debug com a página Senhas, exercício
no device físico via adb (somente leitura/instalação debug), re-execução host L1
com `--test-threads=1`, e relatório. **Nenhum flash/erase/eFuse/Secure Boot foi
tocado; nenhuma escrita serial/COM7 foi feita nesta sessão** (REGRA Nº1 — HIL
invasivo proibido sem `--confirm`).

**Veredito:**
- **HOST + L1: PASS** — `aegis-pm-vault` 17/17, `universal-device-sdk --features pm`
  (filtro `pm`) 9/9, `uniffi-bridge` 46/46, `aegis-fido-firmware --lib pm_store`
  10/10, `PasswordManagerViewerTest` 8/8. Total L1 **17+9+46+10 = 82/82**.
- **DEVICE_E2E: PASS_PARCIAL** — menu Senhas, lista ids opacos (estado vazio/bloqueado),
  zero-persistência e ausência de crash **PASS no device físico**; popup/olho/digital/wipe
  **PENDENTE_INTERAÇÃO** (exige hardware key conectada + sessão desbloqueada + digital
  cadastrada — nenhum dos três disponível sem o usuário).
- **BLOQUEADOR_PARCIAL conhecido (não re-executado aqui):** 2 falhas pré-existentes em
  firmware testmode (`oob_arm_funil_serial…`, `sign_gates_mirror…`) — contexto do
  principal; fora do escopo host desta sessão.

---

## 1. Ambiente

| Item | Valor observado |
|---|---|
| Host | Windows (pwsh), `cargo 1.99.1`, gradle wrapper `app-android` |
| Git | merge `30ae0ac` (página Senhas já fundida) |
| Device adb | `192.168.15.17:38071` — `moto g(60)`, Android 12, `device` (físico) |
| Pacote | `dev.aegiskey.app`, `versionName=0.1.0-wave5`, `versionCode=1` |
| APK | `app-android/app/build/outputs/apk/debug/app-debug.apk`, 63.424.229 bytes, SHA256 `75D9C703…20C990` (rebuild `assembleDebug` → **BUILD SUCCESSFUL**, 38 up-to-date + 1 executed = binário corrente com a UI nova) |
| Instalação | `adb install -r` → `Success` (só reinstall debug; sem tocar dados de outros apps) |
| Serial/COM7 | **não utilizada nesta sessão** (nenhuma escrita; HIL invasivo proibido) |

## 2. Exercício no device (somente leitura + taps, sem credencial real)

1. `am start -n dev.aegiskey.app/.MainActivity` → `ResumedActivity .../.MainActivity`
   (task #234, pid 24514). **PASS.**
2. `uiautomator dump` da home: bottom nav contém **Vault, TOTP, Passwords, Devices,
   Settings**; card "Password Manager (device viewer)" presente. **PASS.**
3. Tap na aba Passwords (bounds `[466,2320][613,2356]` → tap 540,2280) → `PasswordManagerScreen`
   renderizada com (dump `ui_pm.xml`):
   - Título "Password Manager" + subtítulo "Device-only viewer. IDs are opaque; secrets
     show once and are wiped on close." **PASS** (contrato observável de ids opacos).
   - "Connect hardware device first" / "BLE connection is offline. Connect device before
     operation." + diálogo OK — **estado bloqueado-sem-hardware, fail-closed. PASS.**
   - "Search loaded IDs (hex)", "Device census unavailable", "No password entries loaded /
     Refresh while the device is connected and Secure Guard is unlocked." — lista vazia
     por falta de hardware+sessão, **nenhum segredo exibido. PASS.**
   - Bottom nav íntegra na rota Senhas. **PASS.**
4. **Popup/olho/digital/wipe no device: PENDENTE_INTERAÇÃO.** Sem hardware key conectada
   e com Secure Guard travada não há entrada para abrir o popup nem segredo para liberar;
   o caminho do olho exige `BiometricPrompt` + sessão + digital do usuário atual. HAL
   (`dumpsys fingerprint`): sensor presente (Type 1, Strength 2), **usuário corrente com
   0 digitais cadastradas**. Autenticação real fica com o usuário em HIL L3.
   Cobertura lógica correspondente existe em `PasswordManagerViewerTest` 8/8 (ver §3).
5. `logcat -d *:E` filtrado (`aegiskey|AndroidRuntime|FATAL`): **nenhum crash do
   `dev.aegiskey.app`**. Linhas presentes são ruído de install (profile/fs-verity/
   Play 404) e um `AndroidRuntime` de outro pacote (facebook analytics, pid 19766).
   Sem extração de segredo (só tags/pids). **PASS (sem crash do app).**
6. Screenshot: `C:/Users/junior/AppData/Local/Temp/opencode/pm_senhas.png` (157 kB,
   `screencap` da rota Senhas). Não commitado (este relatório é o único artefato da sessão).

## 3. Zero-persistência (PM não persiste nada)

`run-as dev.aegiskey.app` **FUNCIONOU** (esperado: build debug é debuggable — **não**
interpretar como "negado"; em release o `run-as` nega por padrão):
- `files/`: só `binding_id.aegis` + `profileInstalled` (pré-existentes, nada de PM).
- `databases/`: **inexistente**.
- `find` por `*pm*|*password*|*vault*` sob o datadir: **zero matches**.
- `shared_prefs/`: só `__androidx_security_crypto_encrypted_file_pref__.xml`,
  `aegis_keys_vault_prefs.xml` (nomes de chave cifrados — EncryptedSharedPreferences),
  `aegis_locale_preferences.xml`. **Nenhuma pref de PM; valores nunca lidos.**
- Conclusão: fechar a tela sem sessão/hardware deixa **zero rastro de PM**; wipe
  pós-fechamento logicamente coberto por `release_roundtrip_and_wipe` (ver abaixo).
  **PASS.**

## 4. Host L1 (`--test-threads=1`, resultado exato)

| Suíte | Comando | Resultado exato |
|---|---|---|
| `aegis-pm-vault` | `cargo test -p aegis-pm-vault -- --test-threads=1` | `17 passed; 0 failed` |
| `universal-device-sdk --features pm` (filtro `pm`) | `cargo test -p universal-device-sdk --features pm pm -- --test-threads=1` | `9 passed; 0 failed; 64 filtered out` (suíte cheia: 73 passed) |
| `uniffi-bridge` (`aegis_bridge`) | `cargo test -p uniffi-bridge -- --test-threads=1` | `46 passed; 0 failed` |
| `aegis-fido-firmware --lib pm_store` | `cargo test -p aegis-fido-firmware --lib pm_store -- --test-threads=1` | `10 passed; 0 failed; 596 filtered out` |
| `PasswordManagerViewerTest` (Android unit) | `:app:testDebugUnitTest --tests dev.aegiskey.app.PasswordManagerViewerTest` | `tests="8" skipped="0" failures="0" errors="0"` — `release_roundtrip_and_wipe`, `release_rejects_empty_secret_and_oversize_id`, `bottomNav_passwordsDestination_reusesExistingPmRoute`, `gates_preserve_wire_bytes_and_vault_ux`, `pm_opcodes_claim_first_free_range`, `status_response_roundtrip`, `opaque_handles_carry_no_invented_labels`, `list_request_response_roundtrip` |

L1 reconfirmado: **17+9+46+10 = 82/82 + 8/8 Android.**

## 5. Cobertura Senhas (matriz)

| Requisito | Evidência | Estado |
|---|---|---|
| Menu/bottom nav tem Senhas | dump uiautomator home + rota PM (`HubDestination.PASSWORDS`, `AppRoutes.PM`) | PASS (device) |
| Lista ids opacos | "No password entries loaded", "Search loaded IDs (hex)", teste `opaque_handles_carry_no_invented_labels` | PASS (device vazio + unit) |
| Popup abre | requer entrada carregada (hardware) | PENDENTE_INTERAÇÃO |
| Olho exige digital (`BiometricPrompt`) | código em `PasswordManagerScreen`/`BiometricGate`; HAL confirma sensor, 0 digitais no usuário corrente | PENDENTE_INTERAÇÃO |
| Fechamento faz wipe, sem persistência | `release_roundtrip_and_wipe` 8/8 + `find`/prefs vazios de PM no device | PASS (unit + device) |
| Erros sem segredo | `errors_carry_no_secret_payload`, `debug_never_logs_*` (vault/SDK) | PASS (host) |
| Sem crash na rota | logcat sem FATAL do pacote | PASS (device) |

## 6. BLOQUEADOR_PARCIAL — 2 falhas firmware testmode (pré-existentes, conhecidas)

- `freertos_route.rs::oob_arm_funil_serial_com_gates_e_latch` e
  `vendor_exec/vendor_tests/sign.rs::sign_gates_mirror_gen_binding_up_no_pin`
  (existência confirmada no fonte; **suíte testmode NÃO re-executada nesta sessão** —
  fora do escopo host contratado; citação via contexto do principal: secure-guard 62/62,
  clippy testmode limpo).
- Impacto: não bloqueiam PM L1/L2 (82/82 + device parcial), mas **bloqueiam a promoção
  a veredito DEVICE_E2E pleno/HIL L3** até resolução.

## 7. Próximos passos (HIL L3, só com `--confirm` explícito do usuário)

1. Conectar hardware key (USB, só leitura/instalação — sem flash/erase) + desbloquear
   Secure Guard com credencial real do usuário.
2. Com digital cadastrada: abrir popup de entrada, tocar olho, confirmar que
   `BiometricPrompt` (fingerprint) aparece, autenticar, conferir segredo único e wipe
   ao fechar (re-checar `find`/prefs após).
3. Resolver as 2 falhas testmode e re-rodar a suíte firmware completa.
4. Repetir este relatório como `PM_E2E_REPORT_<data>.md` com resultado interativo.

---
*Sessão: rebuild `assembleDebug` OK → `install -r` OK → `am start` + taps + dumps +
logcat + `run-as` (leitura) + screenshots locais + cargo L1 `--test-threads=1`.
Nenhum flash/erase/eFuse/COM7. teléfonos de terceiros/apps não tocados.*
