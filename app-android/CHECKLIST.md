# AegisKey Android — build & QA checklist

Estrutura pronta para build (Kotlin + Material3 + UniFFI). Este host não tem
Android SDK / gradle wrapper / kotlinc: sintaxe validada por inspeção contra
o contrato (`docs/ble-protocol.md`). Rode abaixo num host Android.

## 1. Gerar bindings UniFFI (obrigatório antes do Gradle)

```sh
cargo run -p uniffi-bindgen -- generate crates/uniffi-bridge/src/aegis_bridge.udl \
  --language kotlin --out-dir app-android/app/src/main/java
# produz app-android/app/src/main/java/uniffi/aegis_bridge/ (não versionar stubs manuais)
```

Build da lib nativa por ABI (exemplo arm64):

```sh
rustup target add aarch64-linux-android
cargo ndk -t arm64-v8a build -p uniffi-bridge --release
# .so -> app-android/app/src/main/jniLibs/arm64-v8a/libaegis_bridge.so
```

## 2. Gradle

```sh
cd app-android
gradle wrapper --gradle-version 8.7   # gera ./gradlew (ausente de propósito aqui)
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease      # minify + proguard (mantém uniffi.*)
```

## 3. Lint manual de segurança (bloqueante)

- [ ] `allowBackup=false` no Manifest (ok).
- [ ] `FLAG_SECURE` ativo (MainActivity, cobre Vault/Auth).
- [ ] Zero `Log.*` no app (`grep -r "Log\." app/src` vazio; só `SanitizedLog`).
- [ ] Nenhum secret em prefs (só `SecureStore` p/ metadados; envelopes só em `EncryptedFile`).
- [ ] Permissões runtime `BLUETOOTH_SCAN` (`neverForLocation`) + `BLUETOOTH_CONNECT` pedidas na tela Pair.
- [ ] `FFF4 revision == 0x01` ou desconecta (cliente implementa).
- [ ] Play Integrity + cert-pinning saem de stub antes do release (`AppSecurity.kt`, `WifiApi.kt`).

## 4. QA por tela (device firmware wave4)

- [ ] Onboarding: jornada espelha LCD/LED (sec 4.2).
- [ ] Pair: scan acha `AegisKey-XXXX`, bond JustWorks, `FFF2` mostra `up-needed` sem toque.
- [ ] Accounts: GetInfo responde; MakeCredential exige UP no botão.
- [ ] Auth: GetAssertion responde; Cancel `0xBE` aborta e limpa.
- [ ] Vault: código = LCD do device; countdown 30s; copiar funciona; import/export valida `AEGN`.
- [ ] Settings: senha curta rejeitada local; sem UP+PIN → `401`; wipe duplo só limpa o app.

## 5. Rust (nesta worktree, já verde)

```sh
cargo test -p uniffi-bridge   # 11/11
cargo test --workspace        # sem regressão
```
