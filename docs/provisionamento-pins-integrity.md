# Provisionamento: pins SPKI + verificação Integrity no servidor

Fonte de autoridade no app: `app-android/.../net/WifiApi.kt` (`DevicePinning`)
+ `app-android/.../security/AppSecurity.kt` (`PlayIntegrity`) + `app-android/.../net/OtaApi.kt`
(`validateOnline` / `fetchManifest` / `fetchBinary`). Servidor dev: `tools/ota_server.py`
+ `tools/ota_registry.json.example`. Este doc só traduz o que o código já faz;
não inventa telemetria, estado, valores ou efeitos.

## 1. Pins SPKI — onde colocar

- Instalar uma vez no provisioning, antes de qualquer `https://`:
  `DevicePinning.install(vararg pins)` (`WifiApi.kt`).
- Sem pins instalados, `DevicePinning.guard(url)` nega `https://` com
  `SecurityException("pinning não configurado (HTTPS negado)")`.
  `http://` do AP local passa direto (sem pinning).
- `WifiApi.open()` aplica por-conexão (`pinnedFactory()`), sem default global:
  cadeia validada pelo trust do sistema + pin da folha. HostnameVerifier do
  sistema é mantido. Mismatch = `SSLPeerUnverifiedException` (nunca fallback
  silencioso).
- Logs: só contagem/evento (`"pinning instalado pins=" + size`,
  `"pinning desinstalado"`). Nunca pins, hosts ou corpos.
- Rearme (testes/dev): `DevicePinning.clearPins()` — HTTPS volta a ser recusado.
  `isConfigured()` diz se há pins instalados.

Exemplo (Kotlin, provisioning):

```kotlin
// Pins gravados no provisioning (fora do repo, via canal confiável).
DevicePinning.install(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
)
// A partir daqui WifiApi.open("https://...") usa pinnedFactory().
// Sem install acima, https:// é negado por guard().
```

## 2. Formato base64 32B

- `DevicePinning` exige rígido (`WifiApi.kt`):
  `Regex("[A-Za-z0-9+/]{43}=")` — base64 de 32 bytes com `=` final (44 chars).
  Vazio/formato ruim = `IllegalArgumentException("pins vazios" | "pin fora do formato ...")`.
- Conteúdo: `base64(SHA-256(SPKI da folha))` — o `SubjectPublicKeyInfo` do
  certificado folha, não do intermediário/raiz nem do certificado inteiro.

Gerar (fora do app, no provisioning):

```bash
# Folha atual do servidor OTA/WiFi:
openssl s_client -connect ota.exemplo:443 -servername ota.exemplo </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A
# Saída esperada: 44 chars terminando em `=`, ex.:
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

Rotação: instalar primário + backup juntos (`install(pinAtual, pinFuturo)`);
o `TrustManager` aceita qualquer pin do set (`want.contains(pin)`).

## 3. Verificação Integrity no servidor

App (`AppSecurity.kt` `PlayIntegrity.verify(context, nonce?)`):

- Sem dependência Gradle nova: acesso por reflexão, aceitando
  `com.google.android.play.integrity` (novo) e `com.google.android.play.core.integrity`
  (legado). Sem Play no device = `Result.Unavailable` (fail-closed, nunca sucesso).
- `nonce`: 16 B TRNG por padrão (`SecureRandom`), copiado e zerado após uso;
  chamador pode passar `nonce` próprio (uso único). Token/nonce nunca entram em log
  (só o nome do evento via `SanitizedLog.Event.INTEGRITY_CHECK`).
- `Result`: `Passed(token)` (opaco, só sai para o servidor verificar),
  `Unavailable` (sem Play/rede), `Failed(code)` (timeout/`no-task`/`empty-token`/etc.,
  mensagem truncada em 64 chars, sem corpo).

Exemplo (Kotlin, app):

```kotlin
val res = PlayIntegrity.verify(context)
when (res) {
    is PlayIntegrity.Result.Passed -> {
        // Enviar res.token + nonce para o servidor verificar.
        // Nunca logar o token; só transportar via HTTPS pinado.
        otaServerVerify(res.token)
    }
    PlayIntegrity.Result.Unavailable -> { /* honesto: sem atestação, sem envio */ }
    is PlayIntegrity.Result.Failed -> { /* honesto: mostra code, sem retry silencioso */ }
}
```

Servidor (onde verificar — `tools/ota_server.py` é o ponto):

- O dev-server atual (`ota_server.py`) só faz allow-check por registro
  (`POST /api/ota/validate {serial, aaguid, nonce} -> {allowed}` + `403 unregistered`;
  `OtaApi.validateOnline` retorna `false` em `401/403/offline`, nunca exceção por offline).
  A verificação Integrity entra **antes** do `allowed:true`: exigir o token Play
  no corpo, validar contra a API Google, e só então consultar o registry.
- Contrato sugerido (aditivo, sem quebrar o app atual):
  `POST /api/ota/validate {serial, aaguid, nonce, integrityToken}`.
  Sem `integrityToken` ou veredito negativo = `403 {allowed:false}` (fail-closed).

Exemplo (Python, servidor — verificar via Google, pseudocódigo com stdlib):

```python
import json, urllib.request

def verify_integrity(token: str, package: str) -> bool:
    # Troque pela chamada real: Play Integrity Decode API
    # POST https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken
    # com OAuth2 do servidor. Retorno esperado: deviceIntegrity + appIntegrity.
    req = urllib.request.Request(
        "https://playintegrity.googleapis.com/v1/%s:decodeIntegrityToken" % package,
        data=json.dumps({"integrity_token": token}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + server_oauth_token()},
    )
    with urllib.request.urlopen(req, timeout=8) as fh:
        verdict = json.load(fh)
    device = verdict.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
    app = verdict.get("appIntegrity", {}).get("recognitionVerdict")
    return ("MEETS_DEVICE_INTEGRITY" in device) and (app == "PLAY_RECOGNIZED")
```

Regras:

- Veredito negativo / token ausente / erro de rede na verificação = negar
  (`allowed:false`), nunca liberar.
- Não logar token/nonce/serial/aaguid no servidor além do mínimo;
  no app, `OtaApi` já só loga `HTTP code` + tamanhos (`"OTA validate -> HTTP " + code`),
  nunca serial/aaguid/bodies.
- Produção: `ota_registry.json` (copiado de `ota_registry.json.example`, nunca
  commitar o real) continua sendo o allow-list após o Integrity passar.

## 4. Como testar (sem alegar sucesso físico)

```powershell
# 1) Rotas 22 -> 23 (OtaScreen entrou no NavHost):
Select-String -Path app-android/app/src/main/java/dev/aegiskey/app/MainActivity.kt -Pattern 'composable\("' | Measure-Object
# esperado: 23 (antes 22)

# 2) Allowlist OTA sem 0x33 via BLE:
Select-String -Path app-android/app/src/main/java/dev/aegiskey/app/ble/BleContract.kt -Pattern 'OP_OTA_|isOtaOp|0x33'
# esperado: OP_OTA_BEGIN/CHUNK/FINISH/ABORT + isOtaOp; 0x33 só em comentário "NUNCA/USB-only"

# 3) Zero Log direto (contrato: só DeviceLog/SanitizedLog):
Select-String -Path app-android/app/src/main/java -Pattern 'android\.util\.Log|Log\.d\(|Log\.i\(' -Include *.kt -Recurse
# esperado: vazio
```
