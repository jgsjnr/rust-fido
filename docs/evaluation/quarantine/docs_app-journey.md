# App Journey — Android × Device (Wave5, sec 4.2 app)

App (`app-android/`) + bridge (`crates/uniffi-bridge/`) implementam
**estritamente** o contrato congelado `docs/ble-protocol.md` (GATT `0xFFFD`,
chars `FFF1–FFF4`, opcodes `0x81/0x83/0xBE`, envelope `AEGN`, endpoints
`/ctap`, `/config/wifi`, `/oath/code`) e espelham `docs/screen-journey.md`.
Menus NUNCA decidem auth: UP vem do botão (hold 5s), PIN/UV do `CtapEngine`.

## 1. Tela × estado do device

| Tela (app) | Estado do device espelhado | Gatilho / transporte | O que a tela faz |
|---|---|---|---|
| Onboarding/Jornada | `Boot → Home → PairingBLE/AP → Vault → Locked` (todos) | nenhum (guia) | Mostra a jornada + guia hold-5s; sem I/O |
| Scan/Pair | `Home → PairingBLE{pairing}` / `Locked` | BLE scan filtro `0xFFFD`, bonding, `FFF4` revision, subscribe `FFF2` | Conecta, pareia, exibe `FFF2` (`idle/processing/up-needed`) |
| Accounts | `Busy` (durante CTAP) | `FFF1` `OP_MSG [0x04]` GetInfo, `[0x01 + CBOR]` MakeCredential | Transporta bytes; não interpreta segredos |
| Auth | `Busy` | `FFF1` `OP_MSG [0x02 + CBOR]` GetAssertion, `0xBE` Cancel | GetAssertion + botão dedicado Cancel |
| OATH/Vault | `Vault{account,code}` | `GET /oath/code?account=` (WiFi AP) | Exibe código + countdown 30s; import/export envelope `AEGN` |
| Settings | `Home` (pós-UP+PIN) | `POST /config/wifi` (UP+PIN), bonds locais, wipe local | Troca senha AP, lista bonds, wipe do APP, log sanitizado |

## 2. Transporte por tela (contrato)

| Tela | Seção do contrato | Bytes exatos |
|---|---|---|
| Scan/Pair | §1 GATT, §2 opcodes, §4 bonding+UP | `0000FFFD…`, `FFF1–FFF4`, rev `0x01`, `JustWorks+bonding+UP` |
| Accounts/Auth | §2 framing, §3 `FFF1` | `[op,hi,lo,..]` + `[seq,..]`, `≤244B/frag`, `≤512B` total, `0xBE` aborta |
| Vault | §5 envelope, §7 OATH | `AEGN\|01\|NONCE12\|CT+TAG`, `{"account","code","remaining_seconds"}` |
| Settings | §6 senha AP | body ASCII `8..63`, `401` sem UP+PIN, NVS intacta |

## 3. O que NUNCA sai do device

| Item | Onde vive | O que atravessa no lugar |
|---|---|---|
| Master key (eFuse BLOCK7) / salt (BLOCK8) | SoC, nunca serializado | Nada (envelopes já chegam cifrados) |
| OATH secrets | NVS cifrada (`SecureStorage`) | Só `code` 6–8 dígitos + `account` + `remaining_seconds` |
| Credential private keys / PIN hash | `SecureStorage` / `CtapEngine` | Só respostas CTAP opacas (`[status, CBOR...]`) |
| Senha do AP em claro | NVS (`wifi_ap_pass`, envelope) | Só o resultado `200/401` da troca |
| Chave da bridge (seal/open) | Buffer transitório JNI, `zeroize` no retorno | Envelopes `AEGN` (ct+tag) |
| `SharedPreferences` do app | `EncryptedSharedPreferences` (só metadados não-secretos) | Nada sensível: `allowBackup=false` |

Regras do app: nenhum secret em `SharedPreferences` sem `EncryptedFile`;
`FLAG_SECURE` nas telas de código; zero `Log.*` com PII (só `SanitizedLog`,
nomes de evento fixos); wipe com confirmação dupla apaga SÓ o app
(sem endpoint de wipe no contrato, o device é intocável por aqui).

## 4. Geração de código (bridge → Kotlin)

```
cargo run -p uniffi-bindgen -- generate crates/uniffi-bridge/src/aegis_bridge.udl \
  --language kotlin --out-dir app-android/app/src/main/java   # pacote uniffi.aegis_bridge
```
`AegisBridge.kt` consome os bindings gerados; sem eles o módulo não compila
por desenho (TODO explícito no arquivo + `app-android/CHECKLIST.md`).

## 5. Validação (nesta worktree)

- `cargo test -p uniffi-bridge` → 11/11 verde (fragmentação, envelope,
  COSE parse-only, OATH display-only, senha AP, query — todos espelhando o firmware).
- `cargo test --workspace` → verde (sem regressão no firmware/core).
- Android: estrutura pronta + `CHECKLIST.md` (sem SDK/wrapper neste host;
  sintaxe revisada por inspeção; `./gradlew :app:assembleDebug` no host Android).
