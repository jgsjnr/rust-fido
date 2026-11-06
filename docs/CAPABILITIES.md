# Capabilities da placa

Fonte normativa: `scripts/capability-catalog.json` (versao 1).
Advertisement em tempo de execucao: comando vendor `GET_CAPS 0x3F`
(read-only, sem auth), implementado em
`crates/aegis-fido-firmware/src/vendor_exec/vendor_caps.rs`.
Evidencia adicional: `reports/status/index.html` (leitura `0x3F` na bancada:
`preset full / 18 caps / unsupported_count 0`),
`reports/refactoring/CAPABILITY_DIET.md` (secao 7, advertisement `0x3F`),
`reports/release/RELEASE_NOTES.md` (comando vendor `0x3F`, resposta CBOR),
`reports/compliance/SECURITY_AUDIT_2026-11-04.md` (`0x3F` rejeita payload
nao-vazio com fail-closed).

Regra de dieta: comandos fora da capability respondem
`0x06 UNSUPPORTED_FEATURE` (fail-closed, nunca silencioso).

## 1. Presets e medidas

Metodo de medida (catalogo): build release por feature set + `esptool elf2image`.
Totais medidos (`.bin`) sao autoritativos; custos por capability sao estimativas.

| Preset | Features | Bin (medido) | SHA256 (catalogo) | Factory 2 MB |
|---|---|---|---|---|
| full | `board-devkitc` (default) | 1902288 B | `747691BC...F86F40` | nao cabe |
| fido-only | `board-devkitc,cap-fido-only` | 1128144 B | `36CA330D...D188AE` | cabe (meta 1400000 B) |
| fido-totp | `board-devkitc,cap-fido-totp` | 1251632 B | `55AC03BC...0AE9FD` | cabe |

Placas no catalogo:

| Placa | Chip | Flash | Particao factory | Particao storage |
|---|---|---|---|---|
| devkitc | esp32s3 | 2097152 B | 1572864 B | 458752 B (`partitions-2m.csv`) |
| tdisplay | esp32s3 | 16777216 B | 3145728 B | 917504 B (`partitions.csv`) |
| ttgo-classic | esp32 | 4194304 B | 3145728 B | 917504 B (`partitions.csv`) |

## 2. Matriz por preset

`X` = incluido, `-` = excluido (responde `0x06` quando aplicavel).

| Capability | full | fido-only | fido-totp |
|---|:---:|:---:|:---:|
| ctap-makecred (CTAP2 MakeCredential) | X | X | X |
| ctap-getassert (CTAP2 GetAssertion) | X | X | X |
| ctap-clientpin (CTAP2 ClientPIN/UV) | X | X | X |
| ccid (transporte smartcard USB) | X | X | X |
| piv (applet slots 9A/9C/9D/9E) | X | X | X |
| openpgp (applet) | X | X | X |
| oath-totp (TOTP RFC 6238, CALCULATE no device) | X | - | X |
| oath-hotp (contador + resync, `oath6ctr/`) | X | - | X |
| otp-challenge-response (via path HOTP) | X | - | X |
| wallet (addr/sign, sessao RAM) | X | - | - |
| vault (itens cifrados `vault/` + quota) | X | - | - |
| ble (GATT proxy CTAP + vendor ops) | X | - | - |
| wifi-sntp (AP/station + SNTP + mDNS) | X | - | - |
| display (controladores + jornada UI) | X | - | - |
| proximity (beacon `0xFFFE` rolling-code) | X | - | - |
| vendor-mgmt (keys/OATH ops, console serial) | X | X | X |
| debug-terminal (linhas lifetime) | X | - | - |
| test-hooks (serial `TEST_*`) | X | - | - |

Notas:

- `ctap-*` compartilham o grupo `ctap-core`; custo contado no grupo, sem soma.
- `oath-hotp` e `otp-challenge-response` nao tem modulo proprio: usam o
  dispatcher HOTP de `oath_cmd.rs` + `oath_store.rs` (custo no grupo oath).
- Dieta `fido-only`: OATH responde `0x06`; `totp_view` mostra `NO_ACCOUNTS`.
- Dieta recusa por `compile_error`: `wifi`, display boards, `proximity`,
  `debug-terminal`, `test-mode` com `cap-*`.
- `devkitc` usa stub headless de display em todos os presets.

## 3. Opcodes vendor

Faixas (fontes: `vendor_caps.rs`, `ble/gatt_core.rs`, `ota.rs`, `fw_log.rs`,
`pairing.rs`, `ctap_cmd.rs`, `vendor_keys.rs`, `pm_store.rs`, `ble/oob.rs`).

| Opcode | Nome | Presets | Observacao |
|---|---|---|---|
| 0x20 | KEY_GEN_ONDEVICE | todos | chaves vendor |
| 0x21 | KEY_IMPORT_ENVELOPE | todos | envelope |
| 0x22 | KEY_LIST | todos | lista (resposta com `alg` real) |
| 0x23 | KEY_DELETE | todos | apaga slot |
| 0x24 | OATH_PUT | full, fido-totp | `0x06` em fido-only |
| 0x25 | OATH_LIST | full, fido-totp | `0x06` em fido-only |
| 0x26 | OATH_CODE / CALCULATE | full, fido-totp | `0x06` em fido-only |
| 0x27 | OATH_DELETE | full, fido-totp | `0x06` em fido-only |
| 0x28 | BIND_CLAIM | todos | gestao de vinculo |
| 0x29 | BIND_CHALLENGE | todos | gestao de vinculo |
| 0x2A | BIND_VERIFY | todos | gestao de vinculo |
| 0x2B | BIND_RELEASE | todos | gestao de vinculo |
| 0x2C | RECOVERY_SET | todos | recuperacao |
| 0x2D | RECOVERY_UNLOCK | todos | recuperacao |
| 0x2E | rescue (somente payload OP_MSG) | - | nunca opcode de fragmento |
| 0x2F | HOST_PAIRING_OPEN | - | trigger de pairing, nunca reusavel |
| 0x30 | OTA_BEGIN | full (via vendor-mgmt/OTA) | dieta: sem radio/suporte |
| 0x31 | OTA_CHUNK | full | idem |
| 0x32 | OTA_FINISH | full | idem |
| 0x33 | OTA_COMMIT | full | idem |
| 0x34 | OTA_ABORT | full | idem |
| 0x35 | WALLET_GEN (congelado) | full | `0x06` nas dietas |
| 0x36 | WALLET_LIST (congelado) | full | `0x06` nas dietas |
| 0x37 | WALLET_ADDR (congelado) | full | `0x06` nas dietas |
| 0x38 | FW_LOG | todos | read-only, mesma classe de visibilidade de `0x3F` |
| 0x39 | PIV_ENROLL | todos | fora da faixa 0x20-0x27 por desenho |
| 0x3A | SECURE_GUARD_STATUS | todos | Secure Guard |
| 0x3B | SECURE_GUARD_UNLOCK | todos | Secure Guard |
| 0x3C | SECURE_GUARD_LOCK | todos | Secure Guard |
| 0x3D | SECURE_GUARD_CONFIG | todos | Secure Guard |
| 0x3E | SECURE_GUARD_WIPE_SELECTIVE | todos | Secure Guard |
| 0x3F | GET_CAPS | todos | read-only, sem auth; payload nao-vazio nega `0x04` |
| 0x40 | SET_UP_POLICY | todos | funnel-routed |
| 0x41 | VENDOR_SIGN (SIGN dedicado) | todos | classe GEN sem PIN: binding -> UP; TLV `TAG_SLOT 0x01` + `TAG_CHALLENGE 0x74` |
| 0x42 | BLE_OOB (somente serial/USB) | full | dieta: radio inerte |
| 0x43 | PM_PUT | firmware (`pm_store.rs`) | gerenciador local |
| 0x44 | PM_GET | firmware (`pm_store.rs`) | gerenciador local |
| 0x45 | PM_LIST | firmware (`pm_store.rs`) | gerenciador local |
| 0x46 | PM_DELETE | firmware (`pm_store.rs`) | gerenciador local |
| 0x47 | PM_STATUS | firmware (`pm_store.rs`) | gerenciador local |
| 0x48 | WALLET_DERIVE (compat) | full | reserva; sem execucao |
| 0x49 | WALLET_XPUB (compat) | full | reserva; sem execucao |
| 0x4A | WALLET_PSBT (compat) | full | aprovacao mediada + PIN |
| 0x4B | WALLET_PENDING (preview) | full | expoe preview |

Contagem `unsupported_count` do `GET_CAPS`:

| Preset | `unsupported_count` | Opcodes contados |
|---|---|---|
| full | 0 | - |
| fido-only | 11 | 0x24, 0x25, 0x26, 0x27, 0x35, 0x36, 0x37, 0x48, 0x49, 0x4A, 0x4B |
| fido-totp | 7 | 0x35, 0x36, 0x37, 0x48, 0x49, 0x4A, 0x4B |

Resposta `GET_CAPS`: status `0x00` + mapa CBOR com `fw_version` (versao do
crate), `preset` (`full` / `fido-only` / `fido-totp`), `caps` (exatamente
`presets.<preset>.includes` do catalogo, mesma ordem) e `unsupported_count`.

## 4. Curvas e algoritmos

Curvas suportadas (fonte: `crates/aegis-fido-core/src/crypto/curves.rs`,
`cose.rs`):

| Algoritmo COSE | Curva | Uso |
|---|---|---|
| ES256 (-7) | P-256 | FIDO2, binding (verify P-256, SEC1 65B) |
| ES384 (-35) | P-384 | credenciais FIDO2 / smartcard |
| ES512 (-36) | P-521 | credenciais FIDO2 / smartcard |
| ES256K (-47) | secp256k1 | carteira (BTC/EVM), xpub niveis 44/84 |
| EdDSA (-8) | Ed25519 | credenciais, enderecos da rede Ed25519 |

Simétricos/hash: AES-256-GCM (envelope, vault, sementes), SHA-256
(PIN/PUK com sal, fingerprint de semente), HMAC-SHA1 (camada compativel
challenge-response, relatorio de 8 B). RSA para PIV/smartcard
(`crypto_rsa.rs`, atribuido a capability `piv`).

## 5. Transportes

| Transporte | Presets | Notas |
|---|---|---|
| USB CTAPHID (CTAP2) | todos | MakeCredential/GetAssertion/ClientPIN sempre ativos |
| USB CCID (APDU CLA/INS/P1/P2) | todos | namespace separado do vendor; serve PIV/OpenPGP |
| USB serial CMD_MSG + console texto | todos | `vendor-mgmt`; `0x3F`/`0x38` sem auth |
| BLE GATT (proxy CTAP + funis vendor) | full | dieta: stub fail-closed, sem advertising; reassembler aceita `0x3F`/`0x41` |
| WiFi AP/station + SNTP + mDNS | full | dieta: stubs fail-closed; SNTP e opcional para OATH (ancora NVS + hora do host cobrem) |
| Display fisico | full (tdisplay/ttgo-classic) | devkitc usa stub headless |

## 6. Recursos

- NVS cifrada (`SecureStorage`, envelope): binding (`app_bind_pub` 65B SEC1 +
  `app_bind_id` 16B), slots de credencial/chaves, OATH, vault, WiFi, ancora de
  tempo TOTP, contadores anti-rollback.
- BLE: 1 vinculo max (`BLE_NIMBLE_MAX_BONDS=1`), flag em RAM, idade max 30 dias.
- Display: controladores + jornada UI no full; stub headless no devkitc.
- LED: sinalizacao de presença/estado via `DisplayManager`/stub por placa
  (sem opcode vendor proprio).
- Bancada: leitura `GET_CAPS 0x3F` somente leitura usada como sonda de
  capacidade (ver `reports/status/index.html`).
- OTA: `0x30-0x34` (begin/chunk/finish/commit/abort), chunks de 8 KiB,
  orcamento 917504 B; no layout 2 MB (storage 458752 B) deve transmitir em
  fluxo, sem estagiar imagem cheia.
- PM (gerenciador local): `0x43-0x47` (put/get/list/delete/status),
  implementado em `pm_store.rs`.
- PIV: slots 9A/9C/9D/9E, todos os presets (via CCID).
- OATH: TOTP + HOTP + challenge-response via path HOTP (resync forward-only);
  full e fido-totp.
- Wallet: addr/sign com sessao em RAM; `0x35-0x37` congelados e `0x48-0x4B`
  reserva somente no full.

## 7. Limites

| Pool (NVS) | Limite | Observacao |
|---|---|---|
| `cred/` + `cred/index` (residenciais FIDO2) | 32 slots x 1024 B (total est. 35000 B) | `CRED_MAX_SLOTS=32`, `CRED_SLOT_MAX_BYTES=1024` |
| `oath6/` (blobs OATH) | 64 slots x 512 B (total est. 33000 B) | TLV total <= 512 B, sem indice de quota |
| `oath6ctr/` (contadores HOTP) | blobs 8 B, rotulo <= 64 (total est. 5000 B) | proximo-contador big-endian |
| `vault/` + `vault/index` | padrao 32 slots x 512 B, teto 64 (total est. 18000 B) | quota via `vault/index` cifrado |
| `key_slots_v1` + `keys6/` (carteira) | <= 32 slots (total est. 8000 B) | sessao em RAM; NVS como etapa seguinte |
| `sg_record_v1` (SecureGuard) | 1 registro (512 B) | sempre residente |
| bonding BLE (store do controlador) | 1 vinculo (2048 B) | sempre via BLE quando presente |
| WiFi (`wifi_sta_ssid`, `wifi_sta_pass`, `wifi_ap_pass`) | 3 chaves (total est. 512 B) | full apenas |
| binding (`app_bind_pub`, `app_bind_id`) | 2 chaves (total est. 128 B) | sempre residente |
| OTA staging (`ota_staging`, `ota_stage_len`, `ota_c*`, `ota_manifest`, `ota_committed`) | chunks 8 KiB, orcamento 917504 B (transiente, nao soma no residente) | 2 MB: fluxo; 16 MB: cabe |
| Orcamento NVS layout 2 MB | 458752 B (`storage @0x190000 len 0x070000`) | devkitc |
| Orcamento NVS layout 16 MB | 917504 B (`storage @0x310000 len 0x0e0000`) | demais placas |
