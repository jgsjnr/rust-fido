# App Binding — dono exclusivo de BLE vendor + WiFi mgmt

Implementacao: `crates/aegis-fido-firmware/src/binding.rs`
(`BindingManager`, `ClaimState`, `NEED_BINDING 0x05`),
`crates/aegis-fido-firmware/src/recovery.rs` (PIN 4-6, 8 tentativas NVS),
`crates/aegis-fido-firmware/src/ble_gatt.rs` (despacho 0x28-0x2D + split),
fiação minima em `crates/aegis-fido-firmware/src/main.rs` (`binding_mgr.tick`).
Contrato BLE §9 intacto + apendice §11; este doc cobre vinculo + recovery
(aditivo, sem quebra). USB/CTAP zero mudanca e sempre livre.

## Por que existe

FIDO2 USB continua 100% aberto (qualquer host usa passkeys sem vinculo).
Ja as operacoes de **gerencia** (chaves device, OATH, WiFi) passam a exigir
um **dono**: o app pareado na primeira configuracao. Outro app, mesmo
pareado no BLE, recebe `NEED_BINDING (0x05)` e nada muda no device.
USO (o que ja esta dentro: CODE/LIST, GetAssertion, display TOTP) nunca
exige vinculo (senao keypass nao funciona).

## Split uso/config (normativo, §11.2)

| Caminho | Release (feature OFF) | Teste (`test-mode` ON) |
|---------|----------------------|------------------------|
| USO: `0x22`/`0x25`/`0x26` (LIST/CODE), `0x83` MSG GetAssertion, `GET /oath/code`, display | so UP | so UP |
| CONFIG: `0x20` GEN, `0x21`/`0x23`/`0x24`/`0x27` (IMPORT/DELETE/PUT), `POST /config/wifi`, `/wifi/creds`, `0x28-0x2B` | vinculo+UP(+PIN) | UP(+PIN) com bypass+ltrace |
| USB/CTAP (FIDO2, ClientPIN, reset) | **nunca** vinculo | **nunca** vinculo |

Ordem canonica: binding -> UP -> PIN (app alheio sempre ve NEED_BINDING
primeiro). `vendor_op_requires_pin`: `0x21/0x23/0x24/0x27` exigem PIN.

## Bypass test-mode (normativo, §11.3)

Com `test-mode` ON, `binding_bypass_enabled()==true`: gates CONFIG ignoram
`binding_ok` com `ltrace!(Transport, TpOpen, "binding-bypass")` (cripto
app/chave DESABILITADA em teste). Release = vinculo OBRIGATORIO para
CONFIGURAR. USO nunca e afetado. Cripto `verify` segue valida nos dois modos.

## Jornada de claim (primeira configuracao)

1. Segure BOOT 5s (`LONG_PRESS_MS`) ate entrar em pareamento (janela 60s).
2. Complete o bonding BLE (JustWorks+bonding+UP, como antes).
3. O app gera (ou abre do Keystore) sua chave P-256 e um `binding_id`
   opaco de 16B, e envia `0x28 CLAIM(app_pub SEC1 65B || binding_id 16B)`.
4. O firmware aceita **somente se**: sem dono + janela aberta + UP +
   pubkey valida (ponto P-256). Grava em NVS cifrada:
   `app_bind_pub` (65B) + `app_bind_id` (16B), envelope AEGN v1,
   verify-after-write.
5. Segundo claim (qualquer chave) = `AlreadyClaimed` (dono preservado).
6. Defina o PIN de recovery via `0x2C RECOVERY_SET(pin 4-6)` com UP
   (sobrescreve anterior; novo dono deve definir outro apos re-claim).

## Operacao normal (challenge por op)

Cada op CONFIG usa **um challenge novo** (anti-replay):

1. App pede `0x29 CHALLENGE` -> 32B via TRNG (invalida o anterior).
2. App calcula `payload_hash = SHA-256(payload)` e assina
   `challenge || op || payload_hash` com a chave do app (Keystore,
   nunca sai do celular; DER ou raw).
3. Firmware roda `verify` (dono -> uso-unico -> challenge -> assinatura).
   Sucesso **consome** o challenge; replay do sucesso = `Replay -> 0x05`.
4. Gates na ordem canonica **binding -> UP -> PIN**. Em teste o app pode
   pular 1-3 (bypass); em release e obrigatorio.

## GATT binding mgmt (0x28-0x2D, §11.1)

Framing §3: `[op, len_hi, len_lo, payload...]`. Resposta:
`[op, status, payload...]` (status §9.5+0x05).

| Op | Req | Resp | Gate |
|----|-----|------|------|
| `0x28` CLAIM | 81B | `binding_id` echo | Unclaimed+pareamento+UP |
| `0x29` CHALLENGE | 0B | 32B | Claimed |
| `0x2A` VERIFY | `op\|\|ch\|\|ph\|\|sig` | vazio | Claimed+prova (helper) |
| `0x2B` RELEASE | `ch\|\|ph\|\|sig` (`op=0x52`, `ph=SHA256(id)`) | vazio (wipe) | Claimed+prova+UP (teste: so UP) |
| `0x2C` RECOVERY_SET | `pin` 4-6 | vazio | UP |
| `0x2D` RECOVERY_UNLOCK | `pin` 4-6 | vazio (wipe vinculo) | UP+PIN (8 tentativas) |

## Recovery PIN (perdeu o celular, §11.4)

- `0x2C SET(pin)` com UP: valida 4-6 digitos, gera salt 16B TRNG, grava
  `rec_pin_hash` (SHA-256(salt||pin)) + `rec_pin_salt` + `rec_pin_retries=8`.
  Segredo nunca sai (so hash+salt; PIN nunca logado).
- `0x2D UNLOCK(pin)` com UP: verifica no device (tempo constante); sucesso
  reseta para 8 + `binding.wipe` (volta a Unclaimed, libera re-claim);
  falha decrementa na NVS; 0 restantes => `Locked` (so `factory_reset`
  fisico hold 5s+UP recupera). PIN preservado ate ser sobrescrito.
- `verify` sem UP nega sem consumir tentativa; `Locked` nega mesmo com PIN
  certo; status: `UP->0x01`, `BadPin/Locked->0x02`, resto `->0x04` (nunca `0x05`).

## Transferencia para outro celular (release + reclaim)

1. Dono atual pede challenge, assina `challenge || 0x52 || SHA-256(binding_id)`
   (`BIND_OP_RELEASE`) e chama `0x2B RELEASE` (ou `release_signed`).
2. Firmware verifica e faz **wipe**: apaga `app_bind_pub`/`app_bind_id`,
   zera a RAM (zeroize) e volta a `Unclaimed`.
3. Novo celular faz `0x28 CLAIM` normalmente (janela de pareamento + UP)
   + `0x2C SET` com novo PIN.

Sem a chave do dono nao ha transferencia por software (so recovery PIN+UP
ou reset fisico).

## Reset fisico de fabrica (perdeu tudo)

Segure BOOT 5s + UP (`factory_reset`): wipe total do vinculo, sem
assinatura, com reclaim liberado. **Nao toca em eFuse, nao liga secure
boot nem flash encryption** (proibido; `scripts/ci-guard-secureboot.ps1`
da FAIL se qualquer token nessa direcao aparecer).

## Fiação main (minima)

`main.rs` instancia `BindingManager::load_from_storage(&storage)` no boot
(`Claimed` preservado; `Corrupted` loga e inicia `Unclaimed` com aviso;
`factory_reset` recupera) e alimenta `binding_mgr.tick(now_ms)` todo poll
(hoje no-op de uso unico; reserva expiracao futura sem quebrar API).
USB/CTAP intocavel (bloco `CMD_CBOR/CMD_MSG` inalterado).

## O que um app alheio ve

- Qualquer op CONFIG sem prova valida: `NEED_BINDING (0x05)`.
  (`0x00-0x04` do §9.5 preservados; `0x05` e a unica adicao, so BLE/WiFi.)
- No WiFi mgmt (HTTP): `403 NEED_BINDING` (`WIFI_NEED_BINDING_CODE`).
- FIDO2 USB: funciona normal, sem erro e sem vinculo.
- NVS parcial (queda de energia no meio do `persist`): boot carrega
  `Corrupted` (nunca `Unclaimed` silencioso — bloqueia reclaim hostil);
  o reset fisico recupera.

## NVS (aditivo a `docs/nvs_schema.md`)

| Chave | Conteudo | Gate |
|-------|----------|------|
| `app_bind_pub` | SEC1 65B do app dono | claim (Unclaimed+pareamento+UP) |
| `app_bind_id` | id opaco 16B | claim (eco) |
| `rec_pin_hash` | SHA-256(salt\|\|pin) 32B | `0x2C` com UP (segredo nunca sai) |
| `rec_pin_salt` | salt 16B TRNG | `0x2C` com UP |
| `rec_pin_retries` | restantes 1B (inicia 8) | `0x2D` decrementa; `Locked` em 0 |

Envelope inalterado (AEGN v1, TRNG interno, zeroize). mDNS/AP/BLE seguem
`docs/ble-protocol.md` §1-§11.
