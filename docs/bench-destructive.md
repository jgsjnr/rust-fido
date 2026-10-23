# Plano de testes DESTRUTIVOS — ESP32-S3 (COM13), variante freertos+proximity

> LAB-ONLY, sem secure boot. Autorizado: este plano executa `erase_flash`
> (apaga TUDO: credenciais, PIN, NVS, bonding) + reflash + fábrica +
> wipe. Sem segredo em log/foto/arquivo (`K_prox`, PIN, semente nunca
> colados neste roteiro depois de usados; `K_prox` só via
> `--k-prox-hex` / env `FIDO_PROX_KEY_HEX` na linha de comando local).
> Referência não-destrutiva: `docs/bench-freertos-s3.md` (COM7 no texto
> original; aqui a porta autorizada é **COM13**).

Variante sob teste: `crates/aegis-fido-firmware`, features
`board-devkitc,freertos,proximity`, target `xtensa-esp32s3-espidf`
(build por `scripts/build-freertos-s3.ps1` → bin
`aegis-app-freertos-s3.bin`). Ferramentas citadas abaixo foram
verificadas em `scripts/` e `tools/` neste worktree — nenhum comando
foi inventado; o que não existe como script está marcado como tal.

Gate antes de tocar no hardware (nada destrutivo sem isto verde):

```powershell
.\scripts\env-check.ps1
cargo test -p aegis-fido-firmware --features freertos,proximity
cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity -- -D warnings
python tools/host/win/proximity_agent.py --self-test
```

---

## Etapa 1 — `erase_flash` completo + reflash limpo (COM13)

Comandos (esptool saído de `scripts/common.ps1` —
`Initialize-EspEnvironment`: `C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts\esptool.exe`
ou fallback `python -m esptool`):

```powershell
# 1a. Apaga TUDO (DESTRUTIVO — sem volta)
python -m esptool --chip esp32s3 --port COM13 --baud 921600 --before default_reset --after hard-reset erase_flash
# 1b. Reflash limpo no offset de fábrica (DESTRUTIVO — regrava app)
python -m esptool --chip esp32s3 --port COM13 --baud 921600 --before default_reset --after hard-reset write_flash 0x10000 C:\t\aegis-app-freertos-s3.bin
```

Equivalente via wrapper do repo (usa `scripts/common.ps1`
`Invoke-FirmwareFlash`: offset padrão `0x10000`, `--after hard-reset`,
retry 921600→115200; **diferença documentada**: o wrapper entra com
`--before no-reset` via `TEST_DOWNLOAD` por software e só cai no
fallback manual BOOT+EN se o app não responder — o comando bruto acima
usa o `--before default_reset` autorizado para este plano):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3.ps1
.\scripts\flash.ps1 -BinPath C:\t\aegis-app-freertos-s3.bin -Chip esp32s3 -Port COM13 -Baud 921600 -Monitor
# fallback manual se TEST_DOWNLOAD não responder: segurar BOOT, apertar+soltar EN,
# continuar segurando BOOT e teclar ENTER; se a placa não bootar sozinha, apertar EN.
```

Estado esperado: esptool exit 0, `Hash of data verified`, tamanho ≤
teto factory (`Get-FactoryMaxSize` lê `crates/aegis-fido-firmware/partitions.csv`;
artefato validado por `Test-FirmwareArtifact`, que gera o `.sha256`
sidecar). Placa boota sozinha (`Hard resetting via RTS pin`) e o monitor
mostra `[FREERTOS] AegisKey FreeRTOS variant booting` + linha
`boot tasks=<N> stack_high_water=<B>B core=<C>` sem `TWDT`/`panic`.

Anotar: comando exato + baud efetiva, `Wrote N bytes`, `Hash of data
verified`, `Get-FileHash -Algorithm SHA256` do bin + sidecar `.sha256`,
porta (COM13), AAGUID/serial iniciais (se já visíveis), ATR na porta
nativa. Guardar transcript em `esptool-flash-<data>.log`.

---

## Etapa 2 — Fluxo de fábrica via `tools/factory_provision.py`

O que a ferramenta faz (lido do cabeçalho/`argparse` reais do script):
plano de identidade por unidade — AAGUID/serial (nunca reutilizar),
**BLOCK7 master key (32 B TRNG) + BLOCK8 salt (32 B TRNG)** via
`secrets`, layout dual-slot NVS
(`slot_a`/`slot_b`/`cred_backup` + `verify-after-write`), readback
SHA256 para auditoria. Flags reais: `--serial` (formato
`AEGIS-S3-*`), `--aaguid` (32 hex, senão TRNG), `--slot-a/--slot-b`,
`--dry-run`, `--confirm`, `--port`, `--ota-pubkey` (128 hex = chave
pública **release ed25519**), `--emit-registry` (só fingerprints, nunca
chaves cruas).

```powershell
# 2a. Plano (não toca hardware) — obrigatório primeiro
python tools/factory_provision.py --serial AEGIS-S3-00AF --dry-run
# 2b. Burn real (eFuse é irreversível; exige --confirm + --port)
python tools/factory_provision.py --serial AEGIS-S3-00AF --slot-a cred_slot_a --confirm --port COM13 --emit-registry
```

Precisão honesta sobre o provisionamento pedido: (a) **master key
eFuse + salt** = `factory_provision.py` (BLOCK7/BLOCK8, acima);
(b) **release key** = `--ota-pubkey` do mesmo script (pubkey ed25519 de
OTA, só fingerprint no log); (c) **K_prox NÃO é provisionado por este
script** — `K_prox` (AES-128 em NVS `prox_k`, `zeroize`) nasce por
`rekey` no pareamento (`src/proximity.rs`, `src/main.rs`) e trafega via
`--k-prox-hex`/`FIDO_PROX_KEY_HEX` no agente host
(`tools/host/win/proximity_agent.py`). Limite conhecido: o burn real
hoje **aborta com exit 4** (`NOT IMPLEMENTED ... requires factory jig +
HSM`) — anota-se o `[PLAN]` + `plan_sha256` e o ponto de parada.

Estado esperado: `--dry-run` exit 0 com `[PLAN] serial/aaguid/slots`,
`master_sha256`, `salt_sha256`, `plan_sha256`,
`efuse: BLOCK7=master BLOCK8=salt (write-once, verify-after-write)`;
nenhum segredo cru no log (só sha256). No `--confirm`, registra-se a
saída `[BURN]`/abort como evidência do estado da wave.

Anotar: serial, AAGUID (o da etiqueta/registro, não a chave),
`plan_sha256`, `master_sha256`, `salt_sha256`, fingerprints da release
key (`--emit-registry`), exit codes, contadores de tentativa.

---

## Etapa 3 — Geração de chaves nos 5 algoritmos COSE via cerimônia WebAuthn (`tools/server.py` em `localhost:8888`)

Alvos (valores de `crates/aegis-fido-core/src/crypto/cose.rs`):
**-7 ES256, -35 ES384, -36 ES512, -47 ES256K, -8 EdDSA**.
Cerimônia base (script real, 100% stdlib, porta 8888, serve `web/`):

```powershell
python tools/server.py   # http://localhost:8888
python tools/test_aegiskey_rust.py   # sanidade 8/8 sem hardware (CTAPHID/CCID/YKOATH/WinUSB + GET /api/status, register options rp.id localhost, residentKey required, credentials, PIN status)
```

Limite documentado do `server.py`: `pubKeyCredParams` expõe só
`-7/-8/-257`; portanto cobertura total dos 5 COSE exige o conjunto:
navegador em `http://localhost:8888` (MC+GA com S3 na porta nativa,
tocar BOOT/GPIO0 no pedido de presença; referência serial anterior:
MC ~740 B, GA ~170 B — `docs/teste-ponta-a-ponta.md`) +
`tools/usb_webauthn_test.html` (MC `alg: -7` + GA via USB) +
`tools/validate_aegiskey.py` (requer `pip install fido2`; cobre
CTAPHID direto, GetInfo, ClientPIN, MakeCredential residente com UP,
GetAssertion com verificação P-256) + `cargo test` (curvas
ES384/ES512/ES256K/EdDSA em `aegis-fido-core`, ex.
`crypto::curves`/`crypto::keys`).

Estado esperado: VID `0x303A` PID `0xAE61` (`src/identity.rs`)
enumerado, Problem 0; `test_aegiskey_rust.py` 8/8; 1 credencial por
algoritmo criada e asserção (GA) OK com UP físico.

Anotar por algoritmo: rpId (`localhost`), user, `credential.id`,
bytes MC/GA, UP usado (sim/não), AAGUID retornado, `signCount`
inicial, log do `server.py` + saída do `test_aegiskey_rust`.

---

## Etapa 4 — OATH PUT/CALCULATE/DELETE, wallet gen/addr, vault export/import

Operador serial real: `tools/e2e_user_test.py` (uma sessão serial por
rodada — abrir a porta reseta a placa e mata a janela; fase
destrutiva exige `--confirm`, RELEASE/wipe pede digitar `SIM`).
Mapa op (espelho frozen em `app_simulator.py`/`e2e_user_test.py`):
`OATH_PUT 0x24`, `OATH_LIST 0x25`, `OATH_CODE 0x26` (= CALCULATE),
`OATH_DELETE 0x27`, `WALLET_GEN 0x35`, `WALLET_LIST 0x36`,
`WALLET_ADDR 0x37`, `FW_LOG 0x38`; TLV `0x71` nome / `0x73` segredo.

```powershell
# 4a. OATH no modo seguro (gates UP+PIN; sem PIN espera-se 0x02)
python tools/e2e_user_test.py --phase pairing      # T15 OATH_PUT sem PIN -> 0x02; T16 OATH_CODE conta vazia -> NoSlot 0x03
# 4b. OATH destrutivo (muda estado; PUT HOTP/TOTP real -> 0x00, CODE TOTP bate conta local, HOTP avança contador)
python tools/e2e_user_test.py --phase destructive --confirm   # T15b/T15c PUT, T16b CODE, D02 OATH_DELETE pede PIN, D02b DELETE com sessão PIN executa 0x00
# 4c. Wallet (WALLET_GEN BTC com UP -> 0x00 + addr bc1...; LIST responde; ADDR bate GEN; rede inválida -> 0x04)
python tools/e2e_user_test.py --phase pairing      # T19 WALLET_GEN, T20 WALLET_LIST, T21 WALLET_ADDR, T22 rede inválida
# 4d. Vault export/import NÃO tem comando serial neste worktree: cobertura é host-side
cargo test -p aegis-fido-core wallet
cargo test -p aegis-fido-core vault
# (WalletStore::export_routing/import_routing round-trip + AegisVault seal/open; ver crates/aegis-fido-core/src/wallet/store.rs e src/vault/mod.rs)
```

Estado esperado: PUT real `0x00`; CALCULATE (`OATH_CODE`) retorna
código que bate a conta local (TOTP) / contador avança (HOTP);
DELETE com sessão PIN `0x00`; `WALLET_GEN` BTC `0x00` com endereço
`bc1...` e `WALLET_ADDR == WALLET_GEN`; rede inválida `0x04`;
`cargo test` wallet+vault verdes.

Anotar: slots usados (ex. `E2E_SLOT_WALLET = 6`), labels/contas
(`e2e-t1`, `e2e@test`), códigos **apenas** (nunca segredos),
`export_routing` bytes (roteamento, não chaves), `FW_LOG op 0x38`
(`EV_BOOT` marca o zero; anel em RAM — coletar antes de qualquer
reset), status hex de cada teste (T15/T15b/T15c/T16/T16b/T19/T20/T21/T22/D02/D02b).

---

## Etapa 5 — Wipe via `authenticatorReset` (janela 10 s + UP GPIO0) e verificação de limpeza

Contrato (prova host em `crates/aegis-fido-core/tests/ctap_tests.rs`
`test_authenticator_reset`): `CTAP_CMD_RESET (0x07)` dentro de
**10 s** do boot **com UP** → `CTAP1_ERR_SUCCESS`; após 10 s →
`CTAP2_ERR_NOT_ALLOWED`; sem toque → `CTAP2_ERR_OPERATION_DENIED`.
No hardware, UP = botão físico BOOT em **GPIO0** (active-low,
`src/button.rs`); o wipe E2E do repo passa por `BIND_RELEASE`
(test-mode, só UP) / `RECOVERY_UNLOCK` (PIN+UP) — ambos zeram o
binding (`K_prox` zerado, `prox erase`).

```powershell
# 5a. Reset CTAP dentro da janela: energizar a S3, em < 10 s tocar+segurar BOOT (GPIO0) e emitir CTAP RESET
python tools/validate_aegiskey.py   # caminho interativo CTAPHID (requer admin p/ CTAPHID direto; seguir prompt de toque no BOOT)
# alternativa raw pela sessão serial (vide tools/app_simulator.py Session/CTAP_CMD_*):
python tools/e2e_user_test.py --phase wipe --confirm   # ciclo claim -> release -> re-claim -> unlock (D05b/D07/D07b = prova do wipe)
# 5b. Verificação de limpeza (credMgmt sub 0x01 = SUBCMD_GET_CREDS_METADATA, crates/aegis-fido-core/src/ctap/cred_mgmt.rs; PIN retries sub 0x01 de ClientPIN)
python tools/live_monitor.py --port COM13 --log monitor-poswipe.log
python tools/usb_diag.py            # enumerar VID 0x303A:0xAE61 pós-wipe (se existir neste worktree; senão Gerenciador de Dispositivos, Problem 0)
```

Estado esperado do wipe: RESET in-window+UP `0x00`; RESET tardio
`NotAllowed`; RESET sem UP `OperationDenied`. Verificação de limpeza:
`getCredsMetadata` com `existingResidentCredentialsCount == 0`
(máximo restaurado), `getPinRetries`/`getPinUvAuthToken` mostra **PIN
zerado** (sem PIN definido — `setPIN` volta a ser permitido),
`OATH_CODE`/`WALLET_LIST` vazios (`NoSlot`), `K_prox` ausente
(`[PROX] sem K_prox fail-closed` no boot), fw-log reiniciado em
`EV_BOOT`.

Anotar: `t_boot → t_reset` (s), UP pressionado (sim/não + duração),
código de retorno por caso (janela/sem-UP/tardio), `getCredsMetadata`
completo, retries de PIN, AAGUID pós-wipe, ATR pós-wipe, logs
`monitor-poswipe.log` / `fw-log.txt` (coletar antes de resetar de novo).

---

## Etapa 6 — Re-provisionamento e estado final esperado

```powershell
# 6a. Fábrica de novo (mesmo serial? NÃO reutilizar AAGUID — gerar novo TRNG)
python tools/factory_provision.py --serial AEGIS-S3-00AF --dry-run
python tools/factory_provision.py --serial AEGIS-S3-00AF --confirm --port COM13 --emit-registry
# 6b. Re-bond proximity (hold BOOT 5 s -> LED azul + janela 60 s; parear no SO; agente lock-only)
python tools/host/win/proximity_agent.py --fob-id <MAC-BONDED> --k-prox-hex <K_PROX> --lock-secs 10 --poll-secs 2
# 6c. Sanidade final não-destrutiva
python tools/test_aegiskey_rust.py
.\scripts\env-check.ps1
python tools/live_monitor.py --port COM13 --log monitor-final.log
```

Estado final esperado: placa provisionada (BLOCK7/BLOCK8 + dual-slot
NVS + sha256 auditados), exatamente **1 credencial de fumaça**
pós-reprovisionamento (ou zero, se a política for estoque zerado —
decidir e anotar), PIN definido com 8 retries, `K_prox` bonded,
`test_aegiskey_rust.py` 8/8, LED idle ciano, sem `TWDT`/`panic` em
≥ 90 s de monitor, 9 artefatos de log arquivados sem segredos
(flash/monitor-boot/`lt-boot.log`/`fw-log.txt`/test/server/agente +
`criterios-<data>.md` com PASS/FAIL por etapa).

Anotar: novo AAGUID, `plan_sha256` do re-provisionamento, MAC bonded,
par RSSI/histerese medido (-75/5 dB ou novo par com motivo),
`Get-FileHash` final, decisão estoque (0 ou 1 credencial) + motivo.

---

## Reajustes candidatos

*(a preencher com o resultado — vazio até a execução.)*
