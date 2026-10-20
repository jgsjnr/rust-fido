# Plano follow-ups firmware — escopo, ordem e aceite

Origem: gaps mapeados pelo e2e (`docs/teste-ponta-a-ponta.md`). Nada aqui
mexe em envelope AEGN, eFuse (sem burn) ou secure-boot (sempre OFF).
Test-mode continua gated (`docs/test-hooks.md` + release-clean).

## Ordem (dependências primeiro)

### F1. Plumbing de PIN nas ops vendor [M] — FEITO 20/10, no ar
**Problema**: `main.rs` (BLE) e `serial_ctaphid` passam
`pin_authenticated = false` fixo → IMPORT/DELETE/PUT sempre `0x02`,
mesmo com sessão PIN viva. O app bate nisso nas telas de gerenciar.
**Escopo**: plugar `pin_state.has_valid_pin_uv_session()` nos dois
dispatchs + teste host (sessão viva → gate passa; sem sessão → `0x02`) +
e2e T15/D01/D02 reais com PIN.
**Aceite**: PUT com PIN `0x00`; sem PIN `0x02`; release-clean verde.
**Risco**: baixo (só leitura de estado existente).
**Prova viva**: D01b/D02b `0x04` com sessão (era `0x02`); D01/D02 sem
sessão seguem `0x02`. PUT segue `0x04` (executor é F2).

### F2. Executor vendor keys/OATH on-device [G] — FEITO 20/10, no ar
**Problema**: `0x20–0x27` validam gates e respondem `0x04` — nada é
salvo; `oath_applet` criado e nunca usado; app mostra listas vazias.
**Escopo**: ligar `KeyManager`/`OathApplet` (+ NVS, já persistente) no
dispatch BLE+serial com os mesmos gates; LIST retorna real; GEN/DELETE
persistem; CODE calcula no device. Requer F1 pronto (PUT/DELETE são PIN).
**Aceite**: ciclo GEN→LIST→CODE→DELETE real + NVS pós-EN + roundtrips host.
**Prova viva 20/10**: wipe 23/23 (TOTP `154903` bate conta local, HOTP
avança), slot 5 + CODE lidos pós-EN. App: VaultScreen envia challenge
0x74 (APK rebuildado). IMPORT fica `0x04` (envelope+vault = F2b).

### F3. Persistir `pin_hash` + retries no NVS [P]
**Problema**: `pin_state` só RAM → reboot pede setPIN de novo (`0x35`).
**Escopo**: salvar `pin_hash`, `pin_retries`, `power_cycle_state` no NVS
(backend pronto) nos pontos onde mudam; carregar no boot.
**Aceite**: setPIN → EN → token funciona; retries sobrevivem.
**Risco**: baixo (NVS já provado). Pré-req: nenhum (independente de F1).

### F4. CCID/PIV no USB [G]
**Problema**: OpenSC não vê cartão (USB vivo = só HID; CCID/PIV só
existem como crates desligados).
**Escopo**: driver CCID no TinyUSB (C, bulk IN/OUT + interrupt),
dispatch APDU→`PivApplet`, expor interface no config descriptor,
`opensc-tool`/`pkcs11-tool` fim-a-fim (slots 9A/9C/9D/9E, PIN/PUK).
**Aceite**: `opensc-tool -l` lista AegisKey; VERIFY + SIGN funcionam.
**Risco**: médio (C + spec PIV; sem impacto no HID existente).

### F5. OTA staging + COMMIT [M, NUNCA sem confirmação]
**Problema**: OTA só existe na seção USB; staging grande no NVS e swap
de partição são follow-up; COMMIT jamais automático.
**Escopo**: chunk staging limitado ao blob NVS + validação de manifesto
Ed25519 + COMMIT atrás de UP (e de confirmação explícita no script).
**Aceite**: BEGIN→CHUNKs→FINISH validados; COMMIT só com `--confirm-commit`.
**Risco**: alto (brick); testar com rollback + release intocado de backup.

### F6. Processo: merge + UX hold [P]
- PR `fd/finalizacao-linux` → `main` após F1–F3 verdes no hardware.
- Decisão hold-gesture (colide com pairing?) antes de F2 mexer em UX.

## Fora de escopo
Killswitch real (jig+HSM), factory_reset físico, eFuse burn,
secure-boot (OFF por decisão humana).
