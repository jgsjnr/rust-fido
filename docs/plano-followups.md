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

### F3. Persistir `pin_hash` + retries no NVS [P] — FEITO 20/10, no ar
**Problema**: `pin_state` só RAM → reboot pede setPIN de novo (`0x35`).
**Escopo**: salvar `pin_hash`, `pin_retries`, `power_cycle_state` no NVS
(backend pronto) nos pontos onde mudam; carregar no boot.
**Prova viva 20/10**: setPIN → EN → token `0x00` (era `0x35`); retries 8.
**Aceite**: setPIN → EN → token funciona; retries sobrevivem.
**Risco**: baixo (NVS já provado). Pré-req: nenhum (independente de F1).

### F4. CCID/PIV no USB [G] — CÓDIGO PRONTO 20/10, PROVA HW PENDENTE
**Problema**: OpenSC não vê cartão (USB vivo = só HID; CCID/PIV só
existiam como crates sem driver).
**Feito (host verde: usb 72 + firmware 250, clippy zero, release clean)**:
- C: `ccid_device.c` (class driver CCID via hook `usbd_app_driver_get_cb`,
  bulk OUT/IN + notify, remontagem de frames) + descritor composto
  (HID intacto em 1º, CCID classe 0x0B em 2º) + FFI
  (`aegis_ccid_pop_frame/send/is_mounted`).
- Rust: `CcidTransport::process_ccid_message_store` (applet persiste no
  transporte entre frames; OATH/FIDO=CCID fora do v1 = `6D 00` honesto) +
  `ccid_dispatch.rs` (NVS+KeyManager reais; GEN/AUTH P-256 reais fim-a-fim
  em teste) + poll no loop USB + op enrollment `0x39` (binding→UP, sem PIN;
  BLE+serial; `pin_len||pin(6-8)||puk(8)`).
**Falta (HW)**: flashar, plugar o USB nativo e `opensc-tool -l` + VERIFY +
GEN/AUTH reais. Control class-specific dá stall (v1: OpenSC só precisa do
bulk + enumeração).
**Auditoria CCID/OpenSC (explorer, 20/10)**: descritor byte-a-byte OK vs
CCID 1.1 (única divergência formal: só T=1, aceitável p/ PIV); gap crítico
achado e CORRIGIDO: `SetParameters(0x61)`/`ResetParameters(0x6D)` agora
ecoam os parâmetros T=1 (com `dwFeatures=0` o host manda `0x61` explícito no
caminho feliz). Stall em Abort só afeta cancel/timeout. ATR estático pode
cair em minidriver genérico no Windows (não impede bind).
**Aceite**: `opensc-tool -l` lista AegisKey; VERIFY + SIGN funcionam.
**Risco**: médio (primeira enumeração composta; HID intacto por construção).
**Follow-up app**: tela de enrollment 0x39 no Android.

### F5. OTA staging + COMMIT [M] — CÓDIGO PRONTO, LAB TRAVADO
**Problema**: OTA só existe na seção USB; staging grande no NVS e swap
de partição são follow-up; COMMIT jamais automático.
**Feito**: staging chunked 8 KiB (partição `storage` 896 KB) + serial OTA
+ chave lab + e2e D08 (bad-sig nega, BEGIN+CHUNKs+FINISH verify,
COMMIT∓UP/COMMIT+UP marker, ABORT); host 242 verdes.
**Trava**: BEGIN válido reboota a placa (só ele; GEN/NVS ok; idle 5 min
estável). Suspeitas: NVS-cheio/corrompido ou energia. Próximo passo:
diagnosticar com build limpo + partição zerada.
**20/10 noite (causa raiz REAL)**: NÃO era energia — captura do boot mostra
`hci inits failed` → retry a cada poll reinicializava o NimBLE por cima →
`Malloc failed` → `BLE assert emi.c:164` → panic Interrupt WDT. Fix: gate
`BleStartGate` (backoff 5s, 3 por borda, igual ao WiFi) + `aegis_ble_preinit`
no boot (heap fresco) + heap livre no log de falha. Fonte nova fez bem de
qualquer forma (margem p/ spikes de rádio/flash).
**Firmware inocentado no ciclo bad-sig manual (BEGIN 0x00 → CHUNK ack →
FINISH 0x04).**
**Nota de swap**: partição única (sem ota_*) → COMMIT grava só marker;
swap real = fábrica (reparticionar).

### F6. Processo: merge + UX hold [P]
- PR `fd/finalizacao-linux` → `main` após F1–F3 verdes no hardware.
- Decisão hold-gesture (colide com pairing?) antes de F2 mexer em UX.

## Fora de escopo
Killswitch real (jig+HSM), factory_reset físico, eFuse burn,
secure-boot (OFF por decisão humana).
