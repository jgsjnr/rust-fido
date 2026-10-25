# Falha HIL documentada — L2 LED regressão ON→RED + latch FreeRTOS (fix host-provádo)

## 1. Identificação

- Lane/teste: L2 `test_l2_uart_test_mode_gates` (passo `test_led_state("ON")`) + inspeção `led_probe.py`
- Alvo: firmware worktree (host) + UART COM7 115200 sem DTR/RTS (device AEGIS-S3-0002, bin pré-fix)
- Data (UTC): 2026-10-24
- Operador: hil-subagent (lane fd/hil-usb-tests)
- Commit base: da983da (+ correções LED desta rodada, worktree; device NÃO reflasheado)
- Comando exato: `cargo test -p aegis-fido-firmware --features test-mode --lib` (prova host)

## 2. Resultado observado (coleta curta)

```
cores do LED mudaram + flickering; bluetooth/heartbeat/boot amarelo/pareamento piores
diff 210e980..HEAD: TEST_LED_ON alias→RED (mod.rs + freertos), latch led_test_hold,
  gating [FREERTOS] sob debug-terminal; legado: ON→RED (não-commitado)
host pós-fix: 504 passed, 0 failed (test-mode) / 484 passed (default) / clippy zero warnings
```

- Veredito: [x] FALHA REAL (lógica de firmware provada no host; device segue pré-fix, sem reflash)

## 3. Evidência sem segredo (obrigatório)

| Campo | Valor |
|---|---|
| Transporte | host (cargo test) + UART 115200 sem DTR/RTS (device pré-fix, sem reflash) |
| INIT→CID | N/A nesta ficha (foco LED; ver falha-L2-wedge / falha-L5) |
| PING eco 64B | N/A |
| GetInfo (0x04) | N/A |
| TEST_* (test-mode?) | `TEST_LED_ON`→`led_set TEST_LED_ON` ack-only pós-fix (antes: latch RED); `TEST_LED_STATE` inalterado |
| Gates | LED não é gate (ver `tools/host_sdk/gates.py`: binding→UP→PIN) |
| Contagens | host: 504 lib passed; device: 0 sondagens nesta rodada (sem aprovação p/ UART/flash) |

## 4. Causa provável (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (só energia, sem dados: USB não enumera)
- [ ] Outro: porta ocupada por outro processo
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissão)
- [x] Firmware sem test-mode (parcial: device gravado é pré-fix; worktree prova o fix no host)
- [ ] Gate do device (pairing fechado / UP não pressionado / PIN exigido)
- [ ] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)

Causa raiz (3 itens, ver MAPA-FIX §11): (1) `TEST_LED_ON` aliado a `Solid RED`
nos dois loops — HIL envia ON após PAIRING_OPEN+UP sem RELEASE, deixando
vermelho residual sobre o azul do pairing e o âmbar do UP; (2) bloco
device-side no FreeRTOS forçando `led_test_hold` (contra o contrato "só ack",
`run/mod.rs` + `docs/test-hooks.md`): RED cobria boot-rainbow, UP-Prompt,
sucesso, erro e TOTP; (3) latch legado reaplicado incondicional todo poll, sem
expiração (flicker entre escritores + máscara da jornada).

## 5. Ação / próximo passo

- [x] Fix aplicado na worktree (test-mode only, sem destrutivos): ON=ack-only nos
  dois loops; latch FreeRTOS removido; latch legado só no idle livre + expiração
  60 s + liberação em `TEST_PAIRING_CLOSE`; classificador puro com testes host
- [ ] Reflashar o AEGIS-S3 com `freertos+test-mode` desta worktree (com autorização)
  + power-cycle, e repetir `pytest --uart COM7` (alvo: 4 passed) — ver prescrição §11
- [ ] `led_probe.py` visual (olhos): RED/GREEN/BLUE/OFF sólidos 2 s + RELEASE
- [x] Host prova o fix: `cargo test -p aegis-fido-firmware --features test-mode`
  (504 passed, inclui 4 novos `test_led_line_*` + ON em `led_responde_*_sem_latch`)

## 6. Anexos permitidos

- Log sanitizado: `test result: ok. 504 passed; 0 failed` + `clippy Finished` zero warnings.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.

## 7. Re-teste pos-reflash `freertos+test-mode` (2026-10-24 - CURADO ack-level, visual residual)

- Bin reflasheado: `aegis-app-freertos-s3-testmode.bin` 2.011.696 B
  (`E9ACDA95...`; proveniencia `da983da1`); flash COM7 OK 18 s hash ok.
- `TEST_LED_ON` -> `led_set TEST_LED_ON` **só ack, sem cor, sem latch RED**
  (antes: latch RED + reaplicacao FreeRTOS). R/G/B/OFF: ack `led_set` cada.
  `TEST_LED_STATE`: `screen=freertos pairing=PairingBle up_pending=0`.
  L2 `test_mode_gates`: **PASS** (era o passo FAIL desta ficha).
- Veredito: [x] CURADO no device em nivel de protocolo/ack.
- Residual: cores fisicas por estado (boot/heartbeat/BLE/pairing/UP) seguem
  **REAL_IMPLEMENTED_NOT_RUN** - sem observador diante do LED nesta sessao;
  `tools/led_probe.py` (RED/GREEN/BLUE/OFF solidos 2 s + RELEASE) pendente
  de olhos do usuario. Wedge MSG sob trafego acumulado documentado no
  MAPA-FIX p.12.5 (fora do escopo LED; reboot limpa).
## Verificacao 2026-10-24 1830 bin 923FCC86: TEST_LED_ON ack led sem latch (PingAck); sem residual via ack textual; cores fisicas REAL_IMPLEMENTED_NOT_RUN (sem observador).
