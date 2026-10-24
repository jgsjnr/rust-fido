# Falha HIL documentada — L2 LED residual pós-MAPA-FIX (firmware do device pré-fix)

## 1. Identificação

- Lane/teste: L2 `test_l2_uart_test_mode_gates` (passo `test_led_state("ON")`)
- Alvo: UART COM7 115200 sem DTR/RTS (CP210x); device com firmware anterior ao MAPA-FIX
- Data (UTC): 2026-10-24 (pós-fix, rodada de verificação)
- Operador: hil-subagent (lane fd/hil-usb-tests)
- Commit base: 2c3dcad + MAPA-FIX (worktree; `crates/...` modificado, device NÃO reflasheado)
- Comando exato: `python -m pytest python_hil/tests/test_l2_uart.py --uart COM7 --tb=line -q`

## 2. Resultado observado (coleta curta)

```
2 runs: (a) 2 failed, 2 passed — init_ping TimeoutError (COM7 flaky) + gates LED;
        (b) 1 failed, 3 passed — init_ping/get_info/open PASS, só LED FAIL.
[hil] CID_ALLOCATED + TEXT_DRAINED_LINES ~1 (framing curado, estável)
[hil] TEST_PAIRING_OPEN bytes=34/35 + TEST_UP bytes=10 (OK)
link_serial.py:452: ValueError: device nao confirmou LED (firmware test-mode?)
```

- Veredito: [x] FALHA REAL (HW presente, device com firmware pré-fix: `TEST_LED_ON`
  ainda cai em `UnknownTest` no firmware gravado; esperado até o reflash)

## 3. Evidência sem segredo (obrigatório)

| Campo | Valor |
|---|---|
| Transporte | UART 115200 sem DTR/RTS |
| INIT→CID | ok (CID alocado; `TEXT_DRAINED_LINES` ~1) |
| PING eco 64B | flaky 1x TimeoutError, PASS no retry (COM7 disputa — ver §4) |
| GetInfo (0x04) | PASS |
| TEST_* (test-mode?) | PAIRING_OPEN_300 OK, TEST_UP OK, LED_ON sem resposta |
| Gates | pairing/UP OK; LED não é gate |
| Contagens | PAIRING bytes=34/35, UP bytes=10, LED 0 bytes úteis |

## 4. Causa provável (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (só energia, sem dados: USB não enumera)
- [ ] Outro: porta ocupada por outro processo
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissão)
- [x] Firmware sem test-mode (parcial: device gravado é pré-MAPA-FIX;
  `TEST_LED_ON` sem hook no firmware gravado; host já prova o alias novo)
- [ ] Gate do device (pairing fechado / UP não pressionado / PIN exigido)
- [ ] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)

## 5. Ação / próximo passo

- [ ] Reflashar o AEGIS-S3 com o firmware desta worktree (`test-mode`, sem
  `OTA-COMMIT`) e repetir `pytest --uart COM7` (esperado: 4 passed)
- [ ] COM7 flaky (init_ping 1x TimeoutError, retry PASS): fechar poller
  concorrente; hint já adicionado em `SerialLink.open()`
- [x] Host prova o fix sem HW: `cargo test -p aegis-fido-firmware`
  (476 passed, inclui `classifica_todas_do_manifesto_sem_json` com `TEST_LED_ON`)
  + `cargo test -p aegis-fido-usb` (novo `test_broadcast_init_clears_stale_assembly`)

## 6. Anexos permitidos

- Log sanitizado: `[hil] CID_ALLOCATED`, `TEST_PAIRING_OPEN bytes=35`,
  `TEST_UP bytes=10`, `ValueError: device nao confirmou LED`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.
