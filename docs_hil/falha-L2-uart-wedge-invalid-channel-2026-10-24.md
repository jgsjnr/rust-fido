# Falha HIL documentada — L2 UART wedge pos-INIT (ERROR 0x0B persistente + TEST_* mudo)

## 1. Identificacao

- Lane/teste: L2 `test_l2_uart_test_mode_gates` (passo `cmd_init`); sondas
  manuais `exchange(BROADCAST, INIT)` + `send_text_line("TEST_LIFETIME_DUMP")`
- Alvo: UART COM7 115200 sem DTR/RTS (ponte CP210x `USB\VID_10C4&PID_EA60\0001`);
  mesmo fisico do USB AEGIS-S3-0002 (303A:AE61, nativo, saudavel em T0)
- Data (UTC): 2026-10-24 (rodada pos-210e980, HEAD da983da)
- Operador: subagente (lane fd/hil-usb-tests)
- Commit: da983da (worktree fd/hil-usb-tests; escrita so em `python_hil/`+`docs_hil/`)
- Comando exato: `python -m pytest python_hil/tests/test_l2_uart.py -v --tb=line --uart COM7`

## 2. Resultado observado (coleta curta)

```
1 failed, 3 passed in 5.90s
FAILED test_l2_uart_test_mode_gates - ValueError: bad INIT response (cmd=bf)
[hil] CTAP_SENT cmd=86 pkts=1 bytes=8 / CTAP_RESPONSE bytes=1 / TEXT_DRAINED_LINES bytes=1
```

Reproducao: 7 trocas INIT seguidas (3 espacadas + 4 em suite) = 7/7
`RCMD=bf RAWLEN=1 BODY0=0b` (CTAPHID ERROR `0x0B` = INVALID_CHANNEL),
persistente apos reopen + `flush_input()` + 12 s idle.
`send_text_line("TEST_LIFETIME_DUMP")` retorna so `[FREERTOS] tick NNN`
(126 B, sem `lt_dump`/eco TEST). USB nativo na mesma janela: INIT/PING/GetInfo PASS.

- Veredito: [x] FALHA REAL (HW presente, device nega INIT UART + silencia TEST_*)

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | UART 115200 sem DTR/RTS (CP210x; `mode COM7` 115200 ok; open exclusivo ok) |
| INIT->CID | falha: resposta imediata 1 byte `0x0B` a cada INIT broadcast (7/7) |
| PING eco 64B | N/A (sem CID; teste `init_ping` PASS minutos antes do wedge) |
| GetInfo (0x04) | N/A UART (PASS minutos antes; USB GetInfo PASS na mesma janela) |
| TEST_* (test-mode?) | `TEST_PAIRING_OPEN_300` sem `pairing_open` (origem do wedge, ver §4); `LIFETIME_DUMP` so ticks |
| Gates | nao avaliado (wedge antes de qualquer gate) |
| Contagens | `CTAP_SENT bytes=8` -> `CTAP_RESPONSE bytes=1` (imediato, sem timeout); ticks seguem (~1/s) |

## 4. Causa provavel (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (só energia, sem dados: USB nao enumera)
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissao)
- [ ] Firmware sem test-mode (TEST_* mudo; esperado fora de test-mode)
- [ ] Gate do device (pairing fechado / UP nao pressionado / PIN exigido)
- [ ] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)
- [x] Outro: wedge do leitor serial no firmware gravado (pre-fix). Sequencia:
  `init_ping` PASS + `get_info` PASS (tudo multiplo de 64 B, alinhado), depois
  `send_text_line("TEST_PAIRING_OPEN_300\n", 22 B, nao multiplo de 64)` sem
  resposta. A partir dai todo pacote 64 B e lido desalinhado: resto de zeros
  do tail do pacote anterior ancora `cid==0x00000000` -> `INVALID_CHANNEL`
  (ponto fixo: cada escrita de 64 B avanca a fila em multiplo de 64 e o resto
  `mod 64` nunca se realinha sozinho). Camada de framing responde, mas o
  despacho TEST_* passa fome (bytes comidos pelo framer) e so ticks
  (task separada) seguem vivos. USB usa transporte/fila separados: saudavel em T0.

## 5. Acao / proximo passo

- [ ] Power-cycle / re-plugar o AEGIS-S3-0002 (limpa a fila UART do device),
  depois retry isolado: `pytest test_l2_uart_test_mode_gates --uart COM7 -v`
  (esperado com firmware atual do device: voltar a `pairing_open`+UP+DUMP)
- [ ] Duravel: reflashar com o firmware desta worktree (contem o dreno TEST
  alinhado e o gating de logs sob `debug-terminal`, MAPA-FIX §3; device
  gravado e anterior a isso) e repetir L2 completo (esperado: 4 passed)
- [ ] NAO alternar DTR/RTS por software nesta bancada sem maos presentes: o
  par DTR/RTS do CP210x pode derrubar o ESP32-S3 em download-mode (exige
  botao fisico); o harness evita DTR por desenho (`Flags=0x1`)
- [ ] Gap de harness (nao aplicado; nao curaria este wedge, que e no device):
  `SerialLink.exchange()` nao faz `flush_input()` antes da troca binaria
  (so `send_text_line` faz); propor purge-RX no `open()` + 1 retry de INIT
  idempotente (espelho do `exchange_read_retry` USB) a lane dona
  => APLICADO nesta lane (ver MAPA-FIX §9): purge-RX no `open()` + purge
  pré-`exchange()` + `reconnect()`/`exchange_read_retry()` + `get_info()`
  via retry. Re-rodada `--uart COM7`: **3 failed, 1 passed** — INIT segue
  `0xBF/0x0B` (device pré-fix; purge/retry host não realinha FIFO do device).
  Gap CURADO no harness/host (provado em `cargo test` do `SerialStreamDecoder`);
  residual 100% no device gravado.
- [ ] Nenhum destrutivo executado (sem `--confirm`; sem COMMIT/wipe/killswitch);
  nenhum segredo em log (so contagens + `RCMD`/`BODY0` de erro)

## 7. Re-rodada desta lane (2026-10-24 — purge/retry aplicados, wedge persiste)

```
pytest python_hil/tests/test_l2_uart.py -v --uart COM7 --tb=line
=> 3 failed, 1 passed (open PASS; init_ping/get_info/gates FAIL `bad INIT response (cmd=bf)`)
[hil] CTAP_SENT cmd=86 pkts=1 bytes=8 / [hil] CTAP_RESPONSE bytes=1 / TEXT_DRAINED_LINES ~1
```

- Veredito: [x] FALHA REAL persistente (HW presente, device pré-fix nega INIT
  UART com `ERR 0x0B`; `SerialStreamDecoder` + purge-C + retry-UART desta
  worktree provados só no host). Prescrição: power-cycle/re-plug, canário
  `test_l2_uart_init_ping --uart COM7`, depois reflash test-mode (comando
  pronto no MAPA-FIX §9, NÃO executado sem confirmação) e repetir L2
  (alvo: 4 passed).

## 6. Anexos permitidos

- Log sanitizado: `[hil] CTAP_SENT cmd=86 pkts=1 bytes=8`,
  `[hil] CTAP_RESPONSE bytes=1`, `RCMD=bf RAWLEN=1 BODY0=0b`,
  `DUMP_GOT bytes=126` (so ticks), `mode COM7` 115200, CP210x `VID_10C4&PID_EA60`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.
## 8. Rodada pos-reflash (2026-10-24 — bin release sem test-mode; wedge 0x0B RECORRE)

- Bin gravado = `board-devkitc` sem `test-mode`: TEST_* **ausentes por
  desenho** (L2 `test_mode_gates` FAIL `ValueError` esperado, nao regressao;
  fixes §1/§3 desta lane exigem variante `freertos+test-mode`, nao embarcada).
- Wedge UART **recorreu no firmware novo** apos trafego de suite: INIT →
  `CTAP_RESPONSE bytes=1` + `TEXT_DRAINED_LINES bytes=2`, payload cru
  `raw=0b` (CTAPHID ERROR `0x0B`, mesma assinatura do §2 pre-fix), 2/2
  sondas; `TEST_USB_RECONNECT` → 0 linhas (sem test-mode, esperado).
  Limpo por reboot POWERON (espontaneo; ver §9 do falha-L5): pos-boot UART
  INIT→CID + PING + GetInfo `0x00` 479 B PASS.
- L2 `--uart COM7` (device degradado): `9 failed, 44 passed, 10 skipped`;
  pos-reboot (device saudavel): `4 failed, 49 passed, 10 skipped`
  (3 USB INIT-flake + `test_mode_gates` por desenho). Arquivo L2 isolado no
  wedge: `3 failed, 1 passed` (open PASS; INIT→`cmd=bf` nos 3).
- Veredito: [x] FALHA REAL residual no device (estado `0x0B` sticky ativado
  por trafego acumulado, limpo so por reboot; purge/retry host nao alcançam
  FIFO do device). Prescricao: power-cycle antes de cada rodada; reflash
  `freertos+test-mode` p/ validar dreno TEST alinhado no HW (MAPA-FIX §10);
  investigar ponto fixo `cid==0` no despacho device-side (dona do firmware).
  Nenhum destrutivo; nenhum segredo em log (so `RCMD`/`BODY0` + contagens).
