# Falha HIL documentada - L2 UART COM7 acesso negado

## 1. Identificacao

- Lane/teste: L2 `test_l2_uart_*` (4 testes: open_no_dtr_reset, init_ping, get_info_base, test_mode_gates)
- Alvo: UART COM7 115200 sem DTR/RTS (Silicon Labs CP210x USB to UART Bridge, USB\VID_10C4&PID_EA60\0001)
- Data (UTC): 2026-10-24
- Operador: hil-subagent
- Commit: 2ae4d18 (worktree fd/hil-usb-tests; `python_hil/`+`docs_hil/` untracked)
- Comando exato: `python -m pytest python_hil/tests/test_l2_uart.py -v --uart COM7 --tb=short`

## 2. Resultado observado (coleta curta)

```
python_hil/tests/test_l2_uart.py::test_l2_uart_open_no_dtr_reset FAILED
python_hil/tests/test_l2_uart.py::test_l2_uart_init_ping FAILED
python_hil/tests/test_l2_uart.py::test_l2_uart_get_info_base FAILED
python_hil/tests/test_l2_uart.py::test_l2_uart_test_mode_gates FAILED
E python_hil.link_serial.HwMissingError: uart COM7 inacessivel: GetCommState failed
4 failed in 0.13s
Checagem cruzada pyserial: SerialException: could not open port 'COM7':
PermissionError(13, 'Acesso negado.', None, 5); `mode COM7`: dispositivo nao disponivel.
```

- Veredito: [x] FALHA REAL (HW presente, porta negou acesso: ocupada por outro processo) / nao e ausencia de HW

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | UART 115200 sem DTR/RTS (CreateFileW `\\.\COM7`, share 0) |
| INIT->CID | N/A (falhou no open, antes de qualquer troca CTAPHID) |
| PING eco 64B | N/A |
| GetInfo (0x04) | N/A |
| TEST_* (test-mode?) | N/A (botoes autonomos nao sondados: sem serial nao ha path TEST_*; USB HID nao fala TEST_*) |
| Gates | N/A (porta nunca abriu) |
| Contagens | pkts=0 bytes=0 (nenhum byte trafegado; nenhuma escrita antes do open) |

## 4. Causa provavel (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (so energia, sem dados: USB nao enumera)
- [x] Outro: porta ocupada por outro processo (acesso negado WinError 5; driver OK no Gerenciador: Status OK, CP210x COM7 presente; WMI lista COM7, `mode` diz indisponivel)
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissao)
- [ ] Firmware sem test-mode (TEST_* mudo; esperado fora de test-mode)
- [ ] Gate do device (pairing fechado / UP nao pressionado / PIN exigido)
- [ ] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)

## 5. Acao / proximo passo

- [ ] Liberar COM7 (fechar monitor serial/Renode/outro holder) e re-rodar `pytest python_hil/tests/test_l2_uart.py -v --uart COM7`
- [ ] Se persistir: checar holder via Gerenciador de Tarefas/Resource Monitor (sem matar processo alheio nesta lane); re-conectar o cabo dados
- [ ] So entao sondar TEST_UP/PAIRING_OPEN_300/LED/LIFETIME_DUMP (exigem test-mode; release mudo = esperado)

## 6. Anexos permitidos

- Log sanitizado: `[HwMissingError] uart COM7 inacessivel: GetCommState failed`; PnP `Status=OK Class=Ports FriendlyName=Silicon Labs CP210x USB to UART Bridge (COM7)`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII - nenhum coletado (falha pre-troca).

## 7. Retentativa 2026-10-24 17:05 UTC (porta liberou; novo modo de falha: framing)

- Diagnostico: `Get-CimInstance Win32_SerialPort` lista COM7 `Status=OK`
  (CP210x); `mode COM7` OK (antes: indisponivel); `handle.exe COM7` =
  `No matching handles found`; abertura exclusiva pyserial OK; re-enumeracao
  pyserial: COM7+COM3+COM4 presentes. Holder anterior era transitorio
  (posteriormente a porta voltou a negar acesso 2x de forma intermitente
  durante sondagens pyserial, liberando em seguida — poller periodico de
  outro processo disputando COM7).
- Re-run: `python -m pytest python_hil/tests/test_l2_uart.py -v --uart COM7`
  => `1 passed, 3 failed`: `test_l2_uart_open_no_dtr_reset` PASS;
  `init_ping`, `get_info_base`, `test_mode_gates` FAIL com
  `ValueError: unexpected continuation` (link_serial.py:131).
- Causa raiz (nova, eletrica OK): o firmware multiplexa logs `[FREERTOS] ...`
  sem alinhamento a 64 B antes de cada resposta CTAPHID, ex.:
  `[FREERTOS] ctaphid resp (1 pkt, origem=Some(Serial)).\r\n` + pacote INIT
  (capturado em janela crua). `exchange()` le janelas fixas de 64 B e
  `is_text_chunk` exige 64/64 imprimiveis — janela mista log+binario nao e
  texto nem INIT => `ValueError`. Mesmo com `flush_input()` antes do INIT a
  falha persiste (tick `tick NNN` a cada ~1 s cai na janela da resposta).
- Prova eletrica com resync manual (linha-ate-`\n` + 64 B, so leitura):
  INIT->CID `0x00000003` nonce-eco OK; PING eco `a5 5a 00 ff` OK (2x, com
  `ctaphid resp` logado pelo firmware). Device saudavel; falha e 100%
  framing do harness, nao do device.
- TEST_* (metodos existentes, sem escrita destrutiva): PAIRING_OPEN_300 OK
  (12 B); TEST_UP OK (101 B, `paring=Arming`); LIFETIME_DUMP OK (363 B,
  contadores zerados, `uptime_s=73`, `lt_end` presente — cabecalho veio
  colado `FREERTOS]lt_dump v=1`, `parse_dump` exigiria `lt_dump v=1` puro);
  LED_STATE ON sem resposta (`TEST_LED_ON/TEST_LED_STATE ON/=ON` retornam
  so `tick NNN` — hook LED ausente neste firmware).
- Proximo passo: resync com leitura de linhas no `exchange()` do harness
  (drenar ate `\n` antes de cada pacote 64 B) — mudanca de `python_hil/`,
  fora do escopo desta rodada de sondagem; sem alteracao de codigo feita.

## 8. Retentativa 2026-10-24 pos-fix (rebase 2c3dcad + resync no harness)

- Rebase: `fd/hil-usb-tests` sobre `fd/finalizacao-linux` (2c3dcad, pairing
  no TEST_UP) OK, sem conflito (worktree so tinha `python_hil/`+`docs_hil/`
  untracked; nenhum arquivo rastreado tocado).
- Fix (`python_hil/link_serial.py`, sem DTR/RTS, teto 7609B mantidos):
  `exchange()` agora le via `_read_framed_packet()` — drena linhas texto
  `\r\n` ([FREERTOS]/TEST_*/tick/lt_/pairing/up_latched/led/ctaphid) antes
  de cada janela 64B; resync em INIT (`>IBH`, total>0, CID broadcast p/
  INIT) e CONT (seq sem 0x80 + CID da sessao); janela mista tem o prefixo
  texto descartado 1 B por vez ate marcador valido; janela so-texto e
  drenada. Guards criticos: so drena linha com `\r\n` + texto (0x0A solto
  do payload binario nao quebra o pacote) e INIT com mesmo CID no meio da
  montagem e tratado como falso-positivo (1 B), nao como resync.
- Re-run: `pytest python_hil/tests/test_l2_uart.py -v --uart COM7`
  => `3 passed, 1 failed`: `open_no_dtr_reset`, `init_ping`, `get_info_base`
  PASS (framing 100% curado; `TEXT_DRAINED_LINES` ~1 por troca, INIT->CID +
  PING eco + GetInfo OK); `test_mode_gates` FAIL so no passo LED
  (`TEST_PAIRING_OPEN` 34-36 B OK, `TEST_UP` ~99-103 B OK,
  `test_led_state("ON")` sem eco — hook LED ausente neste firmware, mesma
  conclusao da secao 7: `TEST_LED_ON/TEST_LED_STATE` retornam so `tick`).
- Veredito framing: [x] CURADO no harness. Residual: [x] FALHA REAL de
  firmware (hook TEST_LED_* ausente) — fora do escopo do harness; teste
  mantido como esta (nao enfraquecido); proximo passo e expor o hook LED
  no firmware test-mode ou aceitar SKIP condicional nesse passo.
