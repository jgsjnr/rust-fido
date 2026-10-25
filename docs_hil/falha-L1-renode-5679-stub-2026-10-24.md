# Falha HIL documentada - L1 Renode :5679 (stub RiscV32 não executa bin Xtensa)

## 1. Identificacao

- Lane/teste: L1 `test_l1_tcp_live_needs_sim` + `sim_pilot --tcp 127.0.0.1:5679`
- Alvo: sim Renode `fido-s3-v3` adaptado p/ porta alternativa
  (UART TCP 127.0.0.1:5679, monitor :1240; :5678 do `host_hardware_android_bridge.py` intocado)
- Data (UTC): 2026-10-24 23:10–23:35
- Operador: hil-subagent
- Commit: `da983da` (worktree fido-hil)
- Comandos exatos:
  - `renode.exe --disable-gui --plain -P 1240` + `include @C:\t\fido-s3-v3-5679.resc` + `start`
  - `python -m python_hil.sim_pilot --tcp 127.0.0.1:5679` (rc=3)
  - `python -m pytest python_hil/tests/test_l1_sim.py -v --tcp 127.0.0.1:5679`
- COM7: **jamais aberta nesta lane** (proibido; nenhum handle serial criado;
  somente TCP + monitor telnet :1240; `list_serial_holder` nunca chamado).

## 2. Resultado observado (coleta curta)

```
[hil] BOOT_CHECK online=0 active=0 bytes=0
PILOT HW-ONLY (falha real documentada): boot-check falhou (sem ONLINE&ACTIVE; trocar bin/.resc?)

python_hil/tests/test_l1_sim.py::test_l1_framing_roundtrip_offline PASSED [ 16%]
python_hil/tests/test_l1_sim.py::test_l1_text_chunk_never_masks_ctap PASSED [ 33%]
python_hil/tests/test_l1_sim.py::test_l1_dump_parser_offline PASSED      [ 50%]
python_hil/tests/test_l1_sim.py::test_l1_ble_frag_offline PASSED         [ 66%]
python_hil/tests/test_l1_sim.py::test_l1_pilot_selftest_loopback PASSED  [ 83%]
python_hil/tests/test_l1_sim.py::test_l1_tcp_live_needs_sim SKIPPED      [100%]
======================== 5 passed, 1 skipped in 1.06s ==========================
SKIPPED [1] ...:78: sim inativo em 127.0.0.1:5679 (HW-ONLY): boot-check falhou
  (sem ONLINE&ACTIVE; trocar bin/.resc?)
```

- Renode subiu? **SIM** (v1.17.0, PID proprio, monitor :1240, UART :5679 LISTENING, `start` ok).
- boot-check? **FALHOU** (`online=0 active=0 bytes=0`, ~1 s ate EOF).
- INIT->CID / PING? **N/A** (sem boot, sem troca CTAPHID).
- Botoes (BOOT/RESET via monitor)? `gpio OnGPIO 0 true/false` executados sem erro;
  UART seguiu vazia (`DumpHistoryBuffer` = 0 entradas) — sem caminho firmware p/ reagir.
- Veredito: [x] SKIP HONESTO (sim nao executa este bin) / nao e ausencia de teste

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | TCP 127.0.0.1:5679 (ServerSocketTerminal raw, `telnetMode=false`) + monitor :1240 |
| INIT->CID | N/A (sem boot, sem troca CTAPHID) |
| PING eco 64B | N/A |
| GetInfo (0x04) | N/A |
| TEST_* (test-mode?) | N/A (bin test-mode presente, mas nunca executado) |
| Gates | N/A (CPU abort antes de qualquer gate) |
| Contagens | `LoadBinary` 2013168 bytes @0x0; boot rx bytes=0; UART hist=0; CPU abort PC=0x1000 |

Log Renode (sanitizado, sem segredo):

```
[INFO] System bus created.
[INFO] sysbus: Loading block of 2013168 bytes length at 0x0.
[WARNING] sysbus: Tried to access bytes at non-existing peripheral in range <0x00000000, 0x001EB7EF>.
[INFO] Machine started.
[WARNING] sysbus: [cpu: 0x1000] ReadByte from non existing peripheral at 0x1000.
[ERROR] cpu: CPU abort [PC=0x1000]: Trying to execute code outside RAM or ROM at 0x00001000.
[ERROR] This machine has aborted. Emulation cannot continue until this machine is removed.
```

## 4. Causa provavel (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (so energia, sem dados: USB nao enumera)
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissao)
- [ ] Firmware sem test-mode (TEST_* mudo; esperado fora de test-mode)
- [ ] Gate do device (pairing fechado / UP nao pressionado / PIN exigido)
- [x] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)
- [x] Outro: plataforma stub sem RAM/ROM mapeada + CPU RiscV32 incapaz de
  executar bin Xtensa ESP32-S3 (vetor reset 0x1000 cai no vazio -> abort);
  `.resc`/`.repl` originais usam tipos inexistentes no Renode 1.17.0
  (`UART.LiteUART`, `I2C.I2CBus`, `I2C.DummyI2CSlave`, `GPIOPort.MockGPIOPort`)
  e comando inexistente (`sysbus LoadBIN`; correto: `sysbus LoadBinary`) —
  ou seja, o firmware **nunca foi carregado nem executado** em nenhuma
  tentativa anterior com este sim.

## 5. Veredito SIM-COVERED vs HW-ONLY por item

| Item | Veredito | Motivo (1 linha) |
|---|---|---|
| framing CTAPHID 64B / INIT / PING / dump / TEST_UP (camada) | SIM-COVERED (loopback) | `test_l1_pilot_selftest_loopback` PASSED — prova a camada, rotulado LOOPBACK, nao e HW |
| boot-check ONLINE&ACTIVE no sim | HW-ONLY | bytes=0; CPU abort PC=0x1000, maquina pausada |
| INIT->CID / PING eco no sim | HW-ONLY | sem boot, sem troca CTAPHID |
| TEST_* / GetInfo / gates no sim | HW-ONLY | firmware test-mode nunca executado no stub |
| Botoes BOOT/RESET no sim | HW-ONLY | `OnGPIO` aceito pelo stub, sem efeito observavel (sem firmware rodando; sem botao mapeado no repl) |
| Aceite em dispositivo fisico | HW-ONLY (pendente) | builds/trafego simulado/portas/screenshots/emuladores/handshakes nao sao aceite fisico |

## 6. O que o stub RiscV32 modela / NAO modela (via monitor+logs)

Modela (topologia validavel): `CPU.RiscV32` (rv32imac) existe; NS16550 em
0x60000000 lescrito via TCP :5679; `I2C.OpenCoresI2C` + `Mocks.DummyI2CSlave`
@0x60 (ACK, **sem crypto real**); `SiFive_GPIO` (`OnGPIO` p/ injetar nivel);
carga de 2013168 bytes em 0x0.

NAO modela: timing/execucao Xtensa LX7 / ESP32-S3 (bin real aborta em 0x1000);
**nenhuma RAM/ROM/flash mapeada** (carga cai no vazio); USB-HID / BLE real;
ATECC608A real (apenas Dummy ACK); USB-C fêmea/CC/SBU/SS (só anotação);
LED RGB/PWR; temporização e periféricos do S3.

## 7. Acao / proximo passo

- [ ] Corrigir o sim no upstream (`tscircuit/sim`): tipos validos no Renode 1.17.0
  (`UART.NS16550`+`emulation CreateServerSocketTerminal`+`connector`,
  `I2C.OpenCoresI2C`, `Mocks.DummyI2CSlave`, GPIO existente),
  `sysbus LoadBinary` no `.resc`/`fw_loader.py`, mapear RAM/ROM; sem modelo
  Xtensa/ESP32-S3, bin ESP-IDF jamais boota em RiscV32 (usar QEMU-xtensa ou HW)
- [ ] Repetir com HW (bancada: cabo dados + SSID AegisKey-XXXX) p/ aceite fisico
- [ ] So entao rodar `pytest --tcp` esperando veredito SIM-COVERED
- Adaptacoes desta lane vivem SOMENTE em temp fora do repo
  (`C:\t\fido-s3-v3-5679.resc`, `C:\t\fido-s3-v3-5679.repl`, `C:\t\renode_mon.py`,
  logs `C:\t\renode-5679-*.log`); originais de `tscircuit/sim` e firmware intactos.
  Nenhum Mock/Fake/Stub foi colocado em codigo de producao.

## 8. Anexos permitidos + notas de ambiente

- Trecho de log acima (`[hil] … bytes=0`, `CPU abort [PC=0x1000]`, `lt_*` ausente).
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.
- Portas: :5678 do `host_hardware_android_bridge.py` (PID 40336) nunca tocada;
  :5679/:1240 usados pelo Renode proprio e liberados ao fim (maquina removida,
  processo encerrado). OBS: ao final da lane o PID 40336 ja nao estava presente
  e :5678 estava livre — encerramento alheio a esta lane (aqui so houve
  `Stop-Process` nos PIDs Renode proprios 18072/40644).
- Paralelismo: plugin `xdist` ausente; pytest rodou single-process (sem `-n`),
  equivalente ao requisito `--test-threads=1`; sem paralelismo aplicado.
