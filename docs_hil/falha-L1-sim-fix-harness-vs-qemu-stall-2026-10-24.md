# Falha HIL documentada - L1 sim-fix harness OK / QEMU S3 stall (sem boot)

## 1. Identificacao

- Lane/teste: L1 `test_l1_tcp_live_needs_sim` + `sim_pilot --tcp` (harness) / QEMU xtensa direto (boot real)
- Alvo: (a) Renode 1.17.0 com `sim/fido-s3-v3-fix.resc` + `sim/boards/fido-s3-v3-fix.repl` (NOVOS, sufixo -fix; originais intactos);
  (b) QEMU 9.2.2 `qemu-system-xtensa -machine esp32s3` com flash 16 MB remontada
  (bootloader+PT de `C:\t\qemu-flash-16m.bin` + app `C:\t\aegis-app-freertos-s3-testmode.bin` @0x10000 -> `C:\t\qemu-flash-testmode-16m.bin`)
- Data (UTC): 2026-10-24 ~20:50-21:05
- Operador: sim-subagent (read-only; sem flash HW, COM7 jamais aberta nesta lane)
- Comandos exatos:
  - `renode --disable-gui --plain -P 1241 -e "include @sim/fido-s3-v3-fix.resc" -e "start"` (cwd `E:\projetos\tscircuit`; UART TCP :5681, monitor :1241)
  - `qemu-system-xtensa -machine esp32s3 -drive file=C:\t\qemu-flash-testmode-16m.bin,if=mtd,format=raw -serial tcp:127.0.0.1:5682,server=on,wait=off -monitor tcp:127.0.0.1:5683,server=on,wait=off -display none`

## 2. Resultado observado (coleta curta)

```
RENODE-fix (sem binario, harness puro):
  [INFO] System bus created.                       <- zero erro de tipo/periferico
  [INFO] fido-s3-v3-fix: Machine started.          <- sem abort (antes: CPU abort PC=0x1000)
  :5681 LISTENING + :1241 monitor OK (PID 29536)
  CPU busca em 0x0 mapeado (reset 0x1000): WARNING `Illegal instruction at PC=0x1010: 0x0`
     = memoria responde (zeros, sem dummy RISC-V) em vez de abortar fora de RAM/ROM.
  UART TX (via MMIO, como faria o firmware): `sysbus WriteByte 0x60000000 66`
     -> cliente TCP :5681 recebeu 1 byte `B` (0x42); DumpHistoryBuffer = `B`.
  UART RX (TCP -> firmware): cliente enviou `Z`; `sysbus ReadByte 0x60000000`
     -> 0x41 (`A` de WriteChar anterior, lado RX) e depois 0x5A (`Z`). BIDIRECIONAL OK.
  (NOTA: `uart0 WriteLine` no monitor 1.17 pede 2 args e `uart0 WriteString` nao existe;
   caminho MMIO e a prova valida — e a mais fiel ao hardware.)

QEMU esp32s3 real (flash testmode 16 MB, serial TCP :5682, 60 s):
  `Adding SPI flash device`; :5682 aceita TCP; 0 bytes em 60 s (arquivo
  `C:\t\logs\qemu-s3-testmode-serial-60s.bin` = 0 B; sem ONLINE, sem ACTIVE).
  HMP `info status` = running, mas CPU#0 CONGELADA em 3 amostras espaçadas 8 s:
    PC=0x4212e33f (regiao app em flash), LBEG=0x4212e6d8 LEND=0x4212e6dc,
    CCOUNT=0x03a8f514 fixo, WINDOWBASE=5, EXCSAVE2=0x40034ff4.
  => bootloader+app CHEGARAM a codigo de app (PC em 0x4212xxxx), depois CPU halt
  (waiti / stall em periferico nao emulado: TinyUSB-OTG, systimer ou RF/BLE —
  QEMU esp32s3 tem cobertura parcial). Nenhum banner ROM/bootloader/UART0 saiu.
  Console do app e UART0 115200 por sdkconfig (`CONFIG_ESP_CONSOLE_UART_DEFAULT=y`),
  entao 0 bytes = stall antes de qualquer print, nao problema de backend serial.
```

- Veredito Renode-fix: [x] MAQUINA BOOTA (harness) — `Machine started`, UART bidirecional provada byte-a-byte
- Veredito QEMU: [x] SEM BOOT-LOG — app alcançada mas CPU halt em `PC=0x4212e33f`, 0 bytes / sem ONLINE&ACTIVE

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte Renode | TCP 127.0.0.1:5681 (ServerSocketTerminal raw, `telnetMode=false`) + monitor :1241 |
| INIT->CID / PING / GetInfo / TEST_* no sim | N/A HW-ONLY (sem firmware Xtensa executavel no stub RiscV32 — por arquitetura) |
| TX bytes Renode | 1 byte `B` (MMIO THR -> TCP), history `B` |
| RX bytes Renode | `0x41` + `0x5A` lidos via RBR (TCP -> UART) |
| QEMU serial 60 s | 0 bytes (`qemu-s3-testmode-serial-60s.bin`, 0 B) |
| QEMU stall | PC=0x4212e33f fixo, CCOUNT fixo, `info status`=running (logs `qemu-s3-testmode-hmp.txt`, `qemu-s3-testmode-pc-samples.txt`) |
| Portas | :5678 (bridge) e :1234 intocados; usados :5681/:1241 (Renode) e :5682/:5683 (QEMU); processos proprios encerrados |

## 4. Causa provavel (marque uma)

- [ ] HW ausente / cabo / driver / gate do device
- [ ] Firmware sem test-mode
- [x] Sim desatualizado (originais): tipos `UART.LiteUART`, `I2C.I2CBus`, `I2C.DummyI2CSlave`, `GPIOPort.MockGPIOPort` inexistentes no Renode 1.17 + `LoadBIN` inexistente (correto `LoadBinary`) + sem RAM/ROM mapeada — corrigido nos arquivos `-fix`, originais intactos
- [x] Outro (QEMU): CPU halt em app `0x4212e33f` (periferico S3 nao emulado pelo QEMU 9.2.2); ROM/banner nunca emitidos

## 5. Veredito SIM-COVERED vs HW-ONLY por item

| Item | Veredito | Motivo (1 linha) |
|---|---|---|
| Tipos `.repl`/comandos `.resc` validos no Renode 1.17 | SIM-COVERED | `System bus created` sem erro + `Machine started` sem abort (logs `renode-fix-5681-boot.log`) |
| UART CTAPHID 64B crua (TX+RX byte-a-byte) | SIM-COVERED (harness) | TX `B`->TCP + RX TCP->`0x5A` via MMIO NS16550 (logs `renode-fix-5681-uart-echo.txt`, `-rx*.txt`) |
| framing CTAPHID / INIT / PING / dump / TEST_UP (camada) | SIM-COVERED (loopback) | `test_l1_pilot_selftest_loopback` (lane anterior, sem alteracao) |
| boot-check ONLINE&ACTIVE no Renode | HW-ONLY | stub RiscV32 nao executa bin Xtensa por arquitetura (documentado, sem dummy valido) |
| boot-check ONLINE&ACTIVE no QEMU | HW-ONLY | 0 bytes em 60 s; CPU halt `PC=0x4212e33f` (evidencia HMP salva) |
| INIT->CID / PING / GetInfo / gates / botoes no sim | HW-ONLY | sem firmware executando em nenhum sim desta lane |
| Aceite em dispositivo fisico | HW-ONLY (pendente) | builds/trafego simulado/portas/screenshots/emuladores/handshakes nao sao aceite fisico |

## 6. O que o sim-fix	modela / NAO modela

Modela (validado nesta lane): `CPU.RiscV32` fetch de `Memory.MappedMemory` @0x0 (reset 0x1000 coberto);
`UART.NS16550` TX/RX via MMIO para TCP :5681 crua; `I2C.OpenCoresI2C` + `Mocks.DummyI2CSlave` @0x60 (ACK, sem crypto);
`GPIOPort.SiFive_GPIO`; `LoadBinary` documentado (nao executado por padrao).
NAO modela: Xtensa LX7/ESP32-S3, timing/RF/BLE real, USB-HID/BLE, ATECC608A real (Dummy ACK), USB-C fêmea/CC/SBU/SS (anotacao),
LED RGB/PWR, boot ROM/bootloader/IDF reais, console 115200 real (harness prova o fio, nao o firmware).

## 7. Acao / proximo passo

- [ ] Upstream `tscircuit/sim`: aprovar `fido-s3-v3-fix.resc`/`.repl` (ou portar correcoes p/ v1/v2) — tipos 1.17 + `LoadBinary` + RAM mapeada
- [ ] QEMU: investigar stall `PC=0x4212e33f` (addr2line no ELF testmode; `-d guest_errors,unimp`) ou aceitar HW-ONLY e ir p/ bancada
- [ ] Repetir com HW (bancada: cabo dados + SSID AegisKey-XXXX) p/ aceite fisico; so entao `pytest --tcp` com veredito SIM-COVERED
- Adaptacoes desta lane: SOMENTE arquivos novos `-fix` em `tscircuit/sim` + temp em `C:\t\` (`qemu-flash-testmode-16m.bin`, `renode_fix_*.py`, `qemu_s3_*.py/ps1`) + logs `C:\t\logs\`; originais e firmware intactos; nenhum Mock/Fake/Stub em codigo de producao.

## 8. Anexos permitidos + notas de ambiente

- Logs: `C:\t\logs\renode-fix-5681-boot.log` (head: bus created + started), `renode-fix-5681-uart-{echo,rx,rx2,probe}.txt`, `qemu-s3-testmode-serial-60s.bin` (0 B), `qemu-s3-testmode-60s-summary.txt`, `qemu-s3-testmode-hmp.txt`, `qemu-s3-testmode-pc-samples.txt`, `qemu-s3-testmode-stderr*.log`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.
- COM7 jamais aberta (somente TCP + monitor telnet proprios); :5678/:1234 nunca tocados.