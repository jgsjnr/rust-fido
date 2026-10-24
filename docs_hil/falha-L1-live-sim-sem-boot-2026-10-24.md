# Falha HIL documentada - L1 live sem boot (QEMU mudo + Renode travado)

## 1. Identificacao

- Lane/teste: L1 `test_l1_tcp_live_needs_sim` + `sim_pilot --tcp 127.0.0.1:5678`
- Alvo: sim Renode/QEMU (UART TCP :5678, boot-check ONLINE&ACTIVE, INIT->CID, PING, DUMP, TEST_UP)
- Data (UTC): 2026-10-24 17:05-17:10
- Operador: hil-subagent
- Comando exato: `python -m python_hil.sim_pilot --tcp 127.0.0.1:5678`;
  `python -m pytest python_hil/tests/test_l1_sim.py -v --tcp 127.0.0.1:5678`

## 2. Resultado observado (coleta curta)

```
QEMU 9.2.2 (C:\qemu-esp\qemu\bin\qemu-system-xtensa.exe -machine esp32s3,
-drive file=C:\t\qemu-flash-16m.bin,if=mtd,format=raw -serial tcp:127.0.0.1:5678,server=on,wait=off):
  monitor "Adding SPI flash device"; :5678 aceita TCP mas 0 bytes em 20 s + 8 s
  de leitura (sem banner, sem ONLINE&ACTIVE).
  => PILOT HW-ONLY: boot-check falhou (sem ONLINE&ACTIVE; trocar bin/.resc?)

Renode v1.17.0 (--disable-gui -e '$BIN="C:\t\aegis-app-freertos-s3-testmode.bin";
include @E:\projetos\tscircuit\sim\fido-s3-v3.resc; sysbus LoadBIN $BIN 0x0; start'):
  1a tentativa: crash em 0.0.0.0:1234 AddressAlreadyInUse (porta do monitor
  ocupada por processo alheio, PID 20640; retry com -P -1).
  2a tentativa (-P -1): "System bus created." e trava ~100 s sem
  CreateServerSocketTerminal :5678 (nada escuta; ConnectionRefused).
  Nota: o .resc original tem todos os LoadBIN/LoadELF comentados (so $BIN
  sem Load nao carregaria firmware); o LoadBIN 0x0 foi passado
  explicitamente nesta tentativa.
  => :5678 nunca escutou; piloto nem chegou a conectar.

pytest --tcp 127.0.0.1:5678: 5 passed, 1 skipped
(test_l1_tcp_live_needs_sim SKIP: sim inativo; loopback/offline intactos).
```

- Veredito: [x] SKIP HONESTO (sim nao subiu nesta maquina) / nao e ausencia de teste

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | TCP 127.0.0.1:5678 (QEMU server / Renode ServerSocketTerminal) |
| INIT->CID | N/A (sem boot, sem troca CTAPHID) |
| PING eco 64B | N/A |
| GetInfo (0x04) | N/A |
| TEST_* (test-mode?) | N/A |
| Gates | N/A |
| Contagens | QEMU: pkts=0 bytes=0; Renode: sem listener (:5678 refused) |

## 4. Causa provavel (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (so energia, sem dados: USB nao enumera)
- [ ] Outro: porta ocupada por outro processo
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissao)
- [ ] Firmware sem test-mode (TEST_* mudo; esperado fora de test-mode)
- [ ] Gate do device (pairing fechado / UP nao pressionado / PIN exigido)
- [x] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE) — QEMU com
  `qemu-flash-16m.bin` existente nao emite console em :5678; Renode trava
  apos `System bus created` (repl fido-s3-v3 / modelo ESP32-S3 nesta versao)

## 5. Acao / proximo passo

- [ ] Regenerar imagem QEMU com `-BuildImage` (bootloader + PT 16 MB do repo + app test-mode) e re-rodar `sim_pilot --tcp`
- [ ] Depurar o stall Renode (repl `sim/boards/fido-s3-v3.repl`, uart0 terminal, LoadBIN 0x0) em lane propria
- [ ] So entao rodar `pytest --tcp` (veredito SIM-COVERED esperado)

## 6. Anexos permitidos

- Log sanitizado: QEMU `Adding SPI flash device`, 0 bytes; Renode
  `System bus created.` + `:5678 refused`; `[hil] BOOT_CHECK online=0 active=0 bytes=0`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII - nenhum coletado.
