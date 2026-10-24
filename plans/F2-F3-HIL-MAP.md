# F2 QEMU interativo + F3 D08a via USB — mapa do que falta
Lane: `.slim/worktrees/qemu-usb-hil` (branch `omos/qemu-usb-hil`, base
`fd/finalizacao-linux@805515b`). Regras: R15/R16, ASCII puro, sem segredo
em log, sem flash/COM7 sem gate, 1 sessao HIL por vez. Rollback por
arquivo: `git checkout -- <scope>`.

## Estado atual (evidencia verificavel)

- QEMU: imagem 16 MB monta e boota (`qemu-s3.ps1 -BuildImage` OK;
  `qemu-s3-fileboot.log`: ROM -> bootloader -> partition table ->
  app load -> `cpu_start` -> heap_init; trava visual apos eFuse warn).
  Serial em arquivo FUNCIONA; serial TCP (`-serial tcp:...server,wait=off`)
  entrega 0 bytes em 75 s; monitor `(qemu)` ativo no stdio.
- `tools/sim_ctap_init.py`: reescrito p/ socket TCP cru (INIT/PING/DUMP/
  TEST_UP) + `--self-test` verde contra guest falso (commit `986fae2`).
  Guest real: pendente (sem output interativo p/ validar).
- OTA serial (COM7): bad-sig NUNCA faz stage (`0x01` na porta, sessao
  preservada) — fail-closed provado na fronteira. Host: 45 testes OTA
  verdes incl. `ota_finish_rejects_bad_signature_and_rolls_back` e
  `ota_finish_and_commit_deny_denied_key`.
- USB nesta maquina: WUDF bloqueado (`0x45D/0x54F`, zero URBs no USBPcap;
  prova valida = Linux/WSL2 + usbipd + pyusb, 21/10: SELECT/VERIFY/
  GENERATE/G pennies AUTH 9000). OTA via USB: sem rodada registrada.
- Binarios do dia em `C:\t\` (testmode `15312C18`? ver `ls C:\t\aegis-app-*`).

## F2 — QEMU interativo (fumaça, nunca RealVerified)

- Q1 | UART TCP muda | dono: qemu-serial | scope: `scripts/qemu-s3.ps1`
  (linhas do `-serial tcp`) | gate: `qemu_tcp_log.py 10` mostra `ESP-ROM`
  + Desk: testar `-serial null -serial tcp:...`, `wait=off` vs cliente
  conectado antes do boot, monitor `none` (`-monitor none`), ordem dos
  `-serial`. Rollback: `git checkout -- scripts/qemu-s3.ps1`.
- Q2 | guest trava apos eFuse | dono: qemu-boot | scope: leitura de logs
  + flags (`-d guest_errors`, icount) | gate: file-log passa de
  `heap_init` ate `[FREERTOS]` ticks OU diagnostico escrito do motivo
  (emulacao lenta vs stall). Sem codigo firmware p/ agradar emulador.
- Q3 | sim real-guest | dono: host-sim | scope: `tools/sim_ctap_init.py`
  | gate: `python tools/sim_ctap_init.py 127.0.0.1 5678` imprime
  `INIT_OK + PING_OK + DUMP_OK + TEST_UP + SIM_CTAP_OK` contra QEMU vivo.
  Deps: Q1 + Q2.
- Q4 | aceite QEMU | dono: qa | scope: este arquivo | gate: INIT+PONG+DUMP
  documentados no diario (`docs/teste-ponta-a-ponta.md`). QEMU segue
  fumaça (R11: nunca conta como RealVerified).

## F3 — D08a via USB (FINISH nega bad-sig fim-a-fim)

- U1 | desbloqueio do par | dono: hw-peer | scope: fora do repo |
  gate: par USB limpo (2o PC ou porta USB2) OU rota Linux/WSL2+usbipd
  com pyusb falando CTAPHID (INIT 64B). ExternalBlocked ate la; nao
  fingir com mock.
- U2 | sonda USB CTAPHID | dono: host-usb | scope: `tools/` (NOVO
  `usb_ctap_probe.py`, sem tocar `app_simulator.py`) | gate: INIT/PING
  via USB cru contra o device (pyusb), mesmo framing do serial.
  STATUS 24/10: PRONTO codigo + self-test verde (fake); --live =
  ExternalBlocked (sem pyusb nesta maquina + WUDF). Commit lane.
- U3 | e2e USB OTA | dono: host-ota | scope: `tools/` (estender U2 ou
  novo `e2e_usb_ota.py`, reaproveitando o builder de manifesto de
  `e2e_user_test.py:_d08`) | gate, nesta ordem: BEGIN bad-sig -> FINISH
  nega + rollback (prova F3); BEGIN lab -> CHUNKs -> FINISH 0x00;
  COMMIT sem UP nega (0x01, sessao preservada); COMMIT com UP marker
  (SEM swap — particao unica); ABORT limpa. Deps: U1 + U2.
  COMMIT real JAMAIS via serial; via USB só com chave release + UP.
- U4 | evidencia | dono: qa | scope: diario + interop-matrix |
  gate: log USB + SHA256 do bin + `check-release-clean` verde.

## Nao fazer nesta lane

- Secure-boot/eFuse burn (R13), mocks de radio/HW, `checkout --` no
  checkout principal, flash sem gate verde, COMMIT OTA fora do rito
  (USB + chave release + UP), declarar conformidade FIDO.

## Resultados Q1/Q2 (24/10, apos o mapa)

- Q1: 3 variantes TCP (sem monitor / null-first / combinada) = 0 bytes
  em 20 s cada (porta LISTENING, connect OK). Script intacto (criterio:
  so editar com variante provada). TCP do modelo ESP32-S3 nao entrega
  nem o `ESP-ROM` do reset => roteamento chardev quebrado, nao timing.
- Q2: guest PAROU, nao lento: boot completo em ~1 s de host, congela
  apos `eFuse calibration version ...` com busy-spin (~3 nucleos) e
  3 leituras MMIO rejeitadas em `0x10200C` (regiao `er`); `[FREERTOS]`
  nunca aparece. Causa provavel: poll em periferico nao modelado
  (ADC/RNG/PHY/USB-JTAG pos-calibracao). Logs: `C:\t\qemu-diag-*.log`.
- VEREDITO F2: QEMU = ExternalBlocked por lacuna do modelo p/ este
  firmware (stall antes do app + UART TCP muda). Fumaça maxima
  atingida (boot ate cpu_start/heap via file-mode). HIL segue no HW
  fisico (regra). Nao mexer em firmware p/ agradar emulador; nao
  mexer no modelo QEMU nesta lane.
