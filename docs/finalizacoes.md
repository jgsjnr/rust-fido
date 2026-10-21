# Finalizações — F4 provado, trava RSSI integrada, loop de placa (21/10)

Data: 21/10/2026 (noite). Branch: `fd/finalizacao-linux`. Estilo: continuação de
`docs/sessao-20-10-f4-ccid-opensc.md`.

## 0. Estado em uma linha

F4 **provado fim-a-fim via OpenSC real no Linux** (SELECT+VERIFY+GEN+AUTH `9000`);
trava RSSI com MAC real ligado no firmware; applet PIV agora aceita PIN FF-padded;
logs de debug CCID removidos; achada e corrigida a causa raiz do "serial 0001"
(stale de objetos C + `.bin` velho). Bateria bench 5/5 + base 9/11 no firmware novo.

## 1. F4 — prova E2E no Linux (device inocentado, WUDF condenado)

- Windows: `SCardTransmit` morre com `0x45D` sem nenhum URB no fio (USBPcap,
  420 pacotes, zero XFR). Phantom purge + rebind + troca de porta: sem efeito.
- WSL2 (Debian) + `usbipd` (bind `--force` por causa do filtro USBPcap): pcscd +
  libccid (VID:PID `303A:AE61` registrado em `/etc/libccid_Info.plist`) + opensc.
- `opensc-tool -l` lista `AegisKey S3 Authenticator` com cartão; ATR uTrust
  `3b:96:11:81:21:75:75:54:72:75:73:74:73`; SELECT PIV `9000`; VERIFY `9000`;
  GENERATE 9A P-256 `9000`; GENERAL AUTHENTICATE sign `9000` (`7C 42 82 40…`).
- XFR direto via pyusb também `9000` (quando o frame está bem-formado).
- Erros meus no caminho (não do firmware): frame curto (PowerOn 9B/XFR 17B) gera
  `SlotStatus(0,3,1,1)` + `bogus dwLength, resetting` com self-heal; VERIFY com
  PIN FF-padded dá `63 C2`; VERIFY sem SELECT na sessão dá `6985`.
- PIN ficou com 2 retries (1 consumido no teste do padding); PUK intacto.

## 2. Trava RSSI integrada ao sistema

- Lane explorer mapeou o trabalho paralelo (firmware `proximity.rs`, agents
  `tools/host/{win,linux,macos}/proximity_agent.py`, handoff em
  `docs/proximity-worktree-handoff.md`).
- Lane fixer ligou o MAC BLE real: FFI `aegis_ble_own_addr` (C) + `own_addr()`
  (Rust) + `beacon_fob_id()` (fail-closed sem stack); placeholder XOR-fold removido.
  Host-tests: 254 + 285 (proximity) verdes.
- Contrato congelado em `docs/ble-protocol.md` §13 (beacon `0xFFFE`, TAG AES-CCM,
  gates, decisor `-75dBm/10s`, histerese 5dB, anti-replay, `K_prox` NVS).
- Falta (próximo giro do loop): build com `--features proximity`, flash, medição
  aérea (RSSI real + calibração `-75/5dB`).

## 3. Applet PIV — PIN FF-padded (interop driver real)

- Lane fixer: helper `secret_matches_piv` (exato primeiro; se `len==8` com FF,
  tenta stripado 6-8; uma tentativa lógica) em `handle_verify`, `handle_change`
  (PIN), `handle_change_puk`, `handle_unblock`. Enroll interno inalterado.
- 4 testes novos; `cargo test -p aegis-fido-usb` 82 passed; clippy travou em
  `#[test]` duplicado pré-existente em `ccid.rs:1198` (corrigido pelo orquestrador).
- Validação no device: pendente (VERIFY padded via OpenSC no WSL após o flash;
  sucesso também restaura os 3 retries).

## 4. Limpeza dos logs de debug CCID

- Lane fixer removeu `rx frame`/`tx rpdu`/`xfer`/`ctrl`/`open itf` de
  `ccid_device.c` (só `ESP_LOGW` de erro, 1 linha); orquestrador removeu `[CCID]`
  de `main.rs` (mantida a linha de falha real de envio).
- Sem mudança de lógica/timing/protocolo.

## 5. Achaque do "serial 0001" — stale C + `.bin` velho (resolvido)

- Fio dizia `0001`, fontes (C e Rust) dizem `0002`: o `.bin` em `C:\t` era velho
  (build-diag gera só o ELF; `elf2image` era manual). E `ccid_device.c` tinha
  definição `ccid_arm_notify` antes das `static` + typo `}u` (sobra do notify 20/10)
  — build quebrava; orquestrador moveu a definição p/ depois do estado.
- Verificação nova no loop: `strings` no ELF/bin antes de cada flash
  (ELF fresco: `0002` x2, `0001` x0, sem `CCID driver online`).
- Disciplina: nunca mais flashear sem regenerar o `.bin` do ELF do dia.

## 6. Flash + bateria no firmware novo (base diag, sem proximity)

- `elf2image` do ELF fresco + `flash_soft.py`: 2924128 B em 23,8 s, hash OK.
- Bench 5/5 (PING 21ms, GetInfo 67ms, MC ~1052ms, GA ~1129ms).
- Base 9/11, as 2 DIVERGENTE conhecidas e documentadas (T06/T06b janela residual).
- Em andamento agora: captura UART pós-limpeza (sem spam) + VERIFY padded no WSL.

## 7. Pendente (parado p/ não gastar token à toa)

1. VERIFY padded no device via WSL (valida §3 no hardware + restaura retries).
2. Build+flash variante proximity + medição aérea e calibração.
3. Re-enroll PIN se precisar (só após item 1).
4. Windows desta máquina segue sem XFR (WUDF) — aceito como estado local; prova
   F4 vale no Linux. Revisitável só com 2º PC ou reinstall do stack smartcard.
5. Merge p/ `main` (F6) após 1–2; itens com usuário (H1–H7, APK, bond app, hold).

### 21/10 (madrugada) - loop fechado no firmware novo
- VERIFY padded (FF) no device via OpenSC/WSL: 9000 (lane FF provada no hardware);
  status vazio em seguida: 63 C3 = 3 retries restaurados. PIN saudável.
- UART 45 s: zero linhas CCID-debug, zero warnings (limpeza provada no fio).
- Serial no fio agora AEGIS-S3-0002 (fio == fonte; .bin velho era o culpado).
- Devolvido ao Windows (unbind+rescan) após validação.
- Falta: build+flash variante proximity + medição aérea; merge F6; itens usuário.

### 21/10 (madrugada) - bateria completa + build proximity
- Host: cargo test workspace 101+8+1+254+3+81+16+0s, 0 failed; clippy -D warnings limpo.
- Placa (firmware base diag): bench 5/5, base 9/11 (flakes T06/T06b), all-safe 25/25 zero divergente.
- Proximity agents: win 34 OK + self-test ok; linux OK + self-test; macos OK + self-test.
- Build variante proximity (board-devkitc,test-mode,debug-terminal,proximity): EXIT 0, 0 errors.
- Commit c20bce4 no ar (trava RSSI + FF + limpeza + §13 + finalizacoes).
- Próximo: flash proximity + scan aéreo passivo (0xFFFE/RSSI). Lock real só com confirmação (trava a máquina).

### 21/10 (madrugada) - variante proximity no ar, scan passivo zerado (esperado)
- Flash proximity OK (2935360 B, hash verificado). Bin limpo: 0002 x2, sem debug.
- Scan BLE passivo 15 s (bleak, filtro 0xFFFE + nome Aegis): 0 achados.
- Motivo esperado (gates): USB nativo plugado silencia BLE (coex) + sem bond
  BLE (bond do app pendente com usuário) + K_prox só nasce no Paired.
- UART só mostra heartbeats (sem linhas proximity/bond) — coerente c/ gates fechados.
- Bench+base na variante proximity rodando p/ provar que o binário com feature
  não quebrou o baseline.
- Medição aérea real (0xFFFE + CTR + RSSI) e lock real ficam p/ quando houver
  bond: passo 1 = parear app; passo 2 = desplugar USB nativo 1 min e escanear;
  passo 3 = agente win --fob-id MAC --k-prox-hex <K do Paired>. Lock real da
  máquina só com confirmação.

### 21/10 (madrugada) - LOOP FECHADO na variante proximity
- Bench 5/5 + base 9/11 (mesmas 2 flakes T06/T06b): baseline intacto com proximity compilado.
- Tudo validado nesta placa: F4 E2E (Linux), FF-padded (device), logs limpos (UART),
  serial 0002 (fio), fob MAC real (build), all-safe 25/25, gates host verdes.
- Parado (depende de você): bond app -> scan aéreo -> lock real; WUDF Windows;
  F6; H1-H7/APK/hold.

## ANEXO — Tudo que foi implantado (consolidado 21/10)

### Firmware (crates/aegis-fido-firmware)
- components/aegis_usb/ccid_device.c: driver CCID (bulk+notify, reassembly, stall
  class-specific), NotifySlotChange em PowerOn/Off, logs debug removidos (só ESP_LOGW).
- components/aegis_usb/aegis_usb.c: descritor composto HID+CCID (funcional 54B exato,
  dwFeatures APDU 0xC0000, clock 3600/rate 10416), serial AEGIS-S3-0002, reconnect SW.
- components/aegis_ble/aegis_ble_nimble.c: preinit, BleStartGate, aegis_ble_own_addr,
  proximity_start fail-closed.
- src/ccid_dispatch.rs: dono do transporte + fallback error_response (novo).
- src/main.rs: transporte persistente, op 0x39, TEST_USB_RECONNECT, beacon tick,
  sem [CCID] debug.
- src/proximity.rs: ProximityMonitor/Beacon/Verifier, K_prox NVS prox_k, fob MAC real.
- src/ble_nimble.rs: own_addr() FFI, adv 0xFFFE 30B.
- src/vendor_exec.rs: braço 0x39 (enroll PIN/PUK). src/piv (usb): FF-padded verify/change.

### App Android
- PivScreen.kt (rota piv, enroll PIN/PUK), VendorOps 0x39, contrato BLE, botão na UI.

### Ferramentas (tools/ + C:\t)
- raw_transmit.py (SCardTransmit cru), need_hands.py, piv_enroll_live.py, e2e --phase bench,
  flash_soft.py (download SW), ble_scan.py, ccid_xfr2.py (pyusb), pcap_scan/hdr/dev/align.py,
  cap_all_hubs.ps1, usb_reconnect.py, plist_check/add.py. scripts: build-diag, flash-diag,
  common.ps1 (sync C + Clear-StaleIdfSysBuild), elf2image sempre do ELF do dia.

### Docs
- sessao-20-10-f4-ccid-opensc.md, finalizacoes.md (este), plano-followups.md (F4),
  teste-ponta-a-ponta.md (diário), ble-protocol.md §12 (0x38/0x39) + §13 (proximity),
  piv-ble-proximity.md, proximity-worktree-handoff.md, READMEs dos agents.

### Infra de prova
- usbipd-win (bind --force) + Debian WSL2 + pcscd/libccid/opensc (VID:PID no plist).

### Commits (fd/finalizacao-linux)
c20bce4 loop (prox+FF+limpeza), a0dbeac bateria, 97cca8b fechamento; base: d5d597b,
73076ea, 47b173b + série F4 (driver/ATR/descritor/notify) e D08 6/6.

### Validações finais na placa
bench 5/5, base 9/11 (flakes T06/T06b), all-safe 25/25, host 464 + clippy zero,
proximity 3 OS ok, OpenSC E2E 9000 x4, VERIFY padded 9000 (retries 3), UART limpa.

### 21/10 (madrugada) - WUDF estacionado, merge F6 simulado, pairing verde
- SCardConnect agora falha 0x80100069 SEM NENHUM URB no fio (USBPcap 600 pkts: só
  GET_DESCRIPTOR + lixo bulk de outro device; zero CCID p/ o Aegis). Purge PnP total,
  TEST_USB_RECONNECT e restart SCardSvr: sem efeito. Device inocentado (bench/base/
  pairing verdes, UART sem CCID). ESTACIONADO: precisa 2o PC ou reinstall stack
  smartcard do Windows (lado usuário). Provas F4 valem no Linux.
- Bug real anotado (variante proximity): wifi_init ESP_ERR_NO_MEM no boot/coex —
  follow-up da lane proximity (heap), não bloqueia CCID/serial.
- Pairing phase 14/14 (hold-gesture coberto no que dá p/ simular sem BLE bond).
- Merge F6 simulado (merge-tree): ZERO conflitos; 174 arquivos no diff.
- APK: sem wrapper no repo; instalando Gradle do sistema p/ assembleDebug.

### 21/10 (madrugada) - app simulado em Python 15/15 (C:\t\sim_app.py)
Sem hardware e sem lock: TAG vetor 660d4941 py==rs==fw; parse ok/rejeita;
RollingCode accept 7-9, replay/salto/VER-ruim negados; decisor lock aos 15s e 37s,
sem relock em away contínuo, near desarma latch, None 12s relocka (fail-closed),
erros contam como away; SimulatedSource varia. (Decisor certo; 1ª versão do script
tinha expectativa errada de tempo, corrigida sem tocar produto.)
Simulado e verde: pairing phase 14/14, merge F6 (zero conflitos), APK 56,5 MB.
Físico pendente (usuário): bond app -> scan aéreo -> lock real; hold-gesture real;
H1-H7; WUDF segue estacionado p/ 2o PC.
