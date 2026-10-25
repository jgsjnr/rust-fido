# Falha HIL documentada — L5 USB mudo pos-INIT (CBOR sem resposta)

## 1. Identificacao

- Lane/teste: L5 `test_l5_mgmt_fwlog_free_live_usb`, `test_l5_mgmt_backup_envelope_header_live_usb`
  (GetInfo), `test_l5_mgmt_proximity_walkaway_builder_live_usb` (GetInfo);
  testemunha L3 `test_l3_usb_get_info` com a mesma assinatura
- Alvo: USB 303A:AE61 IF CTAPHID
- Data (UTC): 2026-10-24
- Operador: subagente (lane fd/hil-usb-tests)
- Commit: 2c3dcad (worktree fd/hil-usb-tests; `python_hil/`+`docs_hil/` untracked)
- Comando exato: `python -m pytest python_hil/tests/test_l5_mgmt.py::test_l5_mgmt_fwlog_free_live_usb python_hil/tests/test_l5_mgmt.py::test_l5_mgmt_backup_envelope_header_live_usb python_hil/tests/test_l5_mgmt.py::test_l5_mgmt_proximity_walkaway_builder_live_usb python_hil/tests/test_l5_mgmt.py::test_l5_mgmt_ota_begin_chunk_verify_no_commit_usb -v --tb=short`

## 2. Resultado observado (coleta curta)

```
FAILED test_l5_mgmt_fwlog_free_live_usb - TimeoutError: usb hid read timeout (0/64 bytes)
FAILED test_l5_mgmt_backup_envelope_header_live_usb - TimeoutError: usb hid read timeout (0/64 bytes)
FAILED test_l5_mgmt_proximity_walkaway_builder_live_usb - TimeoutError: usb hid read timeout (0/64 bytes)
[hil] USB_CONNECTED / USB_SENT cmd=86 pkts=1 bytes=8 / USB_RESPONSE bytes=17 / CID_ALLOCATED,
depois USB_SENT cmd=90/83 pkts=1 bytes=1 sem resposta (0/64 bytes em ~10 s)
Retry isolado L3 get_info 1x: ainda FAIL (persistente, nao transiente desta vez)
```

- Veredito: [x] FALHA REAL (HW presente, device negou/mudo no 2o comando)

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | USB-HID 64B+ID00 |
| INIT->CID | ok (`USB_RESPONSE bytes=17`, `CID_ALLOCATED`) em todas as sessoes |
| PING eco 64B | ok (L3 `init_ping` PASS na mesma janela de estado) |
| GetInfo (0x04) | mudo: `USB_SENT cmd=90 pkts=1 bytes=1`, `0/64 bytes` (4 sessoes seguidas) |
| TEST_* (test-mode?) | `TEST_PAIRING_OPEN_300` via COM7 PASS pouco antes (`pairing_open`); `TEST_UP` usado nos probes MC/GA |
| Gates | fw-log 0x38 livre esperado; GetInfo 0x04 sem gate esperado; device mudo antes de qualquer gate |
| Contagens | INIT `bytes=8`->resp `bytes=17`; CBOR/MSG `bytes=1`->resp `0/64 bytes` |

## 4. Causa provavel (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (só energia, sem dados: USB nao enumera)
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissao)
- [ ] Firmware sem test-mode (TEST_* mudo; esperado fora de test-mode)
- [ ] Gate do device (pairing fechado / UP nao pressionado / PIN exigido)
- [ ] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)
- [x] Outro: firmware aparentemente wedged no path CBOR/MSG apos sequencia
  UART `TEST_PAIRING_OPEN_300` + sessoes USB repetidas — INIT/PING (path
  cru) ok, qualquer 2o comando CBOR/MSG mudo. Mesma assinatura do
  transiente de `falha-L4-fwlog-usb-timeout-2026-10-24.md` §7, mas desta
  vez persistente em 4+ sessoes (retry NAO recuperou).

## 5. Acao / proximo passo

- [ ] Re-plugar USB / reset fisico do AEGIS-S3-0002, depois retry isolado:
  `pytest python_hil/tests/test_l3_usb.py::test_l3_usb_get_info -v --tb=line`
- [ ] Se recuperar: repetir L5 mgmt/CTAP focado; se persistir apos reset,
  escalar p/ lane dona do firmware (nao tocar fora de `python_hil/`+`docs_hil/`)
- [ ] Nenhum destrutivo executado (sem OTA-COMMIT/wipe/killswitch; OTA abort
  so com envelope sintetico; nenhum segredo em log)

## 6. Anexos permitidos

- Log sanitizado: `[hil] USB_CONNECTED`, `[hil] USB_SENT cmd=86 pkts=1 bytes=8`,
  `[hil] USB_RESPONSE bytes=17`, `[hil] CID_ALLOCATED`,
  `[hil] USB_SENT cmd=90 pkts=1 bytes=1` (ou `cmd=83`), `TimeoutError: usb hid
  read timeout (0/64 bytes)`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.
- Contraponto funcional da mesma bancada (mesma hora): gates com semantica
  real — CTAP MC/GA/ClientPIN/hmac-secret/credMgmt com CBOR minimo negam
  `status=0x14`; OATH_LIST/CODE e WALLET_LIST/ADDR negam `status=0x01`;
  OTA_BEGIN staged com bug de path do teste (vendor_op 0x30 fora de
  0x20-0x27) antes da correcao para `exchange(CMD_MSG,…)`; pairing
  `TEST_PAIRING_OPEN_300` via COM7 PASS.

## 7. Re-ocorrencia pos-210e980 (rodada 2026-10-24, HEAD da983da)

- Contexto: device saudavel no inicio da rodada — L3+L4 focados **10 passed**
  (INIT->CID, PING eco, GetInfo, iface probes, fw-log livre, wallet LIST
  read-only). Apos a sequencia L2 COM7 (wedge UART §falha-L2-uart-wedge-*
  desta data) + ~15 sessoes USB acumuladas, o USB degradou para a mesma
  assinatura, agora **persistente**:
  `pytest python_hil/tests --tb=no -q` => **7 failed, 40 passed, 16 skipped**;
  retry isolado `test_l5_mgmt_fwlog_free_live_usb` 1x => ainda FAIL
  (reenumerar + INIT novo + timeout maior NAO recuperam desta vez).
- Os 7 FAIL (todos `INIT ok + 2o comando CBOR/MSG mudo 0/64 bytes`):
  `test_l3_usb_get_info`, `test_l4_app_get_info_usb`,
  `test_l4_app_fwlog_usb_free`, `test_l5_ctap_getinfo_versions_usb`,
  `test_l5_mgmt_fwlog_free_live_usb`,
  `test_l5_mgmt_backup_envelope_header_live_usb`,
  `test_l5_mgmt_proximity_walkaway_builder_live_usb`.
  Contraponto na mesma janela: INIT->CID + PING seguem ok; gates com
  semantica seguem negando certo (`0x14` CBOR minimo, `0x01` OATH/WALLET sem
  binding); BLE scan `0` (sem radio); WiFi `HwMissingError` (fora do SSID).
- Leitura: firmware gravado e pre-fix (sem o `broadcast INIT limpa assembly
  orfa` desta worktree, MAPA-FIX §2): sessoes USB back-to-back acumulam
  assembly orfa ate o wedge; USB e UART degradaram juntos apos uso, cada um
  no seu sintoma (USB = mudo pos-INIT; UART = `0x0B` + TEST_* faminto).
- Acao: power-cycle / re-plugar o AEGIS-S3-0002, depois
  `pytest test_l3_usb.py::test_l3_usb_get_info -v --tb=line` como canario;
  duravel = reflash com HEAD (contém o fix §2) e repetir suite (esperado:
  47 passed, 16 skipped, 0 failed). Nenhum destrutivo; nenhum segredo em log.

## 8. Re-rodada desta lane (2026-10-24 — harness retry aplicado, HW segue wedged)

- Suite com HW (303A:AE61 `AEGIS-S3-0002` enumerado, COM7 presente):
  `pytest python_hil/tests --tb=line -q` => **5 failed, 42 passed, 16 skipped**.
  Os 5 FAIL com a mesma assinatura (INIT->CID + PING ok, 2º CBOR/MSG mudo
  `0/64 bytes`, retry+reenumerar+INIT novo+20 s NÃO recupera):
  `test_l3_usb_get_info`, `test_l4_app_get_info_usb`,
  `test_l4_app_fwlog_usb_free`, `test_l5_ctap_getinfo_versions_usb`,
  `test_l5_mgmt_fwlog_free_live_usb`.
  (2 dos 7 anteriores voltaram a SKIP/passar por gates; o núcleo CBOR/MSG
  segue wedged no device pré-fix.)
- Harness desta worktree já purga (`open` + pré-`exchange`), retenta 1x com
  re-enumerar + INIT novo + 20 s só em leituras idempotentes e dá hint
  re-plug `AEGIS-S3-0002` — provado no host, sem efeito no device wedged
  (esperado: fix durável exige reflash; ver MAPA-FIX §9).
- Veredito: [x] FALHA REAL persistente (HW presente, device nega 2º comando).
  Nenhum destrutivo; nenhum segredo em log (só contagens + `cmd`/`op`).
## 9. Rodada pos-reflash (2026-10-24 — firmware novo gravado, assinatura persiste como residual)

- Flash (autorizado; COM7 livre, sem WinError 5): tentativa 1 via
  `.\scripts\build-esp32s3-devkitc.ps1 -Flash -Port COM7` FALHOU —
  soft-entry `TEST_DOWNLOAD` sem ack em 8 s + esptool `--before no_reset`
  sem sync nos 2 bauds (`Invalid head of packet (0x5B)`: app rodando, chip
  fora de download). Retry 1x com esptool reset padrao (desvio documentado:
  o script fixa `no_reset`; reset DTR/RTS padrao e o caminho sem-botoes):
  **FLASH OK** — `C:\t\aegis-app-esp32s3-devkitc.bin` (2.013.888 B,
  SHA256 `6573736B…B2CC9`, factory max 3.145.728) em `0x10000`, 17,8 s,
  hash verificado, hard reset. Bin = feature `board-devkitc` **sem
  `test-mode`, sem `freertos`** (TEST_* ausentes por desenho; fix §2 do
  MAPA-FIX embarcado; fixes §1/§3 freertos/test-mode NAO ativos no bin).
- Boot pos-flash: banner `Compile time: Oct 24 2026 16:50:16` (bin novo);
  USB 303A:AE61 re-enumera; canario `test_l3_usb_get_info` **PASS 0,16 s**.
- Suite sem flags, device saudavel: **3 failed, 46 passed, 14 skipped**
  (vitimas estaveis `oath_challenge`, `wallet_list`, `wallet_addr`,
  `TimeoutError op=init`); apos mais trafego: **6 failed, 43 passed,
  14 skipped** (+2 mgmt live +1); pos-reboot: de volta a **3/46/14**.
- Isolamento `test_l5_oath.py`: falha ALTERNADA — `op=vendor_26` mudo APOS
  INIT ok (antes era `op=init`); loop 6x open→INIT→close: **6/6 OK**
  (re-sessao rapida nao e o gatilho).
- Degradacao progressiva sob trafego ate wedge total (USB INIT-ok+2o-mudo
  persistente mesmo com retry+reenumerar+idle 90 s; UART INIT→ERROR `0x0B`
  + TEST_* mudo), limpo por reboot POWERON espontaneo (suspeita: pulso EN
  no open/close da porta — DTR/RTS reseta este chip, verificado na pratica).
- Veredito: [x] FALHA REAL residual (flake USB 5–10 s, ~3–6 fails/suite;
  wedge progressivo). Prescricao: power-cycle antes de cada rodada HIL;
  retry em `HidLink.cmd_init` (idempotente; lane dona); investigar stalls
  do loop legado + estado `0x0B` sticky (dona do firmware); reflash
  variante `freertos+test-mode` p/ validar §1/§3 no HW (comando no
  MAPA-FIX §10, NAO executado). Nenhum destrutivo; nenhum segredo em log.
## Re-ocorrencia 2026-10-24 1830 bin 923FCC86 (TX-nao-bloqueante): INIT+PING USB ok, GetInfo/fw-log 0/64 bytes persiste a retry+reenumerar; UART viva (GETINFO 479 B). Suite --uart COM7 54/13/7. Nao curado; workaround reboot antes da rodada.
## §10. Rodada 2026-10-24 (lane fd/hil-usb-tests) — reboot RTS/esptool NAO limpou o wedge USB (residual persiste)

- Contexto: device wedged na assinatura conhecida (INIT ok + 2º CBOR/MSG mudo).
  Reboots executados (sem flash, sem download-mode, sem DTR-toggle no harness):
  (1) `python -m esptool --port COM7 --after hard_reset chip_id` => EXIT 0
  (`ESP32-S3 ... MAC 3c:84:27:c7:17:78`, `Hard resetting via RTS pin...`);
  (2) `python -m esptool --port COM7 --before default_reset --after hard_reset chip_id`
  => EXIT 0 (mesma saida/MAC). USB re-enumerou `count=1` apos ambos.
- Canario `pytest python_hil/tests/test_l3_usb.py::test_l3_usb_get_info -v --tb=line`
  **FAIL 3/3** (pos-reboot1, +idle 5 s, pos-reboot2): `USB_CONNECTED`,
  `USB_SENT cmd=86 ...`, `USB_RESPONSE bytes=17`, `CID_ALLOCATED`,
  `USB_SENT cmd=90 ...`, `RETRY_REENUMERATE op=get_info`, `TimeoutError: usb hid
  read timeout op=get_info (0/64 bytes)`. Retry+re-enumerar+INIT novo nao recupera.
- Contraponto na mesma janela: L2 `--uart COM7` **4 passed** (open/init_ping/
  get_info/gates) — device vivo e saudavel no UART (test-mode ativo); wedge e
  exclusivo do path USB CBOR/MSG. `sim_pilot --uart COM7` => `boot-check UART
  falhou bytes=0` (artefato: banner ONLINE&ACTIVE passa nos ~8 s pos-reboot;
  abrir tarde nao captura banner — nao e falha de boot).
- Suites (caracterizacao, sem `--confirm`, sem segredo em log): sem flags
  **6 failed, 47 passed, 21 skipped** e **7 failed, 46 passed, 21 skipped**
  (2 rodadas; `test_l4_app_fwlog_usb_free` alterna — flake). Fails = mesma
  assinatura (L3 get_info; L4 get_info+fwlog; L5 ctap-getinfo + 3 mgmt
  fwlog/AEGN-header/walkaway). Passed bate o alvo 47. Multiprocesso
  `-n auto --test-threads=1`: N/A (`unrecognized arguments`, exit 4).
  L6 BLE em janela nao executado (gated no canario PASS).
- Veredito: [x] FALHA REAL residual (flake USB + wedge progressivo). Novidade
  desta rodada: o workaround "reboot RTS limpa" (precedente MAPA-FIX p.12.5,
  2x OK) **falhou 2/2** — prescricao restante = **power-cycle / re-plug fisico**
  do AEGIS-S3-0002 (fora do alcance desta lane), depois canario isolado.
  Nenhum destrutivo; nenhum segredo em log (so contagens + `cmd`/`op`).
## S11. Rodada 2026-10-24 22:22 UTC pos-RE-PLUG FISICO (usuario) - re-plug NAO curou (residual persiste)
- Contexto: usuario fez RE-PLUG FISICO do AEGIS-S3-0002. USB re-enumerou count=1 (303A:AE61 MI_00, serial AEGIS-S3-0002, AegisKey S3 Authenticator); COM7 CP210x presente.
- Canario pytest python_hil/tests/test_l3_usb.py::test_l3_usb_get_info -v => FAIL 1/1 em 4.92 s: USB_CONNECTED, USB_SENT cmd=86 pkts=1 bytes=8, USB_RESPONSE bytes=17, CID_ALLOCATED, USB_SENT cmd=90 pkts=1 bytes=1, RETRY_REENUMERATE op=get_info, TimeoutError usb hid read timeout op=get_info (0/64 bytes). Retry+re-enumerar+INIT novo nao recupera.
- Gating: suites sem flags / --uart COM7 / L6 BLE em janela TEST_PAIRING_OPEN_300 --ble-addr 3C:84:27:C7:17:7A NAO executados (condicao canario PASS nao atendida).
- Multiprocesso -n auto --test-threads=1 => N/A (unrecognized arguments, xdist nao instalado). Collect-only 74 itens ok.
- Veredito: FALHA REAL residual (nao curado). Precedentes: reboot RTS esptool falhou 2/2 (S10); agora re-plug fisico falha 1/1. Wedge restrito ao path USB CBOR/MSG; enumerate+INIT+UART presumidos vivos (UART nao re-testada nesta rodada, gated).
- Proximo: power-cycle com descarga / troca cabo-porta USB / reflash; depois canario isolado. Nenhum destrutivo (sem --confirm); nenhum segredo em log.
## S12. Rodada 2026-10-24 19:48-19:54 UTC - build 3F6528EB pronto, flash BLOQUEADO COM7, PING-200B FAIL pre-flash
- Build: freertos-s3-testmode EXIT 0, SHA 3F6528EB6400DCC31A8DF13213AF1663D2CEACE71B92C74D98908C6CA57B6190, 2013168 B (vs 923FCC86 2011968 B). Log C:\t\logs\build-freertos-testmode-20261024-1948.log.
- Flash: esptool direto reset-padrao EXIT 2 `Could not open COM7, busy` (WinError 5, mode indisponivel, handle.exe COM7/CP210x sem match, retry 5 s + 20 s). Log C:\t\logs\flash-freertos-testmode-COM7-20261024-1954.log. Script TEST_DOWNLOAD nao tentado (travaria em Read-Host).
- Canarios pre-flash: `test_l3_usb_init_ping` PASS (INIT CID 0x0B + PING 4 B eco); PING-200B FAIL `USB_SENT cmd=81 pkts=4 bytes=200` -> `0/64 bytes`; `test_l3_usb_get_info` FAIL `USB_SENT cmd=90 bytes=1` -> `0/64 bytes` + RETRY_REENUMERATE sem recuperar. Mesma assinatura S10/S11, agora com multi-pacote PING tambem mudo - compativel com TX multi-pacote ainda sem fix no device.
- Suites: sem flags 7/46/21 (L3 get_info, L4 get_info+fwlog, L5 ctap-getinfo + 3 mgmt); L2 --uart COM7 4 failed HwMissingError; L6 BLE 6/5 (scan SKIP). Alvos PING-200B PASS, GetInfo PASS, 47+/16/0, L2 4/4 NAO atingidos.
- Veredito: FALHA REAL residual persiste (device sem fix); flash+validacao EXTERNAL_BLOCKED em COM7 livre. Prescricao: liberar COM7, reflash 3F6528EB, power-cycle, canarios, suites. Nenhum destrutivo; nenhum segredo em log.
## S13. Rodada 2026-10-24 (lane fd/hil-usb-tests) — mitigacao host-side sessao-fresca: NAO zera o flake
- Harness: `HidLink.fresh_session()` (INIT novo/CID novo; `cmd_init` re-enumera se preciso) ANTES de cada multi-pacote idempotente (`get_info`, `fw_log`, `rescue`, `ping>57B`); em TimeoutError, 1 retry com sessao fresca (`exchange_read_retry`). Single-packet (PING<=57B) sem retry; MC/GA/vendor/wallet/PUT nunca retentam (semantica preservada). Testes offline novos em `test_l3_usb.py` (fresca-antes, retry-1x, writes-sem-retry, sem-segredo-em-log) + live `test_l3_usb_ping_large_multipkt_usb` (PING-200B 4 pkts). Doubles so nos testes; nenhum segredo em log (so contagens + `cmd`/`op`); sem --confirm.
- Device no inicio da rodada: SAUDAVEL — canario get_info PASS 0,86 s; PING-200B (`b'A'*200`) PASS; get_info 479 B + fw-log 275 B PASS com a mitigacao ativa. Apos ~10 sessoes acumuladas, wedge reapareceu (mesma assinatura S10/S11/S12).
- Suites com mitigacao (device wedged, 2 rodadas): **8 failed, 52 passed, 21 skipped** e **8 failed, 52 passed, 21 skipped** (85 s cada; sem drain entre rodadas). Os 8 = 7 baseline (L3 get_info; L4 get_info+fwlog; L5 ctap-getinfo + 3 mgmt) + 1 novo (PING-200B live). Baseline §12.7/12.8: 7 failed, 46 passed, 21 skipped (74 itens; +7 itens = 6 offline novos + 1 live novo). INIT ok + CID + PING-1pkt ok; multi-pacote mudo 0/64 mesmo com fresca-antes + retry+re-enumerar+INIT novo.
- Multiprocesso `-n auto --test-threads=1`: N/A (`unrecognized arguments: --test-threads=1`, xdist nao instalado). Offline `-k offline`: 8 passed.
- Veredito: mitigacao host-side NAO zera o flake quando o firmware wedga (cura = power-cycle + fix device-side TX multi-pacote; bin 3F6528EB tem fix parcial). Vale como higiene (sessao fresca reduz assembly orfa no host), sem regressao quando saudavel. Nenhum destrutivo; nenhum segredo em log.
