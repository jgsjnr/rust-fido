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
