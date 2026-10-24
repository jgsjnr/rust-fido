# Falha HIL documentada — L4 fw-log USB timeout transiente

## 1. Identificacao

- Lane/teste: L4 `test_l4_app_fwlog_usb_free`
- Alvo: USB 303A:AE61 IF CTAPHID
- Data (UTC): 2026-10-24
- Operador: fixer (subagente)
- Commit: 2ae4d18 (worktree fd/hil-usb-tests; `python_hil/`+`docs_hil/` untracked)
- Comando exato: `python -m pytest python_hil/tests/ -v` (entao retry `python -m pytest python_hil/tests/test_l4_app.py::test_l4_app_fwlog_usb_free -v --tb=short`)

## 2. Resultado observado (coleta curta)

```
FAILED python_hil/tests/test_l4_app.py::test_l4_app_fwlog_usb_free - TimeoutError: usb hid read timeout (0/64 bytes)
[hil] USB_SENT cmd=83 pkts=1 bytes=1   (MSG fw-log 0x38 enviado; nenhuma resposta em ~10 s)
Retry apos re-enumerar 1x: 1 passed in 0.09s
Primeira passada focada L3+L4 (10 passed) OK; falha so na 2a passada (suite completa).
```

- Veredito: [x] FALHA REAL (HW presente, device nao respondeu 1x) / transiente, recuperada no retry

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | USB-HID 64B+ID00 |
| INIT->CID | ok (USB_RESPONSE bytes=17, CID_ALLOCATED) |
| PING eco 64B | N/A neste teste (L3 ping PASS na mesma sessao) |
| GetInfo (0x04) | N/A neste teste (L4 get_info PASS na mesma suite) |
| TEST_* (test-mode?) | N/A |
| Gates | fw-log 0x38 livre, sem gate esperado; device ficou mudo no MSG |
| Contagens | USB_SENT cmd=83 pkts=1 bytes=1; USB_RESPONSE ausente (0/64 bytes); re-enumerate 1x: enumerate=1 usage_page=61904 (0xF1D0) if=0 |

## 4. Causa provavel (marque uma)

- [x] Outro: instabilidade transiente do devicemid-session (nao respondeu ao MSG 0x38 uma vez; INIT ok; retry imediato PASS) — possivel device ocupado/entre sessoes sem close completo

## 5. Acao / proximo passo

- [x] Re-enumerado 1x + retry: PASS (0.09 s) — nenhuma acao pendente; observar recorrencia
- [ ] Se recorrer: seriar INIT->fw-log isolado com intervalo maior entre sessoes; checar cabo fonte

## 6. Anexos permitidos

- Log sanitizado: `[hil] USB_CONNECTED`, `[log] USB_CONNECTED vid=303A pid=AE61`, `[hil] USB_SENT cmd=86 pkts=1 bytes=8`, `[hil] USB_RESPONSE bytes=17`, `[hil] CID_ALLOCATED`, `[log] CID_ALLOCATED`, `[hil] USB_SENT cmd=83 pkts=1 bytes=1`, `[log] USB_DISCONNECTED`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.

## 7. Recorrencia 2026-10-24 pos-rebase (mesma assinatura, retry PASS)

- Suite completa pos-fix L2 (`pytest python_hil/tests/ --uart COM7`):
  `17 passed, 1 skipped, 2 failed` — este L4 `fwlog_usb_free` FAIL 1x com
  a mesma assinatura (INIT ok + MSG 0x38 mudo, `0/64 bytes`), e retry
  isolado imediato `1 passed in 0.07s` (3a ocorrencia do padrao no dia,
  em teste distinto mas mesma assinatura).
- Nenhuma acao pendente; causa provavel da secao 4 mantida (transiente
  mid-session USB). Commit pos-rebase: 2c3dcad.
