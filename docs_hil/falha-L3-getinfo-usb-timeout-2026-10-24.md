# Falha HIL documentada — L3 GetInfo USB timeout transiente

## 1. Identificacao

- Lane/teste: L3 `test_l3_usb_get_info`
- Alvo: USB 303A:AE61 IF CTAPHID
- Data (UTC): 2026-10-24
- Operador: fixer (subagente)
- Commit: 2ae4d18 (worktree fd/hil-usb-tests; `python_hil/`+`docs_hil/` untracked)
- Comando exato: `python -m pytest python_hil/tests/ -v` (entao retry `python -m pytest python_hil/tests/test_l3_usb.py::test_l3_usb_get_info -v --tb=line`)

## 2. Resultado observado (coleta curta)

```
FAILED python_hil/tests/test_l3_usb.py::test_l3_usb_get_info - TimeoutError: usb hid read timeout (0/64 bytes)
[hil] USB_SENT cmd=90 pkts=1 bytes=1   (CBOR GetInfo 0x04 enviado; nenhuma resposta em ~10 s)
Retry apos re-enumerar 1x (enumerate=1): 1 passed in 0.14s
Mesmo padrao do falha-L4-fwlog do dia: INIT ok, comando seguinte mudo, retry imediato PASS.
```

- Veredito: [x] FALHA REAL (HW presente, device nao respondeu 1x) / transiente, recuperada no retry

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | USB-HID 64B+ID00 |
| INIT->CID | ok (USB_RESPONSE bytes=17, CID_ALLOCATED) |
| PING eco 64B | N/A neste teste |
| GetInfo (0x04) | sem resposta 1x (0/64 bytes); retry PASS |
| TEST_* (test-mode?) | N/A |
| Gates | GetInfo sem gate esperado |
| Contagens | USB_SENT cmd=86 pkts=1 bytes=8; USB_RESPONSE bytes=17; USB_SENT cmd=90 pkts=1 bytes=1; resposta ausente |

## 4. Causa provavel (marque uma)

- [x] Outro: instabilidade transiente em sessoes USB back-to-back (2a ocorrencia no dia, testes distintos, mesma assinatura INIT-ok + proximo comando mudo + retry PASS) — suspeita de device ocupado entre open/INIT rapidos seguidos

## 5. Acao / proximo passo

- [x] Re-enumerado 1x + retry: PASS (0.14 s) — nenhuma acao pendente
- [ ] Se recorrer: espacar sessoes HW ou agrupar leituras (INIT unico por sessao); checar cabo/fonte

## 6. Anexos permitidos

- Log sanitizado: `[hil] USB_CONNECTED`, `[hil] USB_SENT cmd=86 pkts=1 bytes=8`, `[hil] USB_RESPONSE bytes=17`, `[hil] CID_ALLOCATED`, `[hil] USB_SENT cmd=90 pkts=1 bytes=1`.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII — nenhum coletado.
