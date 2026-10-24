# Falha HIL documentada — TEMPLATE

> Copie este arquivo para `docs_hil/falha-<Lx>-<alvo>-AAAA-MM-DD.md` e
> preencha. Falha real documentada > aprovar sem evidencia. Nunca logue segredo
> (contagens e nomes de evento apenas).

## 1. Identificacao

- Lane/teste: (ex. L3 `test_l3_usb_init_ping`, L2 `test_l2_uart_get_info_base`)
- Alvo: (ex. USB 303A:AE61 IF CTAPHID / UART COM7 115200 / BLE 0xFFFD / AP 192.168.4.1 / sim TCP 127.0.0.1:5678)
- Data (UTC): AAAA-MM-DD
- Operador: <nome>
- Commit: <sha da worktree fd/hil-usb-tests>
- Comando exato: (ex. `pytest python_hil/tests/test_l3_usb.py -v --tb=short`)

## 2. Resultado observado (coleta curta)

```
<cole aqui SOMENTE o trecho final do pytest (<= 30 linhas):
ex. FAILED/ERROR/SKIPPED + 1 linha de contexto. Sem dump binario,
sem CBOR/TLV hex, sem codigo TOTP, sem senha/PIN.>
```

- Veredito: [ ] HW-ONLY (falta HW/sim) / [ ] FALHA REAL (HW presente, device negou) / [ ] SIM-COVERED (sim respondeu)

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | USB-HID 64B+ID00 / UART 115200 sem DTR/RTS / BLE 0xFFFD / WiFi AP / TCP sim |
| INIT->CID | ok `cid=0x…` / falhou (motivo curto) / N/A (sem HW) |
| PING eco 64B | ok / falhou / N/A |
| GetInfo (0x04) | status=`0x..` body_bytes=N / negado `0x..` / N/A |
| TEST_* (test-mode?) | quais responderam (`pairing_open`/`up_latched`/`lt_dump v=1`) / fw sem test-mode / N/A |
| Gates | binding->UP->PIN: onde parou (ex. NEED_UP 0x01 apos 25 s sem BOOT) |
| Contagens | pkts=N bytes=N (nunca payload) |

## 4. Causa provavel (marque uma)

- [ ] HW ausente (sem enumerate / sem AP / sem radio BLE / sim desligado)
- [ ] Cabo/carregamento (só energia, sem dados: USB nao enumera)
- [ ] Driver/BLE-stack (hidapi/bleak ausente ou sem permissao)
- [ ] Firmware sem test-mode (TEST_* mudo; esperado fora de test-mode)
- [ ] Gate do device (pairing fechado / UP nao pressionado / PIN exigido)
- [ ] Sim desatualizado (bin/.resc antigo; boot sem ONLINE&ACTIVE)
- [ ] Outro: _______________

## 5. Acao / proximo passo

- [ ] Repetir com HW (reservar bancada: cabo dados + SSID AegisKey-XXXX)
- [ ] Rebuild firmware com `test-mode` (TEST_* exigem)
- [ ] Trocar bin/.resc do sim (Renode `fido-s3-v3.resc` / QEMU `C:\t\*.bin`)
- [ ] Pressionar BOOT no UP (janela 25 s) / segurar 5 s p/ pairing 60 s
- [ ] Escalar p/ lane dona do teste (nao tocar fora de `python_hil/`+`docs_hil/`)

## 6. Anexos permitidos

- Trecho de log sanitizado (`[hil] … bytes=N`, `[log] …`), `lsusb`/enumerate resumido.
- PROIBIDO: hex de CBOR/TLV, AEGN envelope, TOTP, senha/PIN, PII.

---

Guia rapido de classificacao:

- `SKIPPED sem --uart/--tcp/HW` = HW-ONLY, reutilize este template com veredito HW-ONLY.
- `SIM-COVERED` (piloto TCP passou) cobre framing/gates, mas NAO substitui aceite fisico: builds, trafego simulado, portas, screenshots, emuladores e handshakes nao sao aceite em dispositivo fisico.
- Rode multiprocesso E2E com `pytest -n auto --test-threads=1` quando aplicavel; reporte o resultado focado exato (1 linha por teste).
