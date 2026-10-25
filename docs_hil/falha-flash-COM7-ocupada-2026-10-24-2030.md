# Falha HIL documentada - Flash BLOQUEADO COM7 ocupada (bin 3F6528EB pronto, 2a rodada)

## 1. Identificacao

- Lane/teste: flash `esptool write_flash 0x10000` (bin test-mode 3F6528EB) + L2/L6/suite
- Alvo: UART COM7 115200 Silicon Labs CP210x (USB VID_10C4&PID_EA60)
- Data: 2026-10-24 ~20:18 (T0 + retry +20 s; hora local da bancada, mesma base do doc 2001)
- Operador: hil-subagent
- Commit: da983da (worktree fd/hil-usb-tests; sem edicao de codigo nesta rodada)
- Comando exato: `python -m esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin`

## 2. Resultado observado (coleta curta)

```
BIN SHA256 3F6528EB6400DCC31A8DF13213AF1663D2CEACE71B92C74D98908C6CA57B6190 2013168 B (confere com rodada 2001)
COM7 open direto => Access denied (2x: T0 ~20:17 + retry +20 s ~20:18)
esptool chip_id 115200 => Could not open COM7, port busy EXIT 1
esptool write_flash 921600 => Could not open COM7, busy; PermissionError(13, Acesso negado, WinError 5) EXIT 2
Log: C:\t\logs\flash-freertos-testmode-COM7-20261024-2030.log (506 B)
```

- Veredito: [x] FALHA REAL INFRA (porta ocupada; bin integro, device intocado) / nao e falha de firmware
- Recorrencia: mesmo sintoma do doc `falha-flash-COM7-ocupada-2026-10-24-2001.md` (~20:01); usuario havia liberado COM7+USB, mas WinError 5 persiste nesta rodada

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | UART 115200 (CreateFileW `\\.\COM7`, share 0) |
| INIT->CID | N/A no UART (falhou no open, antes de qualquer troca) |
| PING eco | N/A no UART |
| GetInfo | N/A no UART (via USB separado: INIT ok CID 0x42, PING-4B PASS, PING-200B FAIL 0/64, get_info FAIL 0/64 - wedge pre-flash) |
| Gates | N/A |
| Contagens | pkts=0 bytes=0 no path UART (nenhuma escrita antes do open) |
| USB 303A:AE61 | OK enumerado (Composite + HID FIDO MI_00 + CCID MI_01, AEGIS-S3-0002) |

## 4. Causa provavel (marque uma)

- [x] Outro: porta ocupada por outro processo (WinError 5 persistente pos-retry +20 s; PnP Status=OK CP210x COM7 presente; nenhum python desta lane com COM7 no CommandLine; holder-check do harness apontou so o proprio arquivo de log do Tee-Object, falso-positivo)
- [ ] HW ausente / cabo / driver / firmware / gate / sim desatualizado

## 5. Acao / proximo passo

- [ ] Liberar COM7 (fechar poller/monitor que disputa a porta; candidatos: sessoes com serial aberto, Renode/BLE tools), reflash bin 3F6528EB via esptool reset-padrao, power-cycle/re-plug, canario PING-200B + get_info, repetir suites
- [ ] Nao usar `Invoke-FirmwareFlash` (trava em `Read-Host TEST_DOWNLOAD`); precedente reset-padrao direto mantido

## 6. Anexos permitidos

- Log sanitizado: esptool `Could not open COM7, the port is busy`; PnP `Status=OK CP210x COM7`; suites abaixo.
- PROIBIDO: hex CBOR/TLV, AEGN, TOTP, PIN, PII - nenhum coletado.

## 7. Suites desta rodada (sem flash, device no bin anterior wedged)

- Sem flags: `7 failed, 46 passed, 21 skipped` (69 s; log `C:\t\logs\pytest-hil-COM7-20261024-2035.log`) - mesmos 7 USB multi-pacote (L3 get_info, L4 get_info+fwlog, L5 ctap-getinfo + 3 mgmt fwlog/AEGN-header/walkaway), assinatura falha-L5-usb-mudo.
- L2 `--uart COM7`: `4 failed` (HwMissingError COM7 inacessivel - GetCommState failed; log `C:\t\logs\pytest-hil-L2-COM7-20261024-2035.log`).
- L6 BLE (sem --ble-addr, scan 10 s, fora de janela sem UART p/ TEST_PAIRING_OPEN_300): `6 passed, 5 skipped` (live skipam elegante).
- Canario USB PING-200B: FAIL `0/64 bytes` (INIT ok CID 0x42, `USB_SENT cmd=81 pkts=4 bytes=200`; log `C:\t\logs\canario-ping200b-20261024-2035.log`). Prova fix TX multipacote ainda nao no device.
- Canario USB GetInfo: FAIL `0/64 bytes` (INIT ok, `cmd=90 pkts=1 bytes=1` + RETRY_REENUMERATE sem recuperar; log `C:\t\logs\canario-preflash-20261024-2030.log`).
- Alvos NAO atingidos (gated no flash): PING-200B PASS / GetInfo PASS / 47+/16/0 / L2 4/4.
- Nenhum destrutivo (sem --confirm); nenhum segredo em log.
