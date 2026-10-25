# Falha HIL documentada - Flash BLOQUEADO COM7 ocupada (bin 3F6528EB pronto)

## 1. Identificacao

- Lane/teste: flash `esptool write_flash 0x10000` (bin test-mode 3F6528EB) + L2/L6/suite
- Alvo: UART COM7 115200 Silicon Labs CP210x (USB VID_10C4&PID_EA60)
- Data (UTC): 2026-10-24 20:01 (tentativa + retry 20s)
- Operador: hil-subagent
- Commit: da983da (worktree fd/hil-usb-tests; sem edicao de codigo nesta rodada)
- Comando exato: `esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin`

## 2. Resultado observado (coleta curta)

```
BIN SHA256 3f6528eb6400dcc31a8df13213af1663d2ceace71b92c74d98908c6ca57b6190 2013168 B (confere com .sha256)
pyserial open COM7 => PermissionError(13, Acesso negado, WinError 5) (2x: T0 + retry +20s)
esptool chip-id => Could not open COM7, the port is busy or doesn't exist EXIT 1
esptool write_flash => Could not open COM7, the port is busy EXIT 2
Log: C:\t\logs\flash-freertos-testmode-COM7-20261024-200153.log (885 B)
```

- Veredito: [x] FALHA REAL INFRA (porta ocupada; bin integro, device intocado) / nao e falha de firmware

## 3. Evidencia sem segredo (obrigatorio)

| Campo | Valor |
|---|---|
| Transporte | UART 115200 (CreateFileW `\\.\COM7`, share 0) |
| INIT->CID | N/A (falhou no open, antes de qualquer troca) |
| PING eco | N/A |
| GetInfo | N/A (via USB separado: INIT ok CID 0x3C, PING-4B PASS, PING-200B FAIL 0/64, get_info FAIL 0/64 - wedge pre-flash) |
| Gates | N/A |
| Contagens | pkts=0 bytes=0 no path UART (nenhuma escrita antes do open) |

## 4. Causa provavel (marque uma)

- [x] Outro: porta ocupada por outro processo (WinError 5 persistente pos-retry; PnP Status=OK CP210x COM7 presente; `handle.exe COM7` = No matching handles; `handle -p python` sem COM7)
- [ ] HW ausente / cabo / driver / firmware / gate / sim desatualizado

## 5. Acao / proximo passo

- [ ] Liberar COM7 (fechar poller/monitor que disputa a porta), reflash bin 3F6528EB via esptool reset-padrao, power-cycle/re-plug, canario PING-200B + get_info, repetir suites
- [ ] Nao usar `Invoke-FirmwareFlash` (trava em `Read-Host TEST_DOWNLOAD`); precedente reset-padrao direto mantido

## 6. Anexos permitidos

- Log sanitizado: esptool `Could not open COM7, the port is busy`; PnP `Status=OK CP210x COM7`; suites abaixo.
- PROIBIDO: hex CBOR/TLV, AEGN, TOTP, PIN, PII - nenhum coletado.

## 7. Suites desta rodada (sem flash, device no bin anterior wedged)

- Sem flags: `7 failed, 46 passed, 21 skipped` (74 s; log `C:\t\logs\pytest-hil-COM7-20261024-200158.log`) - mesmos 7 USB multi-pacote (get_info/fwlog/backup/proximity 0/64), assinatura falha-L5-usb-mudo.
- L2 `--uart COM7`: `4 failed` (HwMissingError COM7 inacessivel; log `C:\t\logs\pytest-hil-L2-COM7-20261024-200325.log`).
- L6 BLE (sem --ble-addr, scan 10 s): `6 passed, 5 skipped` (fora de janela sem UART p/ TEST_PAIRING_OPEN_300; log `C:\t\logs\pytest-hil-L6-20261024-200417.log`).
- Canario USB PING-200B: FAIL `0/64 bytes` (INIT ok CID 0x3C, PING-4B PASS a55a00ff); GetInfo: FAIL `0/64 bytes` com retry+reenumerar. Prova fix TX ainda nao no device.
- Alvos NAO atingidos (gated no flash): PING-200B PASS / GetInfo PASS / 47+/16/0 / L2 4/4.
- Nenhum destrutivo (sem --confirm); nenhum segredo em log.
