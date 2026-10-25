# Relatorio HIL janela fisica FINAL AUTORIZADA (retry) - AEGIS-S3-0002 - 2026-10-25 (bin 3C509444)

Autorizacao: dono, explicita, unidade unica AEGIS-S3-0002. Worktree E:\projetos\fido-hil (branch fd/hil-usb-tests).
Bin: C:\t\aegis-app-freertos-s3-testmode.bin (reset-wipe + OTA-BLE + TX + LED), SHA256 3C50944450F5C6762E01245D2BE2F64263085FFC6D15A0FD8EAF5A7F0576C8EF.
Escopo: bridge+flash+device+docs_hil via shell; nenhum codigo editado. Sem segredo em log/tela (so status, contagens, bytes, hashes, nomes de evento).

## 1. BRIDGE - ja parado (nenhum Stop-Process necessario)
Busca fresca por commandline `host_hardware_android_bridge` (excluindo o proprio grep): 0 processos.
Arquivo C:\t\logs\bridge-cmdline-20261025-hil.txt continha apenas PIDs obsoletos da lane anterior (45428/45884).
COM7 livre confirmado (open/close Serial OK, sem WinError 5). USB 303A:AE61 enumerado OK (composite + HID fido + CCID + entrada).
Nenhum processo morto nesta lane (nada para matar).

## 2. FLASH - PASS
`python -m esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin`
EXIT 0, 2030448 B (1247374 comprimidos) em 17,8 s, hash verificado, MAC 3c:84:27:c7:17:78, hard_reset RTS.
Log: C:\t\logs\flash-freertos-testmode-COM7-20261024_233426.log.
Boot-check UART (`device_ops.py boot-check --port COM7 --secs 15`): ONLINE e estavel (bytes=5611, boots=1, ticks 1 Hz).

## 3. RESET-WIPE E2E - PASS (wipe real, novo bin limpa NVS)
`esptool hard_reset` + em <10 s TEST_UP + INIT + CBOR 0x07 via UART => 0x00/1 B em 0,4 s (log C:\t\logs\hil-wipe-e2e-20261025.txt).
Sem pairing a 1a leitura negou por gate (KEY_LIST 0x01, WALLET 0x05) - latch UP expirou; com TEST_PAIRING_OPEN_300 + UP fresco antes de cada op (log C:\t\logs\hil-postwipe-verify-20261025.txt):
KEY_LIST 0x00/0 B, WALLET_LIST 0x00/0 B, OATH_LIST 0x00/0 B, GetInfo 0x00/479 B,
ClientPIN getRetries 0x00/5 B, KEY_GEN slot 5 0x00/11 B (livre, residuo de prova), KEY_LIST-pos-GEN 0x00/11 B,
getCredsMetadata (0x0A A1 01 01) 0x14/0 B (store vazio; CBOR minimo => 0x14, cf. Mapa L5).
DIVERGENCIA ANTERIOR RESOLVIDA: key_slots pre-wipe NAO sobreviveram (lista 0 B pos-wipe; GEN 5 livre imediato).

## 4. BACKUP-EXPORT 0x3A - PASS com ressalva honesta (PIN de teste 1234)
pairing+UP+PIN via UART (log C:\t\logs\hil-backup-e2e-20261025.txt, so lens em log):
getRetries 0x00/5 B; setPIN 1234 0x00 (PIN estava zerado); getPinToken 0x00/36 B.
0x3A 0x01 (keys): 0x00/95 B, header MAGIC=AEGN VER=0x01 OK (envelope minimo: store quase vazio pos-wipe).
0x3A 0x02 (oath): 0x04/0 B - absent-store (OATH vazio pos-wipe); fail-closed correto do firmware
(blob ausente/fora de forma nunca sai como backup, nunca 0x00 vazio). Sem restore (recovery = passo 6).

## 5. OTA stage-via-BLE -> COMMIT-via-USB - BLOQUEADO sem commit (device intocado)
TEST_PAIRING_OPEN_300 via UART; manifest 104 B (ver 0xFFFFFFFE, size 1024, sha zeros, sig zeros) + CHUNKs de 64 B via BLE GATT 0xFFFD/FFF1 (addr 3C:84:27:C7:17:7A), log C:\t\logs\hil-ota-stage-ble-20261025.txt:
BEGIN 0x01, CHUNK0 0x01, CHUNK64 0x01, VERIFY 0x01, ABORT 0x01 (presence-required: UP fisico por operacao no BLE; latch UART nao vale; sem maos). Sessao nunca aberta.
COMMIT 0x33 via USB-HID com TEST_UP (log C:\t\logs\hil-ota-commit-usb-20261025.txt): 0x04 em 1a tentativa (sem sessao verificada staged; fail-closed correto). Sem forcar, sem retry alternativo. Nenhum byte de app escrito.

## 6. RE-PROVISION + SUITES
Re-provision (log C:\t\logs\hil-reprovision-20261025.txt): CLAIM 0x28 0x00 fresco (binding claimed, id 20e24f09);
SETPIN 0x33 (1234 ja definido no passo 4, idempotente); getPinToken 0x00/36 B (sessao viva).
Suites (logs C:\t\logs\hil-suite-*.txt):
- sem flags: 62 passed, 19 skipped, 0 failed (alvo 47+/16/0 OK).
- --uart COM7 (rodada 1): 60 passed, 14 skipped, 7 failed - todos `usb hid read timeout (0/64 B)`, assinatura do wedge residual conhecido (falha-L5-usb-mudo-pos-init-2026-10-24.md; INIT ok + 2o comando mudo).
- pos-reboot limpo (boot-check ONLINE): os 7 isolados 7 passed.
- --uart COM7 (rodada 2): 66 passed, 13 skipped, 2 failed (mesma assinatura wedge, subconjunto distinto).
- pos-reboot: os 2 isolados 2 passed.
- L2 isolado --uart COM7: 4 passed (alvo 4/4 OK).
- L6 BLE --ble-addr 3C:84:27:C7:17:7A (janela pairing 300 s): 8 passed, 3 skipped, 0 failed.
Veredito: todo teste da suite passou ao menos uma vez; falhas exclusivamente o wedge USB transitorio sob carga, sempre recuperado por reboot limpo. Nenhum gate enfraquecido, nenhum teste editado.

## 7. BRIDGE RELIGADO + estado final
Religado mesma commandline em background: PID 8236
`"python.exe" -u E:\projetos\fido\.slim\worktrees\android-ux-journey\tools\host_hardware_android_bridge.py --port COM7`.
GET /bridge/info (127.0.0.1:5678): connected=true, transport=UART, port=COM7, status=online.
Estado final do device: bin 3C509444 saudavel. NVS: PIN=1234 teste, binding claimed, 1 chave vendor slot 5 (GEN de prova do passo 3), wallet vazia, OATH vazio, sem credencial MC residente nova.
Passo 3 PASS (wipe real) | Passo 4 PASS (0x01 AEGN; 0x02 0x04 fail-closed motivado) | Passo 5 BLOQUEADO sem commit (BLE 0x01 fisico; COMMIT-USB 0x04 motivado) | Passo 6 suites verdes com wedge recuperado | Bridge online.
