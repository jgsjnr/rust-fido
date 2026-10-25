# Relatorio HIL janela fisica AUTORIZADA - AEGIS-S3-0002 - 2026-10-25 (bin 578450D8)

Autorizacao: dono, explicita, unidade unica AEGIS-S3-0002. Worktree E:\projetos\fido-hil (branch fd/hil-usb-tests).
Escopo: build+flash+device+docs_hil, sem edicao de codigo-fonte. Sem segredo em log/tela (so status, contagens, bytes).
Gaps do parent nesta worktree (modificacoes nao-comitadas, sem edicao por esta lane): backup-export 0x3A + OTA freertos.

## 1. BUILD - PASS
scripts\build-freertos-s3-testmode.ps1 EXIT 0 (ELF 38,45 s).
Bin C:\t\aegis-app-freertos-s3-testmode.bin: 2024352 B, SHA256 578450D82A1BD760184D4FF671F8BE7B7F2278A5E61DDC82532004BA021DDFF2
(SHA8 578450D8, diferente de 3F6528EB: OK). Log: C:\t\logs\build-freertos-testmode-20261025-hil.log.

## 2. BRIDGE - PAUSADO/RELIGADO (PIDs re-descobertos por commandline, nunca assumidos)
Pausado 3x (PIDs python 45428+45884, 45200, 45384, 45944) via Stop-Process apos re-descoberta
(Get-CimInstance Win32_Process, filtro host_hardware_android_bridge). Commandlines capturadas em
C:\t\logs\bridge-cmdline-20261025-hil.txt: (a) ...\tools\host_hardware_android_bridge.py ; (b) ... --port COM7.
COM7 livre confirmado via Serial open OK antes de cada passo UART; USB enumerado (HID FIDO OK + CP210x 10C4:EA60).
Ressalva: supervisor (IDE hub) relanca o bridge --port COM7 em ~1-2 min; passos UART em rajadas rapidas.
RELIGADO no fim (PIDs 21004+41444); /bridge/info: connected=true, transport=UART, port=COM7, status=online.

## 3. FLASH - PASS
esptool reset padrao write_flash 0x10000 EXIT 0: 2024352 B (1243942 compressed) em 18,2 s, hash verificado,
MAC 3c:84:27:c7:17:78, hard_reset RTS. Boot: L2 --uart COM7 4/4 PASS; USB get_info PASS isolado.

## 4. BACKUP-EXPORT 0x3A - PASS (com PIN de teste)
TEST_PAIRING_OPEN_300 + TEST_UP (UART, latch ~1,5 s, repetir antes de cada op gated).
Sem pairing: 0x05. Com pairing+UP sem PIN: 0x02 (NeedPin; binding bypass test-mode OK).
ClientPIN: getRetries 0x00/5 B; getKeyAgreement 0x00/79 B; setPIN 1234 0x00 (PIN estava zerado);
getPinToken 0x00/36 B. 0x3A 0x01: 0x00/744 B header AEGN/0x01 OK. 0x3A 0x02: 0x00/79 B header OK.
So status+len+header em log; restore nao executado (recovery = re-provisionamento, passo 6).

## 5. OTA COMMIT - BLOQUEADO, NENHUM COMMIT (device intocado; sem rebuild improvisado)
Rota freertos OTA funciona (gap implementado): BEGIN 104 B real do proprio bin => 0x04
(over_budget: 2024352 B > OTA_STORAGE_BUDGET_BYTES 917504). BEGIN reduzido (1024 B) => 0x00
(provisioned, sessao abre). VERIFY sig zerada => 0x04 fail-closed (privkey lab fora do repo).
ABORT => 0x00 (2x). COMMIT nunca enviado. Versao-maior exigiria rebuild+assinatura: PAREI e reportei.

## 6. WIPE+RECOVERY - EXECUTADO (Reset 0x00 na janela; wipe PARCIAL - divergencia)
esptool hard_reset + imediato TEST_UP + INIT + CBOR 0x07 => 0x00 (na janela 10 s; fora => 0x30 NOT_ALLOWED).
Zerado: SETPIN 1234 0x00 (PIN zerado); CLAIM 0x00 fresco (binding zerado); WALLET_LIST 0x00/0 B.
DIVERGENCIA: KEY_LIST 0x00/132 B - key_slots_v1 SOBREVIVEU ao Reset; KEY_GEN 5..9 => 0x03 NoSlot.
Re-provisionado: binding CLAIM 0x00 + PIN 1234 (set+token 0x00) + MC T17 0x00/744 B + GA T18 0x00/170 B.
Rescue WIPE/KILLSWITCH nao tocados (jig+HSM).

## 7. FINAL - bridge religado + suite + docs
Religado (21004+41444), /bridge/info online. Canario get_info PASS isolado; L2 4/4 PASS.

Estado final: bin 578450D8 saudavel. NVS: PIN=1234 teste, binding claimed, wallet vazia,
key_slots com chaves pre-wipe (132 B) + credencial MC residente e2e. Bridge online.
Passo 4 PASS | Passo 5 BLOQUEADO sem commit | Passo 6 wipe parcial + recovery PASS.
