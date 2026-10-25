# Relatorio destrutivos AUTORIZADOS - AEGIS-S3-0002 - 2026-10-25 (parado em gap, sem wipe/commit)

Autorizacao: dono, explicita, unidade unica AEGIS-S3-0002. Worktree E:\projetos\fido-hil (HEAD da983da). Escopo device + docs_hil via shell, sem edicao de codigo.
Ordem de risco crescente; parada no primeiro gap irrecuperavel por esta lane. Sem segredo em log/tela (so status, contagens, hashes SHA256, nomes de evento).

## 1. BACKUP - PARTIAL-OK (log sanitizado: C:\t\logs\hil-backup-20261025.txt)

UART COM7 livre em T0 (sem WinError 5); USB com wedge residual conhecido (INIT ok + 2o comando CBOR/MSG mudo 0/64 bytes, ver falha-L5).

- UART GetInfo: status=0x00 bytes=479 (versions FIDO_2_0,FIDO_2_1,hmac-secret,credMgmt,pinUvAuthToken,largeBlobs)
- UART fw-log livre: status=0x00 bytes=660
- UART wallet LIST (com UP): status=0x00 bytes=0 -> 0 slots
- UART key LIST (com UP): status=0x00 bytes=132 -> metadados presentes (chaves existem)
- UART key LIST (sem UP): 0x01 gated NEED_UP; UART OATH LIST (com UP): 0x01 gated (binding-ou-PIN), contagem desconhecida
- UART rescue PING/DIAG: 0x04 gated (UP+PIN via ClientPIN); USB INIT+PING-4B ok; USB wallet LIST 0x01/0x05 gated
- USB GetInfo: FAIL residual wedge (INIT ok + MSG 0x90 mudo); ClientPIN getRetries (A2 01 01 02 01): status=0x00 bytes=5 (UART e USB)
- DKEK export: Unsupported, sem opcode wire (consts publicas MAX_SECRET=64 MAX_SHARES=32)
- Envelope AEGN export: Unsupported, sem opcode wire (header-validacao so offline; NVS nao exposta)
- Veredito: backup logico PARTIAL-OK. Wallet vazia confirmada; chaves presentes (132 B) seriam perdidas num wipe; OATH desconhecido; sem restore byte-a-byte via wire.

## 2. OTA - BLOQUEADO, NENHUM COMMIT (log: C:\t\logs\hil-ota-20261025.txt)

Sonda com manifesto do proprio bin rodando (size=2013168, sha real, version=0xFFFFFFFE, sig zerada) + ABORT de limpeza. BEGIN 105 B (2 pkts), resposta sempre 1 B.

- OTA_BEGIN USB: status=0x01; OTA_BEGIN USB rapido pos-TEST_UP (<1,5 s): status=0x01; OTA_BEGIN UART: status=0x01; OTA_ABORT USB/UART: status=0x01
- Causa raiz (codigo, sem edicao): dispatch_ota_request so e chamado no run_loop_legacy; o bin rodando (freertos+test-mode) usa run_loop_freertos, onde OTA cai no engine CTAP generico que responde 0x01.
- Pecas faltantes p/ re-OTA real: (a) dispatch OTA na rota freertos + reflash; (b) manifesto 104 B (host ops.py usa TLV/begin e seq-u16/chunk, incompativeis com o wire offset-u32BE); (c) assinatura Ed25519 release + version maior que current (anti-rollback nega re-OTA igual).
- Sem verify possivel: COMMIT nunca enviado. Device intocado.

## 3. KILLSWITCH/WIPE + RECOVERY - NAO EXECUTADO (bloqueado, device intacto)

Tentativa de boa-fe: CTAP Reset (0x07) via UART com latch TEST_UP -> status=0x30 NOT_ALLOWED. Causa: ResetHandler exige elapsed-boot <= 10 s; fora da janela nega mesmo com UP.
Reboot via esptool hard_reset OK (MAC 3c:84:27:c7:17:78), mas na volta COM7 estava com o bridge externo (UART 10C4:EA60 uptime_s=5; esptool nega WinError 5). Regra: com WinError 5 usar so USB e reportar em vez de matar o bridge - bridge nao tocado.
Bloqueadores (sem maos, sem COM7): UP exige BOOT fisico ou TEST_UP (COM7 ocupada; USB nao tem TEST_*); janela 10 s exige reboot+Reset imediatos (sem COM7 impossivel); rescue EMERGENCY_WIPE(0x03)/KILLSWITCH(0x06) exigem UP+sessao PIN e no codigo so incrementam contadores RAM (sem erase NVS; kill real = jig+HSM).
Reset do engine (via wire) limpa so PIN-RAM + wrapper + blobs; slots NVS vendor/OATH/binding sobrevivem (factory_reset apaga so namespace PIN; ctap_reset firmware-level sem chamadores em producao). Nenhum wipe/commit executado: NVS intacta.

### Como re-provisionar manualmente (com COM7 livre + maos)
1. Coordenar o bridge p/ liberar COM7 (ou outra bancada). 2. esptool hard_reset e em <10 s: TEST_UP + INIT + CBOR 0x07 via UART. 3. Confirmar zerado: GetInfo, key LIST 0x00/0 B, wallet LIST 0x00/0 B, getRetries A2 01 01 02 01.
4. Recovery: TEST_PAIRING_OPEN_300 + claim 0x28-0x2D (tools/e2e_user_test.py _claim_once), setPin via ClientPIN P-256/ECDH (protocolo 1 no mesmo arquivo), MC teste com UP + pinAuth e GA roundtrip.
5. Sem Reed-Solomon no firmware (so Shamir DKEK em dkek.rs): validar MC/GA basico; DKEK segue sem opcode wire (Unsupported).

## 4. POWER-LOSS - gap documentado (nao simulavel por software)
Corte fisico de energia no meio de escrita NVS/OTA exige interrupcao eletrica real (rele/corte), fora do alcance desta lane; esptool hard_reset nao equivale (reset limpo, sem tearing). Nenhuma tentativa executada.

## Estado final do device (entrega)
Bin 3F6528EB inalterado; nenhum flash escrito. USB: INIT+PING ok; suite sem flags 60 passed, 21 skipped, 0 failed (pos-reboot). Wedge residual reapareceu sob sondas (fw-log multi-pacote mudo; single-packet vivo) - mesma assinatura falha-L5, re-ocorrencia sem arquivo novo.
NVS intacta (getRetries 0x00/5 B, wallet USB 0x05 need-binding, chaves 132 B preservadas). Bridge externo em COM7 (UART) intocado.
Entrega: backup PARTIAL-OK (logado) | OTA COMMIT nao executado (bloqueado) | wipe+recovery nao executado (bloqueado, reportado) | device saudavel, sem perda.
