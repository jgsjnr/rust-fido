# SESSION HANDOFF — fd/finalizacao-linux (estado verdadeiro 2026-11-06)

- Date (UTC): 2026-11-06
- Branch: `fd/finalizacao-linux`
- HEAD: `64e8b7c` (gate 9/9; inclui testes #8/#9: SG parity + bench, fora do 66a95a9)
- Secrets policy: este arquivo contém NENHUM segredo. PIN / recovery codes / material de chaves / passphrases são PROIBIDOS aqui. Onde o procedimento precisa deles, lê-se `<owner-held>`.
- Push: NÃO fazer push a partir deste handoff sem ordem explícita do dono.

---

## 1. Issues FECHADAS (provadas no device)

- **#8 FECHADA** — provada no device, build **4F440673**: `ota_progress` 25% no `0x3A` (surface OTA: LED ramp + CHUNK 5th byte + `0x3A ota_progress` + app Ota2Progress; parseAck tolera ACK 5B).
- **#9 FECHADA** — provada no device, build **4F440673**: bench **24h RAM sem re-provision** (sessão bench estável; sem reprovisionamento).
- **#15 FECHADA** — provada no device, build **4F440673**: `alg` real **-7/-8/-35/-36/-47** (vendor `list_alg`; antes só ES256 efetivo).
- Commit de prova dos testes: `64e8b7c` = "fd: testes #8/#9 (sg parity + bench), fora do 66a95a9".

## 2. Gates (estado verdadeiro)

- Gate host (`python tools/run_all.py`): **9/9 PASS em `64e8b7c`** (`consolidated-result.json` 2026-11-06T00:23:07Z: passed 9, failed 0).
- App (Android unit tests): último registro **225/225 PASS** (release 2026-11-05, commit 4dc19d1; sem rebuild local nesta sessão).
- APK: SHA256 `814C635AF44E624313BF4CEF374ECF7FAC3837F107C08D2140B2A4420655DF0` (prefixo **814C635A**), conforme `reports/release/SHA256SUMS.txt` (atualizado 2026-11-04, HEAD 0e957fc; sem rebuild local — valor registrado, não re-hash nesta sessão).
- Firmware: SHA256 `30AF2DF11ED99C67EB4841064C1335EF185921C41343D055ACE46C91D5B3796A` (prefixo **30AF2DF1**), conforme `reports/release/SHA256SUMS.txt` (binários não commitados; só hashes).
- 5 chaves slots **0–4 provadas** (makeCred + getAssertion com signCount incrementando; nenhuma chave impressa aqui).
- TOTP: **OK** (vetores RFC conferidos; sem segredo registrado aqui).

## 3. Matriz HW (o que PASSou + STOPs)

PASS (placa física ESP32-S3, UART/USB):
- Provision / unlock / lock / wipe round-trip.
- makeCred slots 0–4 + getAssertion (signCount 0→1→2…).
- TOTP vs vetores RFC.
- GET_CAPS `0x3F` + transporte serial/legacy + BLE funnels.
- SG `0x3A–0x3E` via serial legacy + USB-HID.
- Bridge `:5678` (`/bridge/info`, `/bridge/vendor`, `/bridge/ctap`, `/bridge/touch_up`, `/bridge/pairing_open`) com NEED_UP propagado (sem lista vazia como sucesso).
- App bridge-first status + confirmed provision + BLE unlock opcode + ErrorLocked recovery UX.
- Bench 24h RAM sem re-provision (build 4F440673, #9).
- `ota_progress` 25% no `0x3A` (build 4F440673, #8).
- `alg` real -7/-8/-35/-36/-47 via vendor `list_alg` (build 4F440673, #15).

STOPs (não tentar sem dono / hardware / ordem):
- Sem flash sem aprovação do dono (picker nunca escreve flash; `scripts/build-*.ps1 -Flash` só com placa + ordem).
- eFuse: PROIBIDO gravar sem ordem explícita (ver auditoria H-03).
- QEMU/Emu (`qemu-system-xtensa` fora do PATH, script interativo) = NOT-AVAILABLE como aceitação de dispositivo; sims são só protocolo.
- `validate_aegiskey.py` bateria USB CTAPHID direta = HW-NEEDED (S3 USB nativo).
- DTR/RTS auto-reset pode derrubar sessão aberta — re-INIT após reset; UP latch 1-shot ~10 s; janela pairing 60 s via `0x2F`.

## 4. Recovery code ATUAL

- A placa foi **reflasheada** (firmware **30AF2DF1**), logo só vale o recovery code gerado **neste provisionamento atual**.
- NENHUM código escrito neste arquivo (regra dura).
- Onde o dono o guarda: **o dono mantém o recovery code atual fora do repo** (local seguro do dono, `<owner-held>`); quem precisar recuperar pede ao dono, nunca lê deste arquivo/git/logs.
- Fluxo: status provision-confirmed primeiro (bridge-first), depois recovery UX em `ErrorLocked`; não dar wipe sem ordem.

## 5. Pendentes (NÃO fechados)

1. **OTA com detentor**: rodar OTA de verdade com o detentor da chave de release (hook hoje unwired/`0x33` COMMIT ausente por desenho).
2. **FIDO L1**: primeira certificação FIDO (hoje: ausência de claim é o correto).
3. **OOB**: avaliar numeric-comparison/OOB para BLE (pós F-01) + encurtar janela.
4. **wipe-PM #10**: pendente.
5. **Passkeys Reset #12**: pendente.
6. 2 fails test-mode pré-existentes: registrar/corrigir os 2 fails conhecidos (fora do gate 9/9).

## 6. Auditoria (segurança, estado de hoje)

- **Corrigidos: C-01 / C-02 / H-01 / H-02** (verificar relatórios em `reports/compliance/` + commits de fix; não reabrir sem evidência nova).
- **H-03 ABERTO por regra eFuse**: queima de eFuse continua FORBIDDEN sem ordem explícita do dono. `EfuseStorage` expõe só `is_write_protected`; sem `RD_DIS`; prod usa `RamEfuseStorage` keyless + loader; `MockEfuseStorage::with_default_keys` é `cfg(test)`-only. NVS guarda só envelopes AEGN (AES-256-GCM, HKDF master/salt). Dump de flash sozinho = só ciphertext; leitura física de eFuse sem read-protect recuperaria master+salt (modo de falha documentado).
- Médios/baixos: seguem como REVIEW/KEEP nos audits (ex.: F-01 MITM LESC+bonding, F-05 backoff change_pin, SNTP fail-closed, bond expiry 30 d, trademarks 3 medium REVIEW sem remoção, FIDO sem claim de certificação). Detalhe nos arquivos de auditoria; nada novo queimado hoje.

## 7. Como retomar

- `git status --porcelain` + `git log --oneline -n 10` (não commitar sujeira de outra lane).
- Gate: `python tools/run_all.py` (esperado 9/9); app: gradle unit.
- Ponte HW: `tools/host_hardware_android_bridge.py` + `adb -s emulator-5554 reverse tcp:5678 tcp:5678`.
- Flash só com ordem: `scripts/select-capability.ps1 --cap <fido-only|fido-totp> --board devkitc --release` (mede, nunca flasheia) → `scripts/build-*.ps1 -Flash`.

Sem segredos neste arquivo. Sem push.
