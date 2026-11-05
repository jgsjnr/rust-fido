# SESSION HANDOFF — fd/finalizacao-linux (estado verdadeiro 2026-11-04)

- Date (UTC): 2026-11-04
- Branch: `fd/finalizacao-linux`
- HEADs de referência de hoje:
  - `0e957fc` = gate (app-android: SecureGuard detached sem transporte vivo -> LOCKED fail-closed)
  - `2815787` = fixes (app-android: finalizacao-linux bridge/vault/usb-ble/strings + audit tests)
  - HEAD atual da sessão: ver `git rev-parse --short HEAD` (avançou após merges; referência de hoje continua nos dois SHAs acima)
- Secrets policy: este arquivo contém NENHUM segredo. PIN / recovery codes / material de chaves / passphrases são PROIBIDOS aqui. Onde o procedimento precisa deles, lê-se `<owner-held>`.
- Push: NÃO fazer push a partir deste handoff sem ordem explícita do dono.

---

## 1. Gates de hoje (estado verdadeiro)

- Gate host (run_all / sealing): **9/9 PASS**.
- App (Android unit tests): **197/197 PASS**.
- APK debug/release: SHA256 prefixo **2E88E095** (artefato do dia; rebuild muda o hash — registrar data + commit ao promover).
- Firmware do dia: bin SHA prefixo **30AF2DF1** (placa reflasheada com este bin; ver seção 3).
- 5 chaves slots **0–4 provadas** (makeCred + getAssertion com signCount incrementando; nenhuma chave impressa aqui).
- TOTP: **OK** (vetores RFC conferidos; sem segredo registrado aqui).

## 2. Matriz HW (o que PASSou + STOPs)

PASS (placa física ESP32-S3, UART/USB):
- Provision / unlock / lock / wipe round-trip.
- makeCred slots 0–4 + getAssertion (signCount 0→1→2…).
- TOTP vs vetores RFC.
- GET_CAPS `0x3F` + transporte serial/legacy + BLE funnels.
- SG `0x3A–0x3E` via serial legacy + USB-HID.
- Bridge `:5678` (`/bridge/info`, `/bridge/vendor`, `/bridge/ctap`, `/bridge/touch_up`, `/bridge/pairing_open`) com NEED_UP propagado (sem lista vazia como sucesso).
- App bridge-first status + confirmed provision + BLE unlock opcode + ErrorLocked recovery UX.

STOPs (não tentar sem dono / hardware / ordem):
- Sem flash sem aprovação do dono (picker nunca escreve flash; `scripts/build-*.ps1 -Flash` só com placa + ordem).
- eFuse: PROIBIDO gravar sem ordem explícita (ver auditoria H-03).
- QEMU/Emu (`qemu-system-xtensa` fora do PATH, script interativo) = NOT-AVAILABLE como aceitação de dispositivo; sims são só protocolo.
- `validate_aegiskey.py` bateria USB CTAPHID direta = HW-NEEDED (S3 USB nativo).
- DTR/RTS auto-reset pode derrubar sessão aberta — re-INIT após reset; UP latch 1-shot ~10 s; janela pairing 60 s via `0x2F`.

## 3. Recovery code ATUAL

- A placa foi **reflasheada** (firmware **30AF2DF1**), logo só vale o recovery code gerado **neste provisionamento atual**.
- NENHUM código escrito neste arquivo (regra dura).
- Onde o dono o guarda: **o dono mantém o recovery code atual fora do repo** (local seguro do dono, `<owner-held>`); quem precisar recuperar pede ao dono, nunca lê deste arquivo/git/logs.
- Fluxo: status provision-confirmed primeiro (bridge-first), depois recovery UX em `ErrorLocked`; não dar wipe sem ordem.

## 4. Auditoria (segurança, estado de hoje)

- **Corrigidos: C-01 / C-02 / H-01 / H-02** (verificar relatórios em `reports/compliance/` + commits de fix; não reabrir sem evidência nova).
- **H-03 ABERTO por regra eFuse**: queima de eFuse continua FORBIDDEN sem ordem explícita do dono. `EfuseStorage` expõe só `is_write_protected`; sem `RD_DIS`; prod usa `RamEfuseStorage` keyless + loader; `MockEfuseStorage::with_default_keys` é `cfg(test)`-only. NVS guarda só envelopes AEGN (AES-256-GCM, HKDF master/salt). Dump de flash sozinho = só ciphertext; leitura física de eFuse sem read-protect recuperaria master+salt (modo de falha documentado).
- Médios/baixos: seguem como REVIEW/KEEP nos audits (ex.: F-01 MITM LESC+bonding, F-05 backoff change_pin, SNTP fail-closed, bond expiry 30 d, trademarks 3 medium REVIEW sem remoção, FIDO sem claim de certificação). Detalhe nos arquivos de auditoria; nada novo queimado hoje.

## 5. OPORTUNIDADES (próximos passos, sem dono definido)

1. `alg` no LIST/detalhe **ES256**: expor algoritmo no list + detalhe (hoje só ES256 efetivo).
2. Badge `bench_active` via ponte: sinalizar bench ativo através do bridge (`:5678`) em vez de estado local.
3. TOTP enroll UI: tela de cadastro OATH (hoje só leitura/códigos; sem segredo em log).
4. OTA live com detentor: rodar OTA de verdade com o detentor da chave de release (hook hoje unwired/`0x33` COMMIT ausente por desenho).
5. FIDO L1: primeira certificação FIDO (hoje: ausência de claim é o correto).
6. OOB: avaliar numeric-comparison/OOB para BLE (pós F-01) + encurtar janela.
7. 2 fails test-mode pré-existentes: registrar/corrigir os 2 fails conhecidos de `test-mode` (fora do gate 9/9 de hoje).

## 6. Como retomar

- `git status --porcelain` + `git log --oneline -n 10` (não commitar sujeira de outra lane).
- Gate: `python tools/run_all.py` (esperado 9/9); app: gradle unit (esperado 197/197).
- Ponte HW: `tools/host_hardware_android_bridge.py` + `adb -s emulator-5554 reverse tcp:5678 tcp:5678`.
- Flash só com ordem: `scripts/select-capability.ps1 --cap <fido-only|fido-totp> --board devkitc --release` (mede, nunca flasheia) → `scripts/build-*.ps1 -Flash`.
- Arquivo anterior (histórico longo até `cd22b80`, 2026-11-03) foi substituído por este resumo do dia; história completa no `git log` + `reports/<área>/`.

Sem segredos neste arquivo. Sem push.
