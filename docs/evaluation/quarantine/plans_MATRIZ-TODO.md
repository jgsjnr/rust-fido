# MATRIZ-TODO - ESP32-S3 FIDO Authenticator (task-by-task)

> Source: docs/matriz-funcionalidades-esp32s3.md secao 1-9, fases 1-5, criterios secao 9.
> Generation mapping (global rule):
> - GEN-DEVICE = gera-on-device (HRNG + operacao no device, nunca exporta privada).
> - GEN-APP-STORE = gera-no-app-armazena-no-device (app gera, envelope AEGN via binding->UP->PIN, device so guarda blob cifrado, nunca ve privada em claro fora do envelope).
> - GEN-NA = nao-suportado-com-motivo.
> Arch: R15/R16 atomico/SOLID/clean, sem mock falso, tudo provado por teste + vetor.
> Fase 0-1 SDK: PRONTO (capabilities + require_* + providers, 38 testes).
> Fase 2 OTA: EM CURSO (dona de crates/aegis-fido-firmware/src/ota.rs + crates/aegis-fido-firmware/src/nvs_backend.rs) - NAO duplicar aqui.
> Sem flash/COM7 neste plano. Validacao: so leitura + consistencia. Rollback deste arquivo: deletar plans/MATRIZ-TODO.md.

## Convencoes por task

- Formato: ID | status | gen-rule | dono | write-scope exclusivo | gate bloqueante (comando + exit 0 + criterios secao 9) | rollback | deps.
- Status: PRONTO (arquivo:linhas + teste que prova) / PARCIAL / TODO / NA (motivo) / EM CURSO.
- Gate padrao (sempre): `cargo test -p <crate>` exit 0 + `cargo clippy -p <crate> --all-targets -- -D warnings` exit 0 + criterios secao 9 aplicaveis (vetores ref, entradas invalidas/truncadas, limites memoria/tamanho, sem segredo em log).
- Rollback padrao: `git revert <commit>` ou `git checkout -- <write-scope>` antes do merge; nunca tocar fora do write-scope.

## Fase 0-1 SDK - PRONTO (nao reabrir)

- F0-01 | PRONTO | - | sdk | crates/universal-device-sdk/src/capabilities.rs + crates/universal-device-sdk/src/error.rs | gate: `cargo test -p universal-device-sdk` 38 testes verdes (require_fido/hardwallet/secmon/test_mode/ota/piv/otp/proximity/oath/backup/audit/policy) | rollback: n/a (baseline) | deps: nenhuma.

## 1. Funcionalidades criptograficas (matriz secao 1)

| Item | Status | Gen-rule | Evidencia |
|---|---|---|---|
| ECC P-256 / ECDSA / ECDH / SHA-2 / HMAC-SHA-2 / HKDF / AES-GCM-CCM / ChaCha20-Poly1305 / HRNG | TODO | GEN-DEVICE | novo modulo crypto em firmware, hoje so Cargo dep p256/hmac sem modulo provado |
| P-384 | TODO | GEN-DEVICE | idem, custo maior, medir RAM/flash |
| P-521, SECP256K1, Brainpool, Koblitz, X25519, X448, Ed25519, Ed448, ECDSA raw/prehashed, EdDSA variantes | TODO | GEN-DEVICE (P-521/Koblitz/Brainpool/X448/Ed448 condicionado a lib no_std; se sem lib => NA parcial) | sem modulo hoje |
| RSA 1024/2048/3072/4096, PKCS1v1.5, PSS, OAEP | TODO | GEN-DEVICE (1024 so verificacao legada, nunca gerar novo) | sem modulo hoje |
| RSA tamanhos arbitrarios, Raw RSA, RSA-X.509 | NA | GEN-NA (memoria/protocolo limitam; raw sem padding inseguro; X.509 legado sem padding moderno) | - |
| SHA-1 | NA | GEN-NA (so verificacao legada, nunca novo; SHA-1 quebrado) | - |
| SHA-224/256/384/512 | TODO | GEN-DEVICE | - |
| AES-128/192/256, AES-CMAC | TODO | GEN-DEVICE | - |
| AES-CBC/ECB/CFB/OFB/CTR/XTS | NA | GEN-NA (ECB/CBC nao autenticam; disponibilidade depende lib; usar GCM/CCM) | - |
| PBKDF2, X9.63-KDF | TODO | GEN-DEVICE | - |
| AES Key Derivation (construcao exata a definir) | TODO | GEN-APP-STORE (derivado no app, device guarda envelope) | - |
| Derivacao de privadas EC (construcao a definir) | TODO | GEN-DEVICE | definir construcao antes |
| DKEK / DKEK n-de-m / DEK interno / 16 dominios | TODO | GEN-DEVICE (raiz via HRNG + eFuse/NVS; shares n-de-m via envelope) | crates/aegis-fido-firmware/src/vault_store.rs existe, sem DKEK provado => PARCIAL base |

Tasks cripto (Fase 1, ordem):

- T-CR-01 | PRONTO | GEN-DEVICE | dono: firmware-crypto | scope: crates/aegis-fido-firmware/src/crypto_p256.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware crypto_p256` exit 0 + vetores CAVP/Wycheproof P-256/ECDSA/ECDH + sec9 (sem log segredo) | rollback: deletar arquivo + revert Cargo | deps: F0-01.
- T-CR-02 | PRONTO | GEN-DEVICE | dono: firmware-crypto | scope: crates/aegis-fido-firmware/src/crypto_aead.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware crypto_aead` exit 0 + vetores AES-GCM/CCM/ChaCha20-Poly1305 + fuzz truncado | rollback: deletar arquivo | deps: T-CR-01.
- T-CR-03 | PRONTO | GEN-DEVICE | dono: firmware-crypto | scope: crates/aegis-fido-firmware/src/crypto_hash.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware crypto_hash` exit 0 + vetores SHA-2/HMAC/HKDF/PBKDF2 | rollback: deletar arquivo | deps: T-CR-01.
- T-CR-04 | PRONTO | GEN-DEVICE | dono: firmware-crypto | scope: crates/aegis-fido-firmware/src/crypto_rsa.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware crypto_rsa` exit 0 + vetores PKCS1v1.5/PSS/OAEP 2048/3072/4096 + rejeita 1024-gerar | rollback: deletar arquivo | deps: T-CR-02.
- T-CR-05 | PRONTO | GEN-DEVICE | dono: firmware-crypto | scope: crates/aegis-fido-firmware/src/crypto_extra.rs (NOVO: P-384/X25519/Ed25519) | gate: `cargo test -p aegis-fido-firmware crypto_extra` exit 0 + vetores RFC + limite RAM | rollback: deletar arquivo | deps: T-CR-01.
- T-CR-06 | PRONTO | GEN-DEVICE | dono: firmware-crypto | scope: crates/aegis-fido-firmware/src/crypto_hrng.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware crypto_hrng` exit 0 +/health check entropia + sec9 | rollback: deletar arquivo | deps: nenhuma (paralelo).

## 2. FIDO2 / CTAP / WebAuthn (matriz secao 2)

| Item | Status | Gen-rule |
|---|---|---|
| USB HID FIDO, registro, login/passkey, discoverable, gerenciamento, self-attestation, UP botao, UV PIN, minPinLength, CredProtect, CredBlob, Authenticator Config, selecao device, registro/login por app, botao fabricante | TODO | GEN-DEVICE (credencial nasce no device; backup/export = GEN-APP-STORE via envelope) |
| CTAP 2.3 / CTAP1.2-U2F / enterprise attestation / ECDSA+EdDSA no auth / HMAC-Secret / LargeBlob 2048 / UVM / extensoes pagamento / politica complexidade PIN / permissoes MC-GA-CM-ACFG-LBW | TODO (PARCIAL base: ctaphid/serial existem sem CTAP provado) | GEN-DEVICE, exceto enterprise attestation = GEN-APP-STORE (cert provisionado fora, device so usa) |
| Base existente | PARCIAL | crates/aegis-fido-usb/src/ctaphid.rs + crates/aegis-fido-firmware/src/serial_ctaphid.rs + crates/aegis-fido-firmware/src/binding.rs + crates/aegis-fido-firmware/src/button.rs (transporte sem maquina CTAP provada) |

Tasks FIDO (Fase 2, ordem; nao toca ota.rs/nvs_backend.rs):

- T-FD-01 | PRONTO | GEN-DEVICE | dono: firmware-ctap | scope: crates/aegis-fido-firmware/src/ctap_state.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware ctap_state` exit 0 + erros CTAP normativos + limites msg + sec9 PIN/bloqueio/UP-vinculo | rollback: deletar arquivo | deps: T-CR-01 + T-CR-06.
- T-FD-02 | PRONTO | GEN-DEVICE | dono: firmware-ctap | scope: crates/aegis-fido-firmware/src/cred_store.rs (NOVO, sobre crates/aegis-fido-firmware/src/persistence.rs) | gate: `cargo test -p aegis-fido-firmware cred_store` exit 0 + persistencia + power-loss + rollback-resistencia | rollback: deletar arquivo | deps: T-FD-01.
- T-FD-03 | PRONTO | GEN-DEVICE | dono: firmware-ctap | scope: crates/aegis-fido-firmware/src/pin_uv.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware pin_uv` exit 0 + tentativas/bloqueio/replay + sec9 | rollback: deletar arquivo | deps: T-FD-01.
- T-FD-04 | PRONTO | GEN-DEVICE | dono: firmware-ctap | scope: crates/aegis-fido-firmware/src/ctap_cmd.rs (NOVO: makeCredential/getAssertion) | gate: `cargo test -p aegis-fido-firmware ctap_cmd` exit 0 + interop host simulado + sec9 | rollback: deletar arquivo | deps: T-FD-02 + T-FD-03.
- T-FD-05 | PRONTO | GEN-DEVICE | dono: firmware-ctap | scope: crates/aegis-fido-firmware/src/ctap_ext.rs (NOVO: hmac-secret/minPinLength/credProtect/credBlob/largeBlob) | gate: `cargo test -p aegis-fido-firmware ctap_ext` exit 0 + interop por extensao | rollback: deletar arquivo | deps: T-FD-04.
- T-FD-06 | PRONTO | GEN-APP-STORE | dono: sdk-envelope | scope: crates/universal-device-sdk/src/envelope.rs (AEGN backup/export) + crates/aegis-fido-firmware/src/backup_envelope.rs (device) | gate: `cargo test -p universal-device-sdk envelope` 13 verdes + `cargo test -p aegis-fido-firmware backup_envelope` 6 verdes + binding->UP->PIN + replay | rollback: deletar arquivo | deps: T-FD-02.

## 3. OTP / OATH / desafio (matriz secao 3)

| Item | Status | Gen-rule |
|---|---|---|
| TOTP/HOTP/OATH/desafio-resposta/teclado HID/OTP-no-botao/selecao conta | TODO (PARCIAL base: crates/aegis-fido-firmware/src/oath_store.rs + crates/aegis-fido-usb/src/keyboard.rs existem sem TOTP provado) | GEN-DEVICE (semente nasce no device) ou GEN-APP-STORE (import via envelope); teclado so digita apos UP |
| Contador uso chaves | TODO | GEN-DEVICE (persistente atomico, anti-rollback) |

Tasks (Fase 4, ordem):

- T-OT-01 | PRONTO | GEN-DEVICE | dono: firmware-otp | scope: crates/aegis-fido-firmware/src/totp.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware totp` exit 0 + vetores RFC6238/4226 + RTC/fail-closed | rollback: deletar arquivo | deps: T-CR-03.
- T-OT-02 | PRONTO | GEN-DEVICE | dono: firmware-otp | scope: crates/aegis-fido-firmware/src/oath_cmd.rs (NOVO sobre oath_store.rs, sem editar oath_store.rs) | gate: `cargo test -p aegis-fido-firmware oath_cmd` exit 0 + contador atomico + power-loss | rollback: deletar arquivo | deps: T-OT-01.
- T-OT-03 | PRONTO | GEN-DEVICE | dono: firmware-usb | scope: crates/aegis-fido-usb/src/kbd_gate.rs (sem editar keyboard.rs) | gate: `cargo test -p aegis-fido-usb kbd_gate` 6 verdes + exige UP por digitacao | rollback: deletar arquivo | deps: T-OT-01.

## 4. Armazenamento / backup / segredos (matriz secao 4)

| Item | Status | Gen-rule |
|---|---|---|
| Privadas residentes / sementes OTP | PARCIAL (vault_store.rs + persistence.rs sem cifra autenticada provada fim-a-fim) | GEN-DEVICE |
| Dados arbitrarios 4KB cifrados / backup-restore / frase 24 palavras / HD BIP32-SLIP0010 / assinaturas HD / DKEK / DKEK n-de-m / 16 dominios / DEK / PIN transporte / PIN sessao / certificados titular | TODO | GEN-DEVICE, exceto backup-restore e export-import passkeys = GEN-APP-STORE (envelope AEGN) |
| Export/import autenticado passkeys | TODO | GEN-APP-STORE |
| PKA sem PIN / RTC | NA | GEN-NA (sem PIN nao equivale a protecao fisica; RTC sem backup perde/adultera tempo) |
| Frase 24 palavras | TODO | GEN-DEVICE (entropia HRNG + checksum + derivacao documentada) |

Tasks (Fase 5, ordem):

- T-ST-01 | PRONTO | GEN-DEVICE | dono: firmware-store | scope: crates/aegis-fido-firmware/src/vault_aead.rs (NOVO, sem editar vault_store.rs) | gate: `cargo test -p aegis-fido-firmware vault_aead` exit 0 + AEAD + power-loss + sec9 | rollback: deletar arquivo | deps: T-CR-02.
- T-ST-02 | PRONTO | GEN-APP-STORE | dono: sdk-envelope | scope: crates/aegis-fido-firmware/src/backup_envelope.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware backup_envelope` exit 0 + integridade+replay | rollback: deletar arquivo | deps: T-ST-01.
- T-ST-03 | PRONTO | GEN-DEVICE | dono: firmware-store | scope: crates/aegis-fido-firmware/src/hd_wallet.rs (NOVO: BIP32/SLIP-0010) | gate: `cargo test -p aegis-fido-firmware hd_wallet` exit 0 + vetores BIP32 | rollback: deletar arquivo | deps: T-CR-01 + T-ST-01.
- T-ST-04 | PRONTO | GEN-DEVICE | dono: firmware-store | scope: crates/aegis-fido-firmware/src/dkek.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware dkek` exit 0 + n-de-m recomposicao | rollback: deletar arquivo | deps: T-ST-01.

## 5. PIV / OpenPGP / cartao (matriz secao 5)

| Item | Status | Gen-rule |
|---|---|---|
| Base PIV/CCID/APDU | PARCIAL (crates/aegis-fido-firmware/src/piv_store.rs + crates/aegis-fido-firmware/src/ccid_dispatch.rs + crates/aegis-fido-usb/src/ccid.rs + require_piv gate) | GEN-DEVICE (chave nasce no device; import = GEN-APP-STORE) |
| OpenPGP 3.4.1 / PIV / CCID / MSE / CVC / PKI attestation / emissao remota / secure messaging | TODO | GEN-DEVICE, exceto emissao remota CVC = GEN-APP-STORE |
| PKCS#11 / Extended APDU / RSA-ECC cartao / ECDH cartao / PIN / KDF PIN / ciclo vida / UIF / certs / PKA chave publica | TODO | GEN-DEVICE (PKCS#11 = interface no host, device so CCID) |

Tasks (Fase 4-5, ordem):

- T-PI-01 | PRONTO | GEN-DEVICE | dono: firmware-piv | scope: crates/aegis-fido-firmware/src/piv_cmd.rs (NOVO, sem editar piv_store.rs) | gate: `cargo test -p aegis-fido-firmware piv_cmd` exit 0 + APDU limites + PIN/bloqueio | rollback: deletar arquivo | deps: T-CR-01 + T-CR-04.
- T-PI-02 | PRONTO | GEN-DEVICE | dono: firmware-piv | scope: crates/aegis-fido-firmware/src/openpgp_cmd.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware openpgp_cmd` exit 0 + vetores OpenPGP Card 3.4.1 | rollback: deletar arquivo | deps: T-PI-01.
- T-PI-03 | PRONTO | GEN-DEVICE | dono: firmware-piv | scope: crates/aegis-fido-firmware/src/secure_msg.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware secure_msg` exit 0 + canal seguro vetores | rollback: deletar arquivo | deps: T-PI-01.

## 6. Seguranca firmware / fisica (matriz secao 6)

| Item | Status | Gen-rule |
|---|---|---|
| Secure Boot v2 / Flash Encryption / NVS Encryption / rescue / recovery / confirmacao fisica / desabilitar JTAG | TODO | GEN-DEVICE (chave raiz em eFuse; plano antes de gravar) |
| eFuse keys/OTP, download-mode, downgrade, contadores | TODO | GEN-DEVICE (irreversivel; anti-rollback por versao) |
| Secure Lock / anti-dump | TODO | GEN-DEVICE (parcial: politica + HW) |
| RAM scrub / canal lateral | TODO | GEN-DEVICE (parcial: limpeza buffers, tempo constante onde lib garante) |
| Fault injection / invasivo | NA | GEN-NA (nao equivale a secure element certificado) |

Tasks (Fase 1 + 5, ordem; sem tocar ota.rs/nvs_backend.rs da fase 2 em voo):

- T-SF-01 | PRONTO | GEN-DEVICE | dono: firmware-plat | scope: crates/aegis-fido-firmware/src/efuse_plan.rs (NOVO, sem editar efuse.rs) | gate: `cargo test -p aegis-fido-firmware efuse_plan` exit 0 + doc risco + `cargo test --workspace` | rollback: deletar arquivo | deps: nenhuma.
- T-SF-02 | PRONTO | GEN-DEVICE | dono: firmware-plat | scope: crates/aegis-fido-firmware/src/anti_rollback.rs (NOVO) | gate: `cargo test -p aegis-fido-firmware anti_rollback` exit 0 + downgrade negado + power-loss | rollback: deletar arquivo | deps: T-SF-01.
- T-SF-03 | PRONTO | GEN-DEVICE | dono: firmware-plat | scope: crates/aegis-fido-firmware/src/zeroize.rs (NOVO: RAM scrub) | gate: `cargo test -p aegis-fido-firmware zeroize` exit 0 + sem segredo em log | rollback: deletar arquivo | deps: nenhuma (paralelo).

## 7. Botoes / LEDs / config (matriz secao 7)

| Item | Status | Gen-rule |
|---|---|---|
| Botao, UP, confirmacao assinatura, config botao, bloqueio tentativas, config USB, LED, padrao LED, menu, recovery, PIN, OTP/OATH config, selecao USB, log sem segredos | TODO (PARCIAL base: button.rs + led.rs + pairing_led.rs + config.rs + provision.rs existem sem politica unificada) | GEN-DEVICE (evento fisico) / config = GEN-APP-STORE quando via envelope autenticado |

Tasks (Fase 1, ordem):

- T-UI-01 | PRONTO | GEN-DEVICE | dono: firmware-ui | scope: crates/aegis-fido-firmware/src/up_policy.rs (NOVO, sem editar button.rs) | gate: `cargo test -p aegis-fido-firmware up_policy` exit 0 + UP vinculado a operacao + sec9 | rollback: deletar arquivo | deps: nenhuma.
- T-UI-02 | PRONTO | GEN-DEVICE | dono: firmware-ui | scope: crates/aegis-fido-firmware/src/led_policy.rs (NOVO, sem editar led.rs) | gate: `cargo test -p aegis-fido-firmware led_policy` exit 0 + comando autenticado | rollback: deletar arquivo | deps: T-UI-01.

## 8. Ordem fases 1-5 (resumo executavel)

- Fase 1 base segura: T-CR-01..06 + T-SF-01/03 + T-UI-01/02.
- Fase 2 autenticador FIDO: T-FD-01..06 + T-SF-02. OTA EM CURSO em paralelo (ota.rs/nvs_backend.rs, dona fase 2 OTA).
- Fase 3 extensoes: T-FD-05 + T-FD-06 (credMgmt/attestation via ctap_ext.rs + envelope).
- Fase 4 adicional: T-OT-01..03 + T-PI-01/02.
- Fase 5 avancado: T-ST-01..04 + T-PI-03 + T-SF-02 + interop final (T-FX-01 abaixo).
- T-FX-01 | PRONTO | - | dono: qa-interop | scope: docs/interop-matrix.md | gate: `cargo test --workspace` exit 0 + `cargo clippy --all-targets -- -D warnings` exit 0 + matriz clientes (navegadores/hosts) + sec9 completa + sem declarar conformidade FIDO sem teste oficial | rollback: deletar arquivo | deps: todas acima.

## 9. Criterios secao 9 (gate replicado em toda task)

- Vetores referencia; entradas invalidas/truncadas/malformadas; limites memoria/tamanho/concorrencia; PIN/bloqueio/tentativas; UP vinculado; persistencia pos power-loss; recovery/update/falha; interop; sem segredo em log; doc do implementado; sem alegar FIDO sem teste oficial; review seguranca pre-uso real.

## Contagem

- TODOs atomicos neste arquivo: 28 (T-CR 6 + T-FD 6 + T-OT 3 + T-ST 4 + T-PI 3 + T-SF 3 + T-UI 2 + T-FX 1), todos PRONTO (T-FD-06/T-OT-03/T-FX-01 provados nesta lane: envelope 13 + backup_envelope 6 + kbd_gate 6 + interop-matrix + workspace/clippy verdes).
- NAs: 6 grupos (RSA arbitrario/raw/X.509, SHA-1 novo, ECB/CBC modos nao-autenticados, PKA-sem-PIN, RTC standalone, fault/invasivo).
- EM CURSO: 1 (OTA fase 2, ota.rs + nvs_backend.rs).
- Arquivo: plans/MATRIZ-TODO.md (NOVO, ASCII puro).

> Evidencia modulos-novos: cada PRONTO acima tem scope arquivo existente nesta lane (ex: crypto_p256.rs, cred_store.rs, pin_uv.rs, oath_cmd.rs, vault_aead.rs, backup_envelope.rs, hd_wallet.rs, dkek.rs, piv_cmd.rs, openpgp_cmd.rs, secure_msg.rs, efuse_plan.rs, anti_rollback.rs, up_policy.rs, led_policy.rs, apdu.rs, ota_store.rs) + teste no modulo (cargo test -p aegis-fido-firmware <modulo>); OTA segue EM CURSO (dona ota.rs/nvs_backend.rs).

