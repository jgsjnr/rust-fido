# fd-task — AegisKey FIDO2: auditoria mocks + plano NASA + BLE/Android

## Objetivo
Mapear o projeto, inventariar mocks/hardcodes, validar seguranca embarcada, e planejar atomicizacao estilo NASA + BLE/menu/app Android — SEM mudar comportamento atual.

## Escopo confirmado
- 3 crates (core/usb/firmware) + tools/server.py + web/app.js + t_display_simulator.py
- 19 mocks catalogados (boot MockEfuse 0x5A/0xA5, MockFlash volatil, TOTP literal, server RP fake, mock TOTP JS, chave attestation dev, RESC sem gate, nonce fixo, IV zero)
- Hardcodes P0-P3 prontos para config.rs (lifetimes: eFuse-OTP / NVS-cifrada / efemero-TRNG / fixture-teste)
- Riscos R1-R10 (OWASP/NIST 800-193, NASA Po10)
- Arquitetura alvo L0-L5 (HAL/CryptoCore/Servico/Transporte/App) + GATT 0xFFFD + app Kotlin+UniFFI 6 telas

## REGRAS DURAS DE IMUTABILIDADE (ordem do usuario)
1. Logicas NAO podem mudar — so podem ser REESCRITAS com bytes identicos (CTAP/USB/CBOR/APDU).
2. Branch antes do real: tudo em worktree fd-<topico>-<fase>, nunca direto na main.
3. Somente apos testes (cargo test + ctap_tests + clippy -D warnings verdes + fd-verify + aval humano) substituir tudo.
4. Prova de paridade: mesmo input -> mesmo output; grep mock/hardcode zerado fora de #[cfg(test)].
5. ble/wifi/menu default-off; com features off, binario = baseline.

## Fases
- Fase 0 Continuidade P0 | Fase 1 L0-L5 | Fase 2 P0-P3 + migracao AEGN v1->v2 + fabrica | Fase 3 BLE+menu | Fase 4 App Android
- Waves: W0 gates -> W1 (A/B/C) -> W2 (D/E/F/G) -> W3 seq -> W4 (H/I) -> W5 (J/K)

## Status
fd-task COMPLETE, aguardando fd-review.
