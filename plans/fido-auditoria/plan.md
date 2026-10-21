# plan.md — Plano NASA consolidado (fd-task, CONFIRMADO)

## Immutability Gates (regra do usuario)
- G0: nenhuma semantica muda; rewrite com paridade comprovada.
- G1: worktree fd-fido-<fase> antes de qualquer codigo real; main intocavel.
- G2: merge so com cargo test --workspace + ctap_tests + clippy -D warnings verdes + fd-verify + aval humano.
- G3: ble/wifi/menu default-off; default build = baseline.

## Wave 0 — Gates (bloqueante)
- fd-review escopo Fase 0 + baseline testes verdes.

## Wave 1 — Fase 0 P0 (paralelo S)
- A: config.rs bounds + pin retries persistido (config.rs, auth/pin.rs)
- B: RealEfuse+NVS + sign_count atomico (platform/efuse.rs, cred/sign_count.rs)
- C: nonce TRNG + RESC gate UP+PIN (crypto/nonce.rs, ctap/resc.rs)

## Wave 2 — Fase 1 L0-L5 (paralelo M)
- D: UpPolicy + erros tipados | E: Transport trait (move USB sem logica) | F: CryptoCore puro + Vault split | G: watchdog + no-alloc-loop

## Wave 3 — Fase 2 (sequencial M)
- P0->P1->P2->P3 + aegn_v1_to_v2.rs idempotente + factory_provision.py --dry-run

## Wave 4 — Fase 3 (paralelo L, default-off)
- H: BLE GATT 0xFFFD NimBLE esp-idf-svc + bonding+UP | I: menu Boot/Home/Detail/Vault/Locked/Busy + coexistencia USB>BLE>WiFi

## Wave 5 — Fase 4 (XL)
- J: uniffi-bridge (depende W2) | K: app Kotlin 6 telas + BLE/WiFi envelope (depende J+W4)

## Success
- Fase 0: MockEfuse so em test; nonce TRNG; RESC exige UP+PIN; retries/sign_count persistentes.
- Fase 1: clippy zero; USB bytes inalterados; sem alloc no loop.
- Fase 2: grep hardcode zerado fora de testes; migracao com rollback.
- Fase 3: features off = baseline; on = bonding+UP enforced.
- Fase 4: E2E BLE ok; nenhum secret em logcat; replay/clone rejeitados.

## Testes por fase
- efuse/nonce/resc_gate/sign_count unit+integracao; L0-L5 clippy; migration_tests; --features ble,menu; ./gradlew test + e2e BLE.
- Regressao global: cargo test --test ctap_tests.

## Emenda fd-review (CONFIRM-REVIEW 2026-10-18)
- G0-paridade: excecoes que DEVEM mudar (PIN IV/salt zero->TRNG, nonce AEAD) em `excecoes-paridade.md`; resto com golden vectors.
- G3-features: criar ble=[] menu=[] wifi=[] default-off antes da W4; CI diff build+size.
- W1 sequencial: nvs_schema.md -> RESC-gate -> nonce -> retries/sign_count; teste power_loss_mid_write + resc_sem_up_nega/pin_nega.
- W3: dual-slot + backup + verify-after-write + rollback emulador + factory_provision --dry-run + readback sha256.
- W5: Play Integrity + pinning + root/Frida + FLAG_SECURE + allowBackup=false + biometric-bound + zeroize onPause.
- Auditoria: attestation key fora de prod (cfg test), Mock* so em test (CI grep FAIL).

## Diretriz MAX-ESP (ordem do usuario 2026-10-18)
- Sempre usar o maximo possivel do ESP32-S3: dual-core LX7 240MHz (USB/CTAP core dedicado alta prioridade), 512KB SRAM (buffers separados USB/BLE/WiFi, sem partilha), flash maxima (dual-slot A/B + NVS + snapshots), NimBLE tunado (MTU max, max conn, buffers BLE max), WiFi so sob demanda, eFuse OTP total (BLOCK7/8 + serial unico), watchdog + coexistencia USB>BLE>WiFi.
- Medir com `idf.py size` a cada wave; proibir regressao de RAM/flash sem justificativa.

## Wave 2.5 (2026-10-18) — agregado wave0+wave1+wave2, build S3 OK
- merge 28a31fe (nada excluido/adicionado); host 85/85; S3 release exit 0 em 21.58s; ELF 2.188.136 B; bins baseline intactos.
- SEM flash (bloqueado por constraint, aguarda ordem + porta).

## Wave 3 (2026-10-18/19) — P0-P3 DONE 110/110
- config.rs bounds + identity defaults=bytes + provision loader + migracao dual-slot idempotente + factory --dry-run + ci-grep; micro-fix rollback/salt-guard/AUDIT-PREP; commit 35685eb.
- SEM merge na main.

## Pacote UX + vinculo + recovery (19/10) — commit 14e9ecc, 232 testes
- Pareamento 5s wirado (PairingManager no loop, classifica 5s>2s), mDNS aegiskey-*.local, WiFi station NVS + AP fallback, vinculo exclusivo (claim/challenge/verify/release + NEED_BINDING), split uso-livre/config-com-vinculo, bypass test-mode, recovery PIN 4-6 + chave-reserva, UI facil (Explain, dropdowns, USB host, WiFi/mDNS, geradores HW/app, LogScreen ao vivo).
- Flash: COM7 S3 (espflash, boot sem panic, claimed=false) + COM8 LilyGO (0x10000, ONLINE, USB mounted, sem panic). APK debug 56.5MB.
- Secure boot: SEMPRE desligado (guard ci-guard-secureboot PASS, sdkconfigs mínimos, sem burn de segurança).
