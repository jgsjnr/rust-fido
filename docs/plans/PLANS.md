# PLANS — Roadmap, TODO matrix, follow-ups, features, session history

> Style: ASD-STE100. Use short sentences. Use active voice. Use one instruction per sentence.
> Scope: consolidates roadmap, TODO, follow-ups, yellow items, next steps, features, dated sessions as history, and integrated master execution plan.
> Sources: MASTER_EXECUTION_PLAN.md, plans/STATE, MATRIZ-TODO, TASKS-microdetalhe, F2-F3-HIL-MAP, RELEASE-checklist,
> risk-acceptance, SIMULACAO-final, plans/*/plan|architecture|affect, docs/plano-*, finalizacoes,
> firmware-fina, estado-final, seis-produtos, proximos-passos, sessao-20-10, unificacao-worktrees.

---

> [!CAUTION]
> ### CRITICAL HARDWARE SAFETY POLICY — eFuse OTP Protection (`DO NOT EXECUTE`)
> **NEVER EXECUTE COMMANDS TO BURN eFuses ON HARDWARE (`esptool.py burn_efuse`, `BLOCK7`, `SPI_BOOT_CRYPT_CNT`, `SECURE_VERSION`).**  
> eFuse burning in the ESP32-S3 is permanent, irreversible, and locks hardware against reprogramming.  
> All eFuse modules (`efuse_safety_lock.rs`, `GAP-01`, `GAP-03`, `GAP-07`) are guarded by `EFUSE_WRITE_HARD_LOCKED = true` and `feature = "burn-efuse-irreversible-do-not-enable"`. Development boards on `COM7` remain unburned to preserve flashing and test capabilities.

---

## 1. Integrated Master Execution Plan (Fases 0 a 5)

The repository root maintains the canonical [`MASTER_EXECUTION_PLAN.md`](../../MASTER_EXECUTION_PLAN.md).
The master plan organizes work across 6 phases:

| Phase | Title | Scope & Deliverables | Gate Criteria |
|---|---|---|---|
| **Fase 0** | Workspace & Worktree Alignment | Branch `feat/responsive-guard-tray-ssh` created. Consolidated folder hygiene verified. Canonical 4-folder structure in `docs/` locked. | Master plan created at root. Tests baseline confirmed. |
| **Fase 1** | Core & Firmware Hardening | `aegis-fido-core`: ECDH P-256 (`GAP-02`), Glitch Guard (`GAP-06`), CTAP 2.1 extensions (`OPP-02`), Shamir 2-of-3 (`OPP-03/05`), Clear Signing (`OPP-06`). `aegis-fido-firmware`: eFuse safety lock (`GAP-01/03/07`), prod-strict guard (`GAP-04`), SSD1306 code-only driver (`OPP-06`). | `cargo test -p aegis-fido-core` clean. Zero bricking risk. |
| **Fase 2** | Desktop System Tray & Native OpenSSH | `app-tray/`: C# .NET 9 Tray App + Python tray companion. Native OS notifications on plug/unplug. OpenSSH Agent Named Pipe (`OPP-01`). OS Login Companion (`OPP-04`). | Unittest suite in `test_tray_and_ssh_guard.py` PASS. |
| **Fase 3** | Android Companion Alignment | Android app update: Shamir 2-of-3 seed recovery UI, Web3 Clear Signing preview, `hmac-secret` status, eFuse read-only status banner. | `gradlew assembleDebug` compiles. |
| **Fase 4** | Documentation & Architecture Map Sync | Synchronize `PROJECT.md`, `PLANS.md`, `TASKS.md`, `EVALUATION.md`, `AGENT_MAP.md`, `README.md`, and add interactive cards to `ARCHITECTURE-MAP.html`. | All links valid. Interactive map cards verified. |
| **Fase 5** | Non-Destructive Hardware Verification | Non-destructive verification on `COM7`. Execute CTAPHID tests without burning eFuses. | Verification battery passes without OTP writes. |

### 1.1 Summary of 7 Security Gaps (`GAP-01` to `GAP-07`)

1. **GAP-01 (Flash Encryption & Secure Boot v2)**: Flash SPI plain readout threat. Remediated via static audit and hardware specifications in `efuse_safety_lock.rs`, protected with zero-brick developer lock.
2. **GAP-02 (Encrypted PIN Channel)**: Plaintext PIN sniffing on opcode `0x3B`. Remediated via ephemeral ECDH P-256 key exchange + HKDF-SHA256 + AES-256-GCM AEAD (`crates/aegis-fido-core/src/secure_guard/secure_channel.rs`).
3. **GAP-03 (Silicon HMAC-Anchored KDF)**: Offline dictionary brute-force against NVS dump. Remediated via HMAC anchored in eFuse `BLOCK7` with dev fallback (`crates/aegis-fido-core/src/secure_guard/crypto.rs`).
4. **GAP-04 (Presence Simulation Lockout)**: Host malware simulating physical touch (`TEST_UP`). Remediated via strict compile guard `#[cfg(feature = "prod-strict")]` and fail-closed runtime checks (`crates/aegis-fido-firmware/src/prod_strict_guard.rs`).
5. **GAP-05 (Authenticated Host Bridge)**: Cross-origin DNS rebinding and local port tampering on `5678`. Remediated via Bearer Session Token (`X-Aegis-Token`) and Windows Named Pipe ACLs.
6. **GAP-06 (Glitch & Fault Injection Resistance)**: EMFI and voltage glitching bypassing auth branches. Remediated via `GlitchResistantBool` double-checks (`cond && !inv_cond`) and TRNG hardware jitter delay loops (`crates/aegis-fido-core/src/secure_guard/glitch_guard.rs`).
7. **GAP-07 (Silicon Anti-Rollback Monotonic Counter)**: Physical replay of vulnerable firmware. Remediated via eFuse `SECURITY_VERSION` specification in `efuse_safety_lock.rs`.

### 1.2 Summary of 6 Product Opportunities (`OPP-01` to `OPP-06`)

1. **OPP-01 (Native OpenSSH Agent)**: Local Named Pipe (`\\.\pipe\openssh-ssh-agent`) and Unix socket agent delegating `sk-ssh-ed25519@openssh.com` signatures to AegisKey with physical UP enforcement (`app-tray/openssh_native_agent.py`).
2. **OPP-02 (CTAP 2.1 `hmac-secret` & `largeBlobKey`)**: Extensions for KeePassXC/LUKS password vaults and 4 KiB encrypted flash blobs (`crates/aegis-fido-core/src/ctap/extensions_ctap21.rs`).
3. **OPP-03 (Hardware BIP-39 Encrypted Vault)**: Storage of 24-word seeds sealed with silicon hardware KEK and immediate memory `zeroize`.
4. **OPP-04 (OS Login & Proximity Companion)**: Windows Hello Companion Device Framework and Linux PAM (`pam_u2f`) integration with BLE RSSI walk-away auto-lock (`app-tray/os_login_companion.py`).
5. **OPP-05 (Shamir Secret Sharing 2-of-3 SLIP-0039)**: Dividing master seed into 3 shares in Galois Field `GF(256)` (Key 1 + Key 2 + Paper). Any 2 reconstruct the secret (`crates/aegis-fido-core/src/wallet/shamir_slip39.rs`).
6. **OPP-06 (Web3 Clear Signing & Code-Only SSD1306)**: Parser for Ethereum EIP-1559, Bitcoin PSBT, and Solana transactions. Renders into 128x64 monochrome framebuffer driver maintained purely in code (`HARDWARE_I2C_OLED_ATTACHED = false`), preventing blind signing attacks (`crates/aegis-fido-core/src/wallet/clear_signing.rs` and `crates/aegis-fido-firmware/src/oled_ssd1306_code_only.rs`).

---

## 2. Roadmap

| Phase | Goal | Gate |
|---|---|---|
| Fase 0-1 SDK | Freeze capabilities and providers | 38 SDK tests green |
| Fase 1 crypto | Add P-256, AEAD, hash, RSA, extra curves, HRNG | Vectors plus clippy clean per module |
| Fase 2 FIDO | Prove CTAP machine over transport | Host plus device roundtrips |
| Fase 2 OTA | Own `ota.rs` plus `nvs_backend.rs` | Manifest 104 B verified |
| Fase 3 PIV/proximity | Finish transfer plus walk-away | Bonded RF test |
| Fase 4 wallet/OATH | Persist GEN-LIST-CODE-DELETE | NVS post-EN roundtrip |
| Fase 5 release | Run dev to HIL to nightly to pre-release to release | Checklist section 3 green |
| Loop FreeRTOS | Stabilize native tasks plus proximity scheduler | 7/7 bench plus 8/8 suite on HW |
| Master Hardening | Close 7 Gaps and deliver 6 Opportunities | All unit tests pass, eFuse unburned |

- Run phases in order T0, T1, T2, then T3-T12, then T13-T20.
- Close no phase without doc plus build plus flash plus battery on large change.
- Freeze wire from T4. Treat wire change as major plus migration plus HIL.

## 3. TODO matrix (condensed from MATRIZ-TODO)

| ID | Item | Status | Owner |
|---|---|---|---|
| F0-01 | SDK capabilities and providers | Ready | sdk |
| T-CR-01..06 | P-256, AEAD, hash, RSA, extra, HRNG | Ready | firmware-crypto |
| T-FIDO | CTAP machine over CTAPHID and serial | Ready, CTAP 2.1 extensions integrated | firmware-ctap |
| T-OTA | Manifest, stage, apply, rollback | In progress | firmware-ota |
| T-PIV | CCID driver plus applet persist | Partial, handshake done | firmware-piv |
| T-PROX | Beacon, verifier, tick, bonded gates | Ready on host, RF pending | firmware-prox |
| T-WALLET | Store-only slots plus ADDR | Ready | firmware-wallet |
| T-OATH | PUT/LIST/CODE/DELETE on device | Ready | firmware-oath |
| T-BLE | GATT 0xFFFD plus FFF1 plus bonding | Ready | firmware-ble |
| T-WIFI | AP plus station plus mDNS | Ready as C component | firmware-wifi |
| T-DISP | LCD plus headless plus LED table | Ready | firmware-ui |
| T-TRAY | Desktop Companion App (.NET 9 + Python) | Ready in `app-tray/` | desktop-tray |
| T-SSH | Native OpenSSH Agent provider (`OPP-01`) | Ready in `app-tray/openssh_native_agent.py` | desktop-ssh |
| T-SHAMIR | Shamir 2-of-3 in GF(256) (`OPP-03/05`) | Ready in `crates/aegis-fido-core/src/wallet/` | core-wallet |
| T-CLEAR | Web3 Clear Signing + SSD1306 code-only (`OPP-06`) | Ready in core and firmware | core-web3 |
| T-EFUSE | eFuse Safety Lock with zero-brick policy (`GAP-01/03/07`) | Ready in `crates/aegis-fido-firmware/` | firmware-security |

- Apply generation rules: GEN-DEVICE generates on device, GEN-APP-STORE generates in app and stores as envelope, GEN-NA never generates.
- Apply standard gate: `cargo test -p <crate>` plus `cargo clippy -p <crate> --all-targets -- -D warnings` plus section 9 criteria.
- Roll back with `git revert <commit>` or `git checkout -- <scope>`. Never touch outside scope.

## 4. Follow-ups F1-F4 plus yellows plus next steps (single list)

| Item | Severity | Status | Acceptance |
|---|---|---|---|
| F1 PIN plumbing in vendor ops | Medium | Done 20/10, live | PUT with PIN `0x00`, without PIN `0x02` |
| F2 vendor keys and OATH executor | Large | Done 20/10, live | Real GEN-LIST-CODE-DELETE plus NVS post-EN |
| F3 persist `pin_hash` plus retries in NVS | Small | Done 20/10, live | setPIN, EN, token works after reboot |
| F4 CCID/PIV on USB | Large | Enumerated 20/10, handshake 100 percent, transfer pending | OpenSC sees card plus GEN/AUTH P-256 end-to-end |
| Yellow: LED eyes check | User | Open | Confirm order, flicker, green |
| Yellow: BLE bond plus privileged ops with UP | User plus agent | Open | Bond, open 60 s window, run op, close |
| Yellow: walk-away air test | Hardware | Blocked, needs RF bonded | Lock at 15 s away, stay locked on return |
| Yellow: burn eFuse in production | Factory | Blocked, explicit factory approval | Dry-run passes first. Never in lab dev. |
| P0 hardware immediate | Hardware | Open | Needs board on bench |
| P1 end-to-end pairing in app | App | Open | Pair through app screens |
| P2 pending code | Code | Open | Port fob_id FFI plus factory `K_prox` flow |

- Merge the 6 pending lists here. Keep no separate yellow, follow-up, or next-step file.
- Merge the 3 handoffs here as history (see section 6). Keep no separate handoff file.

## 5. Features (one row per plan family)

| Feature | Plan waves | Affect scope | Status |
|---|---|---|---|
| Carteira cripto store | W1 store, W2 policy | Firmware vault plus app screens | Ready, slot policy enforced |
| Conexao BLE fim-a-fim | W1 GATT, W2 bond, W3 app | NimBLE plus Windows agent plus app | Ready on host, RF pending |
| Fido auditoria (NASA) | W0 gates, W1 P0, W2 L0-L5 | Mocks audit plus AEGN v1-v2 | Done, contained mocks, zero hardcoded secrets |
| Fido UX conex | Stage A BLE real | App transport | Approved, in execution |
| PIV BLE proximity | W1 skeleton, W2 beacon, W3 multi-OS | `proximity.rs`, `ble_nimble.rs`, 3 host agents | W1 verified, tick wired, RF pending |
| Seis implementacoes produto | W1 FIDO/PIV/prox, W2 wallet/OATH/OTA | Six product tracks | FIDO ready, PIV partial, prox host-complete |
| Sistema OTA | W1 parallel, W2 sequential | `ota.rs`, `nvs_backend.rs`, server | In progress |
| Unificacao worktrees | W0 base, W1 one-by-one, W2 consolidate | Branches `fd-*` into one | Base recorded, merge rehearsal read-only |
| Validacao USB telas | W0 emulator, W1 serial, W2 screens | Simulator, COM7/COM8, 22 screens | Emulator 22/22 pass, COM7 validated, COM8 pending reflash |
| Desktop System Tray | W1 C# .NET 9, W2 Python, W3 notifications | `app-tray/`, Windows & Linux tray | Ready, notifications on plug/unplug |
| Native OpenSSH Agent (`OPP-01`) | W1 Named Pipe, W2 wire codec, W3 UP hook | `app-tray/openssh_native_agent.py` | Ready, handles sk-ssh-ed25519 |
| OS Login Companion (`OPP-04`) | W1 Hello CDF, W2 PAM u2f, W3 RSSI | `app-tray/os_login_companion.py` | Ready, touch unlock + walk-away |
| Shamir 2-of-3 Backup (`OPP-03/05`)| W1 GF(256), W2 SLIP-39, W3 tests | `crates/aegis-fido-core/src/wallet/` | Ready, 2-of-3 quórum enforced |
| Web3 Clear Signing (`OPP-06`) | W1 Parser, W2 SSD1306 framebuffer | Core wallet + firmware display | Ready, code-only driver decoupled |
| eFuse Safety Lock (`GAP-01/03/07`)| W1 Safety flags, W2 zero-brick lock | Firmware persistence and eFuse | Ready, permanently locked in dev |

- Keep each `task.md` as requirements plus out-of-scope plus acceptance.
- Keep each `architecture.md` as approach plus components plus data flow.
- Keep each `affect.md` as files plus systems plus risk.
- Keep each `plan.md` as dated waves. Treat them as history after merge.

## 6. Release path and risk

- Follow pipeline: dev, HIL, nightly, pre-release, release.
- Run orchestrator: env-check, test, clippy, ESP build, flash, boot `ONLINE and ACTIVE`, simulator demo, Rust suite, e2e, probes, validate, report SHA256.
- Require `--confirm` for destructive steps: wipe, OTA apply, provision load, erase flash, eFuse burn.
- Freeze contract: opcode `0x05 NEED_BINDING` never on USB, `6D 00` honest, `0x2E` rescue, `0x39` PIV enroll, OTA manifest 104 B, PIV slots 24-27, canonical TLV.
- Prove `TEST_*` absence in release with `check-release-clean.py` and `prod_strict_guard.rs`.
- Treat QEMU-S3 as smoke only. Never count QEMU as hardware verification.
- Accept formal risk: no Secure Boot and no Flash Encryption in automatic path. Burn requires explicit factory approval.
- Record SIZE Wave1 offline: keep C baseline 2026-10-18, measure S3 bins, report bytes against factory max 3145728.

## 7. History (dated sessions, summarized)

- 2026-10-19 validacao-usb-telas Step 4: web assisted tab, docs reconciled, store rollback fix, 87/87 crate tests.
- 2026-10-19 Waves 1-2: wallet 17 tests, PIV skeleton plus proximity plus win agent, 291/291 workspace, clippy clean.
- 2026-10-20 F4 session: CCID C driver plus composite descriptor plus FFI plus Rust applet persist, USB 72 plus firmware 250 tests, clippy zero.
- 2026-10-20 finalizacoes: F4 E2E on Linux, RSSI lock integrated, board loop closed.
- 2026-10-20 HANDOFF Wave2 Step3: work done, observed evidence, pending items with reasons.
- 2026-10-20 proximity handoff: Near/Away/Locked plus beacon plus 3 host agents, origin green 34 plus 34/33/33.
- 2026-10-20 FreeRTOS loops 1-4: native tasks, scheduler wiring, FFI MAC, S3 release builds 483936 B then 821808 B, bench 7/7, suite 8/8 on HW.
- 2026-10-21 vigilance: no `entendendo o projeto` branch or lane found, fetch clean, 3-to-5 retry rule set.
- 2026-11-01 Master Plan & Hardening: Established `MASTER_EXECUTION_PLAN.md` covering Fases 0 a 5. Remediated 7 security gaps (`GAP-01` to `GAP-07`) and implemented 6 product opportunities (`OPP-01` to `OPP-06`). Created C# .NET 9 and Python System Tray companion in `app-tray/`, Native OpenSSH agent, Shamir 2-of-3 in GF(256), Web3 Clear Signing parser, SSD1306 code-only virtual framebuffer, ECDH P-256 encrypted PIN channel, Glitch Guard, and eFuse safety lock with zero-brick developer protection.
