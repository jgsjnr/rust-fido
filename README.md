# AegisKey Authenticator — FIDO2 / WebAuthn Hardware Security Key

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-100%25-orange.svg)](https://www.rust-lang.org)
[![FIDO2](https://img.shields.io/badge/FIDO2-CTAP%202.1-green.svg)](https://fidoalliance.org)
[![FreeRTOS](https://img.shields.io/badge/OS-FreeRTOS%20SMP-blue.svg)](https://www.freertos.org)
[![Desktop Tray](https://img.shields.io/badge/.NET%209-C%23%20%7C%20Python-purple.svg)](app-tray/)
[![Style: ASD-STE100](https://img.shields.io/badge/Standard-ASD--STE100-success.svg)](docs/project/PROJECT.md)

> **Specification Language:** ASD-STE100 (Simplified Technical English).  
> **Firmware Language:** 100 percent native Rust (`#![no_std]` core with alloc).  
> **Target Hardware:** ESP32-S3 DevKitC-1 (Xtensa LX7 dual-core 240 MHz) and LilyGO TTGO T-Display (ESP32 classic).  
> **USB Identifiers:** Vendor ID `0x303A` (Espressif Systems), Product ID `0xAE61` (AegisKey S3).  
> **Desktop System Tray:** C# (.NET 9 Windows) and Python multiplatform companion in `app-tray/`.  
> **Management Web Cockpit:** `http://127.0.0.1:5678/dashboard`  
> **Interactive Architecture Map:** `http://127.0.0.1:5678/architecture` or [ARCHITECTURE-MAP.html](docs/project/ARCHITECTURE-MAP.html)  
> **License:** GNU General Public License v3.0 (GPLv3).

---

> [!CAUTION]
> ### CRITICAL HARDWARE SAFETY POLICY — eFuse OTP Protection (`DO NOT EXECUTE`)
> **NEVER EXECUTE COMMANDS TO BURN eFuses ON HARDWARE (`esptool.py burn_efuse`, `BLOCK7`, `SPI_BOOT_CRYPT_CNT`, `SECURE_VERSION`).**  
> eFuse burning in the ESP32-S3 is permanent, irreversible, and locks hardware against reprogramming.  
> All eFuse modules (`efuse_safety_lock.rs`, `GAP-01`, `GAP-03`, `GAP-07`) are guarded by `EFUSE_WRITE_HARD_LOCKED = true` and `feature = "burn-efuse-irreversible-do-not-enable"`. Development boards on `COM7` remain unburned to preserve flashing and test capabilities.

---

## 1. Project Overview

AegisKey is a high-security hardware authenticator key and cryptographic guardian.
The key runs completely in native Rust on ESP32-S3 microcontrollers.
The project removes all legacy C SDK dependencies.
The project strictly follows standards from the FIDO Alliance (CTAP 2.1), W3C WebAuthn, NIST, BIP-32/39, SLIP-0039, OATH (RFC 4226/6238 compatible layer), OpenSSH (`sk-ssh-ed25519@openssh.com`), and OS 2.0 platform capability descriptors.

AegisKey protects user credentials through a four-layer architecture.
AegisKey uses a Zero-Trust Authorization Barrier in the FreeRTOS router.
Standard WebAuthn operations (`0x01..0x0B`) remain accessible and fail-open.
Protected vendor operations (`0x20..0x39`) require an authenticated session in the Secure Guard engine.

---

## 2. Consolidated Project Documentation

All project documentation lives in four canonical directories:

| Document | Path | Scope and Purpose |
|---|---|---|
| **System Architecture** | [`docs/project/PROJECT.md`](docs/project/PROJECT.md) | Vision, hardware maps, 4-layer architecture, security invariants, system tray companion, and module capabilities. |
| **Interactive Map** | [`docs/project/ARCHITECTURE-MAP.html`](docs/project/ARCHITECTURE-MAP.html) | Interactive block diagram, connection wires, component cards, and opcode registry. |
| **Execution Plans** | [`docs/plans/PLANS.md`](docs/plans/PLANS.md) | Wave roadmaps, sprint execution tracking, and integrated master execution plan. |
| **Master Plan (Root)** | [`MASTER_EXECUTION_PLAN.md`](MASTER_EXECUTION_PLAN.md) | Master plan for Fases 0 to 5, mapping 7 security gaps and 6 product opportunities. |
| **Tasks & Checklists** | [`docs/tasks/TASKS.md`](docs/tasks/TASKS.md) | Step-by-step implementation tasks (T0-T20), HIL testing checklists, and release gates. |
| **Verification & Tests** | [`docs/evaluation/EVALUATION.md`](docs/evaluation/EVALUATION.md) | Test reports, gap analysis, product opportunity specs, automated benchmarks, and historical quarantine. |

---

## 3. Four-Layer System Architecture

Open the interactive graphical topology in your browser:  
👉 **[Open ARCHITECTURE-MAP.html](docs/project/ARCHITECTURE-MAP.html)** (or access `http://127.0.0.1:5678/architecture` when the bridge runs).

```text
+--------------------------------------------------------------------------+
| LAYER 1: CLIENTS & USER INTERFACES                                       |
|   • Android Companion App (dev.aegiskey.app): Clean Arch + Atomic Design  |
|   • Desktop Companion System Tray App (app-tray/): C# .NET 9 & Python     |
|   • Web Management Dashboard (tools/web_dashboard/index.html): Port 5678 |
+--------------------------------------------------------------------------+
                                    │
                                    ▼
+--------------------------------------------------------------------------+
| LAYER 2: TRANSPORT, BRIDGE JNI, AGENTS & UNIVERSAL SDK                   |
|   • Native OpenSSH Agent (app-tray/openssh_native_agent.py, OPP-01)       |
|   • OS Login & Proximity Companion (app-tray/os_login_companion.py,OPP-04)|
|   • UniFFI Bridge (crates/uniffi-bridge -> libaegis_bridge.so JNI)        |
|   • Universal Device SDK (crates/universal-device-sdk -> CBOR DTOs)      |
|   • Host Hardware Bridge (tools/host_hardware_android_bridge.py)         |
|   • Physical Links: USB OTG CTAPHID (GPIO 19/20), BLE GATT (0xFFFD),      |
|     Wi-Fi SoftAP (192.168.4.1), and Serial UART (COM7 @ 115200 bps)      |
+--------------------------------------------------------------------------+
                                    │
                                    ▼
+--------------------------------------------------------------------------+
| LAYER 3: ESP32-S3 FIRMWARE & FREERTOS MULTITASKING                       |
|   • FreeRTOS Tasks: UsbCtaphid, BleGatt, SecureGuard (32KB TWDT), Prox    |
|   • Central Router & Zero-Trust Barrier (freertos_route.rs):             |
|     - FIDO2 Standard (0x01..0x0B): Exempt (Fail-Open for WebAuthn)       |
|     - Vendor Ops (0x20..0x39): Intercepted by authorize_vendor_opcode    |
|     - Secure Guard Wire (0x3A..0x3E): Admin, Provisioning, Wipe          |
|   • Code-Only OLED SSD1306 128x64 Driver (oled_ssd1306_code_only.rs,OPP-06)|
|   • Production Isolation Guard (prod_strict_guard.rs, GAP-04)            |
|   • Physical UI: GPIO 0 (BOOT Button, UP), GPIO 48 (WS2812 RGB LED)       |
+--------------------------------------------------------------------------+
                                    │
                                    ▼
+--------------------------------------------------------------------------+
| LAYER 4: CRYPTOGRAPHIC CORE NO_STD & SILICON HARDWARE                    |
|   • SecureGuardEngine: 10 States (0x00..0x09), PBKDF2, constant_time     |
|   • ECDH P-256 + HKDF + AEAD Encrypted Channel (secure_channel.rs, GAP-02)|
|   • Glitch Guard & Fault Injection Resistance (glitch_guard.rs, GAP-06)  |
|   • CTAP 2.1 Extensions: hmac-secret & largeBlobKey (OPP-02)             |
|   • Shamir Secret Sharing 2-of-3 in GF(256) (shamir_slip39.rs, OPP-03/05)|
|   • Web3 Clear Signing Parser (clear_signing.rs, OPP-06)                 |
|   • Silicon eFuse Safety Lock (efuse_safety_lock.rs, GAP-01/03/07) [LOCK] |
|   • Dual Partition Flash: nvs (0x9000, 24KB) + storage (0x310000, 896KB) |
+--------------------------------------------------------------------------+
```

---

## 4. Hardware Pinout and Resources

| Peripheral | Resource / Pin | Description and Invariant |
|---|---|---|
| **Presence Button (UP)** | `GPIO 0` (BOOT) | Active-low input with internal pull-up and 50 ms debouncer. Enforces physical presence for WebAuthn, OTP, and factory reset. |
| **RGB LED WS2812** | `GPIO 48` | Addressable 24-bit GRB LED (800 kHz). Communicates real-time security state across the device lifecycle (see table below). |
| **Native USB OTG** | `GPIO 19` (D-) / `GPIO 20` (D+) | Native Full-Speed USB 2.10 PHY. Exposes 64-byte CTAPHID composite endpoint (VID `0x303A`, PID `0xAE61`). |
| **UART Serial Console** | `GPIO 43` (TX) / `GPIO 44` (RX) | Default console and hardware diagnostic bridge at 115200 bps 8N1 (`COM7`). |
| **I2C OLED Bus (Code)** | `GPIO 4` (SDA) / `GPIO 5` (SCL) | Virtual driver in code (`HARDWARE_I2C_OLED_ATTACHED = false`) for SSD1306 128x64 display framebuffer. |
| **Master Key OTP** | `BLOCK7` (256 bits) | ESP32-S3 eFuse One-Time-Programming block. Hardware-locked in development. |
| **Device Salt OTP** | `BLOCK8` (256 bits) | ESP32-S3 eFuse One-Time-Programming block. Hardware-locked in development. |
| **Flash Configuration** | `nvs` partition (`0x9000`) | 24 KiB SPI flash partition for device configuration and PIN attempt state. |
| **Encrypted Storage** | `storage` partition (`0x310000`) | 896 KiB SPI flash partition for encrypted resident passkeys and wallet seeds (`sg_record_v1` format). |

### 4.1 Official WS2812 RGB LED Status Palette (`GPIO 48`)

| State / Condition | Color Pattern | RGB `(R, G, B)` | Hex Code | Meaning for User |
|---|---|---|---|---|
| **Unprovisioned (0 Keys)** | **Soft Cyan Solid** | `(0, 40, 60)` | `#00283C` | Key connected with clean slate; awaiting master PIN setup in App. |
| **Secure Guard Locked** | **Amber / Orange Solid** | `(60, 25, 0)` | `#3C1900` | Vault, wallets, TOTP, and SSH agent locked. (WebAuthn passkeys ready). |
| **Secure Guard Unlocked** | **Emerald Green Solid** | `(0, 60, 15)` | `#003C0F` | Session active! Full access to vault, Web3 wallets, and OpenSSH agent. |
| **User Presence (UP)** | **Cyan / White Fast Blink** (5 Hz) | `(0, 90, 120)` | `#005A78` | Physical touch requested. Tap the `BOOT` button (`GPIO 0`) to authorize. |
| **Pairing Window (60s)** | **Breathing Blue** (1 Hz) | `(0, 50, 100)` | `#003264` | 60-second window open to bond with smartphone or new workstation. |
| **Rate-Limited Penalty** | **Alternating Red / Amber** | `(80, 10, 0)` | `#500A00` | Incorrect PIN penalty active (2s, 5s backoff delay). |
| **Recovery Required (5th Failure)** | **Intense Red Solid / Alert** | `(90, 0, 0)` | `#5A0000` | 5 PIN failures. Normal keypad locked; 16-char Recovery Code mandatory. |
| **Locate Key (Wink)** | **Rapid Cyan/Green/White Flashes** | Multi-color | Dynamic | Visual locator triggered by *Wink / Locate Key* command. |

> Detailed technical specifications, timing diagrams, and state machines are documented in [`docs/project/PROJECT.md`](docs/project/PROJECT.md#10-definitive-guide-to-ws2812-rgb-led-states-and-visual-feedback-gpio-48).

---

## 5. Repository Directory Layout

```text
e:\projetos\fido\
├── Cargo.toml                              # Root Cargo Workspace manifest
├── .cargo/config.toml                      # Target and compiler toolchain configuration
├── MASTER_EXECUTION_PLAN.md                # Master Execution Plan (Fases 0 a 5, Gaps & Opportunities)
├── AGENT_MAP.md                            # Canonical documentation routing map for agents
├── docs/                                   # Canonical project documentation (4 official folders)
│   ├── project/                            # System architecture, maps, and specifications
│   │   ├── PROJECT.md                      # System design and hardware specification (ASD-STE100)
│   │   └── ARCHITECTURE-MAP.html           # Interactive visual architecture and connection map
│   ├── plans/                              # Execution plans, milestones, and wave roadmaps
│   │   └── PLANS.md                        # Active plans and integrated master execution plan
│   ├── tasks/                              # Task checklists and microtasks
│   │   └── TASKS.md                        # Verification tasks (T0-T20) and checklist gates
│   ├── evaluation/                         # Benchmarks, test evaluation, and quarantine archive
│   │   └── EVALUATION.md                   # Automated verification reports, security gap & OPP specs
│   └── test-hooks.md                       # Test tripwire hooks for firmware integrity
├── crates/                                 # Modular Rust workspace crates
│   ├── aegis-fido-core/                    # Pure #![no_std] cryptographic engines & SecureGuardEngine
│   │   ├── src/secure_guard/secure_channel.rs  # GAP-02: ECDH P-256 + HKDF + AEAD PIN channel
│   │   ├── src/secure_guard/crypto.rs          # GAP-03: Silicon HMAC-anchored KDF
│   │   ├── src/secure_guard/glitch_guard.rs    # GAP-06: GlitchResistantBool + EMFI double-check
│   │   ├── src/ctap/extensions_ctap21.rs       # OPP-02: CTAP 2.1 hmac-secret & largeBlobKey
│   │   ├── src/wallet/shamir_slip39.rs         # OPP-03/05: Shamir 2-of-3 in GF(256)
│   │   └── src/wallet/clear_signing.rs         # OPP-06: Web3 Clear Signing parser
│   ├── aegis-fido-firmware/                # ESP32-S3 FreeRTOS kernel, drivers, router, and NVS persistence
│   │   ├── src/efuse_safety_lock.rs        # GAP-01/03/07: eFuse safety lock [DO NOT BURN]
│   │   ├── src/prod_strict_guard.rs        # GAP-04: prod-strict vs test-mode isolation
│   │   └── src/oled_ssd1306_code_only.rs   # OPP-06: Code-only 128x64 SSD1306 framebuffer
│   ├── aegis-fido-usb/                     # 64-byte CTAPHID framer, channel locks, and CCID ISO 7816-4
│   ├── universal-device-sdk/               # Cross-platform CBOR DTOs and capability enforcement gates
│   └── uniffi-bridge/                      # UniFFI C-ABI/JNI bindings for Android Kotlin (libaegis_bridge.so)
├── app-tray/                               # Desktop Companion App (System Tray + Native OS Integrations)
│   ├── dotnet/AegisKeyTray/                # C# .NET 9 Windows System Tray App & Pipe Server
│   ├── openssh_native_agent.py             # OPP-01: Native OpenSSH agent (sk-ssh-ed25519)
│   ├── os_login_companion.py               # OPP-04: Windows Hello CDF & Linux PAM companion
│   ├── aegis_tray.py                       # Cross-platform Python system tray implementation
│   ├── hardware_client.py                  # Hardware client for serial / CTAPHID transport
│   └── test_tray_and_ssh_guard.py          # Automated verification suite for Desktop Companion
├── app-android/                            # Android companion app in Kotlin (dev.aegiskey.app)
│   └── app/src/main/java/dev/aegiskey/app/ # Clean Architecture + Atomic Design (4 navigation tabs)
├── tools/                                  # Development, bridge, and verification tools
│   ├── host_hardware_android_bridge.py     # Python serial-to-HTTP bridge on port 5678 (Bearer Token)
│   ├── web_dashboard/                      # Standalone Web Cockpit (42 REST endpoints)
│   │   └── index.html                      # Single-page dashboard application
│   └── test_web_dashboard_endpoints.py     # Automated endpoint validation suite
└── scripts/                                # CI/CD automation and release hygiene scripts
    └── check-release-clean.py              # Release cleanliness verifier
```

---

## 6. Zero-Trust Security Model & Hardened Subsystems

1. **Exempt Standard Flow (`0x01..0x0B`):**
   - WebAuthn operations (`MakeCredential`, `GetAssertion`, `GetInfo`, `ClientPin`) do not require the Secure Guard administrative PIN.
   - Standard operations fail open to maintain full compatibility with browsers and operating systems.
2. **Protected Vendor Flow (`0x20..0x39`):**
   - Custom vendor operations (Passkey Vault, OATH TOTP seeds, BIP-32/39 Wallets, PIV Applet, and OTA updates) pass through `authorize_vendor_opcode`.
   - The router rejects requests if the Secure Guard state is not `Unlocked (0x04)`.
3. **Encrypted Admin Channel (GAP-02):**
   - PIN entry and administrative payloads on opcode `0x3B` use an ephemeral ECDH P-256 key exchange, HKDF derivation, and AES-256-GCM AEAD encryption.
4. **Glitch & Fault Injection Resistance (GAP-06):**
   - Critical authorization branches employ `GlitchResistantBool` double-checks with bitwise inverse confirmation (`cond && !inv_cond`) combined with hardware TRNG jitter delay loops.
5. **eFuse Hard-Lock Policy (GAP-01/03/07):**
   - Irreversible hardware eFuse burning is permanently disabled by default (`EFUSE_WRITE_HARD_LOCKED = true`) to safeguard devkits on `COM7`.
6. **Timing Attack Protection:**
   - All secret comparisons use constant-time algorithms (`constant_time_eq_32`).

---

## 7. End-to-End User Journeys (Zero-to-Hero)

AegisKey supports 8 comprehensive operational journeys, validated across the Android App, Desktop System Tray, Host Bridge, and ESP32-S3 firmware:

| Journey | Key Interactions | Firmware & Silicon Flow | WS2812 Visual State |
|---|---|---|---|
| **1. First Use & Clean Slate** | USB plug-in, factory reset trigger (`0x2B`). | Formats `nvs` and `storage` partitions. Wipes all keys to clean `0` baseline. | **Soft Cyan Solid** (`#00283C`) |
| **2. Secure Guard Provisioning** | Master PIN entry in Android / Desktop App. | ECDH P-256 channel (`GAP-02`), 10,000 PBKDF2 iterations, hardware HMAC anchor (`GAP-03`), 16-char Recovery Code. | Soft Cyan -> **Emerald Green** (`#003C0F`) |
| **3. Keys & Web3 Clear Signing** | WebAuthn passkey registration, crypto transfers. | secp256k1/P-256 generation, Clear Signing 128x64 OLED preview (`OPP-06`), Shamir 2-of-3 backup (`OPP-05`). | **Cyan/White Fast Blink** (5 Hz) -> Green |
| **4. Lock & Unlock Gatekeeper** | Click *Lock Now* or disconnect USB. | Revokes session tokens (`zeroize`). Hides vault (`403`). Standard FIDO2 WebAuthn remains open. | Green -> **Amber / Orange** (`#3C1900`) |
| **5. Desktop Tray & Passwordless SSH** | Hotplug detection, Git commit/push, `ssh user@srv`. | OpenSSH Agent Named Pipe (`\\.\pipe\openssh-ssh-agent`), `sk-ssh-ed25519` with touch (`GPIO 0`), auto-purge on unplug. | **Amber** -> **Emerald Green** |
| **6. Proximity Lock & Workstation Security** | Walk away (> 3m) with phone/key. | Kalman-filtered BLE RSSI (< -80 dBm) triggers OS lock. Return (> -65 dBm) enables zero-password touch unlock. | Green -> Lockscreen -> Touch Unlock |
| **7. Emergency Recovery & Rate Limiting** | Incorrect PIN entry (1-5 failures). | 2s/5s progressive backoff delays. 5th failure locks keypad (`RecoveryRequired`). 16-char recovery unseals vault. | **Alternating Red/Amber** -> **Intense Red** (`#5A0000`) |
| **8. Silicon Security & Zero-Brick Safety** | Hardware security verification on devkits (`COM7`). | Flash Encryption & Secure Boot ready in code, but strictly hard-locked (`EFUSE_WRITE_HARD_LOCKED = true`). | Dev boards protected against bricking |

> Complete step-by-step documentation with Mermaid sequence diagrams and protocol payloads is available in [`docs/project/PROJECT.md`](docs/project/PROJECT.md#11-end-to-end-user-journeys-zero-to-hero-journeys-1-to-8).  
> Formal test logs, verification vectors, and audit trails are documented in [`docs/evaluation/EVALUATION.md`](docs/evaluation/EVALUATION.md#6-auditoria-de-verificação-e-matriz-técnica-cores-do-led-ws2812-gpio-48-e-jornadas-ponta-a-ponta-j1-a-j8).

---

## 8. Build and Verification Commands

### Execute Full Workspace Rust Test Suite
```powershell
cargo test
```

### Run Static Analysis and Linter
```powershell
cargo clippy --all-targets -- -D warnings
```

### Run Desktop Companion System Tray and OpenSSH Agent Tests
```powershell
python -m unittest app-tray/test_tray_and_ssh_guard.py
```

### Build C# .NET 9 Desktop System Tray App
```powershell
dotnet build app-tray/dotnet/AegisKeyTray/AegisKeyTray.csproj -c Debug
```

### Start Desktop System Tray Companion
```powershell
python app-tray/aegis_tray.py
```

### Start the Host Hardware Bridge and Web Dashboard
```powershell
python tools/host_hardware_android_bridge.py
```
Open `http://127.0.0.1:5678/dashboard` in your browser.  
Open `http://127.0.0.1:5678/architecture` to view the interactive architecture map.

### Build the Android Companion App
```powershell
cd app-android
./gradlew assembleDebug
```

---

## 9. License

This project is free software licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE) file for the complete license terms.
