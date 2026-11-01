# AegisKey Authenticator — FIDO2 / WebAuthn Hardware Security Key

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-100%25-orange.svg)](https://www.rust-lang.org)
[![FIDO2](https://img.shields.io/badge/FIDO2-CTAP%202.1-green.svg)](https://fidoalliance.org)
[![FreeRTOS](https://img.shields.io/badge/OS-FreeRTOS%20SMP-blue.svg)](https://www.freertos.org)
[![Style: ASD-STE100](https://img.shields.io/badge/Standard-ASD--STE100-success.svg)](docs/project/PROJECT.md)

> **Specification Language:** ASD-STE100 (Simplified Technical English).  
> **Firmware Language:** 100 percent native Rust (`#![no_std]` core with alloc).  
> **Target Hardware:** ESP32-S3 DevKitC-1 (Xtensa LX7 dual-core 240 MHz) and LilyGO TTGO T-Display (ESP32 classic).  
> **USB Identifiers:** Vendor ID `0x303A` (Espressif Systems), Product ID `0xAE61` (AegisKey S3).  
> **Management Web Cockpit:** `http://127.0.0.1:5678/dashboard`  
> **Interactive Architecture Map:** `http://127.0.0.1:5678/architecture` or [ARCHITECTURE-MAP.html](docs/project/ARCHITECTURE-MAP.html)  
> **License:** GNU General Public License v3.0 (GPLv3).

---

## 1. Project Overview

AegisKey is a high-security hardware authenticator key.
The key runs completely in native Rust on ESP32-S3 microcontrollers.
The project removes all legacy C SDK dependencies.
The project strictly follows standards from the FIDO Alliance, W3C WebAuthn, NIST, BIP-32/39, YKOATH, and Microsoft OS 2.0 Descriptors.

AegisKey protects user credentials through a four-layer architecture.
AegisKey uses a Zero-Trust Authorization Barrier in the FreeRTOS router.
Standard WebAuthn operations (`0x01..0x0B`) remain accessible and fail-open.
Protected vendor operations (`0x20..0x39`) require an authenticated session in the Secure Guard engine.

---

## 2. Consolidated Project Documentation

All project documentation lives in four canonical directories:

| Document | Path | Scope and Purpose |
|---|---|---|
| **System Architecture** | [`docs/project/PROJECT.md`](docs/project/PROJECT.md) | Vision, hardware maps, 4-layer architecture, security invariants, and module capabilities. |
| **Interactive Map** | [`docs/project/ARCHITECTURE-MAP.html`](docs/project/ARCHITECTURE-MAP.html) | Interactive block diagram, connection lines, component cards, and opcode registry. |
| **Execution Plans** | [`docs/plans/PLANS.md`](docs/plans/PLANS.md) | Wave roadmaps, sprint execution tracking, and feature development plans. |
| **Tasks & Checklists** | [`docs/tasks/TASKS.md`](docs/tasks/TASKS.md) | Step-by-step implementation tasks, HIL testing checklists, and release gates. |
| **Verification & Tests** | [`docs/evaluation/EVALUATION.md`](docs/evaluation/EVALUATION.md) | Test reports, automated benchmarks, static analysis, and historical quarantine. |

---

## 3. Four-Layer System Architecture

Open the interactive graphical topology in your browser:  
👉 **[Open ARCHITECTURE-MAP.html](docs/project/ARCHITECTURE-MAP.html)** (or access `http://127.0.0.1:5678/architecture` when the bridge runs).

```text
+--------------------------------------------------------------------------+
| LAYER 1: CLIENTS & USER INTERFACES                                       |
|   • Android Companion App (dev.aegiskey.app): Clean Arch + Atomic Design  |
|   • Web Management Dashboard (tools/web_dashboard/index.html): Port 5678 |
+--------------------------------------------------------------------------+
                                    │
                                    ▼
+--------------------------------------------------------------------------+
| LAYER 2: TRANSPORT, BRIDGE JNI & UNIVERSAL SDK                           |
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
|   • Physical UI: GPIO 0 (BOOT Button, UP), GPIO 48 (WS2812 RGB LED)       |
|   • Central Router & Zero-Trust Barrier (freertos_route.rs):             |
|     - FIDO2 Standard (0x01..0x0B): Exempt (Fail-Open for WebAuthn)       |
|     - Vendor Ops (0x20..0x39): Intercepted by authorize_vendor_opcode    |
|     - Secure Guard Wire (0x3A..0x3E): Admin, Provisioning, Wipe          |
+--------------------------------------------------------------------------+
                                    │
                                    ▼
+--------------------------------------------------------------------------+
| LAYER 4: CRYPTOGRAPHIC CORE NO_STD & SILICON HARDWARE                    |
|   • SecureGuardEngine: 10 States (0x00..0x09), PBKDF2, constant_time     |
|   • Domain Engines: CTAP (5 Curves), Wallets (BIP32/39), OATH, PIV, DS   |
|   • Dual Partition Flash: nvs (0x9000, 24KB) + storage (0x310000, 896KB) |
|   • Silicon eFuse OTP: BLOCK7 (256-bit Key) + BLOCK8 (256-bit Salt)      |
+--------------------------------------------------------------------------+
```

---

## 4. Hardware Pinout and Resources

| Peripheral | Resource / Pin | Description and Invariant |
|---|---|---|
| **Presence Button (UP)** | `GPIO 0` (BOOT) | Active-low input with internal pull-up and 50 ms debouncer. Enforces physical presence for WebAuthn, OTP, and factory reset. |
| **RGB LED WS2812** | `GPIO 48` | Addressable 24-bit GRB LED. Shows breathing blue/green for presence, green pulse for success, and red flash for errors. |
| **Native USB OTG** | `GPIO 19` (D-) / `GPIO 20` (D+) | Native Full-Speed USB 2.10 PHY. Exposes 64-byte CTAPHID composite endpoint (VID `0x303A`, PID `0xAE61`). |
| **UART Serial Console** | `GPIO 43` (TX) / `GPIO 44` (RX) | Default console and hardware diagnostic bridge at 115200 bps 8N1 (`COM7`). |
| **Master Key OTP** | `BLOCK7` (256 bits) | ESP32-S3 eFuse One-Time-Programming block. Stores the root device master key. |
| **Device Salt OTP** | `BLOCK8` (256 bits) | ESP32-S3 eFuse One-Time-Programming block. Stores the root derivation salt. |
| **Flash Configuration** | `nvs` partition (`0x9000`) | 24 KiB SPI flash partition for device configuration and PIN attempt state. |
| **Encrypted Storage** | `storage` partition (`0x310000`) | 896 KiB SPI flash partition for encrypted resident passkeys and wallet seeds (`sg_record_v1` format). |

---

## 5. Repository Directory Layout

```text
e:\projetos\fido\
├── Cargo.toml                              # Root Cargo Workspace manifest
├── .cargo/config.toml                      # Target and compiler toolchain configuration
├── docs/                                   # Canonical project documentation
│   ├── project/                            # System architecture, maps, and specifications
│   │   ├── PROJECT.md                      # System design and hardware specification (ASD-STE100)
│   │   └── ARCHITECTURE-MAP.html           # Interactive visual architecture and connection map
│   ├── plans/                              # Execution plans, milestones, and wave roadmaps
│   │   └── PLANS.md                        # Active plans and sprint records
│   ├── tasks/                              # Task checklists and microtasks
│   │   └── TASKS.md                        # Verification tasks and checklist gates
│   └── evaluation/                         # Benchmarks, test evaluation, and quarantine archive
│       └── EVALUATION.md                   # Automated verification reports and logs
├── crates/                                 # Modular Rust workspace crates
│   ├── aegis-fido-core/                    # Pure #![no_std] cryptographic engines & SecureGuardEngine
│   ├── aegis-fido-usb/                     # 64-byte CTAPHID framer, channel locks, and CCID ISO 7816-4
│   ├── aegis-fido-firmware/                # ESP32-S3 FreeRTOS kernel, drivers, router, and NVS persistence
│   ├── universal-device-sdk/               # Cross-platform CBOR DTOs and capability enforcement gates
│   └── uniffi-bridge/                      # UniFFI C-ABI/JNI bindings for Android Kotlin (libaegis_bridge.so)
├── app-android/                            # Android companion app in Kotlin (dev.aegiskey.app)
│   └── app/src/main/java/dev/aegiskey/app/ # Clean Architecture + Atomic Design (4 navigation tabs)
├── tools/                                  # Development, bridge, and verification tools
│   ├── host_hardware_android_bridge.py     # Python serial-to-HTTP bridge on port 5678
│   ├── web_dashboard/                      # Standalone Web Cockpit (42 REST endpoints)
│   │   └── index.html                      # Single-page dashboard application
│   └── test_web_dashboard_endpoints.py     # Automated endpoint validation suite
└── scripts/                                # CI/CD automation and release hygiene scripts
    └── check-release-clean.py              # Release cleanliness verifier
```

---

## 6. Zero-Trust Security Model

AegisKey incorporates a strict Zero-Trust Authorization Barrier:

1. **Exempt Standard Flow (`0x01..0x0B`):**
   - WebAuthn operations (`MakeCredential`, `GetAssertion`, `GetInfo`, `ClientPin`) do not require the Secure Guard administrative PIN.
   - Standard operations fail open to maintain full compatibility with browsers and operating systems.
2. **Protected Vendor Flow (`0x20..0x39`):**
   - Custom vendor operations (Passkey Vault, OATH TOTP seeds, BIP-32/39 Wallets, PIV Applet, and OTA updates) pass through `authorize_vendor_opcode`.
   - The router rejects requests if the Secure Guard state is not `Unlocked (0x04)`.
3. **Ten Discrete States (`0x00..0x09`):**
   - `Unprovisioned (0x00)`, `Provisioning (0x01)`, `Locked (0x02)`, `Authenticating (0x03)`, `Unlocked (0x04)`, `RecoveryRequired (0x05)`, `RateLimited (0x06)`, `WipePending (0x07)`, `WipeInProgress (0x08)`, `ErrorLocked (0x09)`.
4. **Timing Attack Protection:**
   - All secret comparisons use constant-time algorithms (`constant_time_eq_32`).
5. **Brute-Force Rate Limiting:**
   - Five consecutive PIN failures enforce progressive backoff penalties and selective factory wipe.

---

## 7. Build and Verification Commands

### Execute Unit and Integration Tests
```powershell
cargo test
```

### Run Static Analysis and Linter
```powershell
cargo clippy --all-targets -- -D warnings
```

### Start the Host Hardware Bridge and Web Dashboard
```powershell
python tools/host_hardware_android_bridge.py
```
Open `http://127.0.0.1:5678/dashboard` in your browser.  
Open `http://127.0.0.1:5678/architecture` to view the interactive architecture map.

### Validate Web Dashboard REST Endpoints
```powershell
python tools/test_web_dashboard_endpoints.py
```

### Build the Android Companion App
```powershell
cd app-android
./gradlew assembleDebug
```

---

## 8. License

This project is free software licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE) file for the complete license terms.
