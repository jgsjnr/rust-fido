# Seis implementações do produto — status e regressão (Step 6)

Data: 2026-10-19/20 · Baseline: `main@4b28aa4` → HEAD `0743cbb` + árvore de
trabalho (Wave2-Step3 killswitch + diag LED, não commitados).

Gates por item: `cargo test --workspace` + `clippy --all-targets -- -D
warnings` + suítes Python + build S3/classic + flash COM7 + prova em
hardware. Secure-boot sempre OFF (`ci-guard-secureboot.ps1` PASS);
envelope AEGN v1 byte-idêntico; `ble/wifi/menu/proximity` default-off =
baseline.

## 1. FIDO2 / Passkey (R-01) — pronto, regressão verde

CTAP 2.3 (MakeCred/GetAssertion/ClientPIN/credMgmt/largeBlobs/reset),
5 curvas, CBOR, USB HID + serial CTAPHID 64B. Regressão: `ctap_tests`
8/8 + `test_aegiskey_rust.py` 8/8 + GetInfo via simulador.

## 2. PIV seguro (R-02) — Wave 1 commitado

`usb/piv.rs` (SELECT/VERIFY/AUTH/PUT/GEN, slots 9A/9C/9D/9E, PIN 6–8 3x /
PUK 8 3x em NVS, zeroize), `ccid.rs`, `docs/piv-ble-proximity.md`.
Testes: 67 usb (secure_tests PIV) + vetores NIST nos testes.

## 3. Proximidade BLE + agents (R-03) — completo host

Firmware `proximity.rs` (lock <-75 dBm/10s, histerese, nunca
auto-unlock, bonding obrigatório) + `ble_gatt 0xFFFD`. Agents walk-away
lock-only nos 3 SO: `tools/host/win|linux|macos/proximity_agent.py`
cada um com `test_proximity_agent.py` (20/21/21 testes) + README +
`--self-test`/`--simulate`. Falta: pareamento real fob↔host em campo
(depende de hardware do usuário; backend bleak injetável pronto).

## 4. Cofre / TOTP (R-04) — pronto, regressão verde

YKOATH RFC 6238/4226, `vault_store` + `migrations/vault_v7` dual-slot,
`oath_store`, display real. Regressão: firmware 224 testes + migration
3 testes + power-loss injetado nos testes.

## 5. Killswitch (R-05) — Wave2-Step3 na árvore, verificado host

Opcode `0x2E` nos 3 transportes (`rescue.rs` 280L, UP latch uso único,
remoto fail-closed sem PIN), fachada `otp/mod.rs`, dispatch
`serial_ctaphid` + fronteira `ble_gatt`, scripts SO via
`tools/killswitch.py --dry-run --emit-ps1 --emit-pam --emit-udev`
(confirm-gated, jig+HSM pendentes p/ kill real). Testes:
`test_killswitch.py` 13/13. Pendente: commit atômico + plumbing
ClientPIN→`pin_uv_authenticated` (CtapEngine opaco) + gesto hold 5s
(colide com pareamento — decisão UX).

## 6. Dongle Ed25519 (R-06) — Wave 1 commitado

Challenge-response via WinUSB bulk (`winusb.rs` + envelope AEGN +
`challenge_response.rs`, só Ed25519) + verificação no app/bridge.
Testes: winusb 5/5 + bridge 13/13.

## Fora dos seis (R-07/R-08/R-09) — pendente, com critério

- **Carteira fim-a-fim** (ops BLE wallet + NVS rede→slot + UI
  rede/endereço + web): `wallet/` (types/address/store) e aba web
  assisted existem (store-only); falta o transporte BLE + telas.
  Bloqueio: exige SDK Android p/ build do app (fora deste host).
- **App** (pós-pareamento, telas Bitcoin, menus por operação): parcial
  na árvore (`AegisBleClient/BleContract/Press/ScanPair`); telas
  Bitcoin pendentes. Bloqueio: idem SDK Android.
- **Firmware fina** (bridge computa público, S3 menor): auditoria thin
  em `docs/firmware-fina.md` done; mover getters pendente.

## Artefatos de prova (nesta sessão)

- `cargo test --workspace` 406 passed · clippy zero · `test-all.ps1` ok.
- S3 `aegis-app-esp32s3-devkitc.bin` 2.646.512 B / diag
  `aegis-app-esp32s3-diag.bin` 2.656.320 B (< factory 3.145.728).
- Flash COM7 hash-verified + boot `ONLINE & ACTIVE`.
- `TEST_PAIRING_OPEN` → janela 60s + `adv on (pairing=1)` + `AegisKey`
  over-the-air no MAC do device.
