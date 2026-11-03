# HOST-ONLY SWEEP (no hardware)

- Branch: `fd/finalizacao-linux`
- Date (UTC): 2026-11-03
- Scope: host-capable tools only. Board treated as unplugged: anything needing a
  physical device is recorded HW-NEEDED with its exact missing piece, never
  worked around with mocks. No code/config/tool/report edits outside this file.
- Note: `run_all.py` legs rewrite `reports/testing/CONSOLIDATED_RUN.md`,
  `reports/testing/consolidated-result.json` (reverted after the run) and
  `tools/dep_track.py --check` rewrites `reports/refactoring/dep-track.json`
  (left as-found: already dirty before this sweep). Release leg (`--release`)
  skipped to keep the sweep fast — it was green in the sealing run.

## Result table

| # | Tool | Status | Exit | Evidence (3 lines) |
|---|------|--------|------|--------------------|
| 1 | `python tools/webauthn_robot.py` | RAN-PASS | 0 | `==== WEBAUTHN ROBOT: 26/26 PASS in 19.3s ====` / all bridge+firmware+USB+BLE+TOTP+diagnosis checks green / no device, no mocked traffic claimed as evidence |
| 2 | `python tools/run_all.py` (default legs, no `--release`) | RAN-FAIL | 1 | `summary: passed=6 failed=1 advisory_failures=1 skipped=1` / PASS: test-debug 21.4s, firmware-features 7.2s, clippy 9.3s, deny 42.2s, docs, scripts / FAIL: fmt [advisory] + dep-track gate; test-release SKIP (green in sealing run) |
| 2a | └ fmt leg (`cargo fmt --all -- --check`, advisory) | RAN-FAIL | 1 | diffs in `crates/aegis-fido-core/src/crypto/curves.rs:106` (`generate` signature wrap) / `crypto/ecdh.rs:1` (import order `Generate`) / `ctap/extensions_ctap21.rs:42` (`write!` wrap); pre-existing drift, untouched (code edits out of scope) |
| 2b | └ dep-track leg (`tools/dep_track.py --check`, gate) | RAN-FAIL | 2 | `wrote reports/refactoring/dep-track.json (246 files, 23 gods)` / `NEW god-files (score>25, not in allowlist):` / `26.21 crates/aegis-fido-firmware/src/vendor_exec/vendor_tests.rs (lines=371 fan_in=0 fan_out=15)` |
| 3 | `python tools/host_sdk/cli.py --help` | RAN-PASS | 0 | usage prints, options `--self-test --demo --port PORT` / stdlib-only, default port COM7 / no hardware touched |
| 4 | `python tools/host_sdk/cli.py --self-test` | RAN-PASS | 0 | `self-test: 0 failed` / `PASS framing_roundtrip`, `PASS gates_order`, `PASS tlv_*`, `PASS ota_vectors`, `PASS f3_vectors`, `PASS no_hardcoded_secrets` / fully offline, no hardware |
| 5 | `python tools/host_sdk/cli.py --demo` | RAN-PASS | 0 | `demo wallet_gen op=35 tlv_bytes=11` / `demo tlv_hex=0101030203627463080101` / `demo ctaphid pkts=1 port=COM7`; frozen vectors only |
| 6 | `python tools/validate_aegiskey.py --help` | HW-NEEDED | n/a (not run to completion) | script accepts no `--help`: drops straight into the USB CTAPHID battery (CTAPHID Ping + GetInfo + ClientPIN + MakeCredential + GetAssertion) / missing piece: physical ESP32-S3 on native USB (`VID 0x303A / PID 0xAE61`) reachable from this host / not executed further per no-hardware rule |
| 7 | `python tools/depcheck.py` | RAN-FAIL | 1 | `FileNotFoundError: ... 'C:\\t\\xtensa-esp32s3-espidf\\release\\build\\esp-idf-sys-7047177beeb65407\\out\\build\\compile_commands.json'` / hardcoded one-machine DB path, dir does not exist on this host / script unusable here without that ESP-IDF build tree |
| 8 | `python scripts/check-release-clean.py` (read-only) | RAN-FAIL | 1 | `== build lib sem test-mode (release-like) ==` / `artefato: libaegis_fido_firmware.rlib (20184790 B)` / `VAZAMENTO: ['download_mode']` |
| 9 | QEMU (`qemu-system-xtensa` + `scripts/qemu-s3.ps1`) | NOT-AVAILABLE | n/a (not run) | `qemu-system-xtensa` not on PATH (`where.exe`: not found) / repo script is interactive (opens QEMU window; ends on Ctrl+C/close), no headless flag / binary exists only at fixed path `C:\qemu-esp\qemu\bin\qemu-system-xtensa.exe` (+ `C:\t\qemu-flash-16m.bin`), so lane condition (on-PATH + headless repo script, no downloads) not met |
| 10 | `tools/e2e_harness.py` | HW-NEEDED (SKIP, not run) | — | missing piece: live device + app/bridge stream to drive end-to-end |
| 11 | `tools/e2e_zero_press.py` | HW-NEEDED (SKIP, not run) | — | missing piece: physical device for zero-press flow |
| 12 | `tools/hil_test_ds_and_proximity_lock.py` | HW-NEEDED (SKIP, not run) | — | missing piece: hardware-in-the-loop device (DS + proximity lock) |
| 13 | `tools/hil_test_wifi_and_ble_battery.py` | HW-NEEDED (SKIP, not run) | — | missing piece: hardware-in-the-loop device (WiFi + BLE radio) |
| 14 | `tools/wallet_gate_probe.py` | HW-NEEDED (SKIP, not run) | — | missing piece: live device to probe wallet gates |
| 15 | OTA push flows (`tools/ota_server.py` + device push) | HW-NEEDED (SKIP, not run) | — | missing piece: device to receive/push OTA |
| 16 | `tools/live_monitor.py` | HW-NEEDED (SKIP, not run) | — | missing piece: live serial/stream source |
| 17 | `tools/flash_soft.py` | HW-NEEDED (SKIP, not run) | — | missing piece: connected board to flash (flash risk, board unplugged) |
| 18 | `tools/factory_provision.py` | HW-NEEDED (SKIP, not run) | — | missing piece: connected board; burn risk — never run in a host sweep |

## Total

- Rows: 18 (+ 2 sub-rows 2a/2b detailing the run_all failure legs)
- RAN-PASS: 4 (webauthn_robot, host_sdk --help, --self-test, --demo)
- RAN-FAIL: 3 top-level (+2 sub-rows) (run_all overall; depcheck.py crash; check-release-clean VAZAMENTO — sub-rows 2a/2b detail the run_all legs)
- HW-NEEDED: 10 (validate_aegiskey + 9 explicit skips)
- NOT-AVAILABLE: 1 (QEMU)
- Code/config/tool/other-report edits: none. Only this file created.

## Follow-up (sweep findings closed)
- depcheck.py: rewritten to resolve compile_commands.json at runtime (--compile-db override, exit 2 BLOCKED with guidance when absent). Re-run: RC=0 (aegis_usb.c recompiles via xtensa-esp-elf).
- check-release-clean.py download_mode: false positive proven (dis_download_mode/download_mode_disabled rlib metadata only; ack anchored). Re-run exit 0, commit 811ec0d.
- vendor_tests god 26.21: split into vendor_tests/{pin,piv,store,caps}.rs, all below threshold, dep-track leg exit 0, commit 44b7570.

