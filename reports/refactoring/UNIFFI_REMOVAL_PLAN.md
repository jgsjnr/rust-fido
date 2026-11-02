# UNIFFI_REMOVAL_PLAN — `crates/uniffi-bridge` (zero MPL-2.0)

Owner intent: remove the 9 MPL-2.0 `uniffi* 0.28.3` crates that enter the
workspace graph through `crates/uniffi-bridge` (direct `[dependencies]` +
`[build-dependencies]` `uniffi` with feature `build`). This file is the
phase-1 plan required before coding. Status: PLAN (updated as executed).

## 1. `uniffi::` usage map (lib.rs 1378 lines + build.rs + UDL)

| Site | Usage | Replacement |
|---|---|---|
| `src/lib.rs:17` | `uniffi::include_scaffolding!("aegis_bridge");` — pulls OUT_DIR generated `aegis_bridge.rs` (scaffolding) into the cdylib | Deleted. No macro left. |
| `src/lib.rs:1` | `#![allow(clippy::empty_line_after_doc_comments)]` — waiver *only* for generated scaffolding | Deleted with the scaffolding. |
| `build.rs:2` | `uniffi::generate_scaffolding("src/aegis_bridge.udl")` | `build.rs` deleted (nothing to generate). |
| `Cargo.toml` | `uniffi = { version = "0.28", features = ["build"] }` in `[dependencies]` + `[build-dependencies]` | Both entries removed. Zero new deps added (see §3). |
| `src/aegis_bridge.udl` | Contract: `namespace aegis_bridge` (22 fns) + dictionaries `BleInfo`, `OathCode`, `OtpAuthParsed`, `SecureGuardPolicyDto`, `SecureGuardStatusDto` + `[Error] enum BridgeError` (9 variants) | FROZEN in place as reference doc (header amended, body untouched). Code content archived in the removal commit message. |
| `lib.rs` body | 22 plain `pub fn` (no `#[uniffi::export]`, no UDL-macro attributes — the UDL alone drove codegen) | All 22 kept byte-for-byte as typed Rust (`Vec<u8>`/`String`/structs). Domain logic (BLE frag, AEGN seal/open, COSE parse-only, OATH, app-lock PBKDF2, wallet, SecureGuard passthrough, mini JSON parser) unchanged: same bytes-on-wire, same semantics. |

Scaffolding symbols that disappear from the `.so` (OUT_DIR `aegis_bridge.rs`
today emits these; Kotlin/JNA imports them — full list from
`app-android/.../uniffi/aegis_bridge/aegis_bridge.kt`):
`uniffi_aegis_bridge_fn_func_{app_lock_derive, ble_constants,
ble_split_fragments, cose_key_info, envelope_open, envelope_seal,
envelope_validate, oath_account_from_path, oath_code_valid,
oath_parse_response, oath_remaining_seconds,
otpauth_extract_label_and_secret, secure_guard_encode_{change_pin,
config, lock, provision, recover, unlock, wipe}, secure_guard_parse_status,
totp_format_display, wallet_address, wifi_password_valid}` (22) +
`uniffi_aegis_bridge_checksum_func_*` (22) +
`ffi_aegis_bridge_rustbuffer_{alloc, from_bytes, free, reserve}` +
`ffi_aegis_bridge_rust_future_{poll, cancel, free, complete}_*` +
`uniffi_aegis_bridge_contract_version` / checksum verifier.

## 2. Kotlin/JNA call-site analysis (read-only; NOT edited)

`app-android/.../bridge/AegisBridge.kt` calls only the generated
`uniffi.aegis_bridge.*` Kotlin wrappers. Every one of the 22 native call
sites is wrapped as `if (nativeLoaded) { try { native } catch (_: Throwable)
{} }` (or `catch (t: Throwable)` narrowing `BridgeException` → failure) with
a **100% pure-Kotlin/JVM fallback** below it (`splitFragmentsFallback`,
`envelopeSealFallback`, `MiniCbor`, keccak/RIPEMD-160/bech32/PBKDF2-HMAC-SHA1,
etc.). Consequence: after this change the cdylib (still named
`libaegis_bridge`, so `System.loadLibrary("aegis_bridge")` still succeeds)
no longer exports `uniffi_*`/`ffi_*` symbols → each JNA lookup throws at call
time → caught → deterministic fallback. **No Kotlin edit required, no BLOCKED.**
BLE layer (`AegisBleClient`, `BleContract`, `VendorOps`, `BindingOps`,
`WifiApi`) touches only the `AegisBridge` facade + `BleContract` constants,
never raw symbols. Follow-up lanes (Android owner): hand-write JNA
interfaces against the new C ABI (§3), refresh `proguard-rules.pro`
(`-keep class uniffi.**` becomes stale) and the checked-in generated
`uniffi/aegis_bridge/aegis_bridge.kt`.

## 3. Decision: manual `extern "C"` C-ABI, NO `jni` crate

- Keep all 22 logical signatures (typed Rust stays the source of truth).
- Add a stable `extern "C"` surface with `aegis_*` names (mapping table §4)
  using a uniform protocol: `-> i32` status (`0` ok, negative
  `-BridgeError` discriminant); byte outputs via caller buffer
  `(out: *mut u8, out_cap: usize, out_len: *mut usize)` two-call pattern
  (`out == NULL` queries required length); scalars via `*mut u32`/`*mut u8`
  out-slots; UTF-8 strings as `(ptr,len)` pairs, never NUL-terminated.
- Structured values cross **only at the JNI edge as JSON** (internal domains
  keep typed Rust structs; JSON already enters at `oath_parse_response`):
  `BleInfo`, `OathCode`, `OtpAuthParsed`, `SecureGuardStatusDto` serialize
  out; `SecureGuardPolicyDto` parses in. Hand-rolled escaper, no new deps.
- Why not the `jni` crate (MIT/Apache): Android consumes this library via
  **JNA**, which binds plain C symbols directly — the `jni` crate would only
  add new registry packages to the lock, breaking the purely subtractive
  `273 → 264` cleanup and adding review surface for zero functional gain.
  `unsafe` blocks each carry a `// SAFETY:` comment; no `thread::sleep`
  polling anywhere (`tokio::sync::Notify` rule is vacuous here — no async).
- Absent sensors rule is vacuous (no sensors); no Mock/Fake/Stub providers
  added — fallbacks live in the Android lane, untouched.

## 4. C-ABI name map (new symbols; old `uniffi_*` gone)

`ble_constants→aegis_ble_constants`,
`ble_split_fragments→aegis_ble_split_fragments`,
`envelope_validate→aegis_envelope_validate`,
`envelope_seal→aegis_envelope_seal`, `envelope_open→aegis_envelope_open`,
`cose_key_info→aegis_cose_key_info`, `oath_code_valid→aegis_oath_code_valid`,
`oath_remaining_seconds→aegis_oath_remaining_seconds`,
`oath_parse_response→aegis_oath_parse_response`,
`totp_format_display→aegis_totp_format_display`,
`app_lock_derive→aegis_app_lock_derive`,
`wifi_password_valid→aegis_wifi_password_valid`,
`oath_account_from_path→aegis_oath_account_from_path`,
`otpauth_extract_label_and_secret→aegis_otpauth_extract`,
`wallet_address→aegis_wallet_address`,
`secure_guard_parse_status→aegis_secure_guard_parse_status`,
`secure_guard_encode_{provision, unlock, change_pin, recover, lock, config,
wipe}→aegis_secure_guard_encode_*`, plus `aegis_bridge_version() -> *const
c_char` (`"1.0.0"` static).

## 5. Validation

`cargo check -p uniffi-bridge --all-targets`, `cargo test -p uniffi-bridge`
(all 22 domain tests preserved + new `ffi_c_abi` tests driving every
`aegis_*` symbol incl. NULL-reject, length-query, error-code mapping),
`cargo test -p universal-device-sdk` (parity), `cargo clippy -p uniffi-bridge
--all-targets -- -D warnings`, `cargo deny check licenses bans` (MPL gone),
full workspace `cargo check`. `cargo tree -i uniffi` must print nothing.

## 6. Compliance updates (this lane owns these paths) — EXECUTED 2026-11-02

Actuals: 34 rows dropped everywhere (9 uniffi + 25 uniffi-only
transitive); notices `273 → 239`, inventory `273 → 239` entries,
SBOM `280 → 246` packages/relationships; `overall`/approval lines now
14 entries + removal note; deny PASS with MPL entry deleted.

- `deny.toml`: delete the `MPL-2.0` allow entry + its comment (only uniffi x9
  used it — verified post-prune via `cargo deny`); keep CC0/Unlicense/
  Unicode/BSL entries (still used).
- `THIRD_PARTY_NOTICES.md` + `reports/compliance/third-party-notices.md`:
  drop every row whose crate leaves the lock (the 9 uniffi rows + any
  uniffi-only transitive rows such as askama*/weedle2/goblin if pruned),
  recount registry packages (`273 → N`, N verified from the new lock),
  rewrite the owner-approval line (MPL x9 clause removed).
- `reports/compliance/license-inventory.json`: drop pruned third-party
  entries, refresh counts/date note. (Done: 34 entries removed.)
- `reports/compliance/sbom.spdx.json`: drop pruned package + relationship
  entries. (Done: purely subtractive.)
- `reports/compliance/cargo-deny-final.log`: append dated post-removal run
  section (history preserved). `cargo-deny-output.log` baseline untouched.
- `Cargo.lock`: regenerated by cargo (uniffi packages pruned).
  (Done: 34 pruned, 0 added.)
- Pre-existing staleness left untouched for its owning lane: 26 stale
  pre-0.14 elliptic rows still listed; 36 unlisted 0.14-stack packages
  (RUSTSEC-2026-0387).

## 7. Commit

`refactor(ffi): drop UniFFI runtime for manual JNI (zero MPL)`. No push, no
merge. UDL body archived in the commit message.
