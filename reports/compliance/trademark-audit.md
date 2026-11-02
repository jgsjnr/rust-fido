Trademark audit -- AegisKey
=========================

Audit only. No removals were performed. No renaming was performed.
Scope: repository text including README.md, docs, web UI, app-tray, and crate sources.
Rule: protocol and standard names used as functional references stay (KEEP). Product or brand names in claims,
and unregistered namespace identifiers, need review (REVIEW). Risk is low, medium, or high.

Findings
--------
| Reference | Location | Classification | Risk | Action |
| FIDO2, FIDO Alliance, CTAP 2.1, CTAP 2.3 | README.md, docs/project/PROJECT.md, crates/universal-device-sdk/src/ctap21.rs, crates/uniffi-bridge/src/lib.rs, web/app.js | FUNCTIONAL_PROTOCOL_REFERENCE, no certification claimed | low | KEEP factual, no branding change |
| W3C WebAuthn | README.md, docs/project/PROJECT.md, web/index.html, web/app.js | FUNCTIONAL_PROTOCOL_REFERENCE | low | KEEP factual, no branding change |
| NIST P-256, NIST SP 800-73-4, PIV applet | crates/aegis-fido-core wallet and oath modules, crates/aegis-fido-usb/src/piv, crates/universal-device-sdk/src/hardwallet.rs | FUNCTIONAL_PROTOCOL_REFERENCE, standard identifiers | low | KEEP factual, no branding change |
| BIP-32, BIP-39, SLIP-0039 | README.md, docs, crates/aegis-fido-core/src/wallet/shamir_slip39.rs, web UI, app-tray strings | FUNCTIONAL_PROTOCOL_REFERENCE, open standard numbers | low | KEEP factual, no branding change |
| YKOATH, OATH, RFC 6238 | crates/aegis-fido-core/src/oath, crates/aegis-fido-usb/src/ccid.rs, crates/uniffi-bridge/src/lib.rs | FUNCTIONAL_PROTOCOL_REFERENCE with compatibility wording | low | KEEP factual, REVIEW any endorsement claim before release |
| OpenSSH, sk-ssh-ed25519 at openssh.com | README.md, docs/tasks/TASKS.md, app-tray/openssh_native_agent.py | FUNCTIONAL_PROTOCOL_REFERENCE | low | KEEP factual, no branding change |
| Microsoft OS 2.0 Descriptors, Windows Hello CDF, Windows Named Pipe | crates/aegis-fido-usb/src/winusb.rs, README.md, docs | FUNCTIONAL_PROTOCOL_REFERENCE, descriptor and API names | low | KEEP factual, no branding change |
| Espressif, ESP32-S3, ESP32 classic, VID 0x303A | README.md, docs/project/PROJECT.md, web UI, espidf target config | FUNCTIONAL_PROTOCOL_REFERENCE, hardware identifiers | low | KEEP factual, do not present the VID as owned |
| Google Authenticator compatibility wording | web/index.html line 211, web dashboard callouts | REVIEW, third-party product name in a compatibility claim | medium | REVIEW wording, prefer generic OATH application text, no removal performed in this audit |
| dev.aegiskey.app reverse-DNS application id | app-android/app/build.gradle.kts, README.md | REVIEW, unregistered namespace claim with possible store conflict | medium | REVIEW ownership and store registration, no change performed |
| FIDO certification status | no certification claim found, wording is follows and compatible | REVIEW, absence of claim is correct until certified | medium if claimed | KEEP absence, do not claim certification, REVIEW before any cert mark use |

Smallest safe remediation
---------------------------
- Keep all FUNCTIONAL_PROTOCOL_REFERENCE rows as they are. They describe protocols the code implements.
- Reword the Google Authenticator compatibility claim to a generic OATH application reference, or keep it only
  with documented permission. Severity medium. Owner: docs and web UI maintainers.
- Confirm ownership of the dev.aegiskey.app namespace and its store registration. Severity medium.
- Never claim FIDO certification until the certification process completes. Severity medium.
- No removals were performed in this audit.

Severity summary: 8 low KEEP rows, 3 medium REVIEW rows, 0 high rows.
