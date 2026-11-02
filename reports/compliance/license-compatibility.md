License compatibility -- GPL-3.0-only workspace
===================================================

Scope: workspace Cargo.toml plus 6 member crates.
Evidence: Cargo.toml, crates/Cargo.toml files, Cargo.lock, LICENSE.
This file makes no legal determination. It records audit status only.

Policy
------
- Workspace license is GPL-3.0-only, declared in Cargo.toml and shipped as LICENSE at the repo root.
- Rule: every distributable (source archive, firmware image, installer, container) must comply with GPL-3.0-only.
- Provide Corresponding Source, preserve notices, and license the whole conveyed work under GPL-3.0-only.
- Commercial reuse requires GPL compliance. No proprietary relicensing path exists without separate permission from all copyright holders.
- Disclose source, build scripts, and Installation Information for User Products where the license requires it.

Dependency classes
-------------------
- Permissive linked dependencies (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib) are compatible as linked
  dependencies under GPL-3.0-only, provided attribution and license texts are preserved. Status: REVIEW.
  Rationale: permissive status here is by convention only and is UNVERIFIED for each crate in this audit.
  Remediation: confirm each crate with cargo deny check licenses before release.
- Copyleft dependencies (LGPL-2.1, GPL-2.0, GPL-3.0-only, AGPL-3.0) trigger a per-linking REVIEW.
  None were observed in the top-30 inventory. AGPL network interaction needs a separate review. Status: REVIEW.
  Remediation: any future GPL or AGPL addition is BLOCKED until legal review clears it.
- Unknown or undeclared license means do not ship. Status: BLOCKED by default.
- Workspace own code (6 crates inheriting license.workspace=true) is distributed under GPL-3.0-only.
  Status: VERIFIED_MANIFEST_INHERITED for the manifest field. Distribution duties remain.

Why nothing third-party is marked PASS
----------------------------------------
- Cargo.lock carries name, version, source, and checksum only. It carries no license field.
- License labels for third-party crates were therefore NOT verified in this audit.
- All 30 inventoried crates are recorded as REVIEW in license-inventory.json.
- A PASS requires artifact evidence: cargo deny check licenses with the repo deny.toml,
  or cargo license output stored with the release record.

Smallest safe remediation
---------------------------
1. Keep deny.toml at the repo root and run cargo deny check licenses advisories bans sources.
2. Resolve every REVIEW and BLOCKED entry before release.
3. Keep THIRD_PARTY_NOTICES.md in sync with Cargo.lock on every dependency change.
4. For commercial distribution, attach the source offer, preserve LICENSE and notices, and document
   Installation Information handling for ESP32-S3 User-Product shipments.

Severity
--------
- Unknown license in a shipped artifact: high, BLOCKED.
- Unverified permissive dependency at release time: medium, REVIEW, must clear before release.
- Missing per-file SPDX headers: medium, traceability gap, not a license change.
- No vendored code found: info, no action.
