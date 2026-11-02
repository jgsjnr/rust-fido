# CLOSED_MODEL_PLAN — DRAFT (NOT EFFECTIVE)

Status: DRAFT. Nothing below is applied. The switch takes effect only
under an explicit owner order plus `orquestrador` identity confirmation.
Until then the workspace remains GPL-3.0-only and `LICENSE` (GPLv3 full
text) is the sole effective license.

## 0. Preconditions (before any edit)

- [ ] Owner issues an explicit written order naming this plan and the exact
  commit range to be relicensed.
- [ ] `orquestrador` identity confirmation is recorded (who confirmed,
  when, where).
- [ ] Copyright ownership is confirmed: either the owner holds 100% of
  rights, or written consent from every external contributor exists. Without
  this, no switch is possible.
- [ ] Recipient-rights note (read before acting): GPL grants already made
  are irrevocable for copies already conveyed. Anyone who received a version
  under GPL keeps GPL rights to THAT version (see `LICENSE` sections 2, 4-6,
  8-10). The closed model can apply prospectively only: to new versions /
  new distributions from the switch commit forward. Do not represent that
  prior GPL copies are "un-GPLed".

## 1. Exact switch checklist (atomic commit, simultaneous)

All items below land in ONE commit so no intermediate state mixes licenses.

- [ ] 1.1 `LICENSE` file swap. Replace root `LICENSE` (GPLv3, verified full
  text, 622 lines) with the proprietary text finalized from
  `LICENSE.PROPRIETARY.draft` (fill `[COMPANY]` / `[YEAR]`, counsel review).
  Archive the GPL text as `LICENSE.GPL-3.0-only.historical` for the
  recipient-rights record (prior versions stay attributable to GPL).
- [ ] 1.2 Root `Cargo.toml:17`: `license = "GPL-3.0-only"` must change
  SIMULTANEOUSLY with 1.1 (workspace `license` field and `LICENSE` file must
  never disagree, even for one commit). Suggested value: `license = "Proprietary"`
  with `publish = false` kept. Re-scan every manifest at switch time:
  `tools/architecture-analyzer/Cargo.toml:6` carries the same
  `license = "GPL-3.0-only"` field today; any `crates/*/Cargo.toml` that
  inherits or overrides it must be updated in the same commit.
- [ ] 1.3 README strings — the 3 spots (all in root `README.md`):
  - `README.md:3` badge:
    `[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)`
    -> proprietary badge/label pointing at the new `LICENSE`.
  - `README.md:17`: `> **License:** GNU General Public License v3.0 (GPLv3).`
    -> proprietary license line.
  - `README.md:278-281` (`## 9. License` section: "free software licensed
    under the GNU General Public License v3.0 (GPLv3)" + `See the
    [LICENSE](LICENSE) file...`) -> proprietary wording, keep the pointer
    at the `LICENSE` file.
- [ ] 1.4 `docs/project/ARCHITECTURE-MAP.html:1991`:
  `Document Standard: ... License: GPLv3` -> new license label. Regenerate
  or hand-edit that single line; verify no other `GPLv3` string remains in
  the file.
- [ ] 1.5 `deny.toml` re-point (same commit):
  - Header comment `:1` ("AegisKey GPL-3.0-only workspace") -> new model.
  - `[licenses]` allow list (`:19-46`): remove/adjust entries that existed
    only to document GPL-3.0-only compatibility inputs; keep the permissive
    dependency allow entries that remain true (MIT, Apache-2.0, BSD-*,
    ISC, Zlib, CC0-1.0, Unlicense, Unicode-3.0, BSL-1.0 alternative) — each
    still REVIEW-cleared per `THIRD_PARTY_NOTICES.md:16` owner approval
    2026-11-02.
  - `[licenses] exceptions` (`:47-53`): delete the six
    `allow = ["GPL-3.0-only"]` first-party exceptions
    (`aegis-secure-guard`, `aegis-fido-core`, `aegis-fido-usb`,
    `aegis-fido-firmware`, `universal-device-sdk`, `uniffi-bridge`) and
    replace with the proprietary workspace license declaration.
  - Historical MPL comment (`:17`): already informational only (no MPL allow
    entry remains); rewrite or drop to avoid stale references (see section 3).
- [ ] 1.6 CI gate KEEP: `.github/workflows/ci.yml` (bootstrap) +
  `tools/run_all.py` deny leg (`:207-216`,
  `cargo deny check licenses advisories bans sources`) stay active and must
  PASS against the rewritten `deny.toml` before the switch commit is
  accepted. A failing deny gate blocks the switch.
- [ ] 1.7 SPDX headers: OPTIONAL. No per-file `SPDX-License-Identifier`
  headers exist in `crates/` today (verified: zero hits), and
  `reports/compliance/license-inventory.json:63` records the decision point.
  Either add `SPDX-License-Identifier: Proprietary` headers or record a
  documented decision to rely on workspace-level licensing only — do it in
  the same commit, not later.
- [ ] 1.8 Reports refresh (same commit or immediate follow-up, no release
  between): `reports/compliance/license-inventory.json`
  (`workspace_policy`, per-crate `effective_license`, `license_file_identity`),
  `reports/compliance/sbom.spdx.json` (`licenseConcluded`/`licenseDeclared`
  per package), `reports/compliance/third-party-notices.md`,
  `reports/compliance/license-compatibility.md`,
  `reports/testing/FINAL_TEST_REPORT.md:77-80`. These are evidence files;
  stale GPL statements after a switch are defects.
- [ ] 1.9 Docs sweep: re-run the `GPL-3.0|GNU General Public License`
  search repo-wide at switch time; every hit outside `*.historical*` and
  this plan must be resolved.

## 2. Per-binary attribution bundle (each distributable ships its notices)

Closed distribution does NOT remove third-party attribution duties
(permissive licenses still require notice preservation). Every shipped
artifact carries a copy of (or pointer to) `THIRD_PARTY_NOTICES.md`:

- [ ] Firmware `*.bin` (built from `crates/aegis-fido-firmware`): bundle the
  notices text with the release package / download page; on-device "About"
  screen references it where storage allows.
- [ ] Android `libaegis_bridge.so` (built from `crates/uniffi-bridge`,
  consumed via `app-android/` JNA facade `AegisBridge.kt`): include the
  notices in the APK assets / About screen. Refresh `proguard-rules.pro`
  (`-keep class uniffi.**` is stale after UniFFI removal) when touching this
  surface.
- [ ] Tray (`app-tray/`, incl. `aegis_tray.py` and companions): ship
  `THIRD_PARTY_NOTICES.md` alongside the installer / package and link it
  from the tray About dialog.
- [ ] Gradle side: `com.journeyapps:zxing-android-embedded:4.3.0` (+
  build-time transitive `com.google.zxing:core`), declared in
  `app-android/app/build.gradle.kts`, stays Apache-2.0 — duty preserved per
  `THIRD_PARTY_NOTICES.md:497-499`.

## 3. Zero-MPL note (already eliminated, verify at switch time)

- UniFFI runtime crates (9x MPL-2.0 `uniffi* 0.28.3`) left the graph on
  2026-11-02 (see `reports/refactoring/UNIFFI_REMOVAL_PLAN.md`, section 6
  actuals: 34 rows pruned; notices `273 -> 239`). `deny.toml` carries NO MPL
  allow entry (only a historical comment at `:17`).
- At switch time re-verify: `Cargo.lock` must contain no `MPL` string
  (today: zero hits; the remaining `uniffi-bridge` entry at `Cargo.lock:2229`
  is the first-party crate, `GPL-3.0-only`, not the MPL runtime) and
  `cargo deny check licenses` must pass with no MPL finding.
- The switch commit must not reintroduce any MPL-licensed input.

## 4. r-efi note (transitive only, not directly used)

- `r-efi 6.0.0` (MIT OR Apache-2.0 OR LGPL-2.1-or-later) is in the lock as a
  transitive dependency of `getrandom 0.4.3` (`Cargo.lock:1178-1187`; UEFI
  target path). No first-party code references it (zero `r_efi`/`r-efi` hits
  under `crates/`).
- Effective license is taken via the MIT/Apache-2.0 alternative; any use
  under the LGPL alternative stays BLOCKED pending legal review
  (`THIRD_PARTY_NOTICES.md:333-334`, mirrored in
  `reports/compliance/third-party-notices.md:333-334`).
- Attribution duty (preserve crate license text + notices) survives the
  closed-model switch and is covered by the per-binary bundle (section 2).

## 5. License-field simultaneity rule

`GPL-3.0-only` as workspace `license` (root `Cargo.toml:17`) and the GPLv3
`LICENSE` file are a pair: changing one without the other in the same commit
produces a mislabeled tree (manifest says one thing, license text says
another). The switch commit changes both together, plus 1.2-1.8. If the
commit must be split for review, the split happens in DRAFT branches only,
and the merge to the release line is a single squash containing all items.

## 6. After the switch (post-commit verification, before any distribution)

- [ ] `cargo deny check licenses advisories bans sources` green on the
  switch commit.
- [ ] Full test suite + clippy per AGENTS.md (`cargo test`,
  `cargo clippy --all-targets -- -D warnings`) green — the ESP-IDF lane
  builds are unaffected (these drafts touch no build inputs).
- [ ] Grep audit: zero `GPL`/`General Public License` strings outside
  `*.historical*`, this plan, and `reports/` baselines explicitly marked
  pre-switch.
- [ ] Each distributable (firmware `.bin`, Android `.so`/APK, tray package)
  verified to contain or link `THIRD_PARTY_NOTICES.md`.
- [ ] Distribution log opened: every closed distribution recorded (version,
  recipient, date) so the prospective-only boundary (section 0) is provable.
