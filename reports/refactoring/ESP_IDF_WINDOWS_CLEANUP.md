# ESP-IDF Windows Cleanup -- v5.3.1 kept, removal CANCELLED (both installs stay)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `f136e48` (this report committed on top; see return SHA)
- Date (UTC): 2026-11-02
- Mode: record only. Owner order: keep as-is on v5.3.1; legacy removal
  CANCELLED. **NO removal performed. NO uninstall performed.**

## Host state (observed, not modified)

| Slot | Location | State | Evidence |
| ---- | -------- | ----- | -------- |
| Pinned + verified v5.3.1 | `C:\.embuild\espressif\esp-idf\v5.3.1` | Present, ACTIVE, re-verified GREEN (check + release + ELF) | this lane proof 2026-11-02 |
| Future v6.0.3 | `C:\esp\v6.0.3\esp-idf` | Present, INACTIVE, retained for retry | EIM install + venv + tools + managed storage intact; warm v6 cache in `C:/t` |
| v6.1 | absent | NOT INSTALLED | no `C:\esp\v6.1*`, no embuild v6.1 slot |
| Stray embuild v6.0 venv | `C:\.embuild\espressif\python_env\idf6.0_py3.12_env` | Present, purpose unknown | left untouched; parent decides |
| VS Code extension slot | `C:\Users\junior\esp\v5.5.1` + `C:\Users\junior\.espressif` | v5.5.1 dir ABSENT (stale pointer), `.espressif` present | user settings point at nonexistent v5.5.1 path; NOT fixed (removal cancelled) |

## Removal: CANCELLED per owner order (keep as-is on v5.3.1)

No host deletion, no env change, and no VS Code edit were performed. Both IDF
installs stay on disk. Deletion candidates remain documented for a post-GREEN
v6 future: v5.3.1 checkout, idf5.3 venv, `espidf.constraints.v5.3.txt`,
old-version dist zips + old extracted tool dirs.

## Compat note (re-verified this lane)

- Firmware pins `esp-idf-sys 0.36.1` / `hal 0.45.2` / `svc 0.50.1` / `embuild 0.33.5`
  (lock restored byte-identical to pre-migration).
- v5.3.1: check exit 0, release build exit 0, ELF verified (Xtensa magic, v5.3.1
  marker). Host `cargo test --workspace` exit 0.
- v6.0.3: blocked upstream (sys 0.38.1 bindgen vs managed v2 headers; fix
  unreleased). Shims are v2-clean in history (`3378633`); retry on warm cache.

## What was NOT done (explicit)

- NO ESP-IDF version installed, uninstalled, activated, or deactivated.
- NO environment variables changed (persistent or shell-global).
- NO VS Code settings created, modified, or deleted.
- NO host files or directories deleted (except the repo-untracked generated
  `components_esp32s3.lock`, which v5 + manager-off does not use).
- NO product `.rs`, app-*, docs-prose, or other-report files touched.

## Next steps

1. Stay on v5.3.1. Retry v6 only after the upstream sys v2-bindings release.
2. Then: re-apply v6 config on the green base, prove (check + release + ELF),
   and only then execute the authorized removal with fresh-shell re-verification.