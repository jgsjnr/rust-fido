# Review: carteira-cripto-store

**Reviewed:** 2026-10-19
**Validation:** `fdx-validate action:artifacts` → valid:true
**Decision:** CONFIRM (user, no revisions requested)

## Findings

Blocking: 3 (B1 slot-namespace policy, B2 parallel-safety intersection on
docs/carteira-cripto.md, B3 missing Cargo.toml/lock + firmware size gate).
Advisory: 6 (A1 no project-level architecture.md, A2 web tab detachable,
A3 negative no-OTP/no-lock test, A4 parity-harness method, A5 Step 1 file list,
A6 uniffi-bridge follow-up).

## Acceptance record

- Advisory A1–A6 accepted as-is (no artifact changes).
- Blocking B1–B3 accepted as EXPLICIT RISK by user CONFIRM without revisions.
  They MUST be resolved during fd-execute before/along implementation:
  - B1: define slot allocation (dedicated instance vs reserved range vs label
    prefix) + collision test before wallet writes any slot.
  - B2: treat Task B docs and Step 4 as sequential (single owner for
    docs/carteira-cripto.md per wave); clean Step 1 file list.
  - B3: declare address-encoding deps (bech32/base58/keccak), prove no_std
    compat, add firmware size-gate check to validation wave.
- No artifacts revised in fd-review.
