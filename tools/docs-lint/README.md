# docs-lint

Minimal heuristic markdown link + terminology checker stub.

## Status

- ASD-STE100: HEURISTIC ONLY, NOT certified. This tool runs no
  controlled-language checker. Sentence-length hints are style nudges,
  not compliance evidence.
- Brand list: heuristic substring match drawn from
  `reports/compliance/trademark-audit.md` REVIEW rows. Factual protocol
  references (FIDO2, CTAP, WebAuthn, NIST, BIP-32/39) are NOT flagged.
- Warnings are never auto-fixed. Human review decides.

## Run

```sh
python tools/docs-lint/docs_lint.py --root .
python tools/docs-lint/docs_lint.py --root reports --strict
```

Portable: stdlib only, Windows + Linux. Deterministic, emoji-free output.

## Exit codes

- `0` = no broken local links (warnings may still print).
- `1` = broken local links found (or brand hits under `--strict`).
- `2` = usage error (bad arguments, unreadable root).
