# architecture-analyzer

Reusable preservation-first architecture analyzer (Phase 4 tool).
Standalone crate: not a workspace member, so the main workspace `cargo check`
is unaffected. Real parsing only — no mocks, no stubs.

## Parsing

- Manifests: `cargo_metadata` (`crate_dependency_edges`) reads real
  `Cargo.toml` manifests, including workspace inheritance.
- Rust imports: `syn` AST (`parse_rust_source`), never regex-only.
  Records flattened `use` paths, `pub use` re-exports (`is_reexport`) and
  `#[cfg]`-gated symbols (`cfg_gated`, `cfg_gated_count`).

## Commands

```sh
# File graph JSON (FILE, DEFINITIONS, USED BY, DEPENDS ON,
# CURRENT LAYER, RECOMMENDED LAYER, ACTION, REASON)
cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
  analyze --root crates --out /tmp/graph.json

# Forbidden deps: Core->SDK, Firmware->SDK, Core->Firmware.
# Exit 0 = clean, exit 2 = violations found.
cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
  cycles --root . --out /tmp/cycles.json

# God-files (lines + fan-in/out heuristic)
cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
  god-files --root crates --lines 800 --score 12 --out /tmp/god.json

# Before/after compare + impact manifest
# (affected_components, risk, requires_compatibility_adapter)
cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
  analyze --root crates --out /tmp/before.json
# ... make changes ...
cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
  analyze --root crates --out /tmp/after.json
cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
  diff --before /tmp/before.json --after /tmp/after.json --out /tmp/diff.json
```

## CI usage

```yaml
- name: Architecture analyze
  run: |
    cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
      analyze --root crates --out target/arch-graph.json
    cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
      cycles --root . --out target/arch-cycles.json
    cargo run --manifest-path tools/architecture-analyzer/Cargo.toml -- \
      god-files --root crates --out target/arch-god.json
```

`cycles` exits `2` on forbidden edges, so add `|| exit 1` handling or
`continue-on-error` depending on whether the gate is advisory or blocking.

## Output schema

File records:

| Key                | Meaning                                              |
| ------------------ | ---------------------------------------------------- |
| `FILE`             | relative file path                                   |
| `DEFINITIONS`      | item names defined in the file                       |
| `USED BY`          | reverse edges (files importing this one)             |
| `DEPENDS ON`       | raw flattened `use` paths leaving the file           |
| `CURRENT LAYER`    | `Core/Firmware/Sdk/Usb/SecureGuard/Bridge/App/Unknown` |
| `RECOMMENDED LAYER`| suggested layer after heuristic review               |
| `ACTION`           | `KEEP/MOVE/SPLIT/EXTRACT`                            |
| `REASON`           | human-readable justification                         |

Impact manifest (`diff`): `affected_components`, `risk`
(`low/medium/high`), `requires_compatibility_adapter`, `reason`,
`recommended_actions`.

## Checks

```sh
cargo check --manifest-path tools/architecture-analyzer/Cargo.toml
cargo test --manifest-path tools/architecture-analyzer/Cargo.toml
cargo clippy --manifest-path tools/architecture-analyzer/Cargo.toml --all-targets -- -D warnings
cargo fmt --check --manifest-path tools/architecture-analyzer/Cargo.toml
```
