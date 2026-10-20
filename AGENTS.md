# AGENTS.md

## Commands

- `cargo test` — run the full test suite.
- `cargo clippy --all-targets -- -D warnings` — run the lint task.

## Code Map

- `crates` — crates.
- `docs` — project documentation.

## Conventions

- Declare modules with `mod` and re-export with `pub use`.
- Import items with `use` paths rooted at the crate.
- Put unit tests in an inline `mod tests` module inside the source file.
