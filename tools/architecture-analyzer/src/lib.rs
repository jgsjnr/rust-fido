//! Reusable preservation-first architecture analyzer.
//!
//! Real parsing only: `cargo_metadata` for manifests and `syn` AST for
//! `use` paths, re-exports and `cfg`-gated symbols. No regex-only import
//! extraction, no mock providers.

mod cycles;
mod diff;
mod god;
mod graph;
mod model;
mod parse;

pub use cycles::{find_violations, FORBIDDEN_RULES};
pub use diff::{diff_graphs, load_graph_file};
pub use god::{god_files, god_files_with_lines, DEFAULT_GOD_LINES, DEFAULT_GOD_SCORE};
pub use graph::{build_graph, collect_rust_files};
pub use model::{
    Action, CycleReport, CycleViolation, DiffReport, FileGraph, FileRecord, GodFileEntry,
    GodFileReport, ImpactManifest, Layer, Risk,
};
pub use parse::{crate_dependency_edges, parse_rust_file, parse_rust_source, ImportEdge};
