//! Oversized / over-connected file heuristic (`god-files` command).

use crate::model::{FileGraph, GodFileEntry, GodFileReport};

/// Default line threshold for god-file reports.
pub const DEFAULT_GOD_LINES: usize = 800;
/// Default score threshold for god-file reports.
pub const DEFAULT_GOD_SCORE: f64 = 12.0;

/// Flag god-files using `lines + fan-in/fan-out`.
///
/// `lines` comes from the physical source so `analyze` output stays the
/// single source of truth; here we re-derive it from the graph record by
/// treating `definitions + depends_on + used_by` weight plus an explicit
/// line lookup is unnecessary — instead callers pass graphs built by
/// [`crate::graph::build_graph`], and line counts are recovered from the
/// stored report via re-read? To keep this pure and offline, the score uses
/// fan-in/fan-out from the graph and the caller-supplied line threshold is
/// applied against an estimated size (`definitions * 25 + edges * 5`).
/// The `god-files` binary path below re-reads files for exact lines; this
/// pure function keeps unit tests deterministic.
pub fn god_files(graph: &FileGraph, threshold_lines: usize, threshold_score: f64) -> GodFileReport {
    god_files_with_lines(graph, threshold_lines, threshold_score, &|_| None)
}

/// Score entries with exact line counts supplied by the caller.
pub fn god_files_with_lines(
    graph: &FileGraph,
    threshold_lines: usize,
    threshold_score: f64,
    line_lookup: &dyn Fn(&str) -> Option<usize>,
) -> GodFileReport {
    let mut entries: Vec<GodFileEntry> = graph
        .files
        .iter()
        .map(|record| {
            let lines = line_lookup(&record.file).unwrap_or_else(|| {
                record.definitions.len() * 25 + record.depends_on.len() * 5 + 10
            });
            let fan_in = record.used_by.len();
            let fan_out = record.depends_on.len();
            let score = lines as f64 / 100.0 + fan_out as f64 * 1.5 + fan_in as f64 * 0.5;
            let mut reasons: Vec<String> = Vec::new();
            if lines >= threshold_lines {
                reasons.push(format!("{lines} lines >= {threshold_lines}"));
            }
            if score >= threshold_score {
                reasons.push(format!("score {score:.1} >= {threshold_score:.1}"));
            }
            if fan_out > 20 {
                reasons.push(format!("fan-out {fan_out} > 20"));
            }
            if fan_in > 20 {
                reasons.push(format!("fan-in {fan_in} > 20"));
            }
            GodFileEntry {
                file: record.file.clone(),
                lines,
                fan_in,
                fan_out,
                score,
                reason: if reasons.is_empty() {
                    "within budget".to_owned()
                } else {
                    reasons.join("; ")
                },
            }
        })
        .filter(|entry| entry.lines >= threshold_lines || entry.score >= threshold_score)
        .collect();
    entries.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    GodFileReport {
        threshold_lines,
        threshold_score,
        file_count: graph.files.len(),
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, FileRecord, Layer};

    fn record(file: &str, defs: usize, deps: usize, used: usize) -> FileRecord {
        FileRecord {
            file: file.to_owned(),
            definitions: (0..defs).map(|i| format!("Item{i}")).collect(),
            used_by: (0..used).map(|i| format!("user{i}.rs")).collect(),
            depends_on: (0..deps).map(|i| format!("dep{i}::Thing")).collect(),
            current_layer: Layer::Core,
            recommended_layer: Layer::Core,
            action: Action::Keep,
            reason: "test".to_owned(),
        }
    }

    #[test]
    fn flags_oversized_files_first() {
        let graph = FileGraph {
            root: ".".to_owned(),
            files: vec![record("small.rs", 1, 1, 0), record("big.rs", 60, 25, 25)],
        };
        let report = god_files_with_lines(&graph, 800, 12.0, &|file| {
            Some(if file == "big.rs" { 1200 } else { 40 })
        });
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].file, "big.rs");
        assert!(report.entries[0].score > 12.0);
    }
}
