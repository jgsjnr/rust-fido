//! Before/after comparison (`diff` command).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::model::{DiffReport, FileGraph, ImpactManifest, Risk};

/// Load a previously emitted `analyze` graph from disk.
pub fn load_graph_file(path: &Path) -> Result<FileGraph, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("parse {}: {err}", path.display()))
}

/// Compare two graphs and roll up a preservation-first impact manifest.
pub fn diff_graphs(before: &FileGraph, after: &FileGraph) -> DiffReport {
    let before_map: BTreeMap<&str, _> = before.files.iter().map(|f| (f.file.as_str(), f)).collect();
    let after_map: BTreeMap<&str, _> = after.files.iter().map(|f| (f.file.as_str(), f)).collect();
    let before_keys: BTreeSet<&str> = before_map.keys().copied().collect();
    let after_keys: BTreeSet<&str> = after_map.keys().copied().collect();

    let added: Vec<String> = after_keys
        .difference(&before_keys)
        .map(|s| (*s).to_owned())
        .collect();
    let removed: Vec<String> = before_keys
        .difference(&after_keys)
        .map(|s| (*s).to_owned())
        .collect();
    let mut changed: Vec<String> = Vec::new();
    for key in before_keys.intersection(&after_keys) {
        let b = before_map[key];
        let a = after_map[key];
        if b.definitions != a.definitions
            || b.depends_on != a.depends_on
            || b.current_layer != a.current_layer
            || b.recommended_layer != a.recommended_layer
        {
            changed.push((*key).to_owned());
        }
    }
    changed.sort();

    let impact = impact_for(&added, &removed, &changed, after);
    DiffReport {
        added,
        removed,
        changed,
        impact,
    }
}

fn impact_for(
    added: &[String],
    removed: &[String],
    changed: &[String],
    after: &FileGraph,
) -> ImpactManifest {
    let mut affected: Vec<String> = Vec::new();
    affected.extend_from_slice(added);
    affected.extend_from_slice(removed);
    affected.extend_from_slice(changed);
    affected.sort();
    affected.dedup();

    let non_keep = changed
        .iter()
        .filter(|file| {
            after
                .files
                .iter()
                .find(|f| &f.file == *file)
                .is_none_or(|f| !matches!(f.action, crate::model::Action::Keep))
        })
        .count();
    let requires_compatibility_adapter = !removed.is_empty() || non_keep > 0;
    let risk = if !removed.is_empty() || changed.len() > 10 {
        Risk::High
    } else if !added.is_empty() || !changed.is_empty() {
        Risk::Medium
    } else {
        Risk::Low
    };
    let reason = if removed.is_empty() && changed.is_empty() && added.is_empty() {
        "no structural change between snapshots".to_owned()
    } else {
        format!(
            "{} added, {} removed, {} changed; adapter required: {requires_compatibility_adapter}",
            added.len(),
            removed.len(),
            changed.len()
        )
    };
    let mut recommended_actions = Vec::new();
    if !removed.is_empty() {
        recommended_actions.push("restore removed files behind a compatibility adapter".to_owned());
    }
    if non_keep > 0 {
        recommended_actions
            .push("apply EXTRACT/SPLIT recommendations before moving code".to_owned());
    }
    if !added.is_empty() {
        recommended_actions.push("verify new files land in the recommended layer".to_owned());
    }
    if recommended_actions.is_empty() {
        recommended_actions.push("no migration action required".to_owned());
    }
    ImpactManifest {
        affected_components: affected,
        risk,
        requires_compatibility_adapter,
        reason,
        recommended_actions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, FileRecord, Layer};

    fn record(file: &str, defs: &[&str]) -> FileRecord {
        FileRecord {
            file: file.to_owned(),
            definitions: defs.iter().map(|s| (*s).to_owned()).collect(),
            used_by: Vec::new(),
            depends_on: Vec::new(),
            current_layer: Layer::Core,
            recommended_layer: Layer::Core,
            action: Action::Keep,
            reason: "test".to_owned(),
        }
    }

    #[test]
    fn diff_detects_add_remove_change() {
        let before = FileGraph {
            root: ".".to_owned(),
            files: vec![record("a.rs", &["A"]), record("b.rs", &["B"])],
        };
        let after = FileGraph {
            root: ".".to_owned(),
            files: vec![record("a.rs", &["A", "A2"]), record("c.rs", &["C"])],
        };
        let diff = diff_graphs(&before, &after);
        assert_eq!(diff.added, vec!["c.rs".to_owned()]);
        assert_eq!(diff.removed, vec!["b.rs".to_owned()]);
        assert_eq!(diff.changed, vec!["a.rs".to_owned()]);
        assert_eq!(diff.impact.risk, Risk::High);
        assert!(diff.impact.requires_compatibility_adapter);
        assert!(!diff.impact.affected_components.is_empty());
    }
}
