//! Forbidden dependency checks (`cycles` command).
//!
//! Rules are architectural, not import cycles in the graph-theory sense:
//! the layering contract forbids `Core -> SDK`, `Firmware -> SDK` and
//! `Core -> Firmware` edges at both file (`use`) and manifest
//! (`cargo_metadata` package deps) level.

use std::path::Path;

use crate::model::{CycleReport, CycleViolation, FileGraph, Layer};

/// `(from_layer, to_layer)` pairs that must never appear.
pub const FORBIDDEN_RULES: [(&str, &str); 3] =
    [("core", "sdk"), ("firmware", "sdk"), ("core", "firmware")];

/// Scan a file graph plus the workspace manifests for forbidden edges.
pub fn find_violations(graph: &FileGraph, workspace_root: &Path) -> CycleReport {
    let checked_rules: Vec<String> = FORBIDDEN_RULES
        .iter()
        .map(|(from, to)| format!("forbidden:{from}->{to}"))
        .collect();

    let mut violations: Vec<CycleViolation> = Vec::new();
    for record in &graph.files {
        for dep in &record.depends_on {
            if let Some(rule) = forbidden_rule_for(record.current_layer, dep) {
                let (from, to) = rule_layers(&rule);
                violations.push(CycleViolation {
                    file: record.file.clone(),
                    from_layer: from,
                    to_layer: to,
                    via: dep.clone(),
                    rule,
                });
            }
        }
    }

    let crate_edge_count = append_manifest_violations(&mut violations, workspace_root);

    violations.sort_by(|a, b| a.file.cmp(&b.file).then(a.via.cmp(&b.via)));
    CycleReport {
        checked_rules,
        file_count: graph.files.len(),
        crate_edge_count,
        violations,
    }
}

fn rule_layers(rule: &str) -> (Layer, Layer) {
    if rule.ends_with("core->sdk") {
        (Layer::Core, Layer::Sdk)
    } else if rule.ends_with("firmware->sdk") {
        (Layer::Firmware, Layer::Sdk)
    } else {
        (Layer::Core, Layer::Firmware)
    }
}

/// Match one `use` target against the forbidden matrix.
fn forbidden_rule_for(from: Layer, dep: &str) -> Option<String> {
    let lowered = dep.to_lowercase();
    let targets_sdk = lowered.contains("universal-device-sdk")
        || lowered.contains("universal_device_sdk")
        || lowered.trim_end_matches("::*").ends_with("::sdk")
        || lowered == "sdk";
    let targets_firmware = lowered.contains("firmware") || lowered.contains("aegis-fido-firmware");
    for (from_kw, to_kw) in FORBIDDEN_RULES {
        let from_matches = match from_kw {
            "core" => from == Layer::Core,
            "firmware" => from == Layer::Firmware,
            _ => false,
        };
        if !from_matches {
            continue;
        }
        let to_matches = match to_kw {
            "sdk" => targets_sdk,
            "firmware" => targets_firmware,
            _ => false,
        };
        if to_matches {
            return Some(format!("forbidden:{from_kw}->{to_kw}"));
        }
    }
    None
}

fn append_manifest_violations(
    violations: &mut Vec<CycleViolation>,
    workspace_root: &Path,
) -> usize {
    let manifest = workspace_root.join("Cargo.toml");
    let edges = match crate::parse::crate_dependency_edges(&manifest) {
        Ok(edges) => edges,
        Err(_) => return 0,
    };
    let count = edges.iter().map(|(_, deps)| deps.len()).sum();
    for (package, deps) in edges {
        let from = Layer::classify_from_path(&package);
        if from != Layer::Core && from != Layer::Firmware {
            continue;
        }
        for dep in deps {
            if let Some(rule) = forbidden_rule_for(from, &dep) {
                let (from_layer, to_layer) = rule_layers(&rule);
                violations.push(CycleViolation {
                    file: format!("(manifest) {package}"),
                    from_layer,
                    to_layer,
                    via: format!("{package} -> {dep}"),
                    rule,
                });
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, FileRecord};

    fn record(file: &str, layer: Layer, deps: &[&str]) -> FileRecord {
        FileRecord {
            file: file.to_owned(),
            definitions: Vec::new(),
            used_by: Vec::new(),
            depends_on: deps.iter().map(|s| (*s).to_owned()).collect(),
            current_layer: layer,
            recommended_layer: layer,
            action: Action::Keep,
            reason: "test".to_owned(),
        }
    }

    #[test]
    fn flags_all_three_forbidden_pairs() {
        let graph = FileGraph {
            root: ".".to_owned(),
            files: vec![
                record(
                    "crates/aegis-fido-core/src/x.rs",
                    Layer::Core,
                    &["universal_device_sdk::auth::Auth"],
                ),
                record(
                    "crates/aegis-fido-firmware/src/y.rs",
                    Layer::Firmware,
                    &["universal_device_sdk::capabilities::Cap"],
                ),
                record(
                    "crates/aegis-fido-core/src/z.rs",
                    Layer::Core,
                    &["crate::firmware::Helper"],
                ),
                record(
                    "crates/universal-device-sdk/src/ok.rs",
                    Layer::Sdk,
                    &["aegis_fido_core::policy::Policy"],
                ),
            ],
        };
        let report = find_violations(&graph, Path::new("/nonexistent-root"));
        assert_eq!(report.violations.len(), 3);
        let rules: Vec<&str> = report.violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"forbidden:core->sdk"));
        assert!(rules.contains(&"forbidden:firmware->sdk"));
        assert!(rules.contains(&"forbidden:core->firmware"));
    }
}
