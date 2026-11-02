//! File graph construction from real AST parsing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::model::{Action, FileGraph, FileRecord, Layer};
use crate::parse::parse_rust_file;

/// Error type for graph construction.
#[derive(Debug)]
pub enum AnalyzeError {
    /// Filesystem failure while walking or reading the tree.
    Io(std::io::Error),
    /// A Rust file failed to parse.
    Parse {
        /// File that failed.
        file: String,
        /// Parser message.
        message: String,
    },
}

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Parse { file, message } => write!(f, "parse error in {file}: {message}"),
        }
    }
}

impl std::error::Error for AnalyzeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Parse { .. } => None,
        }
    }
}

impl From<std::io::Error> for AnalyzeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Recursively collect `*.rs` files under `root`, sorted for determinism.
pub fn collect_rust_files(root: &Path) -> Result<Vec<PathBuf>, AnalyzeError> {
    let mut out = Vec::new();
    collect_into(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_into(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), AnalyzeError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip build output so generated files never pollute the graph.
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == "target" || name == ".git" {
                    continue;
                }
            }
            collect_into(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Build the full file graph for `root`.
///
/// `root` is typically the workspace root (or `crates/`); stored relative
/// paths keep `analyze`/`diff` outputs comparable across machines.
pub fn build_graph(root: &Path) -> Result<FileGraph, AnalyzeError> {
    let files = collect_rust_files(root)?;
    let mut depends: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut definitions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut line_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut layers: BTreeMap<String, Layer> = BTreeMap::new();

    for path in &files {
        let rel = relative_key(root, path);
        let source = std::fs::read_to_string(path)?;
        let line_count = source.lines().count();
        let body = crate::parse::parse_rust_source(&source).map_err(|err| AnalyzeError::Parse {
            file: rel.clone(),
            message: err.to_string(),
        })?;
        // Keep the disk-read helper exercised so dead-code lints stay honest
        // about both entry points parsing identically.
        debug_assert_parses_like_file(path, &body.definitions);
        let mut edges = BTreeSet::new();
        for import in &body.imports {
            edges.insert(import.raw.clone());
        }
        depends.insert(rel.clone(), edges);
        definitions.insert(rel.clone(), body.definitions);
        line_counts.insert(rel.clone(), line_count);
        layers.insert(rel.clone(), Layer::classify_from_path(&rel));
    }

    // Reverse edges: file A is "used by" file B when one of B's imports
    // mentions A's stem, crate directory, or an item A defines.
    let mut used_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for key in depends.keys() {
        used_by.entry(key.clone()).or_default();
    }
    let keys: Vec<String> = depends.keys().cloned().collect();
    for from in &keys {
        let targets = depends.get(from).cloned().unwrap_or_default();
        for target in targets {
            for candidate in &keys {
                if candidate == from {
                    continue;
                }
                if import_points_at_file(&target, candidate) {
                    used_by
                        .entry(candidate.clone())
                        .or_default()
                        .insert(from.clone());
                }
            }
        }
    }

    let mut records: Vec<FileRecord> = Vec::new();
    for key in keys {
        let current_layer = layers.get(&key).copied().unwrap_or(Layer::Unknown);
        let depends_on: Vec<String> = depends
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let used: Vec<String> = used_by
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let lines = line_counts.get(&key).copied().unwrap_or_default();
        let (recommended_layer, action, reason) =
            recommend(current_layer, &key, &depends_on, lines, used.len());
        records.push(FileRecord {
            file: key.clone(),
            definitions: definitions.get(&key).cloned().unwrap_or_default(),
            used_by: used,
            depends_on,
            current_layer,
            recommended_layer,
            action,
            reason,
        });
    }
    records.sort_by(|a, b| a.file.cmp(&b.file));

    Ok(FileGraph {
        root: root.to_string_lossy().into_owned(),
        files: records,
    })
}

fn relative_key(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn file_stem_of(candidate: &str) -> String {
    Path::new(candidate)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn import_points_at_file(import: &str, candidate: &str) -> bool {
    let lowered = import.to_lowercase();
    let stem = file_stem_of(candidate).to_lowercase();
    if !stem.is_empty() && stem != "lib" && stem != "main" && lowered.contains(&stem) {
        return true;
    }
    for marker in [
        "aegis-fido-core",
        "aegis-fido-firmware",
        "universal-device-sdk",
        "universal_device_sdk",
        "aegis-fido-usb",
        "aegis-secure-guard",
        "aegis_secure_guard",
        "uniffi-bridge",
        "uniffi_bridge",
    ] {
        if lowered.contains(marker) && candidate.to_lowercase().contains(marker) {
            return true;
        }
    }
    false
}

fn recommend(
    current: Layer,
    file: &str,
    depends_on: &[String],
    lines: usize,
    fan_in: usize,
) -> (Layer, Action, String) {
    let mentions = |needle: &str| {
        depends_on
            .iter()
            .any(|dep| dep.to_lowercase().contains(needle))
    };
    // Forbidden-dependency hints surface as EXTRACT (adapter required),
    // never as a silent MOVE, so layering fixes stay preservation-first.
    if current == Layer::Core
        && (mentions("universal-device-sdk") || mentions("universal_device_sdk"))
    {
        return (
            Layer::Sdk,
            Action::Extract,
            format!(
                "core file {file} depends on the SDK; extract a trait/adapter instead of depending upward"
            ),
        );
    }
    if current == Layer::Firmware
        && (mentions("universal-device-sdk") || mentions("universal_device_sdk"))
    {
        return (
            Layer::Firmware,
            Action::Extract,
            format!(
                "firmware file {file} depends on the host SDK; keep firmware no_std and extract a boundary adapter"
            ),
        );
    }
    if current == Layer::Core && (mentions("firmware") || mentions("aegis-fido-firmware")) {
        return (
            Layer::Firmware,
            Action::Extract,
            format!(
                "core file {file} reaches into firmware; extract a shared primitive instead of depending downward"
            ),
        );
    }
    if lines > 800 {
        return (
            current,
            Action::Split,
            format!("{lines} lines with fan-in {fan_in}; split into focused modules"),
        );
    }
    if depends_on.len() > 20 {
        return (
            current,
            Action::Extract,
            format!(
                "fan-out {} exceeds review budget; extract a seam behind an adapter",
                depends_on.len()
            ),
        );
    }
    (
        current,
        Action::Keep,
        "no layering or size signal; keep in place".to_owned(),
    )
}

fn debug_assert_parses_like_file(path: &Path, definitions: &[String]) {
    // Cheap cross-check that the file entry point agrees with source parsing.
    // Failures surface only under `debug_assertions`, never in release CI.
    if cfg!(debug_assertions) {
        if let Ok(body) = parse_rust_file(path) {
            debug_assert_eq!(
                &body.definitions, definitions,
                "parsers disagree for {path:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn builds_graph_with_reverse_edges() {
        let dir = std::env::temp_dir().join("arch-analyzer-graph-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("crates/aegis-fido-core/src")).expect("mkdir");
        fs::write(
            dir.join("crates/aegis-fido-core/src/policy.rs"),
            "pub struct Policy;\n",
        )
        .expect("write");
        fs::write(
            dir.join("crates/aegis-fido-core/src/lib.rs"),
            "use crate::policy::Policy;\npub fn check(_p: Policy) {}\n",
        )
        .expect("write");

        let graph = build_graph(&dir).expect("graph");
        assert_eq!(graph.files.len(), 2);
        let policy = graph
            .files
            .iter()
            .find(|f| f.file.ends_with("policy.rs"))
            .expect("policy record");
        assert_eq!(policy.current_layer, Layer::Core);
        assert!(policy.definitions.contains(&"Policy".to_owned()));
        assert!(
            policy.used_by.iter().any(|u| u.ends_with("lib.rs")),
            "expected reverse edge, got {:?}",
            policy.used_by
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
