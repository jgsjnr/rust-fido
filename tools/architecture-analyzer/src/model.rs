//! Typed output schema for the analyzer.
//!
//! JSON keys use the required report vocabulary (`FILE`, `DEFINITIONS`,
//! `USED BY`, `DEPENDS ON`, `CURRENT LAYER`, `RECOMMENDED LAYER`, `ACTION`,
//! `REASON`). The impact manifest uses `affected_components`, `risk` and
//! `requires_compatibility_adapter`.

use serde::{Deserialize, Serialize};

/// Architectural layer inferred from a file path or crate name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Layer {
    /// `crates/aegis-fido-core`.
    Core,
    /// `crates/aegis-fido-firmware`.
    Firmware,
    /// `crates/universal-device-sdk`.
    Sdk,
    /// `crates/aegis-fido-usb`.
    Usb,
    /// `crates/aegis-secure-guard`.
    SecureGuard,
    /// `crates/uniffi-bridge`.
    Bridge,
    /// `app-*` hosts, `tools/host*`, `tools/web_dashboard`.
    App,
    /// Anything that does not match a known prefix.
    Unknown,
}

impl Layer {
    /// Classify a layer from a slash-separated relative path or crate name.
    #[must_use]
    pub fn classify_from_path(path: &str) -> Self {
        let lowered = path.replace('\\', "/").to_lowercase();
        if lowered.contains("aegis-fido-core") {
            Self::Core
        } else if lowered.contains("aegis-fido-firmware") {
            Self::Firmware
        } else if lowered.contains("universal-device-sdk") {
            Self::Sdk
        } else if lowered.contains("aegis-fido-usb") {
            Self::Usb
        } else if lowered.contains("aegis-secure-guard") || lowered.contains("secure-guard") {
            Self::SecureGuard
        } else if lowered.contains("uniffi-bridge") || lowered.contains("uniffi") {
            Self::Bridge
        } else if lowered.contains("app-")
            || lowered.contains("/app/")
            || lowered.starts_with("app")
            || lowered.contains("host_sdk")
            || lowered.contains("web_dashboard")
        {
            Self::App
        } else {
            Self::Unknown
        }
    }

    /// Short stable label used for dependency-edge matching.
    #[must_use]
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Firmware => "firmware",
            Self::Sdk => "sdk",
            Self::Usb => "usb",
            Self::SecureGuard => "secure-guard",
            Self::Bridge => "bridge",
            Self::App => "app",
            Self::Unknown => "unknown",
        }
    }
}

/// Preservation-first recommendation for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Leave the file where it is.
    #[serde(rename = "KEEP")]
    Keep,
    /// Move the file to the recommended layer as-is.
    #[serde(rename = "MOVE")]
    Move,
    /// Split an oversized file inside its current layer.
    #[serde(rename = "SPLIT")]
    Split,
    /// Extract a seam behind a compatibility adapter.
    #[serde(rename = "EXTRACT")]
    Extract,
}

/// Migration risk for an impact manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Risk {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
}

/// One row of the file graph report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// Relative file path.
    #[serde(rename = "FILE")]
    pub file: String,
    /// Top-level (and nested) item names defined in the file.
    #[serde(rename = "DEFINITIONS")]
    pub definitions: Vec<String>,
    /// Files that depend on this file (reverse edges).
    #[serde(rename = "USED BY")]
    pub used_by: Vec<String>,
    /// Raw `use` paths this file depends on.
    #[serde(rename = "DEPENDS ON")]
    pub depends_on: Vec<String>,
    /// Layer inferred from the file path.
    #[serde(rename = "CURRENT LAYER")]
    pub current_layer: Layer,
    /// Suggested layer after heuristic review.
    #[serde(rename = "RECOMMENDED LAYER")]
    pub recommended_layer: Layer,
    /// Preservation-first recommendation.
    #[serde(rename = "ACTION")]
    pub action: Action,
    /// Human-readable justification.
    #[serde(rename = "REASON")]
    pub reason: String,
}

/// Whole-repo file graph emitted by `analyze`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileGraph {
    /// Repository root the relative paths resolve against.
    pub root: String,
    /// One record per parsed Rust file.
    pub files: Vec<FileRecord>,
}

/// A single forbidden dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleViolation {
    /// File that introduces the edge.
    pub file: String,
    /// Layer of the importing file.
    pub from_layer: Layer,
    /// Forbidden target layer.
    pub to_layer: Layer,
    /// Raw `use` path or `crate:dep` edge that triggered the rule.
    pub via: String,
    /// Rule identifier, e.g. `forbidden:core->sdk`.
    pub rule: String,
}

/// Result of the `cycles` command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleReport {
    /// Rules that were checked.
    pub checked_rules: Vec<String>,
    /// Files scanned.
    pub file_count: usize,
    /// Manifest-level crate edges scanned.
    pub crate_edge_count: usize,
    /// Violations found (empty means the tree is clean).
    pub violations: Vec<CycleViolation>,
}

/// One oversized / over-connected file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GodFileEntry {
    /// Relative file path.
    pub file: String,
    /// Physical lines of code.
    pub lines: usize,
    /// Number of files depending on this file.
    pub fan_in: usize,
    /// Number of distinct `use` targets leaving this file.
    pub fan_out: usize,
    /// `lines / 100 + fan_out * 1.5 + fan_in * 0.5`.
    pub score: f64,
    /// Why this file was flagged.
    pub reason: String,
}

/// Result of the `god-files` command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GodFileReport {
    /// Line threshold used.
    pub threshold_lines: usize,
    /// Score threshold used.
    pub threshold_score: f64,
    /// Flagged files, worst first.
    pub entries: Vec<GodFileEntry>,
    /// Total files scanned.
    pub file_count: usize,
}

/// Preservation-first migration impact manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpactManifest {
    /// Components touched by the change set.
    pub affected_components: Vec<String>,
    /// Overall migration risk.
    pub risk: Risk,
    /// Whether a compatibility adapter is required before moving code.
    pub requires_compatibility_adapter: bool,
    /// Human-readable justification.
    pub reason: String,
    /// Suggested next actions.
    pub recommended_actions: Vec<String>,
}

/// Result of the `diff` command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffReport {
    /// Files only present after the change.
    pub added: Vec<String>,
    /// Files only present before the change.
    pub removed: Vec<String>,
    /// Files present in both but with different definitions or edges.
    pub changed: Vec<String>,
    /// Rolled-up preservation impact.
    pub impact: ImpactManifest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_layers() {
        assert_eq!(
            Layer::classify_from_path("crates/aegis-fido-core/src/lib.rs"),
            Layer::Core
        );
        assert_eq!(
            Layer::classify_from_path("crates/aegis-fido-firmware/src/ctap_cmd.rs"),
            Layer::Firmware
        );
        assert_eq!(
            Layer::classify_from_path("crates/universal-device-sdk/src/auth.rs"),
            Layer::Sdk
        );
        assert_eq!(
            Layer::classify_from_path("tools/other/x.rs"),
            Layer::Unknown
        );
    }

    #[test]
    fn file_record_uses_report_vocabulary() {
        let record = FileRecord {
            file: "crates/aegis-fido-core/src/lib.rs".to_owned(),
            definitions: vec!["lib".to_owned()],
            used_by: vec![],
            depends_on: vec![],
            current_layer: Layer::Core,
            recommended_layer: Layer::Core,
            action: Action::Keep,
            reason: "core primitive".to_owned(),
        };
        let json = serde_json::to_value(&record).expect("serializes");
        for key in [
            "FILE",
            "DEFINITIONS",
            "USED BY",
            "DEPENDS ON",
            "CURRENT LAYER",
            "RECOMMENDED LAYER",
            "ACTION",
            "REASON",
        ] {
            assert!(json.get(key).is_some(), "missing key {key}");
        }
    }
}
