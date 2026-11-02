//! Real manifest + AST parsing.
//!
//! Manifests go through `cargo_metadata`; Rust imports go through the `syn`
//! AST (never regex-only). Re-exports (`pub use`) and `#[cfg]`-gated symbols
//! are recorded explicitly.

use std::path::Path;

use syn::{Attribute, Item, UseTree, Visibility};

/// A single flattened `use` path found in the AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEdge {
    /// Fully flattened path, e.g. `crate::auth::Authenticator`.
    pub raw: String,
    /// Path segments without separators.
    pub segments: Vec<String>,
    /// True for `pub use` / `pub(crate) use` re-exports.
    pub is_reexport: bool,
    /// True when the `use` item (or an enclosing item) carries `#[cfg(..)]`.
    pub cfg_gated: bool,
}

/// Body extracted from one Rust source unit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedBody {
    /// Named items (`fn`, `struct`, `enum`, `trait`, `mod`, `type`, ...).
    pub definitions: Vec<String>,
    /// Flattened `use` edges plus `extern crate` roots.
    pub imports: Vec<ImportEdge>,
    /// Number of `#[cfg]`-gated items seen.
    pub cfg_gated_count: usize,
}

/// Parse Rust source text with the real `syn` parser.
pub fn parse_rust_source(source: &str) -> Result<ParsedBody, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut body = ParsedBody::default();
    visit_items(&file.items, false, &mut body);
    body.definitions.sort();
    body.definitions.dedup();
    Ok(body)
}

/// Parse one file from disk.
pub fn parse_rust_file(path: &Path) -> std::io::Result<ParsedBody> {
    let source = std::fs::read_to_string(path)?;
    parse_rust_source(&source)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
}

fn visit_items(items: &[Item], parent_cfg: bool, body: &mut ParsedBody) {
    for item in items {
        let attrs = item_attrs(item);
        let cfg_gated = parent_cfg || has_cfg_attr(attrs);
        if cfg_gated && !matches!(item, Item::Use(_)) {
            body.cfg_gated_count += 1;
        }
        match item {
            Item::Use(item_use) => {
                let is_reexport = !matches!(item_use.vis, Visibility::Inherited);
                let mut paths: Vec<Vec<String>> = Vec::new();
                flatten_use_tree(&item_use.tree, Vec::new(), &mut paths);
                for segments in paths {
                    if segments.is_empty() {
                        continue;
                    }
                    body.imports.push(ImportEdge {
                        raw: segments.join("::"),
                        segments,
                        is_reexport,
                        cfg_gated,
                    });
                }
                if cfg_gated {
                    body.cfg_gated_count += 1;
                }
            }
            Item::ExternCrate(item) => {
                let name = item.ident.to_string();
                body.imports.push(ImportEdge {
                    raw: name.clone(),
                    segments: vec![name],
                    is_reexport: false,
                    cfg_gated,
                });
            }
            Item::Mod(item_mod) => {
                body.definitions.push(item_mod.ident.to_string());
                if let Some((_, nested)) = &item_mod.content {
                    visit_items(nested, cfg_gated, body);
                }
            }
            Item::Fn(item_fn) => {
                body.definitions.push(item_fn.sig.ident.to_string());
            }
            Item::Struct(item_struct) => {
                body.definitions.push(item_struct.ident.to_string());
            }
            Item::Enum(item_enum) => {
                body.definitions.push(item_enum.ident.to_string());
            }
            Item::Trait(item_trait) => {
                body.definitions.push(item_trait.ident.to_string());
            }
            Item::TraitAlias(item) => {
                body.definitions.push(item.ident.to_string());
            }
            Item::Type(item) => {
                body.definitions.push(item.ident.to_string());
            }
            Item::Const(item) => {
                body.definitions.push(item.ident.to_string());
            }
            Item::Static(item) => {
                body.definitions.push(item.ident.to_string());
            }
            Item::Union(item) => {
                body.definitions.push(item.ident.to_string());
            }
            _ => {}
        }
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn has_cfg_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("cfg"))
}

/// Flatten a `syn` use-tree into `::`-separated segment vectors.
fn flatten_use_tree(tree: &UseTree, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            flatten_use_tree(&path.tree, next, out);
        }
        UseTree::Name(name) => {
            let mut full = prefix;
            full.push(name.ident.to_string());
            out.push(full);
        }
        UseTree::Rename(rename) => {
            let mut full = prefix;
            full.push(rename.ident.to_string());
            out.push(full);
        }
        UseTree::Glob(_) => {
            let mut full = prefix;
            full.push("*".to_owned());
            out.push(full);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix.clone(), out);
            }
        }
    }
}

/// Read `Cargo.toml` manifest dependency edges via `cargo_metadata`.
///
/// Returns `(package_name, dependency_names)` pairs. This shells out to
/// `cargo metadata` under the hood, so it parses real manifests including
/// workspace inheritance — no hand-rolled TOML scraping.
pub fn crate_dependency_edges(
    manifest_path: &Path,
) -> Result<Vec<(String, Vec<String>)>, cargo_metadata::Error> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(manifest_path)
        .no_deps()
        .exec()?;
    let mut edges: Vec<(String, Vec<String>)> = metadata
        .packages
        .iter()
        .map(|package| {
            let deps = package
                .dependencies
                .iter()
                .map(|dep| dep.name.clone())
                .collect::<Vec<_>>();
            (package.name.clone(), deps)
        })
        .collect();
    edges.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(edges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_use_paths_reexports_and_cfg() {
        let body = parse_rust_source(
            r#"
            use crate::auth::{Authenticator, Session};
            pub use universal_device_sdk::capabilities::Capability;
            #[cfg(feature = "ble")]
            use crate::ble_gatt::GattServer;
            pub struct Widget;
            fn run() {}
            trait Runnable {}
            mod nested {
                use super::Widget;
                pub struct Inner;
            }
            "#,
        )
        .expect("parses");
        let raws: Vec<&str> = body.imports.iter().map(|i| i.raw.as_str()).collect();
        assert!(raws.contains(&"crate::auth::Authenticator"));
        assert!(raws.contains(&"crate::auth::Session"));
        assert!(raws.contains(&"universal_device_sdk::capabilities::Capability"));
        assert!(raws.contains(&"crate::ble_gatt::GattServer"));
        assert!(raws.contains(&"super::Widget"));

        let reexport = body
            .imports
            .iter()
            .find(|i| i.raw == "universal_device_sdk::capabilities::Capability")
            .expect("re-export recorded");
        assert!(reexport.is_reexport);

        let gated = body
            .imports
            .iter()
            .find(|i| i.raw == "crate::ble_gatt::GattServer")
            .expect("cfg import recorded");
        assert!(gated.cfg_gated);

        for name in ["Widget", "run", "Runnable", "nested", "Inner"] {
            assert!(
                body.definitions.contains(&name.to_owned()),
                "missing {name}"
            );
        }
        assert!(body.cfg_gated_count >= 1);
    }

    #[test]
    fn parses_group_and_glob_use_trees() {
        let body = parse_rust_source("use foo::{bar, baz::{Qux, Quux}, *};").expect("parses");
        let raws: Vec<&str> = body.imports.iter().map(|i| i.raw.as_str()).collect();
        assert!(raws.contains(&"foo::bar"));
        assert!(raws.contains(&"foo::baz::Qux"));
        assert!(raws.contains(&"foo::baz::Quux"));
        assert!(raws.contains(&"foo::*"));
    }
}
