use camino::Utf8PathBuf;
use uniffi::{generate_bindings, KotlinBindingGenerator};

/// Generate Kotlin bindings from the UDL into the Android source tree.
///
/// Usage: uniffi-gen [udl_path] [out_dir]
/// Defaults resolve relative to CARGO_MANIFEST_DIR (../../).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("..").join("..");
    let root = root.canonicalize().unwrap_or_else(|_| root);
    let default_udl = root.join("crates").join("uniffi-bridge").join("src").join("aegis_bridge.udl");
    let default_out = root.join("app-android").join("app").join("src").join("main").join("java");
    let udl_fs = args.get(1).map(std::path::PathBuf::from).unwrap_or(default_udl);
    let out_fs = args.get(2).map(std::path::PathBuf::from).unwrap_or(default_out);
    if !udl_fs.is_file() {
        return Err(format!("UDL not found: {}", udl_fs.display()).into());
    }
    if !out_fs.is_dir() {
        return Err(format!("out dir not found: {}", out_fs.display()).into());
    }
    let udl = Utf8PathBuf::from_path_buf(udl_fs).map_err(|p| format!("non-utf8 UDL path: {}", p.display()))?;
    let out = Utf8PathBuf::from_path_buf(out_fs).map_err(|p| format!("non-utf8 out path: {}", p.display()))?;
    generate_bindings(&udl, None, KotlinBindingGenerator, Some(&out), None, None, false)?;
    println!("uniffi-gen ok: {} -> {}", udl, out);
    Ok(())
}