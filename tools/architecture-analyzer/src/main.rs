//! `architecture-analyzer` binary: analyze, cycles, god-files, diff.

use std::path::PathBuf;

use architecture_analyzer::{
    build_graph, diff_graphs, find_violations, god_files_with_lines, load_graph_file,
    DEFAULT_GOD_LINES, DEFAULT_GOD_SCORE,
};

fn usage() -> &'static str {
    "architecture-analyzer\n\
     \n\
     USAGE:\n\
     \x20 architecture-analyzer analyze --root <path> [--out <file>]\n\
     \x20 architecture-analyzer cycles --root <path> [--out <file>]\n\
     \x20 architecture-analyzer god-files --root <path> [--lines N] [--score N] [--out <file>]\n\
     \x20 architecture-analyzer diff --before <file> --after <file> [--out <file>]\n\
     \n\
     analyze    emit the file graph JSON (FILE, DEFINITIONS, USED BY, DEPENDS ON,\n\
     \x20           CURRENT LAYER, RECOMMENDED LAYER, ACTION, REASON)\n\
     cycles     check forbidden Core->SDK, Firmware->SDK, Core->Firmware edges\n\
     god-files  flag oversized / over-connected files (lines + fan-in/out)\n\
     diff       compare two analyze snapshots and emit an impact manifest"
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn write_output(json: &str, out: Option<String>) -> Result<(), String> {
    if let Some(path) = out {
        std::fs::write(&path, format!("{json}\n")).map_err(|err| format!("write {path}: {err}"))?;
    }
    println!("{json}");
    Ok(())
}

fn cmd_analyze(args: &[String]) -> Result<i32, String> {
    let root = arg_value(args, "--root").ok_or("analyze requires --root <path>")?;
    let out = arg_value(args, "--out");
    let root_path = PathBuf::from(&root);
    let graph = build_graph(&root_path).map_err(|err| err.to_string())?;
    let json =
        serde_json::to_string_pretty(&graph).map_err(|err| format!("encode graph: {err}"))?;
    write_output(&json, out)?;
    Ok(0)
}

fn cmd_cycles(args: &[String]) -> Result<i32, String> {
    let root = arg_value(args, "--root").ok_or("cycles requires --root <path>")?;
    let out = arg_value(args, "--out");
    let root_path = PathBuf::from(&root);
    let graph = build_graph(&root_path).map_err(|err| err.to_string())?;
    let report = find_violations(&graph, &root_path);
    let json =
        serde_json::to_string_pretty(&report).map_err(|err| format!("encode report: {err}"))?;
    write_output(&json, out)?;
    if report.violations.is_empty() {
        Ok(0)
    } else {
        // Non-zero so CI can gate on forbidden edges.
        Ok(2)
    }
}

fn cmd_god_files(args: &[String]) -> Result<i32, String> {
    let root = arg_value(args, "--root").ok_or("god-files requires --root <path>")?;
    let out = arg_value(args, "--out");
    let lines = arg_value(args, "--lines")
        .map(|v| v.parse::<usize>().map_err(|_| "--lines must be a number"))
        .transpose()?
        .unwrap_or(DEFAULT_GOD_LINES);
    let score = arg_value(args, "--score")
        .map(|v| v.parse::<f64>().map_err(|_| "--score must be a number"))
        .transpose()?
        .unwrap_or(DEFAULT_GOD_SCORE);
    let root_path = PathBuf::from(&root);
    let graph = build_graph(&root_path).map_err(|err| err.to_string())?;
    // Exact physical line counts: re-read each file once (cheap, sync).
    let lookup = |file: &str| {
        std::fs::read_to_string(root_path.join(file))
            .ok()
            .map(|src| src.lines().count())
    };
    let report = god_files_with_lines(&graph, lines, score, &lookup);
    let json =
        serde_json::to_string_pretty(&report).map_err(|err| format!("encode report: {err}"))?;
    write_output(&json, out)?;
    Ok(0)
}

fn cmd_diff(args: &[String]) -> Result<i32, String> {
    let before = arg_value(args, "--before").ok_or("diff requires --before <file>")?;
    let after = arg_value(args, "--after").ok_or("diff requires --after <file>")?;
    let out = arg_value(args, "--out");
    let before_graph = load_graph_file(&PathBuf::from(&before))?;
    let after_graph = load_graph_file(&PathBuf::from(&after))?;
    let report = diff_graphs(&before_graph, &after_graph);
    let json =
        serde_json::to_string_pretty(&report).map_err(|err| format!("encode diff: {err}"))?;
    write_output(&json, out)?;
    Ok(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || has_flag(&args, "--help") || has_flag(&args, "-h") {
        println!("{}", usage());
        std::process::exit(0);
    }
    let rest = args[2..].to_vec();
    let result = match args[1].as_str() {
        "analyze" => cmd_analyze(&rest),
        "cycles" => cmd_cycles(&rest),
        "god-files" => cmd_god_files(&rest),
        "diff" => cmd_diff(&rest),
        other => Err(format!("unknown command '{other}'\n{}", usage())),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}
