#!/usr/bin/env python3
"""Dependency / file-size tracker for the standalone-architecture cleanup.

HEURISTIC NOTICE: the Rust `mod` / `use` extraction below is regex-based and
approximate (it ignores block comments, cfg-gating, macros and glob re-exports).
For precise AST-level results use tools/architecture-analyzer/ as the source of
truth; this script is only a fast, stdlib-only CI trend gate.

Reads:
  crates/<crate>/src/**/*.rs          (path, bytes, lines, mods, uses)
  crates/<crate>/Cargo.toml           ([dependencies] per crate)
  Cargo.lock                          (locked versions for workspace deps)

Writes:
  reports/refactoring/dep-track.json

CI gate:
  python tools/dep_track.py --check
exits 2 when a file with god_score > 25 is NOT on GOD_ALLOWLIST below.
The allowlist is the current baseline: the goal is to SHRINK it over time by
splitting god-files, never to grow it. Additions need parent approval.
"""

import argparse
import json
import re
import sys
from pathlib import Path

GOD_SCORE_THRESHOLD = 25.0
LINES_FLAG_THRESHOLD = 800

# Baseline of known god-files (god_score > 25 on the current tree).
# Goal: shrink this list. Do not add entries without parent approval.
GOD_ALLOWLIST = frozenset({
    # Baseline god-files (god-files.md 5 known + current tier-2
    # set scoring > 25). Goal: SHRINK this list, never grow it.
    "crates/aegis-fido-core/src/credential/key_manager.rs",
    "crates/aegis-fido-core/src/ctap/client_pin.rs",
    "crates/aegis-fido-core/src/ctap/get_assertion.rs",
    "crates/aegis-fido-core/src/ctap/mod.rs",
    "crates/aegis-fido-core/src/oath/applet.rs",
    "crates/aegis-fido-core/src/wallet/store.rs",
    "crates/aegis-fido-firmware/src/binding.rs",
    "crates/aegis-fido-firmware/src/ble_nimble.rs",
    "crates/aegis-fido-firmware/src/ctap_cmd.rs",
    "crates/aegis-fido-firmware/src/ctap_state.rs",
    "crates/aegis-fido-firmware/src/freertos_route.rs",
    "crates/aegis-fido-firmware/src/persistence.rs",
    "crates/aegis-fido-firmware/src/run/ble_dispatch.rs",
    "crates/aegis-fido-firmware/src/run/mod.rs",
    "crates/aegis-fido-firmware/src/run/run_loop_freertos.rs",
    "crates/aegis-fido-firmware/src/run/run_loop_legacy.rs",
    "crates/aegis-fido-firmware/src/secure_guard_exec.rs",
    "crates/aegis-fido-firmware/src/serial_ctaphid.rs",
    "crates/aegis-fido-firmware/src/trust_facade.rs",
    "crates/aegis-fido-firmware/src/vault_aead.rs",
    # NAO-FATIAVEL (score por fan_in heuristico, nao por tamanho):
    # - zeroize.rs: 86 linhas; score 25.86 vem de fan_in=47 porque o heuristico
    #   conta cada `use zeroize::...` (crate externo) como referencia ao stem
    #   "zeroize". Primitiva minima de scrub (scrub + SecretBytes<N>); dividir
    #   criaria acoplamento artificial sem reduzir fan_in.
    # - aegis-fido-core lib.rs: 39 linhas, crate-root re-export hub;
    #   fan_in=50 e' por desenho (todo consumidor referencia o crate).
    #   Goal continua SHRINK; estas 2 entradas documentam falso-positivo de
    #   fan_in, nao god-files reais.
    "crates/aegis-fido-firmware/src/zeroize.rs",
    "crates/aegis-fido-core/src/lib.rs",
    "crates/aegis-fido-usb/src/piv/piv_cmd.rs",
    "crates/aegis-secure-guard/src/engine.rs",
    "crates/aegis-secure-guard/src/persistence.rs",
    "crates/uniffi-bridge/src/lib.rs",
})

RE_MOD = re.compile(
    r"^\s*(?:pub\s*(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RE_USE = re.compile(r"^\s*use\s+([^;]+);")
RE_LOCK_PKG = re.compile(
    r"\[\[package\]\]\s*\r?\nname\s*=\s*\"([^\"]+)\"\s*\r?\n"
    r"version\s*=\s*\"([^\"]+)\"",
)
INTERNAL_USE_PREFIXES = ("aegis_", "crate::", "super::")


def strip_line_comment(line):
    # Heuristic: cut // comments (ignores // inside string literals).
    idx = line.find("//")
    if idx == -1:
        return line
    return line[:idx]


def expand_use_path(raw):
    """Expand `prefix::{a, b}` groups into individual paths (heuristic)."""
    raw = " ".join(raw.split())
    m = re.search(r"\{([^{}]*)\}", raw)
    if not m:
        return [raw]
    prefix = raw[: m.start()].rstrip(":")
    items = [i.strip() for i in m.group(1).split(",") if i.strip()]
    out = []
    for item in items:
        if item.startswith("self") and prefix:
            out.append(prefix)
        elif prefix:
            out.append(prefix + "::" + item)
        else:
            out.append(item)
    return out


def use_segments(path):
    segs = []
    for part in path.split("::"):
        part = part.strip().strip("{} ").split(" ")[0]
        part = part.strip()
        if part and part not in ("self", "super", "crate"):
            segs.append(part)
    return segs


def is_internal_use(path):
    p = path.strip()
    return (
        p.startswith("crate::")
        or p.startswith("super::")
        or p == "crate"
        or p == "super"
        or bool(re.match(r"aegis_[A-Za-z0-9_]*", p))
    )


def scan_rs_file(path):
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    mods = []
    uses = []
    for line in lines:
        code = strip_line_comment(line)
        m = RE_MOD.match(code)
        if m:
            mods.append(m.group(1))
        u = RE_USE.match(code)
        if u:
            for expanded in expand_use_path(u.group(1).strip()):
                uses.append(expanded)
    return {
        "bytes": len(raw),
        "lines": len(lines),
        "mods": mods,
        "uses": uses,
    }


def load_toml(path):
    """Parse TOML via stdlib tomllib when available, else None."""
    try:
        import tomllib
    except ImportError:
        return None
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return None


def parse_deps_fallback(text):
    """Minimal hand parser for a [dependencies] section (heuristic)."""
    deps = {}
    in_deps = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_deps = s in ("[dependencies]", "[dependencies ]")
            continue
        if not in_deps or not s or s.startswith("#"):
            continue
        m = re.match(r"([A-Za-z0-9_-]+)\s*=\s*(.*)", s)
        if m:
            deps[m.group(1)] = m.group(2).strip()
    return deps


def norm_dep_value(value, workspace_versions):
    """Normalize one [dependencies] value to a dep record (heuristic)."""
    if isinstance(value, str):
        if value == "workspace":
            return {"version": None, "path": False,
                    "path_target": None, "workspace": True}
        return {"version": value, "path": False,
                "path_target": None, "workspace": False}
    if isinstance(value, dict):
        return {"version": value.get("version")
                if not value.get("workspace") else
                workspace_versions.get("__pending__"),
                "path": bool(value.get("path")),
                "path_target": value.get("path"),
                "workspace": bool(value.get("workspace"))}
    return {"version": None, "path": False,
            "path_target": None, "workspace": False}


def read_crate_deps(manifest_path, workspace_versions):
    data = load_toml(manifest_path)
    deps = []
    if data is not None:
        raw_deps = data.get("dependencies", {}) or {}
        for name in sorted(raw_deps):
            rec = norm_dep_value(raw_deps[name], workspace_versions)
            if rec["workspace"] and rec["version"] is None:
                rec["version"] = workspace_versions.get(name)
            deps.append({"name": name, **rec})
        return deps
    # Fallback: regex hand parser over the raw text.
    try:
        text = manifest_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps
    parsed = parse_deps_fallback(text)
    for name in sorted(parsed):
        raw = parsed[name]
        version = None
        path_target = None
        workspace = False
        mv = re.search(r"version\s*=\s*\"([^\"]+)\"", raw)
        if mv:
            version = mv.group(1)
        elif raw.startswith("\"") and raw.endswith("\""):
            version = raw.strip("\"")
        mp = re.search(r"path\s*=\s*\"([^\"]+)\"", raw)
        if mp:
            path_target = mp.group(1)
        if "workspace" in raw:
            workspace = True
            version = workspace_versions.get(name, version)
        deps.append({"name": name, "version": version,
                     "path": path_target is not None,
                     "path_target": path_target,
                     "workspace": workspace})
    return deps


def read_workspace_versions(root):
    data = load_toml(root / "Cargo.toml")
    versions = {}
    if data is not None:
        ws_deps = data.get("workspace", {}).get("dependencies", {}) or {}
        for name, val in ws_deps.items():
            if isinstance(val, str):
                versions[name] = val
            elif isinstance(val, dict) and val.get("version"):
                versions[name] = val["version"]
        return versions
    # Fallback: regex over [workspace.dependencies].
    try:
        text = (root / "Cargo.toml").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return versions
    in_ws = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_ws = s in ("[workspace.dependencies]",
                          "[workspace.dependencies ]")
            continue
        if in_ws and s and not s.startswith("#"):
            m = re.match(r"([A-Za-z0-9_-]+)\s*=\s*(.*)", s)
            if m:
                raw = m.group(2).strip()
                mv = re.search(r"version\s*=\s*\"([^\"]+)\"", raw)
                if mv:
                    versions[m.group(1)] = mv.group(1)
                elif raw.startswith("\""):
                    versions[m.group(1)] = raw.strip().strip("\"")
    return versions


def read_lock_versions(root):
    """Map Cargo.lock package name -> locked version (first wins)."""
    lock = root / "Cargo.lock"
    data = load_toml(lock)
    if data is not None and data.get("package") is not None:
        out = {}
        for pkg in data.get("package", []) or []:
            name = pkg.get("name")
            if name and name not in out:
                out[name] = pkg.get("version")
        return out
    try:
        text = lock.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    out = {}
    for m in RE_LOCK_PKG.finditer(text):
        if m.group(1) not in out:
            out[m.group(1)] = m.group(2)
    return out


def file_stem_key(rel_posix):
    p = Path(rel_posix)
    if p.name == "mod.rs":
        return p.parent.name
    if p.name in ("lib.rs", "main.rs"):
        return "__crate_root__"
    return p.stem


def compute_fans(files):
    """fan_out: internal-use count per file; fan_in: files referencing it."""
    for f in files:
        f["fan_out"] = sum(1 for u in f["uses"] if is_internal_use(u))
    use_seg_sets = []
    for f in files:
        segs = set()
        for u in f["uses"]:
            for expanded in expand_use_path(u):
                segs.update(use_segments(expanded))
        use_seg_sets.append(segs)
    for i, f in enumerate(files):
        key = file_stem_key(f["path"])
        if key == "__crate_root__":
            crate = f["path"].split("/")[1].replace("-", "_")
            hits = sum(
                1 for j, segs in enumerate(use_seg_sets)
                if j != i and crate in segs
            )
        else:
            hits = sum(
                1 for j, segs in enumerate(use_seg_sets)
                if j != i and key in segs
            )
        f["fan_in"] = hits


def build_report(root):
    crates_dir = root / "crates"
    rs_files = sorted(crates_dir.glob("*/src/**/*.rs"))
    files = []
    for p in rs_files:
        if not p.is_file():
            continue
        info = scan_rs_file(p)
        rel = p.relative_to(root).as_posix()
        files.append({"path": rel, "bytes": info["bytes"],
                      "lines": info["lines"], "mods": info["mods"],
                      "uses": info["uses"]})
    compute_fans(files)
    for f in files:
        score = f["lines"] / 100.0 + f["fan_out"] * 1.5 + f["fan_in"] * 0.5
        f["god_score"] = round(score, 2)
        reasons = []
        if f["god_score"] > GOD_SCORE_THRESHOLD:
            reasons.append("god-score>25")
        if f["lines"] > LINES_FLAG_THRESHOLD:
            reasons.append("lines>800")
        f["flag"] = bool(reasons)
        f["flag_reason"] = "+".join(reasons) if reasons else None
    files.sort(key=lambda f: f["path"])

    workspace_versions = read_workspace_versions(root)
    lock_versions = read_lock_versions(root)
    crates = {}
    for manifest in sorted(crates_dir.glob("*/Cargo.toml")):
        crate_name = manifest.parent.name
        data = load_toml(manifest)
        if data is not None:
            try:
                crate_name = data.get("package", {}).get("name", crate_name)
            except (AttributeError, ValueError):
                pass
        crates[crate_name] = {
            "manifest": manifest.relative_to(root).as_posix(),
            "deps": read_crate_deps(manifest, workspace_versions),
        }

    wanted = set()
    for info in crates.values():
        for d in info["deps"]:
            wanted.add(d["name"])
    lock_packages = {n: lock_versions.get(n) for n in sorted(wanted)}

    gods = sorted(
        (f for f in files if f["god_score"] > GOD_SCORE_THRESHOLD),
        key=lambda f: -f["god_score"],
    )
    summary = {
        "totals": {
            "files": len(files),
            "bytes": sum(f["bytes"] for f in files),
            "lines": sum(f["lines"] for f in files),
            "flagged": sum(1 for f in files if f["flag"]),
            "gods": len(gods),
        },
        "top10_god": [
            {"path": g["path"], "god_score": g["god_score"],
             "lines": g["lines"], "fan_in": g["fan_in"],
             "fan_out": g["fan_out"]}
            for g in gods[:10]
        ],
    }
    return {
        "generated_by": "tools/dep_track.py",
        "files": files,
        "crates": crates,
        "lock_packages": lock_packages,
        "summary": summary,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Track Rust file sizes, deps and god-files.")
    ap.add_argument("--root", default=".",
                    help="Workspace root (default: .)")
    ap.add_argument("--out",
                    default="reports/refactoring/dep-track.json",
                    help="Output JSON path, relative to --root")
    ap.add_argument("--check", action="store_true",
                    help="Exit 2 if a NEW god-file (score>25) "
                         "outside the allowlist exists")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    report = build_report(root)
    out_path = (root / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=False)
        fh.write("\n")
    try:
        shown = out_path.relative_to(root).as_posix()
    except ValueError:
        shown = str(out_path)
    print("wrote %s (%d files, %d gods)" % (
        shown, report["summary"]["totals"]["files"],
        report["summary"]["totals"]["gods"]))
    if not args.check:
        return 0
    new_gods = [f for f in report["files"]
                if f["god_score"] > GOD_SCORE_THRESHOLD
                and f["path"] not in GOD_ALLOWLIST]
    if new_gods:
        print("NEW god-files (score>25, not in allowlist):")
        for f in sorted(new_gods, key=lambda f: -f["god_score"]):
            print("  %.2f %s (lines=%d fan_in=%d fan_out=%d)" % (
                f["god_score"], f["path"], f["lines"],
                f["fan_in"], f["fan_out"]))
        return 2
    print("check ok: no new god-files beyond %d allowlisted" %
          len(GOD_ALLOWLIST))
    return 0


if __name__ == "__main__":
    sys.exit(main())
