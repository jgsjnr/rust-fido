"""depcheck: recompile aegis_usb.c via the ESP-IDF compile database.

Resolves compile_commands.json at runtime (no hardcoded machine paths):
  $CARGO_TARGET_DIR -> .cargo/config.toml target-dir -> <repo>/target
Globs xtensa-esp32s3-espidf/release/build/esp-idf-sys-*/out/build/compile_commands.json
(newest wins). Override: python tools/depcheck.py --compile-db <path>.
Exit 2 BLOCKED when the DB is absent, with how to generate it.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_db(explicit):
    if explicit:
        return explicit
    cands = []
    roots = [os.environ.get("CARGO_TARGET_DIR", "")]
    try:
        from tomllib import load as toml_load
        with open(os.path.join(REPO, ".cargo", "config.toml"), "rb") as f:
            td = toml_load(f).get("build", {}).get("target-dir")
            if td:
                roots.append(td)
    except Exception:
        pass
    roots.append(os.path.join(REPO, "target"))
    roots.append(r"C:\t")
    for r in roots:
        if r:
            cands += glob.glob(os.path.join(
                r, "xtensa-esp32s3-espidf", "release", "build",
                "esp-idf-sys-*", "out", "build", "compile_commands.json"))
    if not cands:
        return None
    return sorted(cands, key=os.path.getmtime)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compile-db", default=None)
    args = ap.parse_args()
    db = find_db(args.compile_db)
    if not db or not os.path.isfile(db):
        print("BLOCKED: compile_commands.json not found.", file=sys.stderr)
        print("Searched: $CARGO_TARGET_DIR, .cargo/config.toml target-dir, "
              "<repo>/target, C:\\t (newest esp-idf-sys-*).", file=sys.stderr)
        print("Generate it with an ESP-IDF firmware build, e.g. "
              "scripts/build-freertos-s3.ps1, or pass --compile-db <path>.",
              file=sys.stderr)
        return 2
    cc = json.load(open(db))
    for e in cc:
        if e["file"].replace("\\", "/").endswith("aegis_usb/aegis_usb.c"):
            cmd = e["command"]
            break
    else:
        print("BLOCKED: aegis_usb.c entry missing in %s" % db, file=sys.stderr)
        return 2
    # troca o output para um .o de teste
    cmd = re.sub(r"-o \S+", "-o C:/t/ninja_test.o", cmd)
    print("CMD:", cmd[:200], "...")
    r = subprocess.run(cmd, shell=True, cwd=e["directory"],
                       capture_output=True, text=True)
    print("RC=", r.returncode)
    print((r.stdout + r.stderr)[-1500:])
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
