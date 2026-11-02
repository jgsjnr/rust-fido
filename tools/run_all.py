#!/usr/bin/env python3
"""Unified run-all orchestrator (stdlib only, Windows + Linux).

Runs EVERYTHING in order and consolidates results:

Legs (execution order):
  1. test-debug             cargo test --workspace
  2. test-firmware-features cargo test -p aegis-fido-firmware --features freertos,proximity
  3. clippy                 cargo clippy --workspace --all-targets -- -D warnings
  4. fmt                    cargo fmt --all -- --check (ADVISORY, record-only)
  5. deny                   cargo deny check licenses advisories bans sources
  6. dep-track               python tools/dep_track.py --check
  7. docs                   python tools/docs-lint/docs_lint.py --root reports
                            python tools/docs-lint/docs_lint.py --root docs
                            + in-process broken internal-path scan of reports/**
  8. scripts                every scripts/*.ps1 exists + pwsh ParseFile syntax
                            check (parse only, never executes device scripts)
  9. test-release           cargo test --workspace --release (only with --release)

Each leg records: exit code, tail (last 15 lines), duration.
Outputs:
  reports/testing/consolidated-result.json  (machine-readable, overwritten)
  reports/testing/CONSOLIDATED_RUN.md       (human section appended, timestamped)

CLI:
  --release    include the release leg (off by default)
  --json-only  write JSON file, print JSON to stdout, skip markdown append
  --dry-run    list legs/commands without executing (exit 0, no file writes)
  --leg NAME   run a single leg only (test-release runs even without --release)

Exit-code contract:
  0  every non-advisory executed leg passed (advisory FAILs and SKIPs ignored)
  1  at least one non-advisory executed leg failed
  2  usage error (unknown --leg, safety violation)

Safety: never destructive. Any command referencing flash/monitor/esptool/adb
or cargo-update is refused before execution. No network calls are made by this
script itself. Deterministic emoji-free output. No secrets are printed or
persisted (only exit codes, durations, and output tails).
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_JSON = Path("reports/testing/consolidated-result.json")
REPORT_MD = Path("reports/testing/CONSOLIDATED_RUN.md")
TAIL_LINES = 15

# Refused before execution: this orchestrator must never flash, monitor,
# drive hardware tools, or mutate dependencies.
FORBIDDEN_SINGLE_TOKENS = {"flash", "monitor", "esptool", "adb"}

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
REMOTE_PREFIXES = ("http://", "https://", "mailto:", "ftp://", "data:")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def tail_lines(text, n=TAIL_LINES):
    lines = text.splitlines()
    return "\n".join(lines[-n:]) if lines else ""


def command_string(argv):
    return " ".join(str(a) for a in argv)


def assert_safe(argv):
    """Refuse destructive commands. Raises ValueError on violation."""
    lowered = [str(a).lower() for a in argv]
    joined = " ".join(lowered)
    for tok in FORBIDDEN_SINGLE_TOKENS:
        if tok in lowered:
            raise ValueError("refused destructive token: " + tok)
    if "cargo-update" in joined or "cargo update" in joined:
        raise ValueError("refused destructive token: cargo-update")
    return True


def find_pwsh():
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    return None


def pwsh_parse_command(pwsh_exe, ps1_path):
    """Build a parse-only (no-execution) syntax-check command for one file."""
    # Single quotes escaped by doubling; passed as one argv element (no shell).
    escaped = str(ps1_path).replace("'", "''")
    script = (
        "$tokens=$null; $errs=$null; "
        "$null=[System.Management.Automation.Language.Parser]::ParseFile('"
        + escaped
        + "',[ref]$tokens,[ref]$errs); "
        "if ($errs.Count -gt 0) { "
        "$errs | ForEach-Object { Write-Output $_.Message }; exit 1 } "
        "else { Write-Output 'SYNTAX-OK'; exit 0 }"
    )
    return [pwsh_exe, "-NoProfile", "-Command", script]


def scan_reports_links(root):
    """In-process broken internal-path scan of reports/** (.md links)."""
    reports_dir = root / "reports"
    checked = 0
    broken = []
    if not reports_dir.is_dir():
        return checked, [("(reports dir missing)", str(reports_dir))]
    for path in sorted(reports_dir.rglob("*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            broken.append((path.as_posix(), "(unreadable)"))
            continue
        docdir = path.parent
        for target in LINK_RE.findall(text):
            if target.startswith(REMOTE_PREFIXES) or target.startswith("#"):
                continue
            clean = target.split("#")[0]
            if not clean:
                continue
            checked += 1
            full = os.path.normpath(os.path.join(str(docdir), clean))
            if not os.path.exists(full):
                try:
                    rel = path.relative_to(root).as_posix()
                except ValueError:
                    rel = str(path)
                broken.append((rel, target))
    return checked, sorted(broken)


def build_legs(include_release):
    """Define the full ordered leg list. Commands use runtime-resolved paths."""
    py = sys.executable
    pwsh = find_pwsh() or "pwsh"
    script_files = sorted((ROOT / "scripts").glob("*.ps1"))
    scripts_cmds = [pwsh_parse_command(pwsh, p) for p in script_files]
    legs = [
        {
            "name": "test-debug",
            "desc": "workspace tests (debug)",
            "advisory": False,
            "release_only": False,
            "commands": [["cargo", "test", "--workspace"]],
            "internal": None,
        },
        {
            "name": "test-firmware-features",
            "desc": "firmware tests with freertos,proximity features",
            "advisory": False,
            "release_only": False,
            "commands": [
                [
                    "cargo",
                    "test",
                    "-p",
                    "aegis-fido-firmware",
                    "--features",
                    "freertos,proximity",
                ]
            ],
            "internal": None,
        },
        {
            "name": "clippy",
            "desc": "clippy workspace deny warnings",
            "advisory": False,
            "release_only": False,
            "commands": [
                [
                    "cargo",
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ]
            ],
            "internal": None,
        },
        {
            "name": "fmt",
            "desc": "cargo fmt check (ADVISORY record-only)",
            "advisory": True,
            "release_only": False,
            "commands": [["cargo", "fmt", "--all", "--", "--check"]],
            "internal": None,
        },
        {
            "name": "deny",
            "desc": "cargo deny licenses/advisories/bans/sources",
            "advisory": False,
            "release_only": False,
            "commands": [
                [
                    "cargo",
                    "deny",
                    "check",
                    "licenses",
                    "advisories",
                    "bans",
                    "sources",
                ]
            ],
            "internal": None,
        },
        {
            "name": "dep-track",
            "desc": "god-file trend gate",
            "advisory": False,
            "release_only": False,
            "commands": [[py, "tools/dep_track.py", "--check"]],
            "internal": None,
        },
        {
            "name": "docs",
            "desc": "docs-lint (reports, docs) + reports/** path scan",
            "advisory": False,
            "release_only": False,
            "commands": [
                [py, "tools/docs-lint/docs_lint.py", "--root", "reports"],
                [py, "tools/docs-lint/docs_lint.py", "--root", "docs"],
            ],
            "internal": "reports-scan",
        },
        {
            "name": "scripts",
            "desc": "scripts/*.ps1 existence + pwsh ParseFile syntax check",
            "advisory": False,
            "release_only": False,
            "commands": scripts_cmds,
            "internal": "scripts-exists",
        },
        {
            "name": "test-release",
            "desc": "workspace tests (release, opt-in)",
            "advisory": False,
            "release_only": True,
            "commands": [["cargo", "test", "--workspace", "--release"]],
            "internal": None,
        },
    ]
    if not include_release:
        for leg in legs:
            if leg["release_only"]:
                leg["skipped_reason"] = "needs --release"
    return legs


def run_command(argv, cwd):
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        out = proc.stdout or ""
        code = proc.returncode
    except FileNotFoundError as exc:
        out = "COMMAND-NOT-FOUND: %s (%s)" % (command_string(argv), exc)
        code = 127
    except OSError as exc:
        out = "EXEC-ERROR: %s (%s)" % (command_string(argv), exc)
        code = 127
    duration = time.monotonic() - start
    return code, out, duration


def run_leg(leg, cwd):
    """Execute one leg. Returns a result dict."""
    if leg.get("skipped_reason"):
        return {
            "name": leg["name"],
            "desc": leg["desc"],
            "advisory": leg["advisory"],
            "status": "SKIP",
            "exit": None,
            "duration_s": 0.0,
            "tail": leg["skipped_reason"],
            "commands": [command_string(c) for c in leg["commands"]],
            "notes": leg["skipped_reason"],
        }
    outputs = []
    total_dur = 0.0
    worst_exit = 0
    notes = []
    internal = leg.get("internal")

    if internal == "scripts-exists":
        script_files = sorted((ROOT / "scripts").glob("*.ps1"))
        if not script_files:
            outputs.append("SCRIPTS-CHECK: no scripts/*.ps1 files found")
            worst_exit = 1
        else:
            outputs.append(
                "SCRIPTS-CHECK: %d file(s) present" % len(script_files)
            )
        if find_pwsh() is None:
            outputs.append(
                "PWSH-MISSING: neither pwsh nor powershell found in PATH; "
                "parse check cannot run"
            )
            worst_exit = 1
            notes.append("pwsh not found")

    for argv in leg["commands"]:
        if internal == "scripts-exists" and find_pwsh() is None:
            continue  # recorded above; do not attempt execution
        code, out, dur = run_command(argv, cwd)
        total_dur += dur
        worst_exit = max(worst_exit, code)
        outputs.append("$ " + command_string(argv))
        outputs.append(out.rstrip() if out.strip() else "(no output)")
        outputs.append("exit=%d duration_s=%.1f" % (code, dur))

    if internal == "reports-scan":
        checked, broken = scan_reports_links(ROOT)
        outputs.append("REPORTS-SCAN: links checked=%d broken=%d" % (
            checked,
            len(broken),
        ))
        for doc, target in broken:
            outputs.append("BROKEN-PATH: %s -> %s" % (doc, target))
        notes.append("reports-scan checked=%d broken=%d" % (
            checked, len(broken)))
        if broken:
            worst_exit = max(worst_exit, 1)

    combined = "\n".join(outputs)
    status = "PASS" if worst_exit == 0 else "FAIL"
    return {
        "name": leg["name"],
        "desc": leg["desc"],
        "advisory": leg["advisory"],
        "status": status,
        "exit": worst_exit,
        "duration_s": round(total_dur, 1),
        "tail": tail_lines(combined),
        "commands": [command_string(c) for c in leg["commands"]],
        "notes": "; ".join(notes),
    }


def print_dry_run(legs):
    print("run-all dry-run: no commands executed, no files written")
    print("root: " + str(ROOT))
    for leg in legs:
        flag = "advisory" if leg["advisory"] else "gate"
        if leg.get("skipped_reason"):
            print("leg %s [%s] SKIP (%s)" % (
                leg["name"], flag, leg["skipped_reason"]))
            continue
        print("leg %s [%s] %s" % (leg["name"], flag, leg["desc"]))
        if leg.get("internal") == "reports-scan":
            print("  internal: reports/** broken internal-path scan")
        if leg.get("internal") == "scripts-exists":
            print("  internal: scripts/*.ps1 existence check")
        if not leg["commands"]:
            print("  (no subprocess commands)")
        for argv in leg["commands"]:
            print("  $ " + command_string(argv))


def append_markdown(timestamp, include_release, selector, results):
    md_path = ROOT / REPORT_MD
    md_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("## Run %s (release=%s, selector=%s)" % (
        timestamp,
        "on" if include_release else "off",
        selector,
    ))
    lines.append("")
    lines.append("| leg | advisory | status | exit | duration_s | notes |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for r in results:
        exit_s = str(r["exit"]) if r["exit"] is not None else "SKIP"
        dur_s = "%.1f" % r["duration_s"]
        adv_s = "yes" if r["advisory"] else "no"
        notes_s = (r.get("notes") or "").replace("|", "/").replace("\n", " ")
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            r["name"], adv_s, r["status"], exit_s, dur_s, notes_s,
        ))
    lines.append("")
    lines.append("### Tails (last %d lines per leg)" % TAIL_LINES)
    lines.append("")
    for r in results:
        exit_s = str(r["exit"]) if r["exit"] is not None else "SKIP"
        lines.append("#### `%s` - %s (exit %s, %ss)" % (
            r["name"], r["status"], exit_s, "%.1f" % r["duration_s"],
        ))
        lines.append("")
        lines.append("```")
        lines.append(r["tail"] if r["tail"] else "(empty)")
        lines.append("```")
        lines.append("")
    with open(md_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Unified run-all orchestrator (stdlib only)."
    )
    ap.add_argument("--release", action="store_true",
                    help="include the test-release leg (off by default)")
    ap.add_argument("--json-only", action="store_true",
                    help="print JSON to stdout and skip markdown append")
    ap.add_argument("--dry-run", action="store_true",
                    help="list legs/commands without executing")
    ap.add_argument("--leg", default=None, metavar="NAME",
                    help="run a single leg only")
    args = ap.parse_args(argv)

    legs = build_legs(include_release=args.release)
    selector = "all"
    if args.leg is not None:
        names = [leg["name"] for leg in legs]
        if args.leg not in names:
            print("run-all: unknown leg: %s (valid: %s)" % (
                args.leg, ", ".join(names)))
            return 2
        selector = args.leg
        legs = [leg for leg in legs if leg["name"] == args.leg]
        # Explicit --leg test-release runs even without --release.
        for leg in legs:
            leg.pop("skipped_reason", None)

    try:
        for leg in legs:
            for argv in leg["commands"]:
                assert_safe(argv)
    except ValueError as exc:
        print("run-all: safety refusal: %s" % exc)
        return 2

    if args.dry_run:
        print_dry_run(legs)
        return 0

    timestamp = utc_now()
    results = [run_leg(leg, ROOT) for leg in legs]

    failed = [r for r in results
              if r["status"] == "FAIL" and not r["advisory"]]
    advisory_failed = [r for r in results
                       if r["status"] == "FAIL" and r["advisory"]]
    skipped = [r for r in results if r["status"] == "SKIP"]
    passed = [r for r in results if r["status"] == "PASS"]
    overall = 1 if failed else 0

    payload = {
        "generated_by": "tools/run_all.py",
        "timestamp_utc": timestamp,
        "selector": selector,
        "include_release": args.release,
        "legs": results,
        "summary": {
            "passed": len(passed),
            "failed": len(failed),
            "advisory_failures": len(advisory_failed),
            "skipped": len(skipped),
            "exit": overall,
        },
    }

    json_path = ROOT / REPORT_JSON
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")

    if args.json_only:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        append_markdown(timestamp, args.release, selector, results)
        print("run-all %s release=%s selector=%s" % (
            timestamp, "on" if args.release else "off", selector))
        for r in results:
            exit_s = str(r["exit"]) if r["exit"] is not None else "SKIP"
            adv = " [advisory]" if r["advisory"] else ""
            print("  %s: %s exit=%s %.1fs%s" % (
                r["name"], r["status"], exit_s, r["duration_s"], adv))
        print("summary: passed=%d failed=%d advisory_failures=%d skipped=%d"
              % (len(passed), len(failed), len(advisory_failed),
                 len(skipped)))
        print("json: %s" % REPORT_JSON.as_posix())
        print("md: %s" % REPORT_MD.as_posix())
        if failed:
            print("RESULT: FAIL")
        else:
            print("RESULT: PASS")

    return overall


if __name__ == "__main__":
    sys.exit(main())
