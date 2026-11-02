#!/usr/bin/env python3
"""docs-lint: heuristic markdown link + terminology checker (stub).

ASD-STE100 status: HEURISTIC ONLY, NOT certified. No controlled-language
tool is run here. Sentence-length flags below are style hints, not
compliance evidence. Do not claim certification on the basis of this tool.

Checks:
  1. Markdown links: every local relative link target must exist on disk.
     Remote links (http/https/mailto) and pure anchors (#...) are skipped.
  2. Banned-brand heuristic: terms from the trademark audit that need human
     REVIEW before release. These are warnings, never auto-fixes.

Exit codes (deterministic, emoji-free output):
  0 = no broken local links (warnings may still be printed).
  1 = one or more broken local links found.
  2 = usage error (bad arguments, unreadable root).

Usage:
  python tools/docs-lint/docs_lint.py [--root DIR] [--strict]

  --strict also turns brand-heuristic hits into exit 1.
"""
import os
import re
import sys

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
WORD_RE = re.compile(r"[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*")

# Terms needing human REVIEW per reports/compliance/trademark-audit.md.
# Heuristic substring match; factual protocol references are NOT flagged.
BRAND_PATTERNS = [
    "Google Authenticator",
    "FIDO Certified",
    "FIDO Certification",
    "Windows Hello",
    "certified",
]

REMOTE_PREFIXES = ("http://", "https://", "mailto:", "ftp://", "data:")

LONG_SENTENCE_WORDS = 25


def iter_markdown_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in (".git", "node_modules", "target")
        )
        for name in sorted(filenames):
            if name.endswith(".md"):
                yield os.path.join(dirpath, name)


def check_links(root):
    broken = []
    checked = 0
    for path in iter_markdown_files(root):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        docdir = os.path.dirname(path)
        for target in LINK_RE.findall(text):
            if target.startswith(REMOTE_PREFIXES) or target.startswith("#"):
                continue
            clean = target.split("#")[0]
            if not clean:
                continue
            checked += 1
            full = os.path.normpath(os.path.join(docdir, clean))
            if not os.path.exists(full):
                broken.append((path, target))
    return checked, sorted(broken)


def check_brands(root):
    hits = []
    for path in iter_markdown_files(root):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle.read().splitlines(), 1):
                lowered = line.lower()
                if ("not certified" in lowered or "no certification" in lowered
                        or "never claim" in lowered):
                    continue
                for pattern in BRAND_PATTERNS:
                    if pattern.lower() in lowered:
                        hits.append((path, lineno, pattern))
    return sorted(hits)


def check_sentences(root):
    long_hits = []
    for path in iter_markdown_files(root):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "|", "-", "*", ">")):
                continue
            for sentence in re.split(r"(?<=[.!?])\s+", stripped):
                words = WORD_RE.findall(sentence)
                if len(words) > LONG_SENTENCE_WORDS:
                    long_hits.append((path, lineno, len(words)))
    return sorted(long_hits)


def main(argv):
    root = "."
    strict = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--strict":
            strict = True
        elif arg == "--root":
            if i + 1 >= len(argv):
                print("docs-lint: --root needs a directory")
                return 2
            root = argv[i + 1]
            i += 1
        elif arg.startswith("--root="):
            root = arg.split("=", 1)[1]
        elif arg in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        else:
            print("docs-lint: unknown argument: " + arg)
            return 2
        i += 1
    if not os.path.isdir(root):
        print("docs-lint: root not found: " + root)
        return 2

    checked, broken = check_links(root)
    brands = check_brands(root)
    long_sentences = check_sentences(root)

    print("docs-lint root: " + os.path.abspath(root))
    print("links checked: " + str(checked))
    print("broken links: " + str(len(broken)))
    for path, target in broken:
        print("BROKEN: " + path + " -> " + target)
    print("brand-heuristic hits: " + str(len(brands)))
    for path, lineno, pattern in brands:
        print("BRAND-REVIEW: " + path + ":" + str(lineno) + " [" + pattern + "]")
    print("long-sentence hints (>25 words, ASD-STE100 heuristic, NOT certified): "
          + str(len(long_sentences)))
    for path, lineno, count in long_sentences[:20]:
        print("STYLE-HINT: " + path + ":" + str(lineno)
              + " (" + str(count) + " words)")

    if broken:
        return 1
    if strict and brands:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


