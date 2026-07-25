"""Em-dash gate (Phase 4c §4c.X).

Fails if any tracked in-scope file contains U+2014 (em-dash). En-dashes
(U+2013) in numeric ranges like "Phase 0-4b" or "windows 1-4" are a different
glyph with a different job and are deliberately left alone.

Scope: .py, .md, .yaml, .yml, .toml, plus Dockerfile and Makefile by name.
Notebooks are not in scope because no .ipynb is committed.

Usage:

    python scripts/check_no_emdash.py           # report and exit 1 on any hit
    python scripts/check_no_emdash.py --count   # print the count only

Why a script rather than a shell one-liner: the obvious PowerShell version,

    (Select-String -Path *.md,*.py -Recurse -Pattern "—" -SimpleMatch).Count

reports 0 on a tree that contains hundreds of them. `-Path` with a glob does
not recurse into subdirectories the way `-Recurse` implies, so src/, tests/,
and docker/ are never visited, and the literal em-dash in the pattern is
mangled by console encoding before it reaches the matcher. A gate that
silently returns 0 on a dirty tree is worse than no gate. This script reads
git's own tracked-file list and compares codepoints.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

EM_DASH = "—"

# .txt added in the §4c.A redo: requirements.txt carried three em-dashes in its
# comments and the gate reported a clean 0 the whole time, purely because .txt
# was out of scope. A gate whose clean reading depends on not looking at a file
# is worth less than the file it skips.
SCOPE_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".txt", ".cfg", ".ini"}
SCOPE_NAMES = {"Dockerfile", "Makefile"}


def tracked_files(repo_root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        check=True,
        cwd=repo_root,
    ).stdout.splitlines()
    return [repo_root / line for line in out if line.strip()]


def in_scope(path: Path) -> bool:
    return path.suffix.lower() in SCOPE_SUFFIXES or path.name in SCOPE_NAMES


def find_hits(repo_root: Path) -> list[tuple[Path, int, str]]:
    """Return (path, line_number, line_text) for every em-dash occurrence."""
    hits: list[tuple[Path, int, str]] = []
    for path in tracked_files(repo_root):
        if not in_scope(path) or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if EM_DASH not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if EM_DASH in line:
                hits.append((path, lineno, line.strip()))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail if any tracked file contains an em-dash.")
    parser.add_argument(
        "--count",
        action="store_true",
        help="print only the total occurrence count",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    repo_root = Path(__file__).resolve().parent.parent
    hits = find_hits(repo_root)
    occurrences = sum(line.count(EM_DASH) for _, _, line in hits)

    if args.count:
        print(occurrences)
        return 0 if occurrences == 0 else 1

    if not hits:
        print("check_no_emdash: OK, no em-dashes in tracked in-scope files")
        return 0

    print(f"check_no_emdash: FAIL, {occurrences} em-dash(es) on {len(hits)} line(s):")
    for path, lineno, line in hits:
        rel = path.relative_to(repo_root).as_posix()
        excerpt = line if len(line) <= 100 else line[:97] + "..."
        print(f"  {rel}:{lineno}: {excerpt}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
