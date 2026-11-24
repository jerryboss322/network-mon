#!/usr/bin/env python3
"""Accurate authored source-code LOC counter for network-mon.

Counts actual authored source lines while strictly excluding third-party
modules, lockfiles, build artifacts, caches, and generated files.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

SOURCE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX)",
    ".js": "JavaScript",
    ".jsx": "JavaScript (JSX)",
    ".rs": "Rust",
    ".css": "CSS",
    ".scss": "SCSS",
    ".html": "HTML",
    ".sql": "SQL",
    ".sh": "Shell",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".toml": "TOML",
}

EXCLUDED_DIRS: set[str] = {
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    "out",
    ".vercel",
    "coverage",
    "htmlcov",
    ".vite",
    "vendor",
}

EXCLUDED_FILES: set[str] = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "poetry.lock",
    "uv.lock",
}


def count_file_lines(path: Path) -> tuple[int, int]:
    """Return (total_lines, non_blank_lines) for a source file."""
    total = 0
    non_blank = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                total += 1
                if line.strip():
                    non_blank += 1
    except OSError:
        return 0, 0
    return total, non_blank


def scan_repo(root: Path) -> dict:
    by_lang: dict[str, dict[str, int]] = defaultdict(
        lambda: {"files": 0, "total_lines": 0, "code_lines": 0}
    )
    by_dir: dict[str, dict[str, int]] = defaultdict(
        lambda: {"files": 0, "total_lines": 0, "code_lines": 0}
    )

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for fname in filenames:
            if fname in EXCLUDED_FILES or fname.endswith(".min.js") or fname.endswith(".min.css"):
                continue
            fpath = Path(dirpath) / fname
            ext = fpath.suffix.lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            lang = SOURCE_EXTENSIONS[ext]
            total, non_blank = count_file_lines(fpath)
            rel = fpath.relative_to(root)
            top = rel.parts[0] if len(rel.parts) > 1 else "(root)"

            by_lang[lang]["files"] += 1
            by_lang[lang]["total_lines"] += total
            by_lang[lang]["code_lines"] += non_blank

            by_dir[top]["files"] += 1
            by_dir[top]["total_lines"] += total
            by_dir[top]["code_lines"] += non_blank

    grand_files = sum(v["files"] for v in by_lang.values())
    grand_total = sum(v["total_lines"] for v in by_lang.values())
    grand_code = sum(v["code_lines"] for v in by_lang.values())

    return {
        "total_files": grand_files,
        "total_lines": grand_total,
        "non_blank_lines": grand_code,
        "by_language": dict(sorted(by_lang.items(), key=lambda kv: -kv[1]["total_lines"])),
        "by_directory": dict(sorted(by_dir.items(), key=lambda kv: -kv[1]["total_lines"])),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Count authored LOC in network-mon")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--root", default=".", help="Repository root path")
    args = parser.parse_args()

    result = scan_repo(Path(args.root).resolve())
    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"Total source files : {result['total_files']:,}")
    print(f"Total lines (LOC)  : {result['total_lines']:,}")
    print(f"Non-blank lines    : {result['non_blank_lines']:,}")
    print("\nBy Language:")
    for lang, stats in result["by_language"].items():
        print(
            f"  {lang:<18} | {stats['files']:5d} files | "
            f"{stats['total_lines']:8,d} total | {stats['code_lines']:8,d} non-blank"
        )
    print("\nBy Top-Level Directory:")
    for dname, stats in result["by_directory"].items():
        print(
            f"  {dname:<18} | {stats['files']:5d} files | "
            f"{stats['total_lines']:8,d} total | {stats['code_lines']:8,d} non-blank"
        )


if __name__ == "__main__":
    main()
