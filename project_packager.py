#!/usr/bin/env python3
"""
project_packager.py — v2.0.0

A small, safe, audit-friendly Python project packaging CLI.

Copyright 2026 Leon Priest / 7h3v01d
Licensed under the Apache License, Version 2.0.

Purpose:
    Create a clean, verifiable ZIP of a Python project for sharing/uploading.

Default behaviour:
    - Does NOT delete or modify your project.
    - Excludes common Python/build/editor/cache folders from the ZIP.
    - Excludes existing *.zip files (no more packages-inside-packages).
    - Embeds PACKAGE_MANIFEST.json (per-file SHA-256 + sizes) in the ZIP.
    - Writes a <zip>.sha256 sidecar so recipients can verify the archive.
    - Scans included text files for likely secrets and warns.

Profiles:
    --profile share     Default. Standard exclusions, secret scan warns.
    --profile release   Strict + clean + packaging FAILS if secrets found.
    --profile backup    Keep almost everything (only caches/.git excluded),
                        no secret scan, no zip exclusion.

Optional:
    --clean             Delete only disposable cache junk before packaging.
    --dry-run           Show what would happen; write/delete nothing.
    --strict            Extra privacy exclusions (.env, keys) + secrets block.
    --exclude PATTERN   Extra exclusion pattern (repeatable, path-aware).
    --include PATTERN   Force-include pattern (repeatable, beats exclusions).
    --open              Open the output folder when done.

Per-project config:
    Drop a `.packagerignore` in the project root. One pattern per line,
    `#` comments allowed, trailing `/` marks a directory pattern, and any
    pattern containing `/` is matched against the relative POSIX path.

Standard library only. Windows-friendly (UTF-8 console guard).
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

TOOL_NAME = "project_packager"
TOOL_VERSION = "2.0.0"

MANIFEST_ARCNAME = "PACKAGE_MANIFEST.json"

# --------------------------------------------------------------------------
# Exclusion rule data
# --------------------------------------------------------------------------

# Directories excluded from ZIP by default (matched by exact name).
DEFAULT_EXCLUDE_DIR_NAMES = {
    ".git",
    ".vscode",
    ".idea",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    # Working-session debris folders — must never ship
    "scripts",
}

# Directory name patterns excluded from ZIP by default.
DEFAULT_EXCLUDE_DIR_PATTERNS = {
    "*.egg-info",
}

# File names/patterns excluded from ZIP by default.
# Patterns containing "/" are matched against the relative POSIX path.
DEFAULT_EXCLUDE_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    ".coverage",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    # No packages-inside-packages (rescue with --include "*.zip" if needed)
    "*.zip",
    # Working-session debris — must never ship
    "*.bak",
    "*.bak.*",
    "*.tmp",
    "*.old",
    "*.orig",
    "patch_*.py",
    "patch_*.bat",
    "fix_*.py",
    "fix_*.bat",
    "add_*.py",
    "add_*.bat",
    "*New Text Document*",
    # Stale production copies in tests/ (path-aware pattern)
    "tests/web_app.py",
}

# Extra privacy/security exclusions only when strict mode is active.
STRICT_EXCLUDE_DIR_NAMES = {
    "secrets",
    "secret",
    "private",
    "keys",
}

STRICT_EXCLUDE_FILE_PATTERNS = {
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.crt",
    "*.token",
    "*.secret",
    "config.local.*",
    "secrets.json",
    "secret.json",
    "credentials.json",
    "*.keystore",
    "id_rsa*",
    "id_ed25519*",
}

# Minimal exclusions for the "backup" profile.
BACKUP_EXCLUDE_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

# Things --clean is allowed to delete.
# Deliberately conservative: no venv, no build/dist, no logs, no DBs, no ZIPs.
CLEAN_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

CLEAN_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
}

IGNORE_FILE_NAME = ".packagerignore"

# Warn when a single included file exceeds this many bytes.
LARGE_FILE_WARN_BYTES = 25 * 1024 * 1024
# Only secret-scan text files up to this size.
SECRET_SCAN_MAX_BYTES = 1 * 1024 * 1024

# --------------------------------------------------------------------------
# Secret scanning
# --------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{40,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


@dataclass
class SecretFinding:
    rel_path: Path
    line: int
    label: str
    preview: str


# --------------------------------------------------------------------------
# Core data structures
# --------------------------------------------------------------------------


@dataclass
class Decision:
    path: Path
    rel_path: Path
    reason: str


@dataclass
class ScanResult:
    included_files: list[Path] = field(default_factory=list)
    excluded: list[Decision] = field(default_factory=list)
    clean_dirs: list[Path] = field(default_factory=list)
    clean_files: list[Path] = field(default_factory=list)
    force_included: list[Path] = field(default_factory=list)


@dataclass
class Rules:
    """Fully resolved exclusion/inclusion rules for one packaging run."""

    dir_names: set[str] = field(default_factory=set)
    dir_patterns: set[str] = field(default_factory=set)
    file_patterns: set[str] = field(default_factory=set)      # name-based
    path_patterns: set[str] = field(default_factory=set)      # contain "/"
    include_patterns: set[str] = field(default_factory=set)   # force-include


# --------------------------------------------------------------------------
# Pattern helpers
# --------------------------------------------------------------------------


def normalise_rel(path: Path) -> str:
    """Return a stable POSIX-style relative path for ZIP entries and output."""
    return path.as_posix()


def matches_any_pattern(name: str, patterns: Iterable[str]) -> str | None:
    """Return the first matching pattern, or None."""
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return pattern
    return None


def matches_path_pattern(rel_posix: str, patterns: Iterable[str]) -> str | None:
    """Match a relative POSIX path against path-aware patterns.

    A pattern matches the path itself or anything beneath it, so
    "tests/web_app.py" and "data/raw/" style patterns both behave sensibly.
    """
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if fnmatch.fnmatch(rel_posix, clean) or fnmatch.fnmatch(rel_posix, clean + "/*"):
            return pattern
    return None


def is_force_included(file_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return the matching --include pattern, or None."""
    for pattern in rules.include_patterns:
        if "/" in pattern:
            if matches_path_pattern(rel_posix, [pattern]):
                return pattern
        elif fnmatch.fnmatch(file_name, pattern):
            return pattern
    return None


def is_inside(path: Path, possible_parent: Path) -> bool:
    """Return True if path is inside possible_parent."""
    try:
        path.resolve().relative_to(possible_parent.resolve())
        return True
    except ValueError:
        return False


def should_exclude_dir(dir_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return exclusion reason for a directory, or None."""
    if dir_name in rules.dir_names:
        return f"directory exclusion: {dir_name}"

    matched = matches_any_pattern(dir_name, rules.dir_patterns)
    if matched:
        return f"directory pattern: {matched}"

    matched = matches_path_pattern(rel_posix, rules.path_patterns)
    if matched:
        return f"path pattern: {matched}"

    return None


def should_exclude_file(file_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return exclusion reason for a file, or None."""
    matched = matches_any_pattern(file_name, rules.file_patterns)
    if matched:
        return f"file pattern: {matched}"

    matched = matches_path_pattern(rel_posix, rules.path_patterns)
    if matched:
        return f"path pattern: {matched}"

    return None


# --------------------------------------------------------------------------
# Rule building (.packagerignore + CLI + profiles)
# --------------------------------------------------------------------------


def load_ignore_file(project_dir: Path) -> tuple[list[str], int]:
    """Load .packagerignore patterns. Returns (patterns, count)."""
    ignore_path = project_dir / IGNORE_FILE_NAME
    if not ignore_path.is_file():
        return [], 0

    patterns: list[str] = []
    try:
        text = ignore_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"WARNING: could not read {IGNORE_FILE_NAME}: {exc}", file=sys.stderr)
        return [], 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns, len(patterns)


def build_rules(
    *,
    profile: str,
    strict: bool,
    ignore_patterns: list[str],
    extra_excludes: list[str],
    include_patterns: list[str],
) -> Rules:
    """Assemble the final rule set for this run."""
    rules = Rules()

    if profile == "backup":
        rules.dir_names |= BACKUP_EXCLUDE_DIR_NAMES
        rules.file_patterns |= {"*.pyc", "*.pyo"}
    else:
        rules.dir_names |= DEFAULT_EXCLUDE_DIR_NAMES
        rules.dir_patterns |= DEFAULT_EXCLUDE_DIR_PATTERNS
        for pattern in DEFAULT_EXCLUDE_FILE_PATTERNS:
            (rules.path_patterns if "/" in pattern else rules.file_patterns).add(pattern)

    if strict:
        rules.dir_names |= STRICT_EXCLUDE_DIR_NAMES
        for pattern in STRICT_EXCLUDE_FILE_PATTERNS:
            (rules.path_patterns if "/" in pattern else rules.file_patterns).add(pattern)

    for pattern in ignore_patterns + list(extra_excludes):
        if pattern.endswith("/"):
            clean = pattern.rstrip("/")
            if "/" in clean:
                rules.path_patterns.add(clean)
            else:
                rules.dir_patterns.add(clean)
        elif "/" in pattern:
            rules.path_patterns.add(pattern)
        else:
            rules.file_patterns.add(pattern)
            rules.dir_patterns.add(pattern)

    rules.include_patterns |= set(include_patterns)
    return rules


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def scan_project(
    project_dir: Path,
    rules: Rules,
    *,
    output_dir: Path | None = None,
) -> ScanResult:
    """Scan the project and decide what gets included/excluded.

    output_dir is excluded if it sits inside the project, so the package
    output folder does not get accidentally included.
    """
    result = ScanResult()
    project_dir = project_dir.resolve()
    resolved_output_dir = output_dir.resolve() if output_dir else None

    for root, dirs, files in os.walk(project_dir):
        root_path = Path(root)

        # If output dir is inside the project, avoid including it.
        if resolved_output_dir and is_inside(root_path, resolved_output_dir):
            try:
                rel = root_path.relative_to(project_dir)
            except ValueError:
                rel = root_path
            result.excluded.append(
                Decision(root_path, rel, "output directory excluded to avoid self-packaging")
            )
            dirs[:] = []
            continue

        # Mutate dirs in-place so os.walk does not descend into excluded folders.
        kept_dirs: list[str] = []
        for dir_name in sorted(dirs):
            dir_path = root_path / dir_name
            rel_path = dir_path.relative_to(project_dir)
            rel_posix = normalise_rel(rel_path)

            if dir_name in CLEAN_DIR_NAMES:
                result.clean_dirs.append(dir_path)

            reason = should_exclude_dir(dir_name, rel_posix, rules)
            if reason:
                result.excluded.append(Decision(dir_path, rel_path, reason))
            else:
                kept_dirs.append(dir_name)

        dirs[:] = kept_dirs

        for file_name in sorted(files):
            file_path = root_path / file_name
            rel_path = file_path.relative_to(project_dir)
            rel_posix = normalise_rel(rel_path)

            if matches_any_pattern(file_name, CLEAN_FILE_PATTERNS):
                result.clean_files.append(file_path)

            include_hit = is_force_included(file_name, rel_posix, rules)
            if include_hit:
                result.included_files.append(file_path)
                result.force_included.append(file_path)
                continue

            reason = should_exclude_file(file_name, rel_posix, rules)
            if reason:
                result.excluded.append(Decision(file_path, rel_path, reason))
            else:
                result.included_files.append(file_path)

    return result


# --------------------------------------------------------------------------
# Secret scanning
# --------------------------------------------------------------------------


def looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def scan_for_secrets(project_dir: Path, included_files: list[Path]) -> list[SecretFinding]:
    """Scan included text files for likely secrets. Read-only, best-effort."""
    findings: list[SecretFinding] = []

    for file_path in included_files:
        try:
            if file_path.stat().st_size > SECRET_SCAN_MAX_BYTES:
                continue
            data = file_path.read_bytes()
        except OSError:
            continue

        if looks_binary(data[:8192]):
            continue

        text = data.decode("utf-8", errors="ignore")
        rel_path = file_path.relative_to(project_dir)

        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                token = match.group(0)
                preview = token[:10] + "..." if len(token) > 10 else token
                findings.append(SecretFinding(rel_path, line, label, preview))

    return findings


# --------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------


def remove_clean_targets(scan: ScanResult, *, dry_run: bool) -> tuple[int, int]:
    """Delete cache junk collected during scan. Returns (dirs_removed, files_removed)."""
    dirs_removed = 0
    files_removed = 0

    # Delete files first, then dirs.
    for file_path in scan.clean_files:
        if not file_path.exists():
            continue
        if not dry_run:
            try:
                file_path.unlink()
            except OSError as exc:
                print(f"WARNING: could not delete file {file_path}: {exc}", file=sys.stderr)
                continue
        files_removed += 1

    # Sort deepest first for predictable cleanup.
    for dir_path in sorted(scan.clean_dirs, key=lambda p: len(p.parts), reverse=True):
        if not dir_path.exists():
            continue
        if not dry_run:
            try:
                shutil.rmtree(dir_path)
            except OSError as exc:
                print(f"WARNING: could not delete directory {dir_path}: {exc}", file=sys.stderr)
                continue
        dirs_removed += 1

    return dirs_removed, files_removed


# --------------------------------------------------------------------------
# Hashing, manifest, ZIP creation
# --------------------------------------------------------------------------


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(project_dir: Path, included_files: list[Path]) -> dict:
    """Build the embedded manifest: per-file SHA-256 + sizes."""
    entries = []
    total = 0
    for file_path in sorted(included_files):
        rel = normalise_rel(file_path.relative_to(project_dir))
        try:
            size = file_path.stat().st_size
            digest = sha256_of_file(file_path)
        except OSError:
            continue
        total += size
        entries.append({"path": rel, "size": size, "sha256": digest})

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project": project_dir.name,
        "file_count": len(entries),
        "total_bytes": total,
        "files": entries,
    }


def build_zip_name(project_dir: Path, custom_name: str | None) -> str:
    """Build a timestamped ZIP filename."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    base = custom_name.strip() if custom_name else project_dir.name
    base = base[:-4] if base.lower().endswith(".zip") else base
    safe_base = "".join(c if c.isalnum() or c in "._-" else "_" for c in base).strip("._")
    if not safe_base:
        safe_base = "project"
    return f"{safe_base}_{timestamp}.zip"


def create_zip(
    project_dir: Path,
    included_files: list[Path],
    output_zip: Path,
    *,
    overwrite: bool,
    manifest: dict | None,
) -> tuple[int, str]:
    """Create the ZIP. Returns (total uncompressed bytes, zip sha256)."""
    if output_zip.exists() and not overwrite:
        raise FileExistsError(
            f"Output already exists: {output_zip}\n"
            "Use --overwrite or choose a different --name/--output."
        )

    output_zip.parent.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(included_files):
            rel_path = file_path.relative_to(project_dir)
            arcname = normalise_rel(rel_path)
            zf.write(file_path, arcname)
            try:
                total_bytes += file_path.stat().st_size
            except OSError:
                pass

        if manifest is not None:
            zf.writestr(
                MANIFEST_ARCNAME,
                json.dumps(manifest, indent=2, sort_keys=False),
            )

    zip_digest = sha256_of_file(output_zip)

    # Sidecar hash file: "<hash>  <filename>" (sha256sum-compatible).
    sidecar = output_zip.with_name(output_zip.name + ".sha256")
    try:
        sidecar.write_text(f"{zip_digest}  {output_zip.name}\n", encoding="utf-8")
    except OSError as exc:
        print(f"WARNING: could not write hash sidecar: {exc}", file=sys.stderr)

    return total_bytes, zip_digest


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def format_bytes(num: int) -> str:
    """Human-readable byte formatting."""
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num} B"


def group_exclusions(excluded: list[Decision]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in excluded:
        counts[item.reason.split(":", 1)[0]] = counts.get(item.reason.split(":", 1)[0], 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)


def largest_files(project_dir: Path, included_files: list[Path], top: int = 5) -> list[tuple[Path, int]]:
    sized: list[tuple[Path, int]] = []
    for file_path in included_files:
        try:
            sized.append((file_path.relative_to(project_dir), file_path.stat().st_size))
        except OSError:
            continue
    sized.sort(key=lambda item: item[1], reverse=True)
    return sized[:top]


def print_summary(
    *,
    project_dir: Path,
    output_zip: Path | None,
    scan: ScanResult,
    profile: str,
    strict: bool,
    dry_run: bool,
    clean: bool,
    ignore_count: int,
    findings: list[SecretFinding],
    cleaned_dirs: int = 0,
    cleaned_files: int = 0,
    zip_uncompressed_bytes: int = 0,
    zip_sha256: str = "",
) -> None:
    """Print a concise packaging report."""
    print()
    print("=" * 72)
    print(f"Project Packager v{TOOL_VERSION} — Summary")
    print("=" * 72)
    print(f"Project:       {project_dir}")
    print(f"Profile:       {profile}")
    print(f"Mode:          {'DRY RUN' if dry_run else 'WRITE'}")
    print(f"Strict mode:   {'on' if strict else 'off'}")
    print(f"Clean mode:    {'on' if clean else 'off'}")
    if ignore_count:
        print(f"{IGNORE_FILE_NAME}: {ignore_count} pattern(s) loaded")
    if output_zip:
        print(f"Output ZIP:    {output_zip}")

    print()
    print(f"Included files:          {len(scan.included_files)}")
    if scan.force_included:
        print(f"Force-included:          {len(scan.force_included)}")
    print(f"Excluded items:          {len(scan.excluded)}")
    print(f"Cleanable cache dirs:    {len(scan.clean_dirs)}")
    print(f"Cleanable cache files:   {len(scan.clean_files)}")

    if clean:
        action = "Would remove" if dry_run else "Removed"
        print(f"{action} cache dirs:      {cleaned_dirs}")
        print(f"{action} cache files:     {cleaned_files}")

    if scan.excluded:
        print()
        print("Exclusions by reason:")
        for reason, count in group_exclusions(scan.excluded):
            print(f"  {count:>5}  {reason}")

    top = largest_files(project_dir, scan.included_files)
    if top:
        print()
        print("Largest included files:")
        for rel, size in top:
            marker = "  <-- large!" if size > LARGE_FILE_WARN_BYTES else ""
            print(f"  {format_bytes(size):>12}  {normalise_rel(rel)}{marker}")

    if findings:
        print()
        print(f"!! POSSIBLE SECRETS DETECTED ({len(findings)}):")
        for finding in findings[:20]:
            print(
                f"  - {normalise_rel(finding.rel_path)}:{finding.line}"
                f"  [{finding.label}]  {finding.preview}"
            )
        if len(findings) > 20:
            print(f"  ... plus {len(findings) - 20} more finding(s)")

    if output_zip and output_zip.exists() and not dry_run:
        print()
        try:
            print(f"ZIP file size:           {format_bytes(output_zip.stat().st_size)}")
        except OSError:
            pass
        print(f"Uncompressed included:   {format_bytes(zip_uncompressed_bytes)}")
        if zip_sha256:
            print(f"ZIP SHA-256:             {zip_sha256}")
            print(f"Hash sidecar:            {output_zip.name}.sha256")
        print(f"Manifest embedded:       {MANIFEST_ARCNAME}")

    if dry_run:
        print()
        print("Dry run only: no ZIP was created and no files were deleted.")

    print("=" * 72)
    print()


def open_folder(path: Path) -> None:
    """Open a folder in the OS file manager. Best-effort."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError as exc:
        print(f"WARNING: could not open folder: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a clean, verifiable ZIP of a Python project for sharing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "project",
        nargs="?",
        default=".",
        help="Project directory to package.",
    )
    parser.add_argument(
        "--profile",
        choices=("share", "release", "backup"),
        default="share",
        help="Packaging profile: share (default), release (strict+clean, "
        "fails on secrets), backup (keep almost everything).",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output folder for the ZIP. Defaults to ./packaged beside the project.",
    )
    parser.add_argument(
        "--name",
        "-n",
        default=None,
        help="Custom base name for the ZIP. Timestamp is still appended.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be included/excluded without creating a ZIP.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete only safe cache junk before packaging.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Extra privacy exclusions (.env, keys) and secrets block packaging.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Extra exclusion pattern (repeatable; patterns with '/' match paths).",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Force-include pattern (repeatable; overrides all exclusions).",
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Disable the secret scanner.",
    )
    parser.add_argument(
        "--no-manifest",
        action="store_true",
        help="Do not embed PACKAGE_MANIFEST.json in the ZIP.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Package anyway even if strict/release mode finds secrets.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting an existing ZIP with the same name.",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the output folder when packaging completes.",
    )
    parser.add_argument(
        "--list-included",
        action="store_true",
        help="Print every included file.",
    )
    parser.add_argument(
        "--list-excluded",
        action="store_true",
        help="Print every excluded item.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    # Guard against cp1252 console crashes on Windows.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass

    args = parse_args(argv if argv is not None else sys.argv[1:])

    # Apply profile presets.
    strict = args.strict
    clean = args.clean
    scan_secrets = not args.no_scan
    fail_on_secrets = args.strict
    if args.profile == "release":
        strict = True
        clean = True
        fail_on_secrets = True
    elif args.profile == "backup":
        scan_secrets = False
        fail_on_secrets = False

    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.exists():
        print(f"ERROR: project path does not exist: {project_dir}", file=sys.stderr)
        return 2
    if not project_dir.is_dir():
        print(f"ERROR: project path is not a directory: {project_dir}", file=sys.stderr)
        return 2

    if args.output:
        output_dir = Path(args.output).expanduser().resolve()
    else:
        output_dir = project_dir.parent / "packaged"

    output_zip = output_dir / build_zip_name(project_dir, args.name)

    ignore_patterns, ignore_count = load_ignore_file(project_dir)
    rules = build_rules(
        profile=args.profile,
        strict=strict,
        ignore_patterns=ignore_patterns,
        extra_excludes=args.exclude,
        include_patterns=args.include,
    )

    scan = scan_project(project_dir, rules, output_dir=output_dir)

    if args.list_included:
        print()
        print("Included files:")
        for file_path in sorted(scan.included_files):
            print(f"  + {normalise_rel(file_path.relative_to(project_dir))}")

    if args.list_excluded:
        print()
        print("Excluded items:")
        for item in scan.excluded:
            print(f"  - {normalise_rel(item.rel_path)}  ({item.reason})")

    cleaned_dirs = 0
    cleaned_files = 0
    if clean:
        cleaned_dirs, cleaned_files = remove_clean_targets(scan, dry_run=args.dry_run)

        # If actual cleaning happened, rescan so deleted junk no longer appears.
        if not args.dry_run:
            scan = scan_project(project_dir, rules, output_dir=output_dir)

    findings: list[SecretFinding] = []
    if scan_secrets:
        findings = scan_for_secrets(project_dir, scan.included_files)

    if findings and fail_on_secrets and not args.force:
        print_summary(
            project_dir=project_dir,
            output_zip=output_zip,
            scan=scan,
            profile=args.profile,
            strict=strict,
            dry_run=args.dry_run,
            clean=clean,
            ignore_count=ignore_count,
            findings=findings,
            cleaned_dirs=cleaned_dirs,
            cleaned_files=cleaned_files,
        )
        print(
            "ERROR: possible secrets found and strict/release mode is active.\n"
            "Fix the findings, exclude the files, or re-run with --force.",
            file=sys.stderr,
        )
        return 5

    zip_uncompressed_bytes = 0
    zip_sha256 = ""
    if not args.dry_run:
        manifest = None if args.no_manifest else build_manifest(project_dir, scan.included_files)
        try:
            zip_uncompressed_bytes, zip_sha256 = create_zip(
                project_dir,
                scan.included_files,
                output_zip,
                overwrite=args.overwrite,
                manifest=manifest,
            )
        except FileExistsError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 3
        except OSError as exc:
            print(f"ERROR: could not create ZIP: {exc}", file=sys.stderr)
            return 4

    print_summary(
        project_dir=project_dir,
        output_zip=output_zip,
        scan=scan,
        profile=args.profile,
        strict=strict,
        dry_run=args.dry_run,
        clean=clean,
        ignore_count=ignore_count,
        findings=findings,
        cleaned_dirs=cleaned_dirs,
        cleaned_files=cleaned_files,
        zip_uncompressed_bytes=zip_uncompressed_bytes,
        zip_sha256=zip_sha256,
    )

    if args.open and not args.dry_run:
        open_folder(output_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
