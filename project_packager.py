#!/usr/bin/env python3
"""
project_packager.py — v3.0.0

A small, safe, audit-friendly project packaging and release-checking CLI.

Copyright 2026 Leon Priest / 7h3v01d
Licensed under the Apache License, Version 2.0.

Subcommands:
    package     Create a clean, verifiable ZIP of a project (default).
    check       Run universal + per-project release sanity checks.
    verify      Verify a ZIP against its embedded manifest and sidecar hash.
    init        Write starter release_check.toml and .packagerignore files.

Backward compatible: `python project_packager.py .` still packages.

Packaging (see `package --help`):
    - Never deletes or modifies your project (unless --clean, which removes
      only disposable cache junk).
    - Excludes caches, VCS folders, virtualenvs, build output, session
      debris, and existing *.zip files.
    - Embeds PACKAGE_MANIFEST.json (per-file SHA-256 + sizes) in the ZIP
      and writes a sha256sum-compatible <zip>.sha256 sidecar.
    - Scans included text files for likely secrets; warns by default,
      blocks in --strict / --profile release.

Checking (see `check --help`):
    Built-in universal checks (no config required):
      - working-tree debris (patch_*/fix_*/add_* scripts, *.bak, *.tmp, ...)
      - secret scan of tracked text files
      - latest package inspection: junk entries + manifest hash verification
    Per-project checks come from release_check.toml (create with `init`):
      version alignment across files, forbidden strings/regex, required
      files, required/forbidden file contents, requirements.txt hygiene,
      and an optional wheel build with required-contents verification.

Standard library only. Python 3.11+ (tomllib). Windows-friendly.
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
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

TOOL_NAME = "project_packager"
TOOL_VERSION = "3.0.0"

MANIFEST_ARCNAME = "PACKAGE_MANIFEST.json"
CHECK_CONFIG_NAME = "release_check.toml"
IGNORE_FILE_NAME = ".packagerignore"

# --------------------------------------------------------------------------
# Exclusion rule data
# --------------------------------------------------------------------------

# Working-session debris — shared between packager exclusions and checker.
DEBRIS_FILE_PATTERNS = {
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
}

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
} | DEBRIS_FILE_PATTERNS

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

# Directories the checker never descends into.
CHECK_PRUNE_DIR_NAMES = DEFAULT_EXCLUDE_DIR_NAMES - {"scripts"} | {"packaged"}

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


def walk_check_tree(project_dir: Path) -> list[Path]:
    """Yield project files for checking, pruning caches/VCS/venv folders."""
    found: list[Path] = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = sorted(
            d for d in dirs
            if d not in CHECK_PRUNE_DIR_NAMES
            and not matches_any_pattern(d, DEFAULT_EXCLUDE_DIR_PATTERNS)
        )
        for file_name in sorted(files):
            found.append(Path(root) / file_name)
    return found


# --------------------------------------------------------------------------
# Secret scanning
# --------------------------------------------------------------------------


def looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def read_text_safe(path: Path, limit: int = SECRET_SCAN_MAX_BYTES) -> str | None:
    """Read a file as text if it is small and not binary, else None."""
    try:
        if path.stat().st_size > limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if looks_binary(data[:8192]):
        return None
    return data.decode("utf-8", errors="ignore")


def scan_for_secrets(project_dir: Path, files: list[Path]) -> list[SecretFinding]:
    """Scan text files for likely secrets. Read-only, best-effort."""
    findings: list[SecretFinding] = []

    for file_path in files:
        text = read_text_safe(file_path)
        if text is None:
            continue
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
# Archive verification
# --------------------------------------------------------------------------


def verify_archive(zip_path: Path) -> int:
    """Verify a ZIP against its embedded manifest and .sha256 sidecar.

    Returns 0 if everything checks out, 1 otherwise.
    """
    if not zip_path.is_file():
        print(f"ERROR: not a file: {zip_path}", file=sys.stderr)
        return 1

    failures = 0
    print()
    print(f"Verifying: {zip_path.name}")

    # Sidecar check.
    sidecar = zip_path.with_name(zip_path.name + ".sha256")
    if sidecar.is_file():
        try:
            expected = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
            actual = sha256_of_file(zip_path)
            if expected == actual:
                print(f"  OK    sidecar hash matches ({actual[:16]}...)")
            else:
                print(f"  FAIL  sidecar hash mismatch")
                print(f"        expected {expected}")
                print(f"        actual   {actual}")
                failures += 1
        except (OSError, IndexError) as exc:
            print(f"  WARN  could not read sidecar: {exc}")
    else:
        print(f"  WARN  no .sha256 sidecar found")

    # Manifest check.
    try:
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
            if MANIFEST_ARCNAME not in names:
                print(f"  WARN  no {MANIFEST_ARCNAME} embedded — nothing more to verify")
                return 1 if failures else 0

            manifest = json.loads(zf.read(MANIFEST_ARCNAME))
            entries = manifest.get("files", [])
            print(f"  Manifest: {manifest.get('project', '?')} — "
                  f"{manifest.get('file_count', len(entries))} file(s), "
                  f"created {manifest.get('created_utc', '?')}")

            ok_count = 0
            for entry in entries:
                arcname = entry.get("path", "")
                if arcname not in names:
                    print(f"  FAIL  missing from archive: {arcname}")
                    failures += 1
                    continue
                digest = hashlib.sha256(zf.read(arcname)).hexdigest()
                if digest != entry.get("sha256"):
                    print(f"  FAIL  hash mismatch: {arcname}")
                    failures += 1
                else:
                    ok_count += 1

            extras = names - {e.get("path") for e in entries} - {MANIFEST_ARCNAME}
            extras = {n for n in extras if not n.endswith("/")}
            for extra in sorted(extras):
                print(f"  FAIL  not in manifest: {extra}")
                failures += 1

            print(f"  {ok_count}/{len(entries)} file hashes verified")
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"  FAIL  could not verify archive: {exc}")
        failures += 1

    print()
    if failures:
        print(f"RESULT: FAIL — {failures} problem(s) found.")
        return 1
    print("RESULT: OK — archive verified.")
    return 0


# --------------------------------------------------------------------------
# Release checks
# --------------------------------------------------------------------------


@dataclass
class CheckReport:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    passed: int = 0

    def check(self, label: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"  OK    {label}")
            self.passed += 1
        else:
            print(f"  FAIL  {label}" + (f": {detail}" if detail else ""))
            self.failures.append(label)

    def warn(self, label: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"  OK    {label}")
            self.passed += 1
        else:
            print(f"  WARN  {label}" + (f": {detail}" if detail else ""))
            self.warnings.append(label)

    def section(self, name: str) -> None:
        print(f"\n-- {name} --")


def load_check_config(project_dir: Path) -> dict | None:
    """Load release_check.toml from the project root, or None."""
    config_path = project_dir / CHECK_CONFIG_NAME
    if not config_path.is_file():
        return None
    try:
        import tomllib
    except ImportError:
        print(
            f"ERROR: {CHECK_CONFIG_NAME} found but this Python has no tomllib "
            "(needs Python 3.11+).",
            file=sys.stderr,
        )
        return None
    try:
        return tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: could not parse {CHECK_CONFIG_NAME}: {exc}", file=sys.stderr)
        return None


def read_project_file(project_dir: Path, rel: str) -> str:
    """Read one or more '|'-joined project files, concatenated. Missing = ''."""
    parts = []
    for piece in rel.split("|"):
        piece = piece.strip()
        if not piece:
            continue
        try:
            parts.append((project_dir / piece).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            parts.append("")
    return "\n".join(parts)


def run_builtin_checks(project_dir: Path, report: CheckReport) -> None:
    """Universal checks that apply to any project — no config needed."""
    files = walk_check_tree(project_dir)

    # Working-tree debris.
    report.section("Working-tree debris")
    debris = [
        f for f in files
        if matches_any_pattern(f.name, DEBRIS_FILE_PATTERNS)
    ]
    report.check(
        "No session debris (patch_*/fix_*/add_*, *.bak, *.tmp, ...)",
        len(debris) == 0,
        f"{len(debris)} found: "
        + ", ".join(normalise_rel(f.relative_to(project_dir)) for f in debris[:5]),
    )
    scripts_dir = project_dir / "scripts"
    report.warn(
        "No scripts/ working-session folder",
        not scripts_dir.is_dir(),
        "scripts/ exists (packager excludes it, but consider deleting)",
    )

    # Secret scan.
    report.section("Secret scan")
    findings = scan_for_secrets(project_dir, files)
    report.check(
        "No likely secrets in tracked text files",
        len(findings) == 0,
        "; ".join(
            f"{normalise_rel(f.rel_path)}:{f.line} [{f.label}]" for f in findings[:5]
        ),
    )

    # Latest package inspection.
    report.section("Latest package")
    candidates = sorted(
        list((project_dir.parent / "packaged").glob("*.zip"))
        + list(project_dir.glob("*.zip")),
        key=lambda z: z.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        report.warn("Release ZIP found", False,
                    "no *.zip in ../packaged or project root — run `package` first")
        return

    latest = candidates[0]
    print(f"  Checking: {latest.name}")
    try:
        with zipfile.ZipFile(latest) as zf:
            names = zf.namelist()
            junk = [
                n for n in names
                if matches_any_pattern(Path(n).name, DEBRIS_FILE_PATTERNS)
            ]
            report.check("ZIP contains no debris entries", len(junk) == 0,
                         ", ".join(junk[:5]))
            if MANIFEST_ARCNAME in names:
                manifest = json.loads(zf.read(MANIFEST_ARCNAME))
                bad = 0
                for entry in manifest.get("files", []):
                    arc = entry.get("path", "")
                    if arc not in names:
                        bad += 1
                        continue
                    if hashlib.sha256(zf.read(arc)).hexdigest() != entry.get("sha256"):
                        bad += 1
                report.check(
                    f"ZIP manifest hashes verify ({len(manifest.get('files', []))} files)",
                    bad == 0,
                    f"{bad} mismatch(es)",
                )
            else:
                report.warn("ZIP has embedded manifest", False,
                            f"no {MANIFEST_ARCNAME} (older package?)")
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        report.check("ZIP is readable", False, str(exc))


def run_config_checks(project_dir: Path, config: dict, report: CheckReport) -> None:
    """Per-project checks driven by release_check.toml."""
    files = walk_check_tree(project_dir)

    # -- Version alignment --------------------------------------------------
    version_cfg = config.get("version", {})
    target = str(version_cfg.get("target", "")).strip()
    if target:
        report.section(f"Version identity (target: {target})")
        for rel in version_cfg.get("files", []):
            report.check(
                f"{rel} contains {target}",
                target in read_project_file(project_dir, rel),
            )

    # -- Forbidden strings/regex --------------------------------------------
    forbidden_cfg = config.get("forbidden", {})
    patterns = forbidden_cfg.get("patterns", {})
    if patterns:
        report.section("Forbidden strings")
        allow_files = set(forbidden_cfg.get("allow_files", [])) | {
            CHECK_CONFIG_NAME, Path(__file__).name,
        }
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for label, pattern in patterns.items():
            try:
                compiled.append((label, re.compile(pattern)))
            except re.error as exc:
                report.check(f"forbidden pattern '{label}' compiles", False, str(exc))
        for label, regex in compiled:
            hits: list[str] = []
            for file_path in files:
                if file_path.name in allow_files:
                    continue
                text = read_text_safe(file_path)
                if text is None:
                    continue
                for match in regex.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    rel = normalise_rel(file_path.relative_to(project_dir))
                    hits.append(f"{rel}:{line}")
                    if len(hits) >= 5:
                        break
                if len(hits) >= 5:
                    break
            report.check(f"No forbidden '{label}'", len(hits) == 0, ", ".join(hits))

    # -- Required files -----------------------------------------------------
    required_cfg = config.get("required", {})
    required_files = required_cfg.get("files", [])
    if required_files:
        report.section("Required files")
        for rel in required_files:
            report.check(f"{rel} exists", (project_dir / rel).exists())

    # -- Required file contents ----------------------------------------------
    contains = required_cfg.get("contains", {})
    if contains:
        report.section("Required file contents")
        for rel, needles in contains.items():
            src = read_project_file(project_dir, rel)
            for needle in needles:
                report.check(f"{rel} contains '{needle}'", needle in src)

    # -- Forbidden file contents ----------------------------------------------
    not_contains = forbidden_cfg.get("contains", {})
    if not_contains:
        report.section("Forbidden file contents")
        for rel, needles in not_contains.items():
            src = read_project_file(project_dir, rel)
            for needle in needles:
                report.check(f"{rel} does not contain '{needle}'", needle not in src)

    # -- Banned paths ----------------------------------------------------------
    banned = config.get("banned", {}).get("paths", [])
    if banned:
        report.section("Banned paths")
        for rel in banned:
            clean = rel.rstrip("/")
            report.check(f"{clean} does not exist", not (project_dir / clean).exists())

    # -- requirements hygiene ---------------------------------------------------
    req_cfg = config.get("requirements", {})
    req_forbidden = req_cfg.get("forbidden", [])
    if req_forbidden:
        report.section("requirements hygiene")
        req_file = req_cfg.get("file", "requirements.txt")
        req_src = read_project_file(project_dir, req_file)
        heavy = [dep for dep in req_forbidden if dep in req_src]
        report.check(
            f"{req_file} has no forbidden deps",
            len(heavy) == 0,
            f"move to extras: {heavy}",
        )

    # -- Wheel build --------------------------------------------------------------
    wheel_cfg = config.get("wheel", {})
    if wheel_cfg.get("build", False):
        report.section("Wheel build")
        timeout = int(wheel_cfg.get("timeout", 300))
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "wheel", ".", "--no-deps",
                     "-w", tmpdir, "--quiet"],
                    capture_output=True, text=True, cwd=project_dir, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                report.check("Wheel builds successfully", False,
                             f"timed out after {timeout}s")
                return
            if result.returncode != 0:
                report.check("Wheel builds successfully", False,
                             (result.stderr or result.stdout)[:200].strip())
                return
            wheels = sorted(Path(tmpdir).glob("*.whl"))
            if not wheels:
                report.check("Wheel found after build", False, "no .whl produced")
                return
            report.check("Wheel builds successfully", True)
            with zipfile.ZipFile(wheels[0]) as zf:
                wheel_names = set(zf.namelist())
            for member in wheel_cfg.get("must_contain", []):
                present = member in wheel_names or any(
                    n.endswith("/" + member) for n in wheel_names
                )
                report.check(f"Wheel contains {member}", present)


# --------------------------------------------------------------------------
# Starter config templates (init)
# --------------------------------------------------------------------------

CHECK_CONFIG_TEMPLATE = """\
# release_check.toml — per-project rules for `project_packager.py check`.
# Delete any section you do not need. Built-in checks (debris, secrets,
# latest-package manifest verification) always run and need no config.

[version]
# All listed files must contain the target version string.
target = "1.0.0"
files = ["pyproject.toml", "CHANGELOG.md"]

[forbidden]
# Regex patterns that must not appear anywhere in tracked text files.
# allow_files lists filenames exempt from the scan.
allow_files = ["CHANGELOG.md"]

[forbidden.patterns]
"personal IP" = "192\\\\.168\\\\.\\\\d+\\\\.\\\\d+"
# "legacy brand" = "(?i)old_project_name"

# Per-file substrings that must NOT appear. Key may join several files with |.
# [forbidden.contains]
# "main.py" = ["TODO: remove before release"]

[required]
# Files that must exist before releasing.
files = ["LICENSE", "README.md"]

# Per-file substrings that MUST appear. Key may join several files with |.
# [required.contains]
# "core.py|routes/api.py" = ["validate_request"]

# [banned]
# Paths that must not exist in the working tree.
# paths = ["tests/stale_copy.py", "old_stuff/"]

# [requirements]
# file = "requirements.txt"
# forbidden = ["heavy-optional-dep"]

# [wheel]
# build = true
# timeout = 300
# must_contain = ["mypackage/__init__.py", "static/app.css"]
"""

IGNORE_TEMPLATE = """\
# .packagerignore — extra exclusions for project_packager.py
# One pattern per line. Trailing / marks a directory. Patterns containing /
# match against the relative path.
#
# docs/
# *.log
# data/raw/
"""


def cmd_init(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"ERROR: not a directory: {project_dir}", file=sys.stderr)
        return 2

    wrote = []
    for name, template in ((CHECK_CONFIG_NAME, CHECK_CONFIG_TEMPLATE),
                           (IGNORE_FILE_NAME, IGNORE_TEMPLATE)):
        target = project_dir / name
        if target.exists():
            print(f"SKIP  {name} already exists")
            continue
        try:
            target.write_text(template, encoding="utf-8")
            wrote.append(name)
            print(f"WROTE {name}")
        except OSError as exc:
            print(f"ERROR: could not write {name}: {exc}", file=sys.stderr)
            return 4

    if wrote:
        print(f"\nEdit {', '.join(wrote)} to fit this project, then run:")
        print(f"  python {Path(sys.argv[0]).name} check {project_dir}")
    return 0


# --------------------------------------------------------------------------
# Reporting (packager)
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
# Subcommand: check
# --------------------------------------------------------------------------


def run_all_checks(project_dir: Path) -> CheckReport:
    report = CheckReport()
    config = load_check_config(project_dir)

    print()
    print("=" * 72)
    header = f"Release checks — {project_dir.name}"
    if config and str(config.get("version", {}).get("target", "")).strip():
        header += f" (target: {config['version']['target']})"
    print(header)
    print("=" * 72)

    run_builtin_checks(project_dir, report)
    if config:
        run_config_checks(project_dir, config, report)
    else:
        print(f"\n(No {CHECK_CONFIG_NAME} — built-in checks only. "
              f"Run `init` to create one.)")

    print()
    if report.failures:
        print(f"RESULT: FAIL — {len(report.failures)} failed, "
              f"{len(report.warnings)} warning(s), {report.passed} passed.")
    else:
        print(f"RESULT: OK — all checks passed "
              f"({report.passed} passed, {len(report.warnings)} warning(s)).")
    print()
    return report


def cmd_check(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"ERROR: not a directory: {project_dir}", file=sys.stderr)
        return 2
    report = run_all_checks(project_dir)
    return 1 if report.failures else 0


# --------------------------------------------------------------------------
# Subcommand: verify
# --------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    return verify_archive(Path(args.zip).expanduser().resolve())


# --------------------------------------------------------------------------
# Subcommand: package
# --------------------------------------------------------------------------


def cmd_package(args: argparse.Namespace) -> int:
    # Apply profile presets.
    strict = args.strict
    clean = args.clean
    scan_secrets = not args.no_scan
    fail_on_secrets = args.strict
    run_checks_first = args.check
    if args.profile == "release":
        strict = True
        clean = True
        fail_on_secrets = True
        run_checks_first = True
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

    if run_checks_first:
        report = run_all_checks(project_dir)
        if report.failures and not args.force:
            print(
                "ERROR: release checks failed — not packaging.\n"
                "Fix the failures or re-run with --force.",
                file=sys.stderr,
            )
            return 6

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


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

KNOWN_COMMANDS = {"package", "check", "verify", "init"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Package, check, and verify project releases.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- package --------------------------------------------------------------
    p = sub.add_parser(
        "package",
        help="Create a clean, verifiable ZIP of a project (default command).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("project", nargs="?", default=".",
                   help="Project directory to package.")
    p.add_argument("--profile", choices=("share", "release", "backup"),
                   default="share",
                   help="share (default), release (strict+clean+checks, fails "
                        "on secrets), backup (keep almost everything).")
    p.add_argument("--output", "-o", default=None,
                   help="Output folder. Defaults to ./packaged beside the project.")
    p.add_argument("--name", "-n", default=None,
                   help="Custom ZIP base name. Timestamp is still appended.")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen; write and delete nothing.")
    p.add_argument("--clean", action="store_true",
                   help="Delete only safe cache junk before packaging.")
    p.add_argument("--strict", action="store_true",
                   help="Extra privacy exclusions; secrets block packaging.")
    p.add_argument("--check", action="store_true",
                   help="Run release checks first; abort if any fail.")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="Extra exclusion (repeatable; '/' in pattern = path match).")
    p.add_argument("--include", action="append", default=[], metavar="PATTERN",
                   help="Force-include (repeatable; overrides all exclusions).")
    p.add_argument("--no-scan", action="store_true",
                   help="Disable the secret scanner.")
    p.add_argument("--no-manifest", action="store_true",
                   help="Do not embed PACKAGE_MANIFEST.json in the ZIP.")
    p.add_argument("--force", action="store_true",
                   help="Package anyway despite secret findings or failed checks.")
    p.add_argument("--overwrite", action="store_true",
                   help="Allow overwriting an existing ZIP of the same name.")
    p.add_argument("--open", action="store_true",
                   help="Open the output folder when done.")
    p.add_argument("--list-included", action="store_true",
                   help="Print every included file.")
    p.add_argument("--list-excluded", action="store_true",
                   help="Print every excluded item with its reason.")
    p.set_defaults(func=cmd_package)

    # -- check --------------------------------------------------------------
    c = sub.add_parser(
        "check",
        help="Run universal + per-project release checks (release_check.toml).",
    )
    c.add_argument("project", nargs="?", default=".",
                   help="Project directory to check.")
    c.set_defaults(func=cmd_check)

    # -- verify --------------------------------------------------------------
    v = sub.add_parser(
        "verify",
        help="Verify a ZIP against its embedded manifest and .sha256 sidecar.",
    )
    v.add_argument("zip", help="Path to the ZIP to verify.")
    v.set_defaults(func=cmd_verify)

    # -- init --------------------------------------------------------------
    i = sub.add_parser(
        "init",
        help="Write starter release_check.toml and .packagerignore files.",
    )
    i.add_argument("project", nargs="?", default=".",
                   help="Project directory to initialise.")
    i.set_defaults(func=cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Guard against cp1252 console crashes on Windows.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass

    raw = list(argv) if argv is not None else sys.argv[1:]

    # Backward compatibility: `project_packager.py .` still packages.
    if raw and raw[0] not in KNOWN_COMMANDS and not raw[0].startswith("-"):
        raw = ["package"] + raw
    elif not raw:
        raw = ["package"]

    args = build_parser().parse_args(raw)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
