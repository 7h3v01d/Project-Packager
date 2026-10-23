#!/usr/bin/env python3
"""
project_packager.py

A small, safe, audit-friendly project packaging and release-checking CLI.
Version is defined once, in TOOL_VERSION below; run with --version to see it.

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
    - Never follows symlinks. Symlinked files and directories are skipped and
      reported, so a link cannot smuggle material from outside the project
      into the archive. --include cannot override this.
    - Never packages the archive it is writing, its sidecar, or its temporary
      forms, even when --output is the project root itself.
    - Reserves PACKAGE_MANIFEST.json for its own metadata and refuses to
      package a project that already contains a file of that name.
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
import codecs
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
from enum import IntEnum, StrEnum
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

TOOL_NAME = "project_packager"
TOOL_VERSION = "3.0.1"

MANIFEST_ARCNAME = "PACKAGE_MANIFEST.json"
CHECK_CONFIG_NAME = "release_check.toml"
IGNORE_FILE_NAME = ".packagerignore"

# --------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------

class Exit(IntEnum):
    """Exit codes. Part of the CLI contract — automation depends on these.

    Kept granular deliberately: a CI job should be able to distinguish "your
    project has a problem" from "your configuration is broken" from "this tool
    refused on safety grounds" without parsing output.
    """

    OK = 0
    PROBLEMS = 1          # check failures / verification problems
    BAD_PROJECT = 2       # project path missing or not a directory
    OUTPUT_EXISTS = 3     # output ZIP already exists (use --overwrite)
    OS_ERROR = 4          # OS error while writing, or no verification evidence
    SECRETS = 5           # secrets, or unscannable text, in strict/release mode
    CHECKS_FAILED = 6     # non-secret pre-package release checks failed
    PARTIAL = 7           # sidecar valid but no embedded manifest to verify
    RESERVED_NAME = 8     # project file collides with reserved internal name
    BAD_CONFIG = 9        # release_check.toml or .packagerignore present but
                          # unreadable, malformed, or structurally invalid
    CONTAINMENT = 10      # a source path escaped the project between scan and write


# Module-level aliases, so call sites stay readable.
EXIT_OK = Exit.OK
EXIT_PROBLEMS = Exit.PROBLEMS
EXIT_BAD_PROJECT = Exit.BAD_PROJECT
EXIT_OUTPUT_EXISTS = Exit.OUTPUT_EXISTS
EXIT_OS_ERROR = Exit.OS_ERROR
EXIT_SECRETS = Exit.SECRETS
EXIT_CHECKS_FAILED = Exit.CHECKS_FAILED
EXIT_PARTIAL = Exit.PARTIAL
EXIT_RESERVED_NAME = Exit.RESERVED_NAME
EXIT_BAD_CONFIG = Exit.BAD_CONFIG
EXIT_CONTAINMENT = Exit.CONTAINMENT


class ConfigError(Exception):
    """release_check.toml exists but cannot be trusted.

    Deliberately distinct from "no configuration": a broken release gate must
    never be mistaken for an absent one.
    """


class ReservedNameError(Exception):
    """A project file collides with a name the packager reserves internally."""


class ContainmentError(Exception):
    """A source path escaped the project root between scanning and writing."""

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
    skipped_symlinks: list[Decision] = field(default_factory=list)


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


def normalise_pattern(pattern: str) -> str:
    """Accept Windows-style patterns without surprising Windows users.

    Rules are matched against POSIX-style relative paths, so a pattern typed
    as `large_data\\data.csv` must mean the same thing as `large_data/data.csv`.
    """
    return pattern.replace("\\", "/").strip()


def split_include_pattern(pattern: str) -> tuple[bool, str]:
    """Return (is_path_pattern, pattern_to_match) for a force-include pattern.

    A leading slash anchors to the project root, as it does for exclusions.
    Previously "/notes.txt" was kept verbatim and matched against relative
    paths, which never start with "/", so the include silently did nothing.
    """
    if pattern.startswith("/"):
        return True, pattern.lstrip("/")
    return "/" in pattern, pattern


def is_force_included(file_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return the matching --include pattern, or None."""
    for pattern in rules.include_patterns:
        is_path, clean = split_include_pattern(pattern)
        if not clean:
            continue
        if is_path:
            if matches_path_pattern(rel_posix, [clean]):
                return pattern
        elif fnmatch.fnmatch(file_name, clean):
            return pattern
    return None


def include_may_reopen_dir(rel_posix: str, rules: Rules) -> str | None:
    """Return an include pattern that needs this directory kept open, or None.

    P0 #4: `--include ".vscode/settings.json"` cannot work if `.vscode` is
    pruned before the file loop ever sees it. Only path-style patterns reopen
    a directory, and only along their own literal prefix — a bare name pattern
    such as `*.zip` must not drag every excluded tree back into the archive.
    """
    prefix = rel_posix.rstrip("/") + "/"
    for pattern in rules.include_patterns:
        is_path, clean = split_include_pattern(pattern)
        if not is_path:
            continue
        clean = clean.rstrip("/")
        if not clean:
            continue
        if clean.startswith(prefix) or fnmatch.fnmatch(prefix.rstrip("/"), clean):
            return pattern
        # A wildcard segment ("docs/*/notes.md") can still target this branch.
        head = clean.split("/")[0]
        if ("*" in head or "?" in head) and fnmatch.fnmatch(rel_posix.split("/")[0], head):
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
    """Load .packagerignore patterns. Returns (patterns, count).

    Fails closed in every profile. An absent ignore file means no exclusions
    were asked for; a file that exists but cannot be read means exclusions
    *were* asked for and have been lost. Ordinary sharing is exactly where
    people rely on this to keep private notes and local config out of an
    archive they are about to send someone, so it is not the place to
    downgrade the failure to a warning.
    """
    ignore_path = project_dir / IGNORE_FILE_NAME
    if not ignore_path.exists():
        return [], 0
    if not ignore_path.is_file():
        raise ConfigError(f"{IGNORE_FILE_NAME} exists but is not a regular file")

    patterns: list[str] = []
    try:
        # Strict decoding, utf-8-sig so a Windows-authored BOM is fine.
        # errors="replace" silently rewrote damaged bytes, which changed the
        # patterns: an exclusion stopped matching and the file it named shipped.
        # Guessing at corruption in a safety configuration file is not helpful.
        text = ignore_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{IGNORE_FILE_NAME} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {IGNORE_FILE_NAME}: {exc}") from exc

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

    # .packagerignore lines starting with "!" are force-includes, exactly as if
    # given with --include. "\!" escapes a literal leading "!". The CLI's own
    # --exclude values are never reinterpreted: "!" there stays literal.
    file_excludes, file_includes = split_ignore_lines(ignore_patterns)

    for raw_pattern in file_excludes + list(extra_excludes):
        add_exclude_pattern(rules, raw_pattern)

    for raw_include in list(include_patterns) + file_includes:
        pattern = normalise_pattern(raw_include)
        if pattern and pattern.strip("/"):
            rules.include_patterns.add(pattern)
    return rules


def split_ignore_lines(lines: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split .packagerignore pattern lines into (excludes, force-includes)."""
    excludes: list[str] = []
    includes: list[str] = []
    for line in lines:
        if line.startswith("\\!"):
            excludes.append(line[1:])
        elif line.startswith("!"):
            if line[1:].strip():
                includes.append(line[1:].strip())
        else:
            excludes.append(line)
    return excludes, includes


def add_exclude_pattern(rules: Rules, raw_pattern: str) -> None:
    """Add one user exclusion (.packagerignore line or --exclude) to rules."""
    pattern = normalise_pattern(raw_pattern)
    if not pattern:
        return

    # A leading slash anchors the pattern to the project root, as in
    # gitignore. Without this, "/docs/" became the path pattern "/docs",
    # which can never match a relative path — the rule was silently
    # discarded and the user got no exclusion and no warning.
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern.lstrip("/")
        if not pattern:
            return

    if pattern.endswith("/"):
        clean = pattern.rstrip("/")
        if anchored or "/" in clean:
            rules.path_patterns.add(clean)
        else:
            rules.dir_patterns.add(clean)
    elif anchored or "/" in pattern:
        rules.path_patterns.add(pattern)
    else:
        rules.file_patterns.add(pattern)
        rules.dir_patterns.add(pattern)


def user_rules_excluding(rel_posix: str, is_dir: bool, lines: Iterable[str]) -> list[str]:
    """Which user exclusion lines exclude this path, directly or via a parent.

    Used by the GUI to answer "why is this excluded, and what do I remove to
    bring it back?". Built-in and strict rules are deliberately not reported:
    those cannot be removed, only overridden with a force-include.
    """
    parts = rel_posix.strip("/").split("/")
    hits: list[str] = []
    excludes, _ = split_ignore_lines(lines)
    for line in excludes:
        single = Rules()
        add_exclude_pattern(single, line)
        for depth in range(len(parts), 0, -1):
            sub = "/".join(parts[:depth])
            name = parts[depth - 1]
            if depth == len(parts) and not is_dir:
                matched = should_exclude_file(name, sub, single)
            else:
                matched = should_exclude_dir(name, sub, single)
            if matched:
                hits.append(line)
                break
    return hits


def user_includes_matching(rel_posix: str, lines: Iterable[str]) -> list[str]:
    """Which "!" lines force-include this path (as written, without the "!")."""
    _, includes = split_ignore_lines(lines)
    name = rel_posix.rsplit("/", 1)[-1]
    hits = []
    for include in includes:
        single = Rules(include_patterns={normalise_pattern(include)})
        if is_force_included(name, rel_posix, single):
            hits.append(include)
    return hits


class IgnoreFile:
    """Editable view of .packagerignore that preserves comments and order.

    The GUI edits rules through this rather than rewriting the file wholesale,
    so hand-written comments survive. Loading uses the same strict rules as
    packaging: a file that cannot be read raises ConfigError, and the caller
    must refuse to save over it — overwriting an unreadable safety file with
    a blank one would silently discard every exclusion it held.
    """

    def __init__(self, project_dir: Path, lines: list[str], existed: bool):
        self.project_dir = project_dir
        self.lines = lines
        self.existed = existed

    @property
    def path(self) -> Path:
        return self.project_dir / IGNORE_FILE_NAME

    @classmethod
    def load(cls, project_dir: Path) -> "IgnoreFile":
        path = project_dir / IGNORE_FILE_NAME
        if not path.exists():
            return cls(project_dir, [], existed=False)
        load_ignore_file(project_dir)  # strict validation; raises ConfigError
        text = path.read_text(encoding="utf-8-sig")
        return cls(project_dir, text.splitlines(), existed=True)

    def patterns(self) -> list[str]:
        """Active pattern lines, stripped, in file order."""
        out = []
        for raw in self.lines:
            line = raw.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out

    def excludes(self) -> list[str]:
        return [p for p in self.patterns() if not p.startswith("!")]

    def includes(self) -> list[str]:
        return [p[1:] for p in self.patterns() if p.startswith("!")]

    def has(self, line: str) -> bool:
        return line.strip() in self.patterns()

    def add(self, line: str) -> bool:
        """Append a pattern line. Returns False if already present or empty."""
        line = line.strip()
        if not line or line.startswith("#") or self.has(line):
            return False
        self.lines.append(line)
        return True

    def remove(self, line: str) -> bool:
        """Remove every occurrence of a pattern line. Returns True if any."""
        line = line.strip()
        before = len(self.lines)
        self.lines = [raw for raw in self.lines if raw.strip() != line]
        return len(self.lines) != before

    def text(self) -> str:
        body = list(self.lines)
        if not self.existed and not any(raw.strip().startswith("#") for raw in body):
            body = IGNORE_TEMPLATE.rstrip("\n").splitlines() + body
        return "\n".join(body).rstrip("\n") + "\n"

    def save(self) -> None:
        """Write atomically: temp file in the same folder, then os.replace."""
        target = self.path
        fd, tmp_name = tempfile.mkstemp(
            prefix=".packagerignore.", suffix=".part", dir=str(self.project_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(self.text())
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        self.existed = True


def suggest_patterns(rel_posix: str, is_dir: bool) -> dict[str, str]:
    """Ready-made patterns for one path, keyed by what they do.

    Anchored ("/x") so that excluding src/config.json does not also exclude
    an unrelated tests/config.json.
    """
    rel = rel_posix.strip("/")
    name = rel.rsplit("/", 1)[-1]
    out: dict[str, str] = {}
    if is_dir:
        out["exclude_this"] = f"/{rel}/"
        out["exclude_named"] = f"{name}/"
        out["include_this"] = f"!/{rel}/"
    else:
        out["exclude_this"] = f"/{rel}"
        suffix = Path(name).suffix
        if suffix and name != suffix:
            out["exclude_ext"] = f"*{suffix}"
        out["include_this"] = f"!/{rel}"
    return out


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def reserved_output_paths(output_zip: Path | None) -> set[Path]:
    """Paths the packager is about to write, which it must never archive.

    Kept separate from ordinary exclusions because --include must not be able
    to reach them: an archive that contains itself is never what was meant.
    """
    if output_zip is None:
        return set()
    resolved = output_zip.resolve()
    return {
        resolved,
        resolved.with_name(resolved.name + ".sha256"),
        resolved.with_name(resolved.name + ".part"),
        resolved.with_name(resolved.name + ".tmp"),
    }


def scan_project(
    project_dir: Path,
    rules: Rules,
    *,
    output_dir: Path | None = None,
    output_zip: Path | None = None,
) -> ScanResult:
    """Scan the project and decide what gets included/excluded.

    Safety restrictions that --include cannot override:
      - symlinked files and directories are never followed;
      - the archive being written, its sidecar, and its temporary forms are
        never packaged.

    A separate output *directory* inside the project is still pruned whole,
    but when the output directory is the project root itself only the exact
    output files are excluded — pruning the root would produce an archive
    containing nothing but a manifest.
    """
    result = ScanResult()
    project_dir = project_dir.resolve()
    resolved_output_dir = output_dir.resolve() if output_dir else None
    reserved = reserved_output_paths(output_zip)

    # Only prune a *separate* output subdirectory. output_dir == project_dir
    # is the `--output .` case and must not remove the project from itself.
    prune_output_dir = (
        resolved_output_dir is not None and resolved_output_dir != project_dir
    )

    # Directories that an --include reopened: kept open so the wanted file can
    # be reached, but everything else beneath them stays excluded.
    reopened: dict[Path, str] = {}

    def inherited_exclusion(path: Path) -> str | None:
        current = path
        while True:
            if current in reopened:
                return reopened[current]
            if current == project_dir or current.parent == current:
                return None
            current = current.parent

    for root, dirs, files in os.walk(project_dir):
        root_path = Path(root)

        if prune_output_dir and is_inside(root_path, resolved_output_dir):
            try:
                rel = root_path.relative_to(project_dir)
            except ValueError:
                rel = root_path
            result.excluded.append(
                Decision(root_path, rel, "output directory excluded to avoid self-packaging")
            )
            dirs[:] = []
            continue

        suppressed = inherited_exclusion(root_path)

        # Mutate dirs in-place so os.walk does not descend into excluded folders.
        kept_dirs: list[str] = []
        for dir_name in sorted(dirs):
            dir_path = root_path / dir_name
            rel_path = dir_path.relative_to(project_dir)
            rel_posix = normalise_rel(rel_path)

            # Non-overridable: never follow a symlinked directory. os.walk does
            # not descend into one by default, but it would still be reported
            # as an ordinary directory, and its files would be archived.
            if dir_path.is_symlink():
                result.skipped_symlinks.append(
                    Decision(dir_path, rel_path, "symlink directory skipped")
                )
                continue

            if dir_name in CLEAN_DIR_NAMES:
                result.clean_dirs.append(dir_path)

            reason = should_exclude_dir(dir_name, rel_posix, rules)
            if reason:
                reopen_hit = include_may_reopen_dir(rel_posix, rules)
                if reopen_hit:
                    # Keep walking, but remember that everything inside is
                    # excluded unless it is itself force-included.
                    reopened[dir_path] = reason
                    kept_dirs.append(dir_name)
                    continue
                result.excluded.append(Decision(dir_path, rel_path, reason))
            else:
                kept_dirs.append(dir_name)

        dirs[:] = kept_dirs

        for file_name in sorted(files):
            file_path = root_path / file_name
            rel_path = file_path.relative_to(project_dir)
            rel_posix = normalise_rel(rel_path)

            # Non-overridable: never follow a symlinked file. Checked before
            # --include so a link cannot be forced into the archive, and before
            # clean collection so cleaning cannot follow one either.
            if file_path.is_symlink():
                result.skipped_symlinks.append(
                    Decision(file_path, rel_path, "symlink file skipped")
                )
                continue

            # Non-overridable: never archive the output we are about to write.
            if reserved and file_path.resolve() in reserved:
                result.excluded.append(
                    Decision(file_path, rel_path, "reserved output file")
                )
                continue

            if matches_any_pattern(file_name, CLEAN_FILE_PATTERNS):
                result.clean_files.append(file_path)

            include_hit = is_force_included(file_name, rel_posix, rules)
            if include_hit:
                result.included_files.append(file_path)
                result.force_included.append(file_path)
                continue

            if suppressed:
                result.excluded.append(Decision(file_path, rel_path, suppressed))
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


# Control bytes that appear legitimately in text: tab, LF, VT, FF, CR, ESC.
TEXT_CONTROL_BYTES = frozenset({0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B})

# Above this proportion of unexpected control bytes, treat data as binary.
# Real text sits near zero; a stray NUL in a config file is well under it.
BINARY_CONTROL_RATIO = 0.05


def binary_control_ratio(sample: bytes) -> float:
    """Proportion of bytes that would be surprising in text."""
    if not sample:
        return 0.0
    odd = sum(
        1
        for byte in sample
        if (byte < 0x20 and byte not in TEXT_CONTROL_BYTES) or byte == 0x7F
    )
    return odd / len(sample)


def looks_binary(sample: bytes) -> bool:
    """Last-resort heuristic, consulted only after Unicode decoding has failed.

    Density, not presence. A single NUL does not prove a file is binary — it
    may be damaged text, generated configuration, or text disguised on purpose
    — and treating one as definitive meant an otherwise printable file was
    labelled "not scanned by design" while a key inside it shipped.

    Presence was also the wrong question for another reason: UTF-16 encodes
    ASCII as alternating NULs, so this is never the first test applied.
    """
    return binary_control_ratio(sample) > BINARY_CONTROL_RATIO


# Ordered longest-first: the UTF-32LE BOM begins with the UTF-16LE BOM, so
# checking UTF-16 first would mis-detect every UTF-32LE file.
TEXT_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def sniff_utf16(sample: bytes) -> str | None:
    """Detect BOM-less UTF-16 from its alternating-NUL signature.

    PowerShell, .reg exports, and various Windows tools emit UTF-16LE without a
    BOM. Mostly-ASCII UTF-16LE puts a NUL in every odd byte position and almost
    none in even ones; UTF-16BE is the mirror image.
    """
    if len(sample) < 8:
        return None
    even, odd = sample[0::2], sample[1::2]
    pairs = min(len(even), len(odd))
    if pairs == 0:
        return None
    even_nuls = even[:pairs].count(0) / pairs
    odd_nuls = odd[:pairs].count(0) / pairs

    if odd_nuls > 0.3 and even_nuls < 0.1:
        return "utf-16-le"
    if even_nuls > 0.3 and odd_nuls < 0.1:
        return "utf-16-be"
    return None


def detect_text_encoding(sample: bytes) -> str | None:
    """Return a codec that decodes this sample as text, or None.

    Tries, in order: a Unicode BOM, strict UTF-8, then BOM-less UTF-16.
    """
    for bom, codec_name in TEXT_BOMS:
        if sample.startswith(bom):
            return codec_name

    # Before UTF-8, because UTF-16LE ASCII *is* valid UTF-8 — it decodes to the
    # right characters interleaved with NULs, which no pattern then matches.
    # Plain UTF-8 text contains no NULs, so this cannot misfire on it.
    guess = sniff_utf16(sample)
    if guess:
        try:
            sample[: len(sample) // 2 * 2].decode(guess)
            return guess
        except UnicodeDecodeError:
            pass

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A sample cut mid-character is not evidence of binary content.
        if exc.start < len(sample) - 4:
            return None
    # Valid UTF-8, but genuine UTF-8 text does not contain NUL bytes. Reaching
    # here with NULs means the data resolved as UTF-8 only incidentally — it is
    # not BOM-marked and not UTF-16 — so leave it to the binary heuristic.
    if looks_binary(sample):
        return None
    return "utf-8"


def decode_text_strict(data: bytes) -> str | None:
    """Decode bytes as text, or None if they are not decodable text.

    Strict throughout: `errors="ignore"` silently discarded bytes, so a
    malformed file counted as successfully scanned when parts of it had never
    been looked at.
    """
    encoding = detect_text_encoding(data[:8192])
    if encoding is None:
        return None
    try:
        return data.decode(encoding)
    except (UnicodeDecodeError, UnicodeError):
        return None


def read_text_safe(path: Path, limit: int = SECRET_SCAN_MAX_BYTES) -> str | None:
    """Read a file as text if it is small enough and genuinely decodable."""
    try:
        if path.stat().st_size > limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return decode_text_strict(data)


class UnscannedKind(StrEnum):
    """Why a file was not scanned, in the terms policy cares about."""

    BINARY = "binary"        # recognised asset; never a scan candidate
    TEXT_LIKE = "text-like"  # could hold a secret; blocks strict/release
    UNREADABLE = "unreadable"  # treated conservatively as text-like


@dataclass(frozen=True)
class UnscannedFile:
    """A file the secret scanner could not read, and why.

    `kind` drives policy; `reason` is for humans. Deriving the first from the
    second is how a 1 MiB PNG came to be treated as an unscanned text file, so
    the two are kept deliberately separate and `kind` is typed.
    """

    path: Path
    reason: str
    kind: UnscannedKind


LIKELY_TEXT_SUFFIXES = {
    ".txt", ".md", ".rst", ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bat", ".ps1",
    ".sql", ".html", ".css", ".xml", ".csv", ".log", ".java", ".cs", ".go",
    ".rb", ".php", ".rs", ".c", ".h", ".cpp", ".hpp",
}

BINARY_MAGIC_SIGNATURES: tuple[bytes, ...] = (
    b"\x89PNG\r\n\x1a\n",      # PNG
    b"\xff\xd8\xff",           # JPEG
    b"GIF87a", b"GIF89a",      # GIF
    b"BM",                     # BMP
    b"RIFF",                   # WAV / AVI / WEBP
    b"%PDF-",                  # PDF
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",  # ZIP family, incl. wheels
    b"\x1f\x8b",               # gzip
    b"BZh",                    # bzip2
    b"\xfd7zXZ\x00",           # xz
    b"7z\xbc\xaf\x27\x1c",     # 7z
    b"Rar!\x1a\x07",           # RAR
    b"\x7fELF",                # ELF
    b"MZ",                     # PE / DOS
    b"\xca\xfe\xba\xbe",       # Java class / Mach-O fat
    b"\xcf\xfa\xed\xfe",       # Mach-O
    b"OggS",                   # Ogg
    b"fLaC",                   # FLAC
    b"ID3",                    # MP3 with ID3
    b"\x00\x01\x00\x00\x00",   # TrueType
    b"OTTO",                   # OpenType
    b"wOFF", b"wOF2",          # WOFF
    b"\xed\xab\xee\xdb",       # RPM
    b"SQLite format 3\x00",    # SQLite
)

# Retained only to explain a decision in the reason text. Deliberately NOT used
# to classify: a filename asserts nothing about contents, and trusting it let an
# oversized printable file named report.pdf be recorded as "binary content, not
# scanned by design" while a key inside it shipped.
BINARY_SUFFIX_HINTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".whl", ".exe",
    ".dll", ".so", ".dylib", ".bin", ".dat", ".mp3", ".mp4", ".mov", ".avi",
    ".wav", ".flac", ".ttf", ".otf", ".woff", ".woff2", ".pyc", ".pyd", ".class",
}


def has_binary_magic(sample: bytes) -> bool:
    """True if the sample opens with a recognised binary file signature."""
    return any(sample.startswith(sig) for sig in BINARY_MAGIC_SIGNATURES)


def classify_unscannable(file_path: Path) -> UnscannedFile | None:
    """Explain why a file cannot be secret-scanned, or None if it can be.

    Content decides. The sample is read before size is considered, so a large
    binary asset is recognised as binary rather than as an oversized text file,
    and anything not *demonstrably* binary is treated conservatively as
    text-like — including when its extension suggests otherwise, since the
    extension is the one thing an attacker or an accident controls freely.
    """
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return UnscannedFile(file_path, f"unreadable: {exc}", UnscannedKind.UNREADABLE)

    try:
        with file_path.open("rb") as handle:
            sample = handle.read(8192)
    except OSError as exc:
        return UnscannedFile(file_path, f"unreadable: {exc}", UnscannedKind.UNREADABLE)

    suffix = file_path.suffix.lower()

    # A recognised signature is definitive.
    if has_binary_magic(sample):
        detail = f", {format_bytes(size)}" if size > SECRET_SCAN_MAX_BYTES else ""
        return UnscannedFile(
            file_path,
            f"binary content{detail} — not scanned by design",
            UnscannedKind.BINARY,
        )

    # Otherwise try to read it as text before reaching for the NUL heuristic:
    # UTF-16 is mostly NULs and is ordinary on Windows.
    encoding = detect_text_encoding(sample)

    if encoding is None and looks_binary(sample):
        detail = f", {format_bytes(size)}" if size > SECRET_SCAN_MAX_BYTES else ""
        return UnscannedFile(
            file_path,
            f"binary content{detail} — not scanned by design",
            UnscannedKind.BINARY,
        )

    if size > SECRET_SCAN_MAX_BYTES:
        # Printable content with a binary-looking name is exactly the case that
        # must not be waved through, so the mismatch is called out explicitly.
        mismatch = (
            f" (despite the {suffix} extension, its contents are printable text)"
            if suffix in BINARY_SUFFIX_HINTS
            else ""
        )
        return UnscannedFile(
            file_path,
            f"too large: {format_bytes(size)} exceeds the "
            f"{format_bytes(SECRET_SCAN_MAX_BYTES)} scan limit{mismatch}",
            UnscannedKind.TEXT_LIKE,
        )

    # Not demonstrably binary and within the size limit: it should have been
    # scannable, so anything that still fails to decode is reported rather than
    # read with holes in it.
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        return UnscannedFile(file_path, f"unreadable: {exc}", UnscannedKind.UNREADABLE)

    if decode_text_strict(data) is None:
        return UnscannedFile(
            file_path,
            "not decodable as UTF-8, UTF-16, or UTF-32 text",
            UnscannedKind.TEXT_LIKE,
        )
    return None


@dataclass
class SecretScanResult:
    """Findings plus, just as importantly, what could not be looked at.

    A scanner that silently drops files it cannot read reports "no secrets"
    when it means "no secrets in the part I read". Release mode needs to know
    the difference.
    """

    findings: list[SecretFinding] = field(default_factory=list)
    unscanned: list[UnscannedFile] = field(default_factory=list)
    # Matches on a line carrying ALLOW_SECRET_MARKER. Kept, never dropped, so
    # every report can still show what was waved through and where.
    allowed: list[SecretFinding] = field(default_factory=list)

    def __iter__(self):
        # Backwards compatible with callers that treat the result as a list.
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __getitem__(self, index):
        return self.findings[index]

    def __bool__(self) -> bool:
        return bool(self.findings)

    @property
    def skipped(self) -> list[Path]:
        return [entry.path for entry in self.unscanned]

    def unscanned_text_files(self) -> list[UnscannedFile]:
        """Unscanned files that could plausibly contain a key.

        Binary assets are excluded: they were never candidates, and blocking a
        release because it contains a large image helps nobody.
        """
        return [
            entry
            for entry in self.unscanned
            if entry.kind in {UnscannedKind.TEXT_LIKE, UnscannedKind.UNREADABLE}
        ]


def scan_for_secrets(project_dir: Path, files: list[Path]) -> SecretScanResult:
    """Scan text files for likely secrets. Read-only, best-effort.

    Heuristic by nature: it detects known token shapes in files it can read.
    It cannot prove a project is secret-free, so everything it could not read
    is recorded rather than dropped.
    """
    result = SecretScanResult()

    for file_path in files:
        text = read_text_safe(file_path)
        if text is None:
            unscannable = classify_unscannable(file_path) or UnscannedFile(
                file_path, "could not be read as text", UnscannedKind.TEXT_LIKE
            )
            try:
                rel = file_path.relative_to(project_dir)
            except ValueError:
                rel = file_path
            result.unscanned.append(
                UnscannedFile(rel, unscannable.reason, unscannable.kind)
            )
            continue
        rel_path = file_path.relative_to(project_dir)

        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                token = match.group(0)
                preview = token[:10] + "..." if len(token) > 10 else token
                finding = SecretFinding(rel_path, line, label, preview)
                if line_allows_secret(text, match.start()):
                    result.allowed.append(finding)
                else:
                    result.findings.append(finding)

    return result


ALLOW_SECRET_MARKER = "packager: allow-secret"
_ALLOW_SECRET_RE = re.compile(r"packager:\s*allow-secret\b")


def line_allows_secret(text: str, offset: int) -> bool:
    """True if the line containing `offset` carries the allow marker.

    Same line only, by design: a marker cannot reach a token it is not
    visibly sitting beside, so it cannot quietly bless a whole file.
    """
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    line = text[start:] if end == -1 else text[start:end]
    return bool(_ALLOW_SECRET_RE.search(line))


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


def assert_no_reserved_collision(project_dir: Path, included_files: list[Path]) -> None:
    """P0 #5: refuse to package a project that ships its own manifest name.

    Silently dropping the user's file would lose material; writing both
    produces two members with the same name, and the resulting archive fails
    its own verification. Neither is acceptable, so the run stops instead.
    """
    for file_path in included_files:
        if normalise_rel(file_path.relative_to(project_dir)) == MANIFEST_ARCNAME:
            raise ReservedNameError(
                f"{MANIFEST_ARCNAME} is reserved for the packager's own metadata, "
                f"but the project contains a file of that name.\n"
                f"This applies with --no-manifest too: verify would read the "
                f"project's file as the internal manifest.\n"
                f"Rename it, or exclude it with --exclude \"{MANIFEST_ARCNAME}\"."
            )


def assert_contained(project_dir: Path, file_path: Path) -> None:
    """Recheck a source immediately before it is written into the archive.

    Scanning and writing are separate passes, so a path that was safe when
    scanned may not be safe by the time it is read.
    """
    if file_path.is_symlink():
        raise ContainmentError(f"refusing to archive a symlink: {file_path}")
    try:
        resolved = file_path.resolve(strict=True)
    except OSError as exc:
        raise ContainmentError(f"could not resolve {file_path}: {exc}") from exc
    if not is_inside(resolved, project_dir):
        raise ContainmentError(
            f"refusing to archive a path outside the project: {file_path} -> {resolved}"
        )


def create_zip(
    project_dir: Path,
    included_files: list[Path],
    output_zip: Path,
    *,
    overwrite: bool,
    manifest: dict | None,
) -> tuple[int, str, bool]:
    """Create the ZIP.

    Returns (total uncompressed bytes, zip sha256, sidecar written).
    """
    if output_zip.exists() and not overwrite:
        raise FileExistsError(
            f"Output already exists: {output_zip}\n"
            "Use --overwrite or choose a different --name/--output."
        )

    # Unconditional: the name belongs to the verification protocol, not to the
    # manifest-writing path. With --no-manifest a project's own file of that
    # name would otherwise be archived and later mistaken for the internal one.
    assert_no_reserved_collision(project_dir, included_files)

    output_zip.parent.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    try:
        total_bytes = _write_members(project_dir, included_files, output_zip, manifest)
    except (ReservedNameError, ContainmentError):
        # Full atomic replacement lands in v3.1.0. Until then, at least do not
        # leave a partial archive behind for the failures introduced here.
        try:
            output_zip.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    zip_digest = sha256_of_file(output_zip)

    # Sidecar hash file: "<hash>  <filename>" (sha256sum-compatible).
    sidecar = output_zip.with_name(output_zip.name + ".sha256")
    sidecar_written = True
    try:
        sidecar.write_text(f"{zip_digest}  {output_zip.name}\n", encoding="utf-8")
    except OSError as exc:
        print(f"WARNING: could not write hash sidecar: {exc}", file=sys.stderr)
        sidecar_written = False

    return total_bytes, zip_digest, sidecar_written


def _write_members(
    project_dir: Path,
    included_files: list[Path],
    output_zip: Path,
    manifest: dict | None,
) -> int:
    """Write every member into the archive. Returns uncompressed byte total."""
    total_bytes = 0
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        written: set[str] = set()
        for file_path in sorted(included_files):
            rel_path = file_path.relative_to(project_dir)
            arcname = normalise_rel(rel_path)
            if arcname in written:
                raise ReservedNameError(f"duplicate archive member: {arcname}")
            assert_contained(project_dir, file_path)
            zf.write(file_path, arcname)
            written.add(arcname)
            try:
                total_bytes += file_path.stat().st_size
            except OSError:
                pass

        if manifest is not None:
            if MANIFEST_ARCNAME in written:
                raise ReservedNameError(
                    f"{MANIFEST_ARCNAME} is reserved for the packager's own metadata."
                )
            zf.writestr(
                MANIFEST_ARCNAME,
                json.dumps(manifest, indent=2, sort_keys=False),
            )

    return total_bytes


# --------------------------------------------------------------------------
# Archive verification
# --------------------------------------------------------------------------


def verify_archive(zip_path: Path) -> int:
    """Check a ZIP against its embedded manifest and .sha256 sidecar.

    Tracks *positive evidence*, not merely the absence of detected failures.
    An archive with no trusted hash and no manifest has been checked against
    nothing at all, and saying so is the only honest result.

    Returns:
        0  every available check passed
        1  a check failed, or nothing could be checked
        7  partial: the sidecar matched, but there is no manifest to check
           the contents against
    """
    if not zip_path.is_file():
        print(f"ERROR: not a file: {zip_path}", file=sys.stderr)
        return EXIT_PROBLEMS

    failures = 0
    sidecar_verified = False   # a trusted hash matched the archive as a whole
    manifest_verified = False  # contents matched the archive's own manifest
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
                sidecar_verified = True
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
                print(f"  WARN  no {MANIFEST_ARCNAME} embedded")
                print()
                if failures:
                    print(f"RESULT: FAIL — {failures} problem(s) found.")
                    return EXIT_PROBLEMS
                if not sidecar_verified:
                    print("RESULT: FAIL — nothing could be checked.")
                    print("        No trusted sidecar hash and no embedded "
                          "manifest: this archive")
                    print("        carries no evidence about its own contents.")
                    return EXIT_PROBLEMS
                print("RESULT: PARTIAL — the sidecar hash matched, so the archive "
                      "matches the")
                print("        hash it was distributed with, but it contains no "
                      "manifest to")
                print("        check its individual members against.")
                return EXIT_PARTIAL

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
            if not failures:
                manifest_verified = True
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"  FAIL  could not verify archive: {exc}")
        failures += 1

    print()
    if failures:
        print(f"RESULT: FAIL — {failures} problem(s) found.")
        return EXIT_PROBLEMS
    if not (sidecar_verified or manifest_verified):
        print("RESULT: FAIL — nothing could be checked.")
        return EXIT_PROBLEMS
    if manifest_verified and not sidecar_verified:
        print("RESULT: OK — archive is internally consistent with its own manifest.")
        print("        No trusted sidecar hash was available, so this shows the "
              "archive is")
        print("        self-consistent, not that it is the archive you were sent.")
        return EXIT_OK
    print("RESULT: OK — archive verified against its sidecar hash and manifest.")
    return EXIT_OK


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


CHECK_CONFIG_SCHEMA_VERSION = 1

CONFIG_SCHEMA: dict[str, dict[str, str]] = {
    "version": {"target": "str", "files": "list[str]"},
    "forbidden": {
        "allow_files": "list[str]",
        "patterns": "dict[str,regex]",
        "contains": "dict[str,list[str]]",
    },
    "required": {"files": "list[str]", "contains": "dict[str,list[str]]"},
    "banned": {"paths": "list[str]"},
    "requirements": {"file": "str", "forbidden": "list[str]"},
    "wheel": {"build": "bool", "timeout": "int", "must_contain": "list[str]"},
    "limits": {"max_file_mb": "number", "max_total_mb": "number", "max_files": "int"},
}


def _check_type(where: str, value: object, expected: str) -> None:
    """Validate one configuration value against the schema, or raise."""
    if expected == "str":
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a string, got {type(value).__name__}")
    elif expected == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigError(f"{where} must be a positive number, got {value!r}")
    elif expected == "bool":
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false, got {value!r}")
    elif expected == "int":
        # bool is an int subclass, so reject it explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where} must be an integer, got {value!r}")
    elif expected == "list[str]":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings, got {value!r}")
    elif expected == "dict[str,list[str]]":
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a table, got {type(value).__name__}")
        for key, item in value.items():
            _check_type(f"{where}.{key}", item, "list[str]")
    elif expected == "dict[str,regex]":
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a table, got {type(value).__name__}")
        for key, pattern in value.items():
            if not isinstance(pattern, str):
                raise ConfigError(f"{where}.{key} must be a string, got {pattern!r}")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{where}.{key} is not a valid regex: {exc}") from exc


def validate_check_config(config: dict) -> None:
    """Reject a structurally invalid configuration before any check runs.

    P0 #2: a type error deep in a check produces either a crash or, worse, a
    plausible-looking failure list. Validate the whole document up front so
    the operator is told the configuration is wrong, not the project.
    """
    # Optional, for backwards compatibility with configurations written before
    # the field existed. Declaring it lets a future format change fail closed
    # on older builds instead of being silently half-interpreted.
    declared = config.get("schema_version", CHECK_CONFIG_SCHEMA_VERSION)
    if isinstance(declared, bool) or not isinstance(declared, int):
        raise ConfigError(f"schema_version must be an integer, got {declared!r}")
    if declared > CHECK_CONFIG_SCHEMA_VERSION:
        raise ConfigError(
            f"schema_version {declared} is newer than this build understands "
            f"(supports up to {CHECK_CONFIG_SCHEMA_VERSION}). Upgrade "
            f"{TOOL_NAME}, or lower the declared version."
        )
    if declared < 1:
        raise ConfigError(f"schema_version must be 1 or greater, got {declared}")

    for section, value in config.items():
        if section == "schema_version":
            continue
        if section not in CONFIG_SCHEMA:
            raise ConfigError(
                f"unknown section [{section}] — expected one of: "
                + ", ".join(sorted(CONFIG_SCHEMA))
            )
        if not isinstance(value, dict):
            raise ConfigError(f"[{section}] must be a table, got {type(value).__name__}")

        known = CONFIG_SCHEMA[section]
        for key, item in value.items():
            if key not in known:
                raise ConfigError(
                    f"unknown key {section}.{key} — expected one of: "
                    + ", ".join(sorted(known))
                )
            _check_type(f"{section}.{key}", item, known[key])


def load_check_config(project_dir: Path) -> dict | None:
    """Load release_check.toml from the project root.

    Returns None only when no configuration exists. Anything present but
    untrustworthy raises ConfigError: a broken release gate must fail closed,
    never degrade quietly into "built-in checks only".
    """
    config_path = project_dir / CHECK_CONFIG_NAME

    if not config_path.exists():
        return None
    if not config_path.is_file():
        raise ConfigError(f"{CHECK_CONFIG_NAME} exists but is not a regular file")

    try:
        import tomllib
    except ImportError as exc:  # pragma: no cover - 3.11+ is a hard requirement
        raise ConfigError(
            f"{CHECK_CONFIG_NAME} found but this Python has no tomllib (needs 3.11+)"
        ) from exc

    try:
        text = config_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        # UnicodeDecodeError is a ValueError, not an OSError, so it previously
        # escaped this handler entirely and surfaced as a traceback.
        raise ConfigError(f"{CHECK_CONFIG_NAME} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {CHECK_CONFIG_NAME}: {exc}") from exc

    try:
        config = tomllib.loads(text)
    except ValueError as exc:
        raise ConfigError(f"could not parse {CHECK_CONFIG_NAME}: {exc}") from exc

    validate_check_config(config)
    return config


def evaluate_limits(
    project_dir: Path, files: list[Path], limits: dict
) -> list[tuple[str, bool, str]]:
    """Check a package's file set against [limits]. Returns (label, ok, detail)."""
    sizes: list[tuple[str, int]] = []
    for file_path in files:
        try:
            size = file_path.stat().st_size
        except OSError:
            size = 0
        sizes.append((normalise_rel(file_path.relative_to(project_dir)), size))
    results: list[tuple[str, bool, str]] = []
    mb = 1024 * 1024

    if "max_files" in limits:
        cap = limits["max_files"]
        results.append((f"At most {cap} files", len(sizes) <= cap, f"{len(sizes)} files"))
    if "max_total_mb" in limits:
        cap = limits["max_total_mb"]
        total = sum(size for _, size in sizes)
        results.append((f"Total size at most {cap} MB", total <= cap * mb,
                        f"{format_bytes(total)} uncompressed"))
    if "max_file_mb" in limits:
        cap = limits["max_file_mb"]
        big = sorted(((rel, size) for rel, size in sizes if size > cap * mb),
                     key=lambda item: item[1], reverse=True)
        results.append((f"No single file over {cap} MB", not big,
                        ", ".join(f"{rel} ({format_bytes(size)})" for rel, size in big[:5])))
    return results


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


def run_builtin_checks(
    project_dir: Path, report: CheckReport, *, include_secret_scan: bool = True
) -> None:
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

    # Secret scan. Skipped when packaging: the package stage scans exactly the
    # files that will ship, so running both gates would ask the same question
    # twice, of different file sets, and answer with different exit codes.
    if include_secret_scan:
        report.section("Secret scan")
        secret_scan = scan_for_secrets(project_dir, files)
        findings = secret_scan.findings
        report.check(
            "No likely secrets in tracked text files",
            len(findings) == 0,
            "; ".join(
                f"{normalise_rel(f.rel_path)}:{f.line} [{f.label}]" for f in findings[:5]
            ),
        )

        if secret_scan.allowed:
            report.warn(
                f"No secret matches allowed by '{ALLOW_SECRET_MARKER}'",
                False,
                "; ".join(
                    f"{normalise_rel(f.rel_path)}:{f.line} [{f.label}]"
                    for f in secret_scan.allowed[:5]
                ),
            )

        if secret_scan.unscanned:
            report.check(
                "All tracked text files could be scanned",
                len(secret_scan.unscanned_text_files()) == 0,
                "; ".join(
                    f"{normalise_rel(entry.path)} ({entry.reason})"
                    for entry in secret_scan.unscanned_text_files()[:5]
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


def run_config_checks(
    project_dir: Path, config: dict, report: CheckReport, *, include_limits: bool = True
) -> None:
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

    # -- Size limits (against what a release package would contain) ------------
    limits = config.get("limits", {}) if include_limits else {}
    if limits:
        report.section("Package size limits (release profile)")
        ignore_lines, _ = load_ignore_file(project_dir)
        preview = preview_package(project_dir, profile="release",
                                  ignore_lines=ignore_lines, scan_secrets=False)
        for label, ok, detail in evaluate_limits(project_dir, preview.scan.included_files,
                                                 limits):
            report.check(label, ok, detail)

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
#
# Unknown sections and keys are rejected: a misspelled gate that silently does
# nothing is more dangerous than a stale config that fails visibly.

# Format version. A build that does not understand a newer version refuses the
# file rather than half-interpreting it.
schema_version = 1

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

# [limits]
# Size gates for the release package (checked by `check`, enforced by
# `package --profile release` / --check). All optional.
# max_file_mb = 25
# max_total_mb = 200
# max_files = 5000

# [wheel]
# build = true
# timeout = 300
# must_contain = ["mypackage/__init__.py", "static/app.css"]
"""

IGNORE_TEMPLATE = """\
# .packagerignore — extra exclusions for project_packager.py
# One pattern per line. Trailing / marks a directory. Patterns containing /
# match against the relative path. A leading / anchors to the project root.
# A leading ! force-includes, like --include (overrides every exclusion
# except symlinks and the output archive). Use \\! for a literal leading !.
#
# Edit by hand, or visually with:  python project_packager.py --gui
#
# docs/
# *.log
# data/raw/
# !data/raw/sample.csv
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
    unscanned: list[UnscannedFile] | None = None,
    allowed: list[SecretFinding] | None = None,
    cleaned_dirs: int = 0,
    cleaned_files: int = 0,
    zip_uncompressed_bytes: int = 0,
    zip_sha256: str = "",
    manifest_embedded: bool = True,
    sidecar_written: bool = True,
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
    if scan.skipped_symlinks:
        print(f"Skipped symlinks:        {len(scan.skipped_symlinks)}")
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

    if allowed:
        print()
        print(f"Secret matches ALLOWED by inline '{ALLOW_SECRET_MARKER}' "
              f"({len(allowed)}) — these ship:")
        for finding in allowed[:20]:
            print(f"  ~ {normalise_rel(finding.rel_path)}:{finding.line}"
                  f"  [{finding.label}]  {finding.preview}")
        if len(allowed) > 20:
            print(f"  ... plus {len(allowed) - 20} more")

    if unscanned:
        print()
        print(f"NOT SCANNED for secrets ({len(unscanned)}) — these ship unexamined:")
        for entry in unscanned[:20]:
            print(f"  - {normalise_rel(entry.path)}  ({entry.reason})  "
                  f"[{entry.kind.value}]")
        if len(unscanned) > 20:
            print(f"  ... plus {len(unscanned) - 20} more file(s)")

    if output_zip and output_zip.exists() and not dry_run:
        print()
        try:
            print(f"ZIP file size:           {format_bytes(output_zip.stat().st_size)}")
        except OSError:
            pass
        print(f"Uncompressed included:   {format_bytes(zip_uncompressed_bytes)}")
        if zip_sha256:
            print(f"ZIP SHA-256:             {zip_sha256}")
            if sidecar_written:
                print(f"Hash sidecar:            {output_zip.name}.sha256")
            else:
                print("Hash sidecar:            NOT WRITTEN — recipients have "
                      "no trusted hash")
        if manifest_embedded and sidecar_written:
            print(f"Manifest embedded:       {MANIFEST_ARCNAME}")
        elif manifest_embedded:
            print(f"Manifest embedded:       {MANIFEST_ARCNAME}")
            print("Verification:            self-consistency only — no sidecar "
                  "hash was written")
        elif sidecar_written:
            print("Manifest embedded:       disabled (--no-manifest)")
            print("Verification:            partial — sidecar hash only, no "
                  "per-file manifest")
        else:
            print("Manifest embedded:       disabled (--no-manifest)")
            print("Verification:            NO VERIFICATION EVIDENCE — no "
                  "manifest and no sidecar")

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


def run_all_checks(
    project_dir: Path, *, include_secret_scan: bool = True, include_limits: bool = True
) -> CheckReport:
    """Run the built-in checks, plus any configured in release_check.toml.

    `include_secret_scan` is disabled when packaging: the package stage scans
    exactly the files that will ship, which is both the honest question and a
    narrower one than scanning the whole working tree. Running both gates gave
    two different exit codes for the same problem and could block a release
    over a secret in a file the release profile excludes anyway.
    """
    report = CheckReport()
    config = load_check_config(project_dir)

    print()
    print("=" * 72)
    header = f"Release checks — {project_dir.name}"
    if config and str(config.get("version", {}).get("target", "")).strip():
        header += f" (target: {config['version']['target']})"
    print(header)
    print("=" * 72)

    run_builtin_checks(project_dir, report, include_secret_scan=include_secret_scan)
    if config:
        run_config_checks(project_dir, config, report, include_limits=include_limits)
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


def report_config_error(exc: ConfigError) -> None:
    print(
        f"ERROR: invalid release configuration in {CHECK_CONFIG_NAME}: {exc}\n"
        "Release gates fail closed: fix the configuration, or remove the file "
        "to run built-in checks only.",
        file=sys.stderr,
    )


def cmd_check(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"ERROR: not a directory: {project_dir}", file=sys.stderr)
        return EXIT_BAD_PROJECT
    try:
        report = run_all_checks(project_dir)
    except ConfigError as exc:
        report_config_error(exc)
        return EXIT_BAD_CONFIG
    return EXIT_PROBLEMS if report.failures else EXIT_OK


# --------------------------------------------------------------------------
# Subcommand: verify
# --------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    return verify_archive(Path(args.zip).expanduser().resolve())


# --------------------------------------------------------------------------
# Subcommand: why
# --------------------------------------------------------------------------


def classify_rule_origin(pattern: str) -> str:
    """Where a matched exclusion pattern came from, for humans."""
    if pattern in DEFAULT_EXCLUDE_DIR_NAMES | DEFAULT_EXCLUDE_DIR_PATTERNS | DEFAULT_EXCLUDE_FILE_PATTERNS:
        if pattern in DEBRIS_FILE_PATTERNS:
            return "built-in: session debris"
        return "built-in default"
    if pattern in STRICT_EXCLUDE_DIR_NAMES | STRICT_EXCLUDE_FILE_PATTERNS:
        return "strict privacy set (--strict / release profile)"
    return "your rule"


def ignore_line_numbers(project_dir: Path, wanted: str) -> list[int]:
    """1-based line numbers in .packagerignore whose pattern equals `wanted`."""
    try:
        text = (project_dir / IGNORE_FILE_NAME).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return []
    return [n for n, raw in enumerate(text.splitlines(), 1) if raw.strip() == wanted]


def resolve_project_rel(project_dir: Path, raw: str) -> str | None:
    """Turn a user-supplied path into a project-relative POSIX path, or None."""
    candidate = Path(raw.replace("\\", "/")).expanduser()
    options = [candidate] if candidate.is_absolute() else [project_dir / candidate,
                                                           Path.cwd() / candidate]
    for option in options:
        # Lexical, deliberately not resolve(): a symlink must be explained as a
        # symlink, not as whatever it happens to point at.
        absolute = Path(os.path.abspath(option))
        try:
            rel = absolute.relative_to(project_dir)
        except ValueError:
            continue
        if option.exists() or option.is_symlink():
            return normalise_rel(rel)
    return None


def explain_path(project_dir: Path, rel: str, preview: PreviewResult) -> list[str]:
    """Human explanation of one path's fate in `preview`. Read-only."""
    project_dir = preview.project_dir
    target = project_dir / rel
    out: list[str] = []
    user_lines, _ = load_ignore_file(project_dir) if (project_dir / IGNORE_FILE_NAME).exists() else ([], 0)

    def cite(line: str) -> str:
        nums = ignore_line_numbers(project_dir, line)
        where = f"{IGNORE_FILE_NAME} line {', '.join(map(str, nums))}" if nums else "rule"
        return f"{line}   ({where})"

    for d in preview.scan.skipped_symlinks:
        if normalise_rel(d.rel_path) == rel:
            return [f"SKIPPED   {rel}", "  symlinks are never packaged — not even with a "
                    "force-include. This cannot be overridden."]

    if target.is_dir() and not target.is_symlink():
        inc = [p for p in preview.scan.included_files if is_inside(p, target)]
        own = [d for d in preview.scan.excluded if normalise_rel(d.rel_path) == rel]
        if not own:
            exc = [d for d in preview.scan.excluded
                   if normalise_rel(d.rel_path).startswith(rel + "/")]
            out.append(f"FOLDER    {rel}/")
            out.append(f"  {len(inc)} file(s) included beneath it, {len(exc)} item(s) excluded.")
            parent_hits = user_rules_excluding(rel, True, user_lines)
            if parent_hits:
                out.append("  The folder itself matches an exclusion but stays open because a "
                           "force-include reaches inside:")
                out += [f"    {cite(h)}" for h in parent_hits]
            return out

    if target in preview.scan.force_included or any(
            p == target for p in preview.scan.force_included):
        out.append(f"INCLUDED  {rel}   (force-included)")
        name = rel.rsplit("/", 1)[-1]
        for pattern in sorted(preview.rules.include_patterns):
            if is_force_included(name, rel, Rules(include_patterns={pattern})):
                bang = "!" + pattern
                nums = ignore_line_numbers(project_dir, bang)
                where = f"{IGNORE_FILE_NAME} line {', '.join(map(str, nums))}" if nums else "--include"
                out.append(f"  by {bang if nums else pattern}   ({where})")
        hidden = [d for d in user_rules_excluding(rel, False, user_lines)]
        if hidden:
            out.append("  It would otherwise be excluded by:")
            out += [f"    {cite(h)}" for h in hidden]
        return out

    if any(p == target for p in preview.scan.included_files):
        out.append(f"INCLUDED  {rel}")
        out.append("  No exclusion rule matches it.")
        return out

    # Excluded: the path itself, or an ancestor folder that was pruned.
    parts = rel.split("/")
    decisions = {normalise_rel(d.rel_path): d for d in preview.scan.excluded}
    for depth in range(len(parts), 0, -1):
        here = "/".join(parts[:depth])
        decision = decisions.get(here)
        if decision is None:
            continue
        prefix = "" if depth == len(parts) else f"inside excluded folder {here}/ — "
        out.append(f"EXCLUDED  {rel}")
        reason = decision.reason
        out.append(f"  {prefix}{reason}")
        if ":" in reason:
            pattern = reason.split(":", 1)[1].strip()
            origin = classify_rule_origin(pattern)
            mine = user_rules_excluding(here, depth != len(parts) or target.is_dir(), user_lines)
            if mine:
                out.append("  from your rule(s):")
                out += [f"    {cite(m)}" for m in mine]
                out.append("  Remove the rule, or force-include with:  "
                           f"{suggest_patterns(rel, target.is_dir())['include_this']}")
            else:
                out.append(f"  source: {origin}")
                if origin != "your rule":
                    out.append("  Built-in rules can't be removed; override with this line "
                               f"in {IGNORE_FILE_NAME}:  "
                               f"{suggest_patterns(rel, target.is_dir())['include_this']}")
        return out

    return [f"UNKNOWN   {rel}", "  Not reached by the scan (unexpected — please report)."]


def cmd_why(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"ERROR: not a directory: {project_dir}", file=sys.stderr)
        return EXIT_BAD_PROJECT
    try:
        preview = preview_package(project_dir, profile=args.profile, strict=args.strict,
                                  scan_secrets=False)
    except ConfigError as exc:
        print(f"ERROR: invalid {IGNORE_FILE_NAME}: {exc}", file=sys.stderr)
        return EXIT_BAD_CONFIG
    code = EXIT_OK
    print(f"Profile: {args.profile}{' + strict' if preview.strict and args.profile != 'release' else ''}")
    for raw in args.paths:
        rel = resolve_project_rel(project_dir, raw)
        print()
        if rel is None or rel in ("", "."):
            print(f"NOT FOUND {raw}  (no such path inside {project_dir})")
            code = EXIT_PROBLEMS
            continue
        for line in explain_path(project_dir, rel, preview):
            print(line)
    print()
    return code


# --------------------------------------------------------------------------
# Subcommand: diff
# --------------------------------------------------------------------------


@dataclass
class Listing:
    """What one side of a diff contains: rel path -> (size, sha256)."""

    label: str
    source: str            # "manifest", "hashed members", or "working tree"
    files: dict[str, tuple[int, str]]
    created: str = ""


def listing_from_zip(zip_path: Path) -> Listing:
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if MANIFEST_ARCNAME in names:
            try:
                manifest = json.loads(zf.read(MANIFEST_ARCNAME))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError(f"{zip_path.name}: unreadable manifest: {exc}") from exc
            files: dict[str, tuple[int, str]] = {}
            for entry in manifest.get("files", []) if isinstance(manifest, dict) else []:
                if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                    files[entry["path"]] = (int(entry.get("size") or 0), str(entry.get("sha256", "")))
            return Listing(zip_path.name, "manifest", files, str(manifest.get("created_utc", "")))
        files = {}
        for name in names:
            digest = hashlib.sha256()
            with zf.open(name) as member:
                for chunk in iter(lambda: member.read(1024 * 1024), b""):
                    digest.update(chunk)
            files[name] = (zf.getinfo(name).file_size, digest.hexdigest())
        return Listing(zip_path.name, "hashed members (no manifest)", files)


def listing_from_dir(project_dir: Path, profile: str, strict: bool) -> Listing:
    preview = preview_package(project_dir, profile=profile, strict=strict, scan_secrets=False)
    files = {}
    for path in preview.scan.included_files:
        try:
            files[normalise_rel(path.relative_to(preview.project_dir))] = (
                path.stat().st_size, sha256_of_file(path))
        except OSError:
            continue
    return Listing(f"{preview.project_dir.name}/", f"working tree, {profile} profile", files)


def diff_listings(a: Listing, b: Listing) -> dict[str, list]:
    added = sorted(set(b.files) - set(a.files))
    removed = sorted(set(a.files) - set(b.files))
    common = sorted(set(a.files) & set(b.files))
    changed = [p for p in common if a.files[p][1] != b.files[p][1]]
    return {"added": added, "removed": removed, "changed": changed,
            "unchanged": [p for p in common if p not in set(changed)]}


def cmd_diff(args: argparse.Namespace) -> int:
    listings = []
    for raw in (args.old, args.new):
        path = Path(raw).expanduser()
        try:
            if path.is_dir():
                listings.append(listing_from_dir(path.resolve(), args.profile, args.strict))
            elif path.is_file():
                listings.append(listing_from_zip(path))
            else:
                print(f"ERROR: not found: {path}", file=sys.stderr)
                return EXIT_BAD_PROJECT
        except ConfigError as exc:
            print(f"ERROR: invalid {IGNORE_FILE_NAME} in {path}: {exc}", file=sys.stderr)
            return EXIT_BAD_CONFIG
        except (OSError, zipfile.BadZipFile, ValueError) as exc:
            print(f"ERROR: could not read {path}: {exc}", file=sys.stderr)
            return EXIT_OS_ERROR
    a, b = listings
    result = diff_listings(a, b)
    differs = bool(result["added"] or result["removed"] or result["changed"])

    if args.json:
        print(json.dumps({
            "old": {"label": a.label, "source": a.source, "created": a.created,
                    "file_count": len(a.files)},
            "new": {"label": b.label, "source": b.source, "created": b.created,
                    "file_count": len(b.files)},
            "added": [{"path": p, "size": b.files[p][0]} for p in result["added"]],
            "removed": [{"path": p, "size": a.files[p][0]} for p in result["removed"]],
            "changed": [{"path": p, "old_size": a.files[p][0], "new_size": b.files[p][0]}
                        for p in result["changed"]],
            "unchanged_count": len(result["unchanged"]),
        }, indent=2))
        return EXIT_PROBLEMS if differs else EXIT_OK

    def side(tag: str, lst: Listing) -> str:
        when = f", created {lst.created}" if lst.created else ""
        return f"  {tag}  {lst.label}  ({len(lst.files)} files, {lst.source}{when})"

    print()
    print("Comparing")
    print(side("old", a))
    print(side("new", b))
    print()
    for p in result["added"]:
        print(f"  + {p}  ({format_bytes(b.files[p][0])})")
    for p in result["removed"]:
        print(f"  - {p}  ({format_bytes(a.files[p][0])})")
    for p in result["changed"]:
        old, new = a.files[p][0], b.files[p][0]
        delta = new - old
        sign = "+" if delta >= 0 else "-"
        print(f"  ~ {p}  ({format_bytes(old)} -> {format_bytes(new)}, "
              f"{sign}{format_bytes(abs(delta))})")
    if differs:
        print()
    total_old = sum(v[0] for v in a.files.values())
    total_new = sum(v[0] for v in b.files.values())
    print(f"{len(result['added'])} added, {len(result['removed'])} removed, "
          f"{len(result['changed'])} changed, {len(result['unchanged'])} unchanged.  "
          f"Size {format_bytes(total_old)} -> {format_bytes(total_new)}.")
    if "manifest" in (a.source, b.source):
        print("Manifests are compared as recorded; run `verify` to confirm an archive "
              "still matches its own.")
    print()
    return EXIT_PROBLEMS if differs else EXIT_OK


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
        return EXIT_BAD_PROJECT
    if not project_dir.is_dir():
        print(f"ERROR: project path is not a directory: {project_dir}", file=sys.stderr)
        return EXIT_BAD_PROJECT

    if run_checks_first:
        try:
            # Limits are gated below against the real file set of this run.
            report = run_all_checks(
                project_dir, include_secret_scan=False, include_limits=False
            )
        except ConfigError as exc:
            report_config_error(exc)
            return EXIT_BAD_CONFIG
        if report.failures and not args.force:
            print(
                "ERROR: release checks failed — not packaging.\n"
                "Fix the failures or re-run with --force.",
                file=sys.stderr,
            )
            return EXIT_CHECKS_FAILED

    if args.output:
        output_dir = Path(args.output).expanduser().resolve()
    else:
        output_dir = project_dir.parent / "packaged"

    output_zip = output_dir / build_zip_name(project_dir, args.name)

    try:
        ignore_patterns, ignore_count = load_ignore_file(project_dir)
    except ConfigError as exc:
        # Deliberately not overridable by --force: --force is for judgement
        # calls about findings, not for proceeding with unusable configuration.
        print(
            f"ERROR: invalid packaging configuration in {IGNORE_FILE_NAME}: {exc}\n"
            "Packaging fails closed rather than silently dropping every "
            "project-specific exclusion. Repair, rename, or remove the file.",
            file=sys.stderr,
        )
        return EXIT_BAD_CONFIG
    rules = build_rules(
        profile=args.profile,
        strict=strict,
        ignore_patterns=ignore_patterns,
        extra_excludes=args.exclude,
        include_patterns=args.include,
    )

    scan = scan_project(
        project_dir, rules, output_dir=output_dir, output_zip=output_zip
    )

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

    # Replacement is not atomic until v3.1.0, so a failed write can destroy a
    # good archive. Refused where that matters most, unless stated explicitly.
    if args.overwrite and fail_on_secrets and not args.force:
        print(
            "ERROR: --overwrite is refused in strict/release mode because archive "
            "replacement\nis not yet atomic (scheduled for v3.1.0): a failed write "
            "can destroy the\nexisting archive. Use a new --name, or accept the "
            "risk with --force.",
            file=sys.stderr,
        )
        return EXIT_OUTPUT_EXISTS

    if not scan_secrets and fail_on_secrets and not args.force:
        print(
            "ERROR: --no-scan disables the secret gate that strict/release mode "
            "exists to enforce.\nDrop --no-scan, or state the override "
            "explicitly with --force.",
            file=sys.stderr,
        )
        return EXIT_SECRETS

    secret_scan = SecretScanResult()
    if scan_secrets:
        secret_scan = scan_for_secrets(project_dir, scan.included_files)
    findings = secret_scan.findings

    # Release mode claims to refuse shipping secrets. It cannot honour that
    # claim for files it never read, so an unscanned text file blocks too.
    blocking_unscanned = (
        secret_scan.unscanned_text_files() if fail_on_secrets and scan_secrets else []
    )

    if (findings or blocking_unscanned) and fail_on_secrets and not args.force:
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
            unscanned=secret_scan.unscanned,
            allowed=secret_scan.allowed,
            cleaned_dirs=cleaned_dirs,
            cleaned_files=cleaned_files,
            manifest_embedded=not args.no_manifest,
        )
        if findings:
            print(
                "ERROR: possible secrets found and strict/release mode is active.\n"
                "Fix the findings, exclude the files, or re-run with --force.",
                file=sys.stderr,
            )
        if blocking_unscanned:
            print(
                "ERROR: text files could not be secret-scanned and strict/release "
                "mode is active:",
                file=sys.stderr,
            )
            for entry in blocking_unscanned[:10]:
                print(f"  - {normalise_rel(entry.path)} ({entry.reason})", file=sys.stderr)
            print(
                "These files ship unexamined. Exclude them, reduce their size, "
                "or re-run with --force.",
                file=sys.stderr,
            )
        return EXIT_SECRETS

    # Size limits gate the release path only (release profile or --check),
    # which is also the only path that has loaded and validated the config.
    if run_checks_first:
        try:
            config = load_check_config(project_dir) or {}
        except ConfigError as exc:
            report_config_error(exc)
            return EXIT_BAD_CONFIG
        if config.get("limits"):
            broken = [
                (label, detail)
                for label, ok, detail in evaluate_limits(
                    project_dir, scan.included_files, config["limits"])
                if not ok
            ]
            for label, detail in broken:
                print(f"  FAIL  {label}: {detail}", file=sys.stderr)
            if broken and not args.force:
                print("ERROR: [limits] in release_check.toml exceeded — not packaging.\n"
                      "Exclude something, raise the limit, or re-run with --force.",
                      file=sys.stderr)
                return EXIT_CHECKS_FAILED

    # Preflight the reserved-name collision here, where it is already known
    # from the scan, rather than discovering it inside create_zip() after
    # cleaning has already deleted things. create_zip() checks again as
    # defence in depth.
    try:
        assert_no_reserved_collision(project_dir, scan.included_files)
    except ReservedNameError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_RESERVED_NAME

    # The most common refusal of all: the output already exists. Checked here,
    # before anything mutates the project. create_zip() checks again as defence
    # in depth against a race, but by then cleaning has already run.
    if output_zip.exists() and not args.overwrite and not args.dry_run:
        print(
            f"ERROR: Output already exists: {output_zip}\n"
            "Use --overwrite or choose a different --name/--output.",
            file=sys.stderr,
        )
        return EXIT_OUTPUT_EXISTS

    # Cleaning deletes files, so it happens only once every blocking condition
    # has passed. Previously it ran before the --no-scan, secret, and overwrite
    # refusals, so a command that packaged nothing still mutated the project.
    # A failed package must not change anything it was not asked to change.
    if clean:
        cleaned_dirs, cleaned_files = remove_clean_targets(scan, dry_run=args.dry_run)

        # Rescan so deleted junk no longer appears in the manifest or summary.
        if not args.dry_run and (cleaned_dirs or cleaned_files):
            scan = scan_project(
                project_dir, rules, output_dir=output_dir, output_zip=output_zip
            )

    zip_uncompressed_bytes = 0
    zip_sha256 = ""
    sidecar_written = True
    if not args.dry_run:
        manifest = None if args.no_manifest else build_manifest(project_dir, scan.included_files)
        try:
            zip_uncompressed_bytes, zip_sha256, sidecar_written = create_zip(
                project_dir,
                scan.included_files,
                output_zip,
                overwrite=args.overwrite,
                manifest=manifest,
            )
        except FileExistsError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_OUTPUT_EXISTS
        except ReservedNameError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_RESERVED_NAME
        except ContainmentError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_CONTAINMENT
        except OSError as exc:
            print(f"ERROR: could not create ZIP: {exc}", file=sys.stderr)
            return EXIT_OS_ERROR

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
        unscanned=secret_scan.unscanned,
        allowed=secret_scan.allowed,
        cleaned_dirs=cleaned_dirs,
        cleaned_files=cleaned_files,
        zip_uncompressed_bytes=zip_uncompressed_bytes,
        zip_sha256=zip_sha256,
        manifest_embedded=not args.no_manifest,
        sidecar_written=sidecar_written,
    )

    # An archive with neither a manifest nor a sidecar carries no evidence
    # about its own contents at all. That is a failure in any profile.
    if not sidecar_written and args.no_manifest and not args.dry_run:
        print(
            "ERROR: this archive has no embedded manifest and no hash sidecar, "
            "so nothing\ncan ever be verified about its contents. "
            "Fix the output location and re-run.",
            file=sys.stderr,
        )
        return EXIT_OS_ERROR

    # A release with no sidecar has no trusted hash for its recipient to check
    # against, which removes the point of shipping it as a verified artifact.
    if not sidecar_written and fail_on_secrets and not args.force:
        print(
            "ERROR: the hash sidecar could not be written, so this release has "
            "no trusted\nhash to verify against. Fix the output location, or "
            "re-run with --force.",
            file=sys.stderr,
        )
        return EXIT_OS_ERROR

    if args.open and not args.dry_run:
        open_folder(output_dir)

    return 0


# --------------------------------------------------------------------------
# Preview (shared by the GUI; no side effects)
# --------------------------------------------------------------------------

EXIT_MEANINGS: dict[int, str] = {
    Exit.OK: "done",
    Exit.PROBLEMS: "checks failed, or verification found a fault",
    Exit.BAD_PROJECT: "project path missing or not a directory",
    Exit.OUTPUT_EXISTS: "that ZIP already exists — tick Overwrite or change the name",
    Exit.OS_ERROR: "write error, or no verification evidence",
    Exit.SECRETS: "blocked: secrets, or text that could not be scanned",
    Exit.CHECKS_FAILED: "blocked: release checks failed — run checks for detail",
    Exit.PARTIAL: "partial: hash matched, but no manifest to check against",
    Exit.RESERVED_NAME: "a project file is named PACKAGE_MANIFEST.json",
    Exit.BAD_CONFIG: "release_check.toml or .packagerignore present but unusable",
    Exit.CONTAINMENT: "a path escaped the project between scan and write",
}


@dataclass
class PreviewResult:
    """Everything `package` would decide, computed without writing anything."""

    project_dir: Path
    scan: ScanResult
    secrets: SecretScanResult
    output_dir: Path
    output_zip: Path
    strict: bool
    scanned_secrets: bool
    rules: Rules = field(default_factory=Rules)
    profile: str = "share"


def preview_package(
    project_dir: Path,
    *,
    profile: str = "share",
    strict: bool = False,
    ignore_lines: list[str] | None = None,
    output: str | None = None,
    name: str | None = None,
    scan_secrets: bool = True,
) -> PreviewResult:
    """Run the same rule building and scan as `package`, read-only.

    `ignore_lines` lets the GUI preview unsaved .packagerignore edits. When it
    is None the file on disk is loaded, with the same fail-closed handling.
    """
    project_dir = project_dir.resolve()
    effective_strict = strict or profile == "release"
    if ignore_lines is None:
        ignore_lines, _ = load_ignore_file(project_dir)
    output_dir = (
        Path(output).expanduser().resolve() if output else project_dir.parent / "packaged"
    )
    output_zip = output_dir / build_zip_name(project_dir, name)
    rules = build_rules(
        profile=profile,
        strict=effective_strict,
        ignore_patterns=list(ignore_lines),
        extra_excludes=[],
        include_patterns=[],
    )
    scan = scan_project(project_dir, rules, output_dir=output_dir, output_zip=output_zip)
    do_scan = scan_secrets and profile != "backup"
    secrets = scan_for_secrets(project_dir, scan.included_files) if do_scan else SecretScanResult()
    return PreviewResult(
        project_dir=project_dir,
        scan=scan,
        secrets=secrets,
        output_dir=output_dir,
        output_zip=output_zip,
        strict=effective_strict,
        scanned_secrets=do_scan,
        rules=rules,
        profile=profile,
    )


# --------------------------------------------------------------------------
# GUI (tkinter — stdlib, imported only when --gui is used)
# --------------------------------------------------------------------------

GUI_THEME = {
    "bg": "#0b0f14",       # Obsidian
    "panel": "#11161d",    # Panel
    "border": "#1e2831",   # Border
    "teal": "#2fd6c3",
    "green": "#4be08a",    # Phosphor
    "amber": "#ffb454",
    "red": "#ff6b6b",
    "text": "#c8d3da",
    "dim": "#5f6d78",
    "select": "#173634",
}

GUI_FONT_CANDIDATES = (
    "JetBrains Mono", "Cascadia Mono", "Consolas", "DejaVu Sans Mono",
    "Menlo", "Courier New",
)

# status -> (glyph, label, colour key)
GUI_STATUS = {
    "included": ("✓", "included", "text"),
    "forced": ("★", "force-included", "green"),
    "secret": ("⚠", "POSSIBLE SECRET", "red"),
    "allowed": ("~", "secret (allowed)", "amber"),
    "unscanned": ("?", "not scannable", "amber"),
    "excluded": ("✕", "excluded", "dim"),
    "inherited": ("✕", "excluded (parent)", "dim"),
    "symlink": ("↪", "symlink (skipped)", "amber"),
    "folder": ("", "", "text"),
}


class GuiSettings:
    """Per-user GUI memory: recent projects and per-project choices.

    Stored in the user's config folder, never inside a project. A setting
    that lived in the project would travel with a clone and silently change
    how someone else's packaging behaves; this only remembers what *you*
    picked last time. Convenience data only — it never affects the CLI.
    """

    KEYS = ("profile", "strict", "secrets", "name", "output", "overwrite",
            "clean", "check", "open")
    MAX_RECENT = 12

    def __init__(self, path: Path | None = None):
        self.path = path or self.default_path()
        self.data: dict = {"version": 1, "recent": [], "projects": {}}
        self.writable = True
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.data["recent"] = [r for r in raw.get("recent", []) if isinstance(r, str)]
                projects = raw.get("projects", {})
                if isinstance(projects, dict):
                    self.data["projects"] = {k: v for k, v in projects.items()
                                             if isinstance(v, dict)}
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            # Unreadable: leave it alone rather than overwrite what we can't parse.
            self.writable = False

    @staticmethod
    def default_path() -> Path:
        override = os.environ.get("PROJECT_PACKAGER_CONFIG_DIR")
        if override:
            base = Path(override)
        elif sys.platform.startswith("win"):
            base = Path(os.environ.get("APPDATA") or Path.home()) / "project_packager"
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "project_packager"
        return base / "gui.json"

    def recent(self) -> list[str]:
        return list(self.data["recent"])

    def for_project(self, project: Path) -> dict:
        return dict(self.data["projects"].get(str(project), {}))

    def remember(self, project: Path, values: dict) -> None:
        key = str(project)
        self.data["projects"][key] = {k: values[k] for k in self.KEYS if k in values}
        recent = [r for r in self.data["recent"] if r != key]
        self.data["recent"] = ([key] + recent)[: self.MAX_RECENT]

    def save(self) -> bool:
        if not self.writable:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="gui.", suffix=".part", dir=str(self.path.parent))
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print(
            "ERROR: the GUI needs tkinter, which this Python does not include.\n"
            "On Windows, re-run the Python installer and tick 'tcl/tk and IDLE'.\n"
            "On Debian/Ubuntu: sudo apt install python3-tk",
            file=sys.stderr,
        )
        return EXIT_OS_ERROR
    project = Path(args.project).expanduser().resolve() if args.project else Path.cwd()
    if not project.is_dir():
        print(f"ERROR: not a directory: {project}", file=sys.stderr)
        return EXIT_BAD_PROJECT
    app = PackagerGUI(project)
    app.run()
    return EXIT_OK


class PackagerGUI:
    """Visual include/exclude editor and runner for project_packager.

    Design rules:
      - The preview is computed by preview_package(), i.e. the same
        build_rules/scan_project/scan_for_secrets the CLI uses. The GUI has no
        matching logic of its own, so it cannot disagree with `package`.
      - Rules live in .packagerignore. Unsaved edits are previewed live but
        nothing touches disk until Save.
      - Packaging, checks and verification run the CLI itself as a
        subprocess, so exit codes and safety gates are identical.
      - An unreadable .packagerignore disables editing: saving over it would
        silently discard whatever exclusions it held.
    """

    POLL_MS = 60
    REFRESH_DELAY_MS = 250
    LAZY_LIMIT = 400

    def __init__(self, project_dir: Path):
        import queue
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.queue: "queue.Queue[tuple]" = queue.Queue()
        self.project_dir = project_dir
        self.ignore: IgnoreFile | None = None
        self.ignore_error: str | None = None
        self.saved_lines: list[str] = []
        self.undo_stack: list[list[str]] = []
        self.result: PreviewResult | None = None
        self.records: dict[str, dict] = {}
        self.generation = 0
        self.refresh_job: str | None = None
        self.proc: subprocess.Popen | None = None
        self.proc_queue: list[tuple[list[str], str]] = []
        self.last_zip: Path | None = None
        self.current_label = ""
        self.settings = GuiSettings()

        if sys.platform.startswith("win"):
            try:  # crisp text on high-DPI displays
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
            except Exception:
                pass

        self.root = tk.Tk()
        self.root.title(f"Project Packager v{TOOL_VERSION}")
        self.root.geometry("1280x820")
        self.root.minsize(980, 620)
        self.root.configure(bg=GUI_THEME["bg"])
        self._init_fonts()
        self._init_style()
        self._build()
        self._bind_keys()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.load_project(project_dir)
        self.root.after(self.POLL_MS, self._poll)

    # ---- setup ---------------------------------------------------------

    def _init_fonts(self) -> None:
        from tkinter import font as tkfont

        families = set(tkfont.families(self.root))
        family = next((f for f in GUI_FONT_CANDIDATES if f in families), "TkFixedFont")
        self.font = (family, 10)
        self.font_bold = (family, 10, "bold")
        self.font_small = (family, 9)
        self.font_title = (family, 12, "bold")

    def _init_style(self) -> None:
        t = GUI_THEME
        style = self.ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=t["bg"], foreground=t["text"],
                        fieldbackground=t["panel"], bordercolor=t["border"],
                        lightcolor=t["border"], darkcolor=t["border"],
                        troughcolor=t["bg"], focuscolor=t["teal"],
                        selectbackground=t["select"], selectforeground=t["text"],
                        insertcolor=t["text"], font=self.font, relief="flat",
                        borderwidth=0)
        style.configure("TFrame", background=t["bg"])
        style.configure("Panel.TFrame", background=t["panel"])
        style.configure("TLabel", background=t["bg"], foreground=t["text"])
        style.configure("Panel.TLabel", background=t["panel"])
        style.configure("Dim.TLabel", foreground=t["dim"])
        style.configure("PanelDim.TLabel", background=t["panel"], foreground=t["dim"],
                        font=self.font_small)
        style.configure("Title.TLabel", foreground=t["teal"], font=self.font_title)
        style.configure("Head.TLabel", background=t["panel"], foreground=t["teal"],
                        font=self.font_bold)
        style.configure("Warn.TLabel", foreground=t["amber"])
        style.configure("Err.TLabel", foreground=t["red"])
        style.configure("TButton", background=t["border"], foreground=t["text"],
                        padding=(10, 4), borderwidth=1, relief="flat",
                        bordercolor=t["border"])
        style.map("TButton",
                  background=[("disabled", t["panel"]), ("pressed", t["teal"]),
                              ("active", "#26333e")],
                  foreground=[("disabled", t["dim"]), ("pressed", t["bg"])])
        style.configure("Accent.TButton", background=t["teal"], foreground=t["bg"],
                        font=self.font_bold)
        style.map("Accent.TButton",
                  background=[("disabled", t["panel"]), ("active", "#5ee3d4")],
                  foreground=[("disabled", t["dim"])])
        style.configure("Danger.TButton", background="#3a1f24", foreground=t["red"])
        style.map("Danger.TButton", background=[("disabled", t["panel"]),
                                                ("active", "#4a262c")])
        for name in ("TCheckbutton", "TRadiobutton"):
            style.configure(name, background=t["bg"], foreground=t["text"],
                            indicatorbackground=t["panel"], indicatorforeground=t["teal"],
                            indicatorrelief="flat", indicatormargin=4)
            style.map(name,
                      background=[("active", t["bg"])],
                      foreground=[("disabled", t["dim"])],
                      indicatorbackground=[("selected", t["teal"]),
                                           ("disabled", t["panel"])],
                      indicatorforeground=[("selected", t["bg"])])
        style.configure("TEntry", fieldbackground=t["panel"], foreground=t["text"],
                        insertcolor=t["teal"], padding=4, bordercolor=t["border"])
        style.map("TEntry", bordercolor=[("focus", t["teal"])],
                  fieldbackground=[("disabled", t["bg"])])
        style.configure("TCombobox", fieldbackground=t["panel"], background=t["border"],
                        foreground=t["text"], arrowcolor=t["text"], padding=3)
        style.map("TCombobox", fieldbackground=[("readonly", t["panel"])],
                  foreground=[("readonly", t["text"])],
                  selectbackground=[("readonly", t["panel"])],
                  selectforeground=[("readonly", t["text"])])
        self.root.option_add("*TCombobox*Listbox.background", t["panel"])
        self.root.option_add("*TCombobox*Listbox.foreground", t["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", t["select"])
        self.root.option_add("*TCombobox*Listbox.font", self.font)
        style.configure("Treeview", background=t["panel"], fieldbackground=t["panel"],
                        foreground=t["text"], rowheight=22, borderwidth=0)
        style.map("Treeview", background=[("selected", t["select"])],
                  foreground=[("selected", t["teal"])])
        style.configure("Treeview.Heading", background=t["border"], foreground=t["teal"],
                        font=self.font_bold, relief="flat", padding=4)
        style.map("Treeview.Heading", background=[("active", "#26333e")])
        for name in ("TScrollbar", "Vertical.TScrollbar", "Horizontal.TScrollbar"):
            style.configure(name, background=t["border"], troughcolor=t["bg"],
                            bordercolor=t["bg"], lightcolor=t["border"],
                            darkcolor=t["border"], arrowcolor=t["dim"],
                            borderwidth=0, gripcount=0, arrowsize=12)
            style.map(name, background=[("active", "#2a3a46"), ("disabled", t["bg"])],
                      arrowcolor=[("active", t["teal"])])
        style.configure("TPanedwindow", background=t["bg"])
        style.configure("Sash", sashthickness=6, background=t["border"])

    def _build(self) -> None:
        tk, ttk, t = self.tk, self.ttk, GUI_THEME
        self.var_project = tk.StringVar()
        self.var_profile = tk.StringVar(value="share")
        self.var_strict = tk.BooleanVar(value=False)
        self.var_secrets = tk.BooleanVar(value=True)
        self.var_filter = tk.StringVar(value="All")
        self.var_search = tk.StringVar()
        self.var_name = tk.StringVar()
        self.var_output = tk.StringVar()
        self.var_overwrite = tk.BooleanVar(value=False)
        self.var_clean = tk.BooleanVar(value=False)
        self.var_check = tk.BooleanVar(value=False)
        self.var_open = tk.BooleanVar(value=False)
        self.var_status = tk.StringVar(value="")
        self.var_dirty = tk.StringVar(value="")

        outer = ttk.Frame(self.root, padding=(12, 10, 12, 8))
        outer.pack(fill="both", expand=True)

        # Header row ----------------------------------------------------------
        head = ttk.Frame(outer)
        head.pack(fill="x")
        ttk.Label(head, text="PROJECT PACKAGER", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text=f"  v{TOOL_VERSION}", style="Dim.TLabel").pack(side="left")
        ttk.Button(head, text="Refresh  F5", command=self.refresh_now).pack(side="right")
        ttk.Button(head, text="Browse…", command=self.choose_project).pack(side="right", padx=6)
        self.cmb_project = ttk.Combobox(head, textvariable=self.var_project,
                                        values=self.settings.recent())
        self.cmb_project.pack(side="right", fill="x", expand=True, padx=(24, 0))
        self.cmb_project.bind("<Return>",
                              lambda e: self.load_project(Path(self.var_project.get())))
        self.cmb_project.bind("<<ComboboxSelected>>",
                              lambda e: self.load_project(Path(self.var_project.get())))

        # Options row -----------------------------------------------------------
        opts = ttk.Frame(outer, padding=(0, 8, 0, 6))
        opts.pack(fill="x")
        ttk.Label(opts, text="Profile").pack(side="left")
        prof = ttk.Combobox(opts, textvariable=self.var_profile, width=9, state="readonly",
                            values=("share", "release", "backup"))
        prof.pack(side="left", padx=(6, 14))
        prof.bind("<<ComboboxSelected>>", lambda e: self._on_profile())
        self.chk_strict = ttk.Checkbutton(opts, text="Strict privacy set",
                                          variable=self.var_strict,
                                          command=self.schedule_refresh)
        self.chk_strict.pack(side="left", padx=(0, 14))
        self.chk_secrets = ttk.Checkbutton(opts, text="Secret-scan preview",
                                           variable=self.var_secrets,
                                           command=self.schedule_refresh)
        self.chk_secrets.pack(side="left")
        self.lbl_profile = ttk.Label(opts, text="", style="Dim.TLabel")
        self.lbl_profile.pack(side="left", padx=14)

        # Main split ------------------------------------------------------------
        paned = ttk.Panedwindow(outer, orient="horizontal")

        left = ttk.Frame(paned)
        paned.add(left, weight=3)
        bar = ttk.Frame(left, padding=(0, 0, 0, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Show").pack(side="left")
        flt = ttk.Combobox(bar, textvariable=self.var_filter, width=12, state="readonly",
                           values=("All", "Included", "Excluded", "Attention"))
        flt.pack(side="left", padx=6)
        flt.bind("<<ComboboxSelected>>", lambda e: self.repaint())
        ttk.Label(bar, text="Find").pack(side="left", padx=(10, 0))
        find = ttk.Entry(bar, textvariable=self.var_search, width=24)
        find.pack(side="left", padx=6)
        self.var_search.trace_add("write", lambda *a: self.repaint())
        ttk.Button(bar, text="Collapse", command=lambda: self._open_all(False)).pack(side="right")
        ttk.Button(bar, text="Expand", command=lambda: self._open_all(True)).pack(side="right", padx=6)

        tree_wrap = ttk.Frame(left)
        tree_wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_wrap, columns=("status", "size", "why"),
                                 selectmode="extended")
        self.tree.heading("#0", text="Path", anchor="w")
        self.tree.heading("status", text="Status", anchor="w")
        self.tree.heading("size", text="Size", anchor="e")
        self.tree.heading("why", text="Rule / reason", anchor="w")
        self.tree.column("#0", width=360, stretch=True)
        self.tree.column("status", width=150, stretch=False)
        self.tree.column("size", width=90, stretch=False, anchor="e")
        self.tree.column("why", width=260, stretch=True)
        for status, (_, _, colour) in GUI_STATUS.items():
            self.tree.tag_configure(status, foreground=t[colour])
        self.tree.tag_configure("folder_excl", foreground=t["dim"])
        self.tree.tag_configure("folder_warn", foreground=t["amber"])
        ysb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewOpen>>", self._on_open)
        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<space>", lambda e: self.toggle_selected())
        self.tree.bind("<Return>", lambda e: self.toggle_selected())
        self.tree.bind("<Button-3>", self._on_context)
        self.tree.bind("<Button-2>", self._on_context)  # macOS
        ttk.Label(left, style="Dim.TLabel", text=(
            "Double-click / Space: toggle in or out   ·   Right-click: more options   ·   "
            "Ctrl+Z undo   ·   Ctrl+S save"), font=self.font_small).pack(fill="x", pady=(4, 0))

        right = ttk.Frame(paned, style="Panel.TFrame", padding=10)
        paned.add(right, weight=2)
        self._build_rules_panel(right)

        # Output + actions ----------------------------------------------------
        act = ttk.Frame(outer, padding=(0, 8, 0, 0))
        ttk.Label(act, text="Name").pack(side="left")
        ttk.Entry(act, textvariable=self.var_name, width=18).pack(side="left", padx=(6, 12))
        ttk.Label(act, text="Output").pack(side="left")
        out_entry = ttk.Entry(act, textvariable=self.var_output, width=30)
        out_entry.pack(side="left", padx=6)
        ttk.Button(act, text="…", width=2, command=self.choose_output).pack(side="left")
        self.var_name.trace_add("write", lambda *a: self._update_output_hint())
        self.var_output.trace_add("write", lambda *a: self._update_output_hint())
        for text, var in (("Overwrite", self.var_overwrite), ("Clean caches", self.var_clean),
                          ("Checks first", self.var_check), ("Open folder", self.var_open)):
            cb = ttk.Checkbutton(act, text=text, variable=var)
            cb.pack(side="left", padx=(12, 0))
            if text == "Clean caches":
                self.chk_clean = cb
            if text == "Checks first":
                self.chk_check = cb

        btns = ttk.Frame(outer, padding=(0, 8, 0, 0))
        self.btn_package = ttk.Button(btns, text="Package", style="Accent.TButton",
                                      command=lambda: self.run_package(dry=False))
        self.btn_package.pack(side="left")
        self.btn_dry = ttk.Button(btns, text="Dry run",
                                  command=lambda: self.run_package(dry=True))
        self.btn_dry.pack(side="left", padx=6)
        self.btn_check = ttk.Button(btns, text="Run checks", command=self.run_checks)
        self.btn_check.pack(side="left")
        self.btn_verify = ttk.Button(btns, text="Verify…", command=self.run_verify)
        self.btn_verify.pack(side="left", padx=6)
        self.btn_diff = ttk.Button(btns, text="Compare…", command=self.run_diff)
        self.btn_diff.pack(side="left")
        self.btn_init = ttk.Button(btns, text="Init release_check.toml", command=self.run_init)
        self.btn_init.pack(side="left", padx=6)
        self.btn_stop = ttk.Button(btns, text="Stop", style="Danger.TButton",
                                   command=self.stop_process, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.lbl_output = ttk.Label(btns, text="", style="Dim.TLabel")
        self.lbl_output.pack(side="right")

        log_wrap = ttk.Frame(outer, padding=(0, 8, 0, 0))
        self.log = tk.Text(log_wrap, height=7, bg=t["panel"], fg=t["text"],
                           insertbackground=t["teal"], relief="flat", font=self.font_small,
                           wrap="none", highlightthickness=1,
                           highlightbackground=t["border"], highlightcolor=t["border"],
                           padx=8, pady=6, state="disabled")
        lsb = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set)
        self.log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")
        for tag, colour in (("ok", "green"), ("fail", "red"), ("warn", "amber"),
                            ("cmd", "teal"), ("dim", "dim")):
            self.log.tag_configure(tag, foreground=t[colour])

        status = ttk.Frame(outer, padding=(0, 6, 0, 0))
        ttk.Label(status, textvariable=self.var_status).pack(side="left")
        self.lbl_dirty = ttk.Label(status, textvariable=self.var_dirty, style="Warn.TLabel")
        self.lbl_dirty.pack(side="right")

        # Bottom-up, so the tree/rules split takes whatever height is left
        # and the log and status bar can never be pushed off-screen.
        status.pack(side="bottom", fill="x")
        log_wrap.pack(side="bottom", fill="x")
        btns.pack(side="bottom", fill="x")
        act.pack(side="bottom", fill="x")
        paned.pack(fill="both", expand=True)
        self.paned = paned
        self.root.after(30, self._place_sash)

        self.menu = tk.Menu(self.root, tearoff=0, bg=t["panel"], fg=t["text"],
                            activebackground=t["select"], activeforeground=t["teal"],
                            disabledforeground=t["dim"], relief="flat", bd=1,
                            font=self.font)

    def _build_rules_panel(self, parent) -> None:
        tk, ttk, t = self.tk, self.ttk, GUI_THEME

        top = ttk.Frame(parent, style="Panel.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text=".packagerignore", style="Head.TLabel").pack(side="left")
        self.btn_save = ttk.Button(top, text="Save", style="Accent.TButton",
                                   command=self.save_rules)
        self.btn_save.pack(side="right")
        self.btn_revert = ttk.Button(top, text="Revert", command=self.revert_rules)
        self.btn_revert.pack(side="right", padx=6)
        self.btn_undo = ttk.Button(top, text="Undo", command=self.undo)
        self.btn_undo.pack(side="right")
        self.lbl_ignore_err = ttk.Label(parent, text="", style="Panel.TLabel",
                                        foreground=t["red"], justify="left",
                                        wraplength=340)
        self.lbl_ignore_err.pack(fill="x")
        wrap_labels: list = []
        # Packed first, at the bottom, so it is never the thing that gets clipped.
        foot = ttk.Label(parent, text=(
            "Built-in exclusions (caches, VCS, venvs, build output, *.zip, session "
            "debris) can't be removed — force-include to override one."),
            style="PanelDim.TLabel", justify="left", wraplength=340)
        foot.pack(side="bottom", anchor="w", fill="x", pady=(8, 0))
        wrap_labels.append(foot)

        def rule_list(title: str, hint: str, prefix: str):
            ttk.Label(parent, text=title, style="Head.TLabel").pack(anchor="w", pady=(12, 2))
            hint_lbl = ttk.Label(parent, text=hint, style="PanelDim.TLabel", justify="left",
                                 wraplength=340)
            hint_lbl.pack(anchor="w", fill="x")
            wrap_labels.append(hint_lbl)
            wrap = ttk.Frame(parent, style="Panel.TFrame")
            wrap.pack(fill="both", expand=True, pady=(4, 4))
            lb = tk.Listbox(wrap, bg=t["bg"], fg=t["text"], selectbackground=t["select"],
                            selectforeground=t["teal"], relief="flat", font=self.font,
                            highlightthickness=1, highlightbackground=t["border"],
                            highlightcolor=t["teal"], activestyle="none",
                            selectmode="extended", height=5, exportselection=False)
            sb = ttk.Scrollbar(wrap, orient="vertical", command=lb.yview)
            lb.configure(yscrollcommand=sb.set)
            lb.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            row = ttk.Frame(parent, style="Panel.TFrame")
            row.pack(fill="x")
            var = tk.StringVar()
            ent = ttk.Entry(row, textvariable=var)
            ent.pack(side="left", fill="x", expand=True)
            def add(_event=None):
                value = var.get().strip()
                if prefix:
                    value = value.lstrip(prefix)
                self.add_rule(prefix + value if value else "", var)
            ent.bind("<Return>", add)
            ttk.Button(row, text="Add", command=add).pack(side="left", padx=(6, 0))
            ttk.Button(row, text="Remove", command=lambda: self.remove_rules(lb, prefix)
                       ).pack(side="left", padx=(6, 0))
            lb.bind("<Delete>", lambda e: self.remove_rules(lb, prefix))
            lb.bind("<Double-1>", lambda e: self._edit_rule(lb, var, prefix))
            lb.bind("<<ListboxSelect>>", lambda e: self._highlight_rule(lb, prefix))
            return lb, ent

        self.lb_excl, self.ent_excl = rule_list(
            "EXCLUDE",
            "docs/  any folder named docs  ·  /docs/  only the root one  ·  "
            "*.log  by name, anywhere  ·  data/raw/  that path and below",
            "",
        )
        self.lb_incl, self.ent_incl = rule_list(
            "FORCE-INCLUDE  (saved as !pattern)",
            "Overrides every exclusion, built-in or yours, except symlinks "
            "and the archive itself. Secret scanning still applies.",
            "!",
        )
        wrap_labels.append(self.lbl_ignore_err)
        parent.bind("<Configure>", lambda e: [lbl.configure(wraplength=max(200, e.width - 24))
                                              for lbl in wrap_labels])

    def _place_sash(self) -> None:
        width = self.paned.winfo_width()
        if width > 100:
            self.paned.sashpos(0, int(width * 0.64))

    def _bind_keys(self) -> None:
        self.root.bind("<F5>", lambda e: self.refresh_now())
        self.root.bind("<Control-s>", lambda e: self.save_rules())
        self.root.bind("<Control-z>", lambda e: self.undo())

    def run(self) -> None:
        self.root.mainloop()

    # ---- project + rules state --------------------------------------------

    def load_project(self, project_dir: Path) -> None:
        if not self._confirm_discard():
            self.var_project.set(str(self.project_dir))
            return
        project_dir = project_dir.expanduser().resolve()
        if not project_dir.is_dir():
            self._message("error", "Not a folder", f"{project_dir} is not a directory.")
            self.var_project.set(str(self.project_dir))
            return
        if getattr(self, "_loaded_once", False) and project_dir != self.project_dir:
            self._remember()
        self._loaded_once = True
        self.project_dir = project_dir
        self._apply_settings(self.settings.for_project(project_dir))
        self.var_project.set(str(project_dir))
        self.root.title(f"Project Packager — {project_dir.name}")
        self.undo_stack.clear()
        try:
            self.ignore = IgnoreFile.load(project_dir)
            self.ignore_error = None
        except (ConfigError, OSError) as exc:
            self.ignore = None
            self.ignore_error = (
                f"{IGNORE_FILE_NAME} can't be used: {exc}\n"
                "Editing is disabled so it can't be overwritten. Packaging will "
                "refuse (exit 9) until it is repaired or removed."
            )
        self.saved_lines = list(self.ignore.lines) if self.ignore else []
        self._remember()
        self._sync_rule_lists()
        self._on_profile()
        self._update_output_hint()

    def _lines(self) -> list[str]:
        return self.ignore.patterns() if self.ignore else []

    def is_dirty(self) -> bool:
        return bool(self.ignore) and self.ignore.lines != self.saved_lines

    def _change_rules(self, mutate) -> bool:
        """Apply a mutation to the rules with undo support. Returns changed."""
        if not self.ignore:
            self._message("error", "Editing disabled", self.ignore_error or "")
            return False
        before = list(self.ignore.lines)
        changed = mutate(self.ignore)
        if changed and self.ignore.lines != before:
            self.undo_stack.append(before)
            del self.undo_stack[:-100]
            self._sync_rule_lists()
            self.schedule_refresh()
            return True
        return False

    def add_rule(self, line: str, var=None) -> None:
        if not line or line == "!":
            return
        if self._change_rules(lambda ig: ig.add(line)):
            if var is not None:
                var.set("")
            self._set_status(f"Added rule  {line}")
        else:
            self._set_status(f"Rule already present: {line}")

    def remove_rules(self, lb, prefix: str) -> None:
        lines = [prefix + lb.get(i) for i in lb.curselection()]
        if not lines:
            return
        self._change_rules(lambda ig: any([ig.remove(line) for line in lines]))
        self._set_status("Removed " + ", ".join(lines))

    def _edit_rule(self, lb, var, prefix: str) -> None:
        sel = lb.curselection()
        if not sel:
            return
        text = lb.get(sel[0])
        if self._change_rules(lambda ig: ig.remove(prefix + text)):
            var.set(text)
            self._set_status("Editing rule — change it and press Enter to re-add")

    def undo(self) -> None:
        if not self.ignore or not self.undo_stack:
            return
        self.ignore.lines = self.undo_stack.pop()
        self._sync_rule_lists()
        self.schedule_refresh()
        self._set_status("Undone")

    def revert_rules(self) -> None:
        if not self.ignore or not self.is_dirty():
            return
        self.undo_stack.append(list(self.ignore.lines))
        self.ignore.lines = list(self.saved_lines)
        self._sync_rule_lists()
        self.schedule_refresh()

    def save_rules(self) -> bool:
        if not self.ignore:
            self._message("error", "Editing disabled", self.ignore_error or "")
            return False
        try:
            self.ignore.save()
            # Re-read through the strict loader: what is on disk is what counts.
            self.ignore = IgnoreFile.load(self.project_dir)
        except (ConfigError, OSError) as exc:
            self._message("error", "Save failed", str(exc))
            return False
        self.saved_lines = list(self.ignore.lines)
        self._sync_rule_lists()
        self._set_status(f"Saved {self.ignore.path}")
        return True

    def _confirm_discard(self) -> bool:
        if not self.is_dirty():
            return True
        from tkinter import messagebox
        answer = messagebox.askyesnocancel(
            "Unsaved rules", f"Save changes to {IGNORE_FILE_NAME} first?", parent=self.root)
        if answer is None:
            return False
        if answer:
            return self.save_rules()
        return True

    def _sync_rule_lists(self) -> None:
        for lb, values in ((self.lb_excl, self.ignore.excludes() if self.ignore else []),
                           (self.lb_incl, self.ignore.includes() if self.ignore else [])):
            lb.delete(0, "end")
            for value in values:
                lb.insert("end", value)
        state = "normal" if self.ignore else "disabled"
        for widget in (self.lb_excl, self.lb_incl, self.ent_excl, self.ent_incl):
            widget.configure(state=state)
        self.lbl_ignore_err.configure(text=self.ignore_error or "")
        dirty = self.is_dirty()
        self.var_dirty.set(f"● unsaved changes to {IGNORE_FILE_NAME}" if dirty else "")
        self.btn_save.configure(state="normal" if dirty else "disabled")
        self.btn_revert.configure(state="normal" if dirty else "disabled")
        self.btn_undo.configure(state="normal" if self.undo_stack else "disabled")

    def _on_profile(self) -> None:
        profile = self.var_profile.get()
        notes = {
            "share": "standard exclusions · secrets warn",
            "release": "strict + clean + checks · secrets BLOCK",
            "backup": "minimal exclusions · no secret scan",
        }
        self.lbl_profile.configure(text=notes.get(profile, ""))
        release = profile == "release"
        self.chk_strict.configure(state="disabled" if release else "normal")
        self.chk_clean.configure(state="disabled" if release else "normal")
        self.chk_check.configure(state="disabled" if release else "normal")
        self.chk_secrets.configure(state="disabled" if profile == "backup" else "normal")
        self.schedule_refresh()

    # ---- preview -----------------------------------------------------------

    def schedule_refresh(self) -> None:
        if self.refresh_job:
            self.root.after_cancel(self.refresh_job)
        self.refresh_job = self.root.after(self.REFRESH_DELAY_MS, self.refresh_now)

    def refresh_now(self) -> None:
        import threading

        self.refresh_job = None
        self.generation += 1
        gen = self.generation
        if self.ignore_error:
            self.result = None
            self.records = {}
            self.repaint()
            self._set_status("Preview unavailable: " + IGNORE_FILE_NAME + " is unusable")
            return
        params = dict(
            profile=self.var_profile.get(),
            strict=self.var_strict.get(),
            ignore_lines=self._lines(),
            output=self.var_output.get().strip() or None,
            name=self.var_name.get().strip() or None,
            scan_secrets=self.var_secrets.get(),
        )
        project = self.project_dir
        self._set_status("Scanning…")

        def work():
            try:
                res = preview_package(project, **params)
                self.queue.put(("preview", gen, res))
            except Exception as exc:  # reported, never swallowed
                self.queue.put(("preview_error", gen, exc))

        threading.Thread(target=work, daemon=True).start()

    def _poll(self) -> None:
        import queue as _q
        try:
            while True:
                msg = self.queue.get_nowait()
                kind = msg[0]
                if kind == "preview" and msg[1] == self.generation:
                    self.result = msg[2]
                    self._build_records()
                    self.repaint()
                elif kind == "preview_error" and msg[1] == self.generation:
                    self._set_status(f"Preview failed: {msg[2]}")
                elif kind == "log":
                    self._log(msg[1])
                elif kind == "proc_done":
                    self._proc_done(msg[1], msg[2])
        except _q.Empty:
            pass
        self.root.after(self.POLL_MS, self._poll)

    def _build_records(self) -> None:
        res = self.result
        records: dict[str, dict] = {}
        if res is None:
            self.records = records
            return
        base = res.project_dir
        forced = {p for p in res.scan.force_included}
        secrets: dict[str, list[str]] = {}
        for f in res.secrets.findings:
            secrets.setdefault(normalise_rel(f.rel_path), []).append(f"{f.label} (line {f.line})")
        unscanned = {normalise_rel(u.path): u.reason for u in res.secrets.unscanned_text_files()}
        allowed: dict[str, list[str]] = {}
        for f in res.secrets.allowed:
            allowed.setdefault(normalise_rel(f.rel_path), []).append(
                f"{f.label} (line {f.line}, allowed by marker)")
        lines = self._lines()

        for path in res.scan.included_files:
            rel = normalise_rel(path.relative_to(base))
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            status, why = "included", ""
            if path in forced:
                status = "forced"
                why = "force-include: " + ", ".join(user_includes_matching(rel, lines) or ["(rule)"])
            if rel in secrets:
                status, why = "secret", "; ".join(secrets[rel])
            elif rel in unscanned:
                status, why = "unscanned", unscanned[rel]
            elif rel in allowed:
                status, why = "allowed", "; ".join(allowed[rel])
            records[rel] = dict(kind="file", status=status, why=why, size=size)

        for d in res.scan.excluded:
            rel = normalise_rel(d.rel_path)
            if rel in ("", "."):
                continue
            is_dir = d.path.is_dir()
            records[rel] = dict(kind="dir" if is_dir else "file", status="excluded",
                                why=d.reason, size=None, lazy=is_dir)
        for d in res.scan.skipped_symlinks:
            rel = normalise_rel(d.rel_path)
            records[rel] = dict(kind="file", status="symlink", why=d.reason, size=None)
        self.records = records

    def _visible(self, rel: str, rec: dict) -> bool:
        flt = self.var_filter.get()
        needle = self.var_search.get().strip().lower()
        if needle and needle not in rel.lower():
            return False
        status = rec["status"]
        if flt == "Included":
            return status in ("included", "forced", "secret", "unscanned", "allowed")
        if flt == "Excluded":
            return status in ("excluded", "inherited", "symlink")
        if flt == "Attention":
            return status in ("secret", "unscanned", "symlink", "forced", "allowed")
        return True

    def repaint(self) -> None:
        tree = self.tree
        opened = {iid for iid in self._all_items() if tree.item(iid, "open")}
        selected = set(tree.selection())
        first_paint = not getattr(self, "_painted", False)
        tree.delete(*tree.get_children(""))
        filtering = self.var_filter.get() != "All" or bool(self.var_search.get().strip())

        visible = {rel: rec for rel, rec in self.records.items() if self._visible(rel, rec)}
        # Every visible item needs its ancestor folders.
        folders: dict[str, dict] = {}
        for rel, rec in visible.items():
            parts = rel.split("/")
            for depth in range(1, len(parts)):
                folder = "/".join(parts[:depth])
                if folder in visible:
                    continue
                agg = folders.setdefault(folder, dict(inc=0, exc=0, size=0, warn=0))
                if rec["status"] in ("included", "forced", "secret", "unscanned", "allowed"):
                    agg["inc"] += 1
                    agg["size"] += rec.get("size") or 0
                else:
                    agg["exc"] += 1
                if rec["status"] in ("secret", "unscanned", "symlink", "allowed"):
                    agg["warn"] += 1

        children: dict[str, list[tuple[bool, str]]] = {}
        for rel in list(visible) + list(folders):
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            is_dir = rel in folders or visible.get(rel, {}).get("kind") == "dir"
            children.setdefault(parent, []).append((is_dir, rel))

        def insert(parent: str) -> None:
            for is_dir, rel in sorted(children.get(parent, []),
                                      key=lambda x: (not x[0], x[1].lower())):
                name = rel.rsplit("/", 1)[-1] + ("/" if is_dir else "")
                if rel in folders:
                    agg = folders[rel]
                    status_text = f"{agg['inc']} in" + (f" · {agg['exc']} out" if agg["exc"] else "")
                    tag = "folder_warn" if agg["warn"] else ("folder_excl" if not agg["inc"] else "folder")
                    tree.insert(parent, "end", iid=rel, text="  " + name,
                                values=(status_text, format_bytes(agg["size"]) if agg["size"] else "", ""),
                                tags=(tag,),
                                open=filtering or rel in opened or (first_paint and "/" not in rel))
                    insert(rel)
                else:
                    rec = visible[rel]
                    glyph, label, _ = GUI_STATUS[rec["status"]]
                    size = format_bytes(rec["size"]) if rec.get("size") is not None else ""
                    tree.insert(parent, "end", iid=rel, text=f"{glyph} {name}",
                                values=(label, size, rec.get("why", "")),
                                tags=(rec["status"],))
                    if rec.get("lazy"):
                        tree.insert(rel, "end", iid=rel + "/\0lazy", text="…")
                        if rel in opened:
                            tree.item(rel, open=True)
                            self._fill_lazy(rel)

        insert("")
        self._painted = True
        keep = [iid for iid in selected if tree.exists(iid)]
        if keep:
            tree.selection_set(keep)
        self._update_summary()

    def _fill_lazy(self, rel: str) -> None:
        """List the inside of an excluded folder on demand (never followed links)."""
        tree = self.tree
        dummy = rel + "/\0lazy"
        if not tree.exists(dummy):
            return
        tree.delete(dummy)
        folder = self.project_dir / rel
        try:
            entries = sorted(os.scandir(folder), key=lambda e: (not e.is_dir(follow_symlinks=False),
                                                                e.name.lower()))
        except OSError as exc:
            tree.insert(rel, "end", text=f"(cannot list: {exc})", tags=("excluded",))
            return
        for entry in entries[: self.LAZY_LIMIT]:
            child = f"{rel}/{entry.name}"
            if tree.exists(child):
                continue
            is_link = entry.is_symlink()
            is_dir = entry.is_dir(follow_symlinks=False)
            status = "symlink" if is_link else "inherited"
            why = "symlink — never packaged" if is_link else f"inside excluded {rel}/"
            self.records.setdefault(child, dict(kind="dir" if is_dir else "file",
                                                status=status, why=why, size=None,
                                                lazy=is_dir and not is_link, virtual=True))
            glyph, label, _ = GUI_STATUS[status]
            tree.insert(rel, "end", iid=child, text=f"{glyph} {entry.name}{'/' if is_dir else ''}",
                        values=(label, "", why), tags=(status,))
            if is_dir and not is_link:
                tree.insert(child, "end", iid=child + "/\0lazy", text="…")
        if len(entries) > self.LAZY_LIMIT:
            tree.insert(rel, "end", text=f"… {len(entries) - self.LAZY_LIMIT} more not shown",
                        tags=("excluded",))

    def _on_open(self, _event=None) -> None:
        iid = self.tree.focus()
        if iid and self.tree.exists(iid + "/\0lazy"):
            self._fill_lazy(iid)

    def _all_items(self, parent: str = ""):
        for iid in self.tree.get_children(parent):
            yield iid
            yield from self._all_items(iid)

    def _open_all(self, state: bool) -> None:
        for iid in list(self._all_items()):
            if iid in self.records and self.records[iid].get("lazy"):
                continue  # don't expand excluded trees like node_modules
            if self.tree.get_children(iid):
                self.tree.item(iid, open=state)

    def _update_summary(self) -> None:
        res = self.result
        if res is None:
            return
        inc = len(res.scan.included_files)
        size = sum((r.get("size") or 0) for r in self.records.values()
                   if r["status"] in ("included", "forced", "secret", "unscanned", "allowed"))
        bits = [f"{inc} files in  ·  {format_bytes(size)}",
                f"{len(res.scan.excluded)} excluded"]
        if res.scan.force_included:
            bits.append(f"{len(res.scan.force_included)} forced")
        if res.secrets.findings:
            bits.append(f"⚠ {len(res.secrets.findings)} possible secret(s)")
        if res.secrets.allowed:
            bits.append(f"{len(res.secrets.allowed)} allowed by marker")
        if res.secrets.unscanned_text_files():
            bits.append(f"{len(res.secrets.unscanned_text_files())} unscannable")
        if res.scan.skipped_symlinks:
            bits.append(f"{len(res.scan.skipped_symlinks)} symlinks skipped")
        if not res.scanned_secrets:
            bits.append("secret scan off")
        self._set_status("   ·   ".join(bits))

    def _update_output_hint(self) -> None:
        out = self.var_output.get().strip()
        out_dir = Path(out).expanduser() if out else self.project_dir.parent / "packaged"
        name = build_zip_name(self.project_dir, self.var_name.get().strip() or None)
        self.lbl_output.configure(text=f"→ {out_dir / name}")
        self.schedule_refresh()

    def _highlight_rule(self, lb, prefix: str) -> None:
        sel = lb.curselection()
        if not sel or not self.records:
            return
        line = prefix + lb.get(sel[0])
        hits = []
        for rel, rec in self.records.items():
            if prefix == "!":
                if user_includes_matching(rel, [line]):
                    hits.append(rel)
            elif user_rules_excluding(rel, rec["kind"] == "dir", [line]):
                hits.append(rel)
        shown = [h for h in hits if self.tree.exists(h)]
        for rel in shown:
            parent = self.tree.parent(rel)
            while parent:
                self.tree.item(parent, open=True)
                parent = self.tree.parent(parent)
        if shown:
            self.tree.selection_set(shown)
            self.tree.see(shown[0])
        self._set_status(f"{line}  matches {len(hits)} item(s) in this preview")

    # ---- tree actions -----------------------------------------------------

    def _item_info(self, iid: str) -> tuple[str, bool, str] | None:
        """(rel, is_dir, status) for a tree item, or None for placeholders."""
        if not iid or "\0" in iid:
            return None
        rec = self.records.get(iid)
        if rec is not None:
            return iid, rec["kind"] == "dir", rec["status"]
        if self.tree.exists(iid) and self.tree.get_children(iid):
            return iid, True, "folder"
        return None

    def toggle(self, iid: str) -> None:
        info = self._item_info(iid)
        if not info:
            return
        rel, is_dir, status = info
        lines = self._lines()
        sugg = suggest_patterns(rel, is_dir)
        if status == "symlink":
            self._set_status("Symlinks are never packaged — this cannot be overridden.")
            return
        if status in ("included", "secret", "unscanned", "allowed", "folder"):
            self.add_rule(sugg["exclude_this"])
        elif status == "forced":
            own = [inc for inc in user_includes_matching(rel, lines)]
            exact = [i for i in own if "!" + i == sugg["include_this"]]
            if exact:
                self._change_rules(lambda ig: ig.remove(sugg["include_this"]))
                self._set_status(f"Removed {sugg['include_this']}")
            else:
                self.add_rule(sugg["exclude_this"])
                if own:
                    self._set_status(
                        f"Also force-included by {', '.join('!' + o for o in own)} — "
                        "remove that rule to exclude it")
        else:  # excluded / inherited
            if sugg["exclude_this"] in lines:
                self._change_rules(lambda ig: ig.remove(sugg["exclude_this"]))
                self._set_status(f"Removed {sugg['exclude_this']}")
            else:
                self.add_rule(sugg["include_this"])

    def toggle_selected(self) -> None:
        for iid in list(self.tree.selection()):
            self.toggle(iid)

    def _on_double(self, event) -> str | None:
        iid = self.tree.identify_row(event.y)
        info = self._item_info(iid)
        if info and info[1]:
            # Folders only expand/collapse on double-click. Toggling one is a
            # bulk action (double-clicking .git to look inside must not
            # force-include it), so it needs Space or the context menu.
            return None
        if iid:
            self.toggle(iid)
            return "break"
        return None

    def _on_context(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        info = self._item_info(iid)
        if not info:
            return
        rel, is_dir, status = info
        lines = self._lines()
        sugg = suggest_patterns(rel, is_dir)
        menu = self.menu
        menu.delete(0, "end")
        menu.add_command(label=rel + ("/" if is_dir else ""), state="disabled")
        menu.add_separator()
        editable = "normal" if self.ignore else "disabled"
        if status == "symlink":
            menu.add_command(label="Symlinks are never packaged", state="disabled")
        elif status in ("excluded", "inherited"):
            mine = user_rules_excluding(rel, is_dir, lines)
            for line in mine:
                menu.add_command(label=f"Remove rule   {line}", state=editable,
                                 command=lambda l=line: self._remove_line(l))
            if not mine:
                menu.add_command(label="Excluded by a built-in rule", state="disabled")
            menu.add_command(label=f"Force-include   {sugg['include_this']}", state=editable,
                             command=lambda: self.add_rule(sugg["include_this"]))
        else:
            if is_dir:
                # A folder can be excluded yet still shown, when a force-include
                # reaches inside it. Its rule should still be removable here.
                for line in user_rules_excluding(rel, True, lines):
                    menu.add_command(label=f"Remove rule   {line}", state=editable,
                                     command=lambda l=line: self._remove_line(l))
            menu.add_command(label=f"Exclude this   {sugg['exclude_this']}", state=editable,
                             command=lambda: self.add_rule(sugg["exclude_this"]))
            if "exclude_ext" in sugg:
                menu.add_command(label=f"Exclude every   {sugg['exclude_ext']}",
                                 state=editable,
                                 command=lambda: self.add_rule(sugg["exclude_ext"]))
            if "exclude_named" in sugg:
                menu.add_command(label=f"Exclude every folder   {sugg['exclude_named']}",
                                 state=editable,
                                 command=lambda: self.add_rule(sugg["exclude_named"]))
            for inc in user_includes_matching(rel, lines):
                menu.add_command(label=f"Remove force-include   !{inc}", state=editable,
                                 command=lambda l="!" + inc: self._remove_line(l))
        menu.add_separator()
        menu.add_command(label="Why?  (explain in log)", command=lambda: self.run_why(rel))
        menu.add_command(label="Copy relative path", command=lambda: self._copy(rel))
        menu.add_command(label="Show in file manager",
                         command=lambda: open_folder(self.project_dir / (rel if is_dir else
                                                                         str(Path(rel).parent))))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _remove_line(self, line: str) -> None:
        if self._change_rules(lambda ig: ig.remove(line)):
            self._set_status(f"Removed {line}")

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status(f"Copied {text}")

    # ---- running the CLI ---------------------------------------------------

    def _cli(self, *args: str) -> list[str]:
        return [sys.executable, str(Path(__file__).resolve()), *args]

    def run_package(self, *, dry: bool) -> None:
        if self.ignore_error:
            self._message("error", "Cannot package", self.ignore_error)
            return
        if self.is_dirty():
            from tkinter import messagebox
            if not messagebox.askokcancel(
                    "Save rules?",
                    f"Packaging uses {IGNORE_FILE_NAME} on disk.\n\n"
                    "Save your rule changes and continue?", parent=self.root):
                return
            if not self.save_rules():
                return
        profile = self.var_profile.get()
        args = ["package", str(self.project_dir), "--profile", profile]
        if self.var_strict.get() and profile != "release":
            args.append("--strict")
        if self.var_clean.get() and profile != "release":
            args.append("--clean")
        if self.var_check.get() and profile != "release":
            args.append("--check")
        if self.var_overwrite.get():
            args.append("--overwrite")
        if self.var_name.get().strip():
            args += ["--name", self.var_name.get().strip()]
        if self.var_output.get().strip():
            args += ["--output", self.var_output.get().strip()]
        if dry:
            args += ["--dry-run", "--list-included"]
        elif self.var_open.get():
            args.append("--open")
        self._start([(self._cli(*args), "dry" if dry else "package")])

    def run_checks(self) -> None:
        self._start([(self._cli("check", str(self.project_dir)), "check")])

    def _profile_args(self) -> list[str]:
        args = ["--profile", self.var_profile.get()]
        if self.var_strict.get() and self.var_profile.get() != "release":
            args.append("--strict")
        return args

    def _note_unsaved(self) -> None:
        if self.is_dirty():
            self._log(f"(note: uses the saved {IGNORE_FILE_NAME}; you have unsaved edits)\n",
                      "warn")

    def run_why(self, rel: str) -> None:
        self._note_unsaved()
        self._start([(self._cli("why", rel, "--project", str(self.project_dir),
                                *self._profile_args()), "why")])

    def run_diff(self) -> None:
        from tkinter import filedialog
        out = self.var_output.get().strip()
        start = Path(out).expanduser() if out else self.project_dir.parent / "packaged"
        chosen = filedialog.askopenfilename(
            parent=self.root, title="Compare an earlier package with the project as it is now",
            initialdir=str(start if start.is_dir() else self.project_dir),
            filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")])
        if not chosen:
            return
        self._note_unsaved()
        self._start([(self._cli("diff", chosen, str(self.project_dir),
                                *self._profile_args()), "diff")])

    def run_init(self) -> None:
        self._start([(self._cli("init", str(self.project_dir)), "init")])

    def run_verify(self, path: Path | None = None) -> None:
        if path is None:
            from tkinter import filedialog
            out = self.var_output.get().strip()
            start = Path(out).expanduser() if out else self.project_dir.parent / "packaged"
            chosen = filedialog.askopenfilename(
                parent=self.root, title="Verify archive",
                initialdir=str(start if start.is_dir() else self.project_dir),
                filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")])
            if not chosen:
                return
            path = Path(chosen)
        self._start([(self._cli("verify", str(path)), "verify")])

    def _start(self, jobs: list[tuple[list[str], str]]) -> None:
        import threading

        if self.proc is not None:
            self._set_status("Already running — wait or press Stop.")
            return
        cmd, label = jobs[0]
        self.proc_queue = jobs[1:]
        self.current_label = label
        self.last_zip = None
        shown = " ".join(f'"{c}"' if " " in c else c for c in cmd[1:])
        self._log(f"\n$ python {shown}\n", "cmd")
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
                errors="replace", env=env, creationflags=flags, bufsize=1)
        except OSError as exc:
            self._log(f"could not start: {exc}\n", "fail")
            self.proc = None
            return
        self._set_running(True)
        proc = self.proc

        def pump():
            assert proc.stdout is not None
            for line in proc.stdout:
                self.queue.put(("log", line))
            code = proc.wait()
            self.queue.put(("proc_done", code, label))

        threading.Thread(target=pump, daemon=True).start()

    def stop_process(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
            except OSError:
                pass
            self.proc_queue = []

    def _proc_done(self, code: int, label: str) -> None:
        self.proc = None
        self._set_running(False)
        meaning = EXIT_MEANINGS.get(code, "stopped" if code < 0 else "unknown exit code")
        if label == "diff" and code in (0, 1):
            meaning = "identical" if code == 0 else "differences listed above"
            code_tag = "ok"
            self._log(f"── exit {code}: {meaning}\n", code_tag)
            return
        self._log(f"── exit {code}: {meaning}\n", "ok" if code == 0 else "fail")
        if label == "package" and code == 0 and self.last_zip and self.last_zip.is_file():
            self._log("Verifying the new archive…\n", "dim")
            self._start([(self._cli("verify", str(self.last_zip)), "verify")])
            return
        if label == "init":
            self.load_project(self.project_dir)
        elif label == "package":
            self.schedule_refresh()  # --clean may have changed the tree

    def _set_running(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        for btn in (self.btn_package, self.btn_dry, self.btn_check, self.btn_verify,
                    self.btn_init, self.btn_diff):
            btn.configure(state=state)
        self.btn_stop.configure(state="normal" if running else "disabled")

    def _log(self, line: str, tag: str | None = None) -> None:
        if tag is None:
            s = line.lstrip()
            if s.startswith(("OK", "RESULT: OK", "WROTE", "DONE")):
                tag = "ok"
            elif s.startswith(("FAIL", "ERROR", "RESULT: FAIL", "!!", "BLOCKED")):
                tag = "fail"
            elif s.startswith(("WARN", "NOT SCANNED", "RESULT: PARTIAL", "SKIP")):
                tag = "warn"
            elif s.startswith("+ "):
                tag = "dim"
        if line.startswith("Output ZIP:"):
            self.last_zip = Path(line.split(":", 1)[1].strip())
            if self.current_label != "package":
                self.last_zip = None
        self.log.configure(state="normal")
        self.log.insert("end", line, (tag,) if tag else ())
        self.log.see("end")
        self.log.configure(state="disabled")

    # ---- misc ---------------------------------------------------------------

    def choose_project(self) -> None:
        from tkinter import filedialog
        chosen = filedialog.askdirectory(parent=self.root, initialdir=str(self.project_dir),
                                         title="Choose project folder")
        if chosen:
            self.load_project(Path(chosen))

    def choose_output(self) -> None:
        from tkinter import filedialog
        chosen = filedialog.askdirectory(parent=self.root, title="Choose output folder",
                                         initialdir=str(self.project_dir.parent))
        if chosen:
            self.var_output.set(chosen)

    def _set_status(self, text: str) -> None:
        self.var_status.set(text)

    def _message(self, kind: str, title: str, text: str) -> None:
        from tkinter import messagebox
        getattr(messagebox, "showerror" if kind == "error" else "showinfo")(
            title, text, parent=self.root)

    def _setting_vars(self) -> dict:
        return {"profile": self.var_profile, "strict": self.var_strict,
                "secrets": self.var_secrets, "name": self.var_name,
                "output": self.var_output, "overwrite": self.var_overwrite,
                "clean": self.var_clean, "check": self.var_check, "open": self.var_open}

    def _apply_settings(self, stored: dict) -> None:
        defaults = {"profile": "share", "strict": False, "secrets": True, "name": "",
                    "output": "", "overwrite": False, "clean": False, "check": False,
                    "open": False}
        for key, var in self._setting_vars().items():
            value = stored.get(key, defaults[key])
            if key == "profile" and value not in ("share", "release", "backup"):
                value = "share"
            if type(value) is not type(defaults[key]):
                value = defaults[key]
            var.set(value)

    def _remember(self) -> None:
        values = {k: v.get() for k, v in self._setting_vars().items()}
        self.settings.remember(self.project_dir, values)
        self.settings.save()
        self.cmb_project.configure(values=self.settings.recent())

    def on_close(self) -> None:
        if not self._confirm_discard():
            return
        self._remember()
        if self.proc is not None:
            self.stop_process()
        self.root.destroy()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

KNOWN_COMMANDS = {"package", "check", "verify", "init", "gui", "why", "diff"}


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

    # -- why ---------------------------------------------------------------
    w = sub.add_parser(
        "why",
        help="Explain why a path is included or excluded, and by which rule.",
    )
    w.add_argument("paths", nargs="+", metavar="PATH",
                   help="File or folder (relative to the project, or absolute).")
    w.add_argument("--project", "-p", default=".", help="Project directory.")
    w.add_argument("--profile", choices=("share", "release", "backup"), default="share")
    w.add_argument("--strict", action="store_true", help="Apply the strict privacy set.")
    w.set_defaults(func=cmd_why)

    # -- diff ---------------------------------------------------------------
    d = sub.add_parser(
        "diff",
        help="Compare two packages, or a package and a project folder. "
             "Exit 0 identical, 1 different.",
    )
    d.add_argument("old", help="Older ZIP (or project folder).")
    d.add_argument("new", help="Newer ZIP or project folder (e.g. '.').")
    d.add_argument("--profile", choices=("share", "release", "backup"), default="share",
                   help="Profile used when a side is a project folder.")
    d.add_argument("--strict", action="store_true",
                   help="Apply the strict privacy set when a side is a folder.")
    d.add_argument("--json", action="store_true", help="Machine-readable output.")
    d.set_defaults(func=cmd_diff)

    # -- gui --------------------------------------------------------------
    g = sub.add_parser(
        "gui",
        help="Open the visual include/exclude editor (also: --gui).",
    )
    g.add_argument("project", nargs="?", default=".",
                   help="Project directory to open.")
    g.set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Guard against cp1252 console crashes on Windows.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass

    raw = list(argv) if argv is not None else sys.argv[1:]

    # `--gui [project]` (or `-gui`) anywhere opens the GUI. Any other option
    # alongside it is refused rather than silently ignored.
    if "--gui" in raw or "-gui" in raw:
        rest = [a for a in raw if a not in ("--gui", "-gui", "gui", "package")]
        flags = [a for a in rest if a.startswith("-")]
        if flags or len(rest) > 1:
            print("ERROR: --gui takes only an optional project folder "
                  f"(got: {' '.join(rest)})", file=sys.stderr)
            return EXIT_PROBLEMS
        raw = ["gui"] + rest

    # Backward compatibility: `project_packager.py .` still packages.
    if raw and raw[0] not in KNOWN_COMMANDS and not raw[0].startswith("-"):
        raw = ["package"] + raw
    elif not raw:
        raw = ["package"]

    args = build_parser().parse_args(raw)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
