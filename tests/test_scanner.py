"""Scanner and rule-engine regression tests.

Includes the ten pysharepack v0.2.0 regression tests, adapted to Project
Packager's rule API and default profile, plus the scanner cases required by
the remediation report.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import (
    pkg,
    make_demo_project,
    rel_excluded,
    rel_included,
    rel_skipped_symlinks,
    scan,
    write,
)

# --------------------------------------------------------------------------
# Ported pysharepack regression tests
# --------------------------------------------------------------------------


def test_default_scan_keeps_source_and_excludes_junk(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 1: the core include/exclude contract."""
    result = scan(demo_project, output_dir=out_dir)
    included = rel_included(result, demo_project)
    excluded = rel_excluded(result)

    assert "README.md" in included
    assert "main.py" in included
    assert "test_main.py" in included
    assert "src/app/core.py" in included
    assert "run.log" in included
    assert "large_data/data.csv" in included

    assert "data.db" in excluded
    assert "scratch.tmp" in excluded
    assert "notes.bak" in excluded
    assert "patch_thing.py" in excluded
    assert ".git" in excluded
    assert ".vscode" in excluded
    assert ".idea" in excluded
    assert "node_modules" in excluded
    assert "__pycache__" in excluded
    assert ".venv" in excluded
    assert "build" in excluded
    assert "dist" in excluded
    assert "demo.egg-info" in excluded
    assert "scripts" in excluded


def test_env_file_survives_default_profile(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 1 (cont.): .env is only a strict-mode exclusion."""
    result = scan(demo_project, output_dir=out_dir)
    assert ".env" in rel_included(result, demo_project)


def test_strict_scan_excludes_env_file(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 2."""
    result = scan(demo_project, strict=True, output_dir=out_dir)
    assert ".env" not in rel_included(result, demo_project)
    assert ".env" in rel_excluded(result)


def test_custom_exclude_and_include_override(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 3: CLI excludes apply, CLI includes beat default excludes."""
    result = scan(
        demo_project,
        exclude=["*.log", "large_data/"],
        include=["*.db"],
        output_dir=out_dir,
    )
    included = rel_included(result, demo_project)
    excluded = rel_excluded(result)

    assert "data.db" in included, "--include must override a default file exclusion"
    assert "run.log" in excluded
    assert "large_data" in excluded


def test_include_can_reopen_excluded_directory(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 4 — report P0 #4.

    --include is documented as overriding all exclusions, but v3.0.0 pruned
    .vscode during the directory pass, so the file was never reached.
    """
    result = scan(demo_project, include=[".vscode/settings.json"], output_dir=out_dir)
    assert ".vscode/settings.json" in rel_included(result, demo_project)


def test_include_reopens_only_the_named_branch(demo_project: Path, out_dir: Path) -> None:
    """Reopening .vscode must not drag in the rest of the excluded tree."""
    result = scan(demo_project, include=[".vscode/settings.json"], output_dir=out_dir)
    included = rel_included(result, demo_project)
    assert ".vscode/settings.json" in included
    assert ".git/config" not in included
    assert "node_modules/package.js" not in included


def test_packagerignore_rules_are_applied(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 5, adapted: config rules come from .packagerignore."""
    write(demo_project / ".packagerignore", "# comment\n\n*.log\nlarge_data/\n")
    patterns, count = pkg.load_ignore_file(demo_project)
    assert count == 2
    assert "*.log" in patterns

    result = scan(demo_project, ignore_patterns=patterns, output_dir=out_dir)
    excluded = rel_excluded(result)
    assert "run.log" in excluded
    assert "large_data" in excluded


@pytest.mark.defect
def test_later_rules_override_earlier_rules(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 6, adapted — report: 'later rules override earlier rules'.

    pysharepack supported gitignore-style negation. The consolidated ordered
    rule engine needs the same, so a re-inclusion later in .packagerignore
    beats an exclusion earlier in the file.
    """
    write(demo_project / ".packagerignore", "*.log\n!run.log\n")
    patterns, _ = pkg.load_ignore_file(demo_project)

    result = scan(demo_project, ignore_patterns=patterns, output_dir=out_dir)
    assert "run.log" in rel_included(result, demo_project)


def test_clean_targets_are_collected_not_deleted(demo_project: Path, out_dir: Path) -> None:
    """Legacy test 7, adapted: scanning identifies clean targets but scanning
    alone must never touch disk."""
    result = scan(demo_project, output_dir=out_dir)

    clean_dir_names = {p.name for p in result.clean_dirs}
    assert "__pycache__" in clean_dir_names
    assert (demo_project / "__pycache__").is_dir(), "scan must not delete anything"
    assert not any(p.name == ".venv" for p in result.clean_dirs)
    assert not any(p.name in {"build", "dist"} for p in result.clean_dirs)


def test_output_folder_inside_project_is_excluded(demo_project: Path) -> None:
    """Legacy test 9: a packaged/ folder inside the project is not archived."""
    packaged = demo_project / "packaged"
    packaged.mkdir()
    (packaged / "previous.zip").write_bytes(b"earlier output")

    result = scan(demo_project, output_dir=packaged)
    included = rel_included(result, demo_project)

    assert "packaged/previous.zip" not in included
    assert "packaged" in rel_excluded(result)


def test_symlinked_file_is_skipped(demo_project: Path, out_dir: Path, needs_symlinks) -> None:
    """Legacy test 10 — report P0 #1."""
    os.symlink(demo_project / "main.py", demo_project / "linked_main.py")

    result = scan(demo_project, output_dir=out_dir)
    assert "linked_main.py" in rel_skipped_symlinks(result)
    assert "linked_main.py" not in rel_included(result, demo_project)


# --------------------------------------------------------------------------
# Symlink containment (report P0 #1)
# --------------------------------------------------------------------------


def test_symlinked_directory_is_skipped(demo_project: Path, out_dir: Path, needs_symlinks) -> None:
    os.symlink(demo_project / "src", demo_project / "linked_src", target_is_directory=True)

    result = scan(demo_project, output_dir=out_dir)
    included = rel_included(result, demo_project)

    assert "linked_src" in rel_skipped_symlinks(result)
    assert not any(name.startswith("linked_src/") for name in included)


def test_broken_symlink_is_skipped(demo_project: Path, out_dir: Path, needs_symlinks) -> None:
    os.symlink(demo_project / "does_not_exist.py", demo_project / "dangling.py")

    result = scan(demo_project, output_dir=out_dir)
    assert "dangling.py" in rel_skipped_symlinks(result)
    assert "dangling.py" not in rel_included(result, demo_project)


def test_symlink_to_external_target_is_skipped(
    demo_project: Path, tmp_path: Path, out_dir: Path, needs_symlinks
) -> None:
    """The privacy defect: a link whose target lives outside the project."""
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("PRIVATE — must never be packaged\n", encoding="utf-8")
    os.symlink(outside, demo_project / "innocent_notes.txt")

    result = scan(demo_project, output_dir=out_dir)
    assert "innocent_notes.txt" in rel_skipped_symlinks(result)
    assert "innocent_notes.txt" not in rel_included(result, demo_project)


def test_include_cannot_force_an_external_symlink(
    demo_project: Path, tmp_path: Path, out_dir: Path, needs_symlinks
) -> None:
    """Report: internal safety restrictions must always win over --include."""
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("PRIVATE\n", encoding="utf-8")
    os.symlink(outside, demo_project / "innocent_notes.txt")

    result = scan(demo_project, include=["innocent_notes.txt"], output_dir=out_dir)
    assert "innocent_notes.txt" not in rel_included(result, demo_project)


def test_internal_symlink_is_still_skipped(demo_project: Path, out_dir: Path, needs_symlinks) -> None:
    """Even a contained target is skipped by default: no unrestricted following."""
    os.symlink(demo_project / "README.md", demo_project / "README_link.md")

    result = scan(demo_project, output_dir=out_dir)
    assert "README_link.md" in rel_skipped_symlinks(result)


# --------------------------------------------------------------------------
# Output protection (report P0 #3)
# --------------------------------------------------------------------------


def test_output_dir_equal_to_project_root_still_packages_project(demo_project: Path) -> None:
    """`--output .` must not prune the entire project."""
    result = scan(demo_project, output_dir=demo_project)
    included = rel_included(result, demo_project)

    assert "README.md" in included
    assert "main.py" in included
    assert "src/app/core.py" in included


def test_exact_output_zip_is_excluded_but_siblings_survive(demo_project: Path) -> None:
    """The archive being written must be excluded by exact path.

    Requires scan_project to accept the calculated output ZIP path.
    """
    output_zip = demo_project / "demo_2026-01-01_0000.zip"
    output_zip.write_bytes(b"partially written output")
    (demo_project / "keepsake.zip").write_bytes(b"a user's own archive")

    result = scan(
        demo_project,
        include=["*.zip"],
        output_dir=demo_project,
        output_zip=output_zip,
    )
    included = rel_included(result, demo_project)

    assert "demo_2026-01-01_0000.zip" not in included
    assert "keepsake.zip" in included


def test_include_cannot_force_the_output_zip(demo_project: Path) -> None:
    output_zip = demo_project / "demo_2026-01-01_0000.zip"
    output_zip.write_bytes(b"output")

    result = scan(
        demo_project,
        include=["demo_2026-01-01_0000.zip"],
        output_dir=demo_project,
        output_zip=output_zip,
    )
    assert "demo_2026-01-01_0000.zip" not in rel_included(result, demo_project)


# --------------------------------------------------------------------------
# Path handling and profiles
# --------------------------------------------------------------------------


def test_windows_style_separators_are_normalised(demo_project: Path, out_dir: Path) -> None:
    """Report: 'Normalise Windows and POSIX path separators'."""
    result = scan(demo_project, exclude=[r"large_data\data.csv"], output_dir=out_dir)
    assert "large_data/data.csv" not in rel_included(result, demo_project)


@pytest.mark.defect
def test_path_patterns_are_root_anchored(tmp_path: Path, out_dir: Path) -> None:
    """Report rule-engine requirement: 'Root-anchored patterns'.

    Found during suite construction, beyond the report's P0 list: build_rules
    files a trailing-slash pattern like "docs/" into rules.dir_patterns, which
    should_exclude_dir matches against the bare directory *name*. Any docs/
    directory at any depth is therefore pruned, so an exclusion aimed at the
    project root silently removes unrelated nested trees.
    """
    project = make_demo_project(tmp_path, name="anchored")
    write(project / "docs" / "guide.md", "top level docs\n")
    write(project / "src" / "docs" / "internal.md", "nested docs\n")

    result = scan(project, exclude=["docs/"], output_dir=out_dir)
    included = rel_included(result, project)

    assert "docs/guide.md" not in included
    assert "src/docs/internal.md" in included


def test_backup_profile_keeps_build_venv_and_debris(demo_project: Path, out_dir: Path) -> None:
    result = scan(demo_project, profile="backup", output_dir=out_dir)
    included = rel_included(result, demo_project)

    assert ".venv/pyvenv.cfg" in included
    assert "build/artifact.txt" in included
    assert "dist/artifact.txt" in included
    assert "data.db" in included
    assert "old.zip" in included
    assert ".git/config" not in included, "backup still drops VCS metadata"


def test_share_profile_excludes_nested_archives(demo_project: Path, out_dir: Path) -> None:
    result = scan(demo_project, output_dir=out_dir)
    assert "old.zip" in rel_excluded(result)


def test_archives_can_be_rescued_with_include(demo_project: Path, out_dir: Path) -> None:
    """The docstring promises `--include "*.zip"` as the escape hatch."""
    result = scan(demo_project, include=["*.zip"], output_dir=out_dir)
    assert "old.zip" in rel_included(result, demo_project)


def test_every_decision_carries_a_reason(demo_project: Path, out_dir: Path) -> None:
    """Report: 'Report which rule caused each inclusion or exclusion'."""
    result = scan(demo_project, output_dir=out_dir)
    for decision in result.excluded:
        assert decision.reason, f"no reason recorded for {decision.rel_path}"


def test_scan_is_deterministic(demo_project: Path, out_dir: Path) -> None:
    first = scan(demo_project, output_dir=out_dir)
    second = scan(demo_project, output_dir=out_dir)
    assert sorted(first.included_files) == sorted(second.included_files)
    assert [d.rel_path for d in first.excluded] == [d.rel_path for d in second.excluded]
