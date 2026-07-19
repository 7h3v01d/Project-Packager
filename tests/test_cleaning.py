"""Cleaning tests.

--clean is the only operation that deletes anything, so its blast radius has
to be provably small: approved cache names only, inside the project only,
never through a symlink.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import pkg, scan, write


def snapshot(project: Path) -> set[str]:
    return {p.relative_to(project).as_posix() for p in project.rglob("*")}


# --------------------------------------------------------------------------
# Dry run
# --------------------------------------------------------------------------


def test_dry_run_changes_nothing(demo_project: Path, out_dir: Path) -> None:
    before = snapshot(demo_project)
    result = scan(demo_project, output_dir=out_dir)
    pkg.remove_clean_targets(result, dry_run=True)
    assert snapshot(demo_project) == before


def test_dry_run_still_reports_counts(demo_project: Path, out_dir: Path) -> None:
    result = scan(demo_project, output_dir=out_dir)
    dirs_removed, files_removed = pkg.remove_clean_targets(result, dry_run=True)
    assert dirs_removed >= 1
    assert (demo_project / "__pycache__").is_dir()


def test_package_dry_run_with_clean_deletes_nothing(demo_project: Path, out_dir: Path) -> None:
    before = snapshot(demo_project)
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--clean", "--dry-run"])
    assert snapshot(demo_project) == before


# --------------------------------------------------------------------------
# What cleaning removes and keeps
# --------------------------------------------------------------------------


def test_approved_caches_are_removed(demo_project: Path, out_dir: Path) -> None:
    write(demo_project / ".pytest_cache" / "CACHEDIR.TAG", "tag\n")
    write(demo_project / "src" / "app" / "__pycache__" / "core.cpython-311.pyc", "cache\n")
    write(demo_project / "src" / "stale.pyc", "cache\n")

    result = scan(demo_project, output_dir=out_dir)
    pkg.remove_clean_targets(result, dry_run=False)

    assert not (demo_project / "__pycache__").exists()
    assert not (demo_project / ".pytest_cache").exists()
    assert not (demo_project / "src" / "app" / "__pycache__").exists()
    assert not (demo_project / "src" / "stale.pyc").exists()


@pytest.mark.parametrize(
    "survivor",
    [
        ".venv/pyvenv.cfg",
        "build/artifact.txt",
        "dist/artifact.txt",
        "run.log",
        "data.db",
        "old.zip",
        ".env",
        "node_modules/package.js",
        "README.md",
        "src/app/core.py",
    ],
)
def test_cleaning_never_touches_these(demo_project: Path, out_dir: Path, survivor: str) -> None:
    result = scan(demo_project, output_dir=out_dir)
    pkg.remove_clean_targets(result, dry_run=False)
    assert (demo_project / survivor).exists(), f"--clean must not delete {survivor}"


def test_cleaning_leaves_the_project_otherwise_intact(demo_project: Path, out_dir: Path) -> None:
    before = snapshot(demo_project)
    result = scan(demo_project, output_dir=out_dir)
    pkg.remove_clean_targets(result, dry_run=False)
    removed = before - snapshot(demo_project)

    for path in removed:
        parts = Path(path).parts
        assert any(part in pkg.CLEAN_DIR_NAMES for part in parts) or path.endswith((".pyc", ".pyo")), (
            f"unexpected deletion: {path}"
        )


# --------------------------------------------------------------------------
# Containment (report P1: revalidate before cleaning)
# --------------------------------------------------------------------------


def test_cleaning_does_not_follow_a_symlinked_cache(
    demo_project: Path, tmp_path: Path, out_dir: Path, needs_symlinks
) -> None:
    """A __pycache__ symlink pointing outside the project must not be followed.

    This already holds, but only because shutil.rmtree refuses to act on a
    symlink and the resulting OSError is caught and warned about. The explicit
    pre-deletion containment check is driven by the two tests below.
    """
    outside_cache = tmp_path / "external_cache"
    outside_cache.mkdir()
    (outside_cache / "important.pyc").write_bytes(b"not ours to delete")

    link = demo_project / "src" / "__pycache__"
    os.symlink(outside_cache, link, target_is_directory=True)

    result = scan(demo_project, output_dir=out_dir)
    pkg.remove_clean_targets(result, dry_run=False)

    assert outside_cache.is_dir()
    assert (outside_cache / "important.pyc").is_file()


@pytest.mark.defect
def test_cleaning_refuses_a_target_that_moved_outside_the_project(
    demo_project: Path, tmp_path: Path, out_dir: Path
) -> None:
    """Report: 'Immediately before every deletion, confirm the path is still
    inside the project.' Paths collected at scan time are not trustworthy."""
    result = scan(demo_project, output_dir=out_dir)

    outsider = tmp_path / "not_in_project" / "__pycache__"
    outsider.mkdir(parents=True)
    (outsider / "keep.pyc").write_bytes(b"outside the project")
    result.clean_dirs.append(outsider)

    pkg.remove_clean_targets(result, dry_run=False)
    assert outsider.is_dir(), "deletion outside the project root must be refused"


@pytest.mark.defect
def test_cleaning_refuses_a_target_with_an_unapproved_name(
    demo_project: Path, out_dir: Path
) -> None:
    """Re-check the name and type at deletion time, not only at scan time."""
    result = scan(demo_project, output_dir=out_dir)

    precious = demo_project / "src" / "app"
    result.clean_dirs.append(precious)

    pkg.remove_clean_targets(result, dry_run=False)
    assert (precious / "core.py").is_file(), "only approved cache names may be deleted"


def test_clean_then_rescan_drops_removed_junk(demo_project: Path, out_dir: Path) -> None:
    code = pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo", "--clean"]
    )
    assert code == 0
    assert not (demo_project / "__pycache__").exists()
