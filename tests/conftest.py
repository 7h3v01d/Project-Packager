"""Shared fixtures for the Project Packager regression suite.

The suite is written against the *target* behaviour described in the
remediation report rather than against whatever the tool currently does. The
v3.0.1 hardening pass is complete; tests carrying the ``defect`` marker encode
work still outstanding for the v3.1.0 consolidation release, so a clean
baseline can still be run:

    pytest -m "not defect"      # must be green at all times
    pytest -m defect            # the v3.0.1 work list; green when done
    pytest                      # everything

Copyright 2026 Leon Priest / 7h3v01d. Apache License 2.0.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module():
    """Import project_packager whether it is a single file or a package.

    Keeps the suite valid across the v3.1.0 restructure into
    ``src/project_packager/``.
    """
    src_dir = REPO_ROOT / "src"
    if src_dir.is_dir():
        sys.path.insert(0, str(src_dir))
        import project_packager  # type: ignore[import-not-found]

        return project_packager

    single_file = REPO_ROOT / "project_packager.py"
    spec = importlib.util.spec_from_file_location("project_packager", single_file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["project_packager"] = module
    spec.loader.exec_module(module)
    return module


pkg = _load_module()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "defect: encodes a known outstanding defect; expected to fail until "
        "the v3.1.0 consolidation pass lands.",
    )


# --------------------------------------------------------------------------
# Module handle
# --------------------------------------------------------------------------


@pytest.fixture()
def pp():
    """The project_packager module under test."""
    return pkg


# --------------------------------------------------------------------------
# Symlink support
# --------------------------------------------------------------------------


def symlinks_available(tmp_path: Path) -> bool:
    """True if this platform/account can actually create symlinks.

    Windows needs Developer Mode or elevation, so this is a runtime probe
    rather than a platform check.
    """
    probe_target = tmp_path / "_symlink_probe_target"
    probe_link = tmp_path / "_symlink_probe_link"
    try:
        probe_target.write_text("probe", encoding="utf-8")
        os.symlink(probe_target, probe_link)
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        for path in (probe_link, probe_target):
            try:
                if path.is_symlink() or path.exists():
                    path.unlink()
            except OSError:
                pass
    return True


@pytest.fixture()
def needs_symlinks(tmp_path: Path) -> None:
    if not symlinks_available(tmp_path):
        pytest.skip("symlink creation is not permitted on this platform/account")


# --------------------------------------------------------------------------
# Project fixtures
# --------------------------------------------------------------------------


def write(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def make_demo_project(root: Path, name: str = "demo_project") -> Path:
    """A project exercising every default exclusion category.

    Deliberately contains working-session debris, so `check` on this tree is
    expected to report failures.
    """
    project = root / name
    project.mkdir(parents=True)

    # Ordinary source that must always survive.
    write(project / "README.md", "# Demo\n")
    write(project / "main.py", "print('hello')\n")
    write(project / "test_main.py", "def test_ok(): assert True\n")
    write(project / "src" / "app" / "core.py", "VALUE = 1\n")
    write(project / "run.log", "logs are kept in the tree\n")

    # Excluded by default file patterns.
    write(project / "data.db", "local database\n")
    write(project / "scratch.tmp", "temp file\n")
    write(project / "notes.bak", "backup file\n")
    write(project / "patch_thing.py", "# session debris\n")
    (project / "old.zip").write_bytes(b"an existing archive")

    # Only excluded under strict/release.
    write(project / ".env", "TOKEN=not-a-real-secret\n")

    # Excluded by default directory names.
    write(project / ".git" / "config", "[core]\n")
    write(project / ".vscode" / "settings.json", "{}\n")
    write(project / ".idea" / "workspace.xml", "<xml />\n")
    write(project / "node_modules" / "package.js", "module.exports = {}\n")
    write(project / "scripts" / "helper.py", "# session helper\n")
    write(project / "__pycache__" / "main.cpython-311.pyc", "cache\n")
    write(project / ".venv" / "pyvenv.cfg", "home = /usr\n")
    write(project / "build" / "artifact.txt", "built\n")
    write(project / "dist" / "artifact.txt", "distributed\n")
    write(project / "demo.egg-info" / "PKG-INFO", "Name: demo\n")

    # Ordinary nested data directory (kept unless excluded explicitly).
    write(project / "large_data" / "data.csv", "a,b\n1,2\n")

    return project


def make_clean_project(root: Path, name: str = "clean_project") -> Path:
    """A minimal, debris-free project so `check` can pass cleanly."""
    project = root / name
    project.mkdir(parents=True)
    write(project / "README.md", "# Clean\n")
    write(project / "LICENSE", "Apache License 2.0\n")
    write(project / "main.py", "VERSION = '1.0.0'\n")
    write(project / "pyproject.toml", '[project]\nname = "clean"\nversion = "1.0.0"\n')
    write(project / "CHANGELOG.md", "## 1.0.0\nFirst release.\n")
    return project


@pytest.fixture()
def demo_project(tmp_path: Path) -> Path:
    return make_demo_project(tmp_path)


@pytest.fixture()
def clean_project(tmp_path: Path) -> Path:
    return make_clean_project(tmp_path)


@pytest.fixture()
def out_dir(tmp_path: Path) -> Path:
    path = tmp_path / "out"
    path.mkdir()
    return path


# --------------------------------------------------------------------------
# Scan helpers
# --------------------------------------------------------------------------


def scan(
    project: Path,
    *,
    profile: str = "share",
    strict: bool = False,
    ignore_patterns: list[str] | None = None,
    exclude: list[str] | None = None,
    include: list[str] | None = None,
    output_dir: Path | None = None,
    **scan_kwargs,
):
    """Build rules and scan in one call, mirroring cmd_package's wiring."""
    rules = pkg.build_rules(
        profile=profile,
        strict=strict,
        ignore_patterns=ignore_patterns or [],
        extra_excludes=exclude or [],
        include_patterns=include or [],
    )
    return pkg.scan_project(project, rules, output_dir=output_dir, **scan_kwargs)


def rel_included(scan_result, project: Path) -> set[str]:
    return {p.relative_to(project).as_posix() for p in scan_result.included_files}


def rel_excluded(scan_result) -> set[str]:
    return {d.rel_path.as_posix() for d in scan_result.excluded}


def rel_skipped_symlinks(scan_result) -> set[str]:
    """Symlinks the scanner refused to follow.

    getattr rather than direct access so the suite still reports a clean
    assertion failure, not an AttributeError, if the field is ever dropped.
    """
    return {d.rel_path.as_posix() for d in getattr(scan_result, "skipped_symlinks", [])}


# --------------------------------------------------------------------------
# Archive helpers
# --------------------------------------------------------------------------


def sole_zip(directory: Path) -> Path:
    zips = sorted(directory.glob("*.zip"))
    assert len(zips) == 1, f"expected exactly one ZIP in {directory}, found {zips}"
    return zips[0]


def members(zip_path: Path) -> set[str]:
    with zipfile.ZipFile(zip_path) as zf:
        return {n for n in zf.namelist() if not n.endswith("/")}


def member_list(zip_path: Path) -> list[str]:
    """Raw namelist, preserving duplicates."""
    with zipfile.ZipFile(zip_path) as zf:
        return list(zf.namelist())


# --------------------------------------------------------------------------
# Output assertions
# --------------------------------------------------------------------------


def assert_reason_reported(capsys, *keywords: str) -> None:
    """Assert the tool explained *why* something failed.

    Several v3.0.0 behaviours fail for incidental reasons — a duplicate member
    trips a hash mismatch, a malformed manifest trips a "not in manifest"
    error. Those accidents are not the same as detection, and they evaporate
    the moment an implementation detail changes. Tests that care about a
    specific guard assert the stated reason, not just the exit code.
    """
    captured = capsys.readouterr()
    combined = (captured.out + captured.err).lower()
    missing = [word for word in keywords if word.lower() not in combined]
    assert not missing, (
        f"failure was not explained; expected mention of {missing}\n--- output ---\n{combined}"
    )


def failure_lines(capsys) -> list[str]:
    """The verifier's own FAIL lines, excluding stdlib warnings.

    zipfile emits its own "Duplicate name:" UserWarning to stderr, which is
    easy to mistake for detection. Only lines the tool itself printed count.
    """
    captured = capsys.readouterr()
    return [
        line.strip()
        for line in captured.out.splitlines()
        if line.strip().startswith("FAIL")
    ]


def assert_failure_line(capsys, *keywords: str) -> None:
    """Assert the tool printed a FAIL line naming the specific guard."""
    lines = failure_lines(capsys)
    for word in keywords:
        assert any(word.lower() in line.lower() for line in lines), (
            f"no FAIL line mentioning {word!r}\n--- FAIL lines ---\n"
            + ("\n".join(lines) or "(none)")
        )


# --------------------------------------------------------------------------
# Outstanding work
# --------------------------------------------------------------------------

DEFECT_REASON = (
    "Scheduled for v3.1.0: see tests/README.md. Marked strict so the test "
    "fails loudly if the behaviour is fixed but the marker is left behind."
)
