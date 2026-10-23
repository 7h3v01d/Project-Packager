# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest / 7h3v01d
"""Tests for the GUI's rule engine: `!` force-include lines, anchored
includes, the editable IgnoreFile model, rule attribution, and a Tk smoke test.

Revert-proven: the tests marked REVERT-PROVEN fail against 3.0.1 as shipped.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pp", ROOT / "project_packager.py")
pp = importlib.util.module_from_spec(spec)
sys.modules["pp"] = pp
spec.loader.exec_module(pp)


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("PROJECT_PACKAGER_CONFIG_DIR", str(tmp_path / "_cfg"))


def make(tmp_path: Path, files: dict[str, str]) -> Path:
    proj = tmp_path / "proj"
    for rel, body in files.items():
        p = proj / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    proj.mkdir(exist_ok=True)
    return proj


def included(proj: Path, **kw) -> set[str]:
    res = pp.preview_package(proj, scan_secrets=False, **kw)
    return {pp.normalise_rel(p.relative_to(proj)) for p in res.scan.included_files}


# -- anchored includes ---------------------------------------------------------

def test_anchored_include_rescues_only_the_root_file(tmp_path):
    """REVERT-PROVEN: "/notes.txt" was matched verbatim and never fired."""
    proj = make(tmp_path, {"notes.txt": "a", "sub/notes.txt": "b"})
    rules = pp.build_rules(profile="share", strict=False, ignore_patterns=[],
                           extra_excludes=["notes.txt"], include_patterns=["/notes.txt"])
    scan = pp.scan_project(proj, rules)
    got = {pp.normalise_rel(p.relative_to(proj)) for p in scan.included_files}
    assert got == {"notes.txt"}


def test_anchored_include_reopens_excluded_directory(tmp_path):
    """REVERT-PROVEN: the reopen check also ignored a leading slash."""
    proj = make(tmp_path, {".vscode/settings.json": "{}", ".vscode/other.json": "{}"})
    rules = pp.build_rules(profile="share", strict=False, ignore_patterns=[],
                           extra_excludes=[], include_patterns=["/.vscode/settings.json"])
    scan = pp.scan_project(proj, rules)
    got = {pp.normalise_rel(p.relative_to(proj)) for p in scan.included_files}
    assert got == {".vscode/settings.json"}


# -- "!" lines in .packagerignore ---------------------------------------------

def test_bang_line_force_includes(tmp_path):
    """REVERT-PROVEN: "!x" was a literal exclusion pattern before."""
    proj = make(tmp_path, {"keep.zip": "z", "drop.zip": "z", "a.py": ""})
    (proj / ".packagerignore").write_text("!keep.zip\n", encoding="utf-8")
    lines, _ = pp.load_ignore_file(proj)
    rules = pp.build_rules(profile="share", strict=False, ignore_patterns=lines,
                           extra_excludes=[], include_patterns=[])
    scan = pp.scan_project(proj, rules)
    got = {pp.normalise_rel(p.relative_to(proj)) for p in scan.included_files}
    assert got == {"keep.zip", "a.py", ".packagerignore"}


def test_bang_line_overrides_user_exclusion_in_subtree(tmp_path):
    proj = make(tmp_path, {"data/raw/big.csv": "", "data/raw/sample.csv": ""})
    lines = ["data/raw/", "!data/raw/sample.csv"]
    assert included(proj, ignore_lines=lines) == {"data/raw/sample.csv"}


def test_escaped_bang_is_a_literal_exclusion(tmp_path):
    proj = make(tmp_path, {"!odd.txt": "", "b.txt": ""})
    assert included(proj, ignore_lines=["\\!odd.txt"]) == {"b.txt"}


def test_cli_exclude_bang_stays_literal(tmp_path):
    """--exclude values are never reinterpreted as includes."""
    proj = make(tmp_path, {"x.zip": ""})
    rules = pp.build_rules(profile="share", strict=False, ignore_patterns=[],
                           extra_excludes=["!x.zip"], include_patterns=[])
    assert rules.include_patterns == set()


def test_bang_cannot_reach_a_symlink(tmp_path):
    proj = make(tmp_path, {"real.txt": "x"})
    outside = tmp_path / "secret.txt"
    outside.write_text("k", encoding="utf-8")
    try:
        os.symlink(outside, proj / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert "link.txt" not in included(proj, ignore_lines=["!/link.txt", "!*"])


def test_bang_cannot_reach_the_output_archive(tmp_path):
    proj = make(tmp_path, {"a.py": ""})
    res = pp.preview_package(proj, ignore_lines=["!*"], output=str(proj), name="out",
                             scan_secrets=False)
    res.output_zip.write_text("old", encoding="utf-8")
    res2 = pp.preview_package(proj, ignore_lines=["!*"], output=str(proj), name="out",
                              scan_secrets=False)
    assert res2.output_zip not in res2.scan.included_files


# -- IgnoreFile model -------------------------------------------------------------

def test_ignorefile_preserves_comments_and_order(tmp_path):
    proj = make(tmp_path, {})
    (proj / ".packagerignore").write_text(
        "# keep me\n*.log\n\n# section\ndocs/\n", encoding="utf-8")
    ig = pp.IgnoreFile.load(proj)
    assert ig.add("!/docs/readme.md")
    assert not ig.add("*.log")            # duplicate
    assert ig.remove("docs/")
    ig.save()
    text = (proj / ".packagerignore").read_text(encoding="utf-8")
    assert text == "# keep me\n*.log\n\n# section\n!/docs/readme.md\n"
    assert pp.load_ignore_file(proj)[0] == ["*.log", "!/docs/readme.md"]


def test_ignorefile_new_file_gets_template_header(tmp_path):
    proj = make(tmp_path, {})
    ig = pp.IgnoreFile.load(proj)
    assert not ig.existed
    ig.add("build-cache/")
    ig.save()
    text = (proj / ".packagerignore").read_text(encoding="utf-8")
    assert text.startswith("# .packagerignore")
    assert pp.load_ignore_file(proj)[0] == ["build-cache/"]


def test_ignorefile_refuses_unreadable_file(tmp_path):
    """Fail closed: the GUI must never load (and then save over) a bad file."""
    proj = make(tmp_path, {})
    (proj / ".packagerignore").write_bytes(b"secrets/\n\xff\xfe bad\n")
    with pytest.raises(pp.ConfigError):
        pp.IgnoreFile.load(proj)


def test_ignorefile_save_leaves_no_temp_files(tmp_path):
    proj = make(tmp_path, {})
    ig = pp.IgnoreFile.load(proj)
    ig.add("*.tmp")
    ig.save()
    assert sorted(p.name for p in proj.iterdir()) == [".packagerignore"]


def test_ignorefile_handles_bom(tmp_path):
    proj = make(tmp_path, {})
    (proj / ".packagerignore").write_bytes(b"\xef\xbb\xbf*.log\n")
    assert pp.IgnoreFile.load(proj).patterns() == ["*.log"]


# -- attribution + suggestions ----------------------------------------------------

def test_user_rules_excluding_reports_direct_and_parent_rules():
    lines = ["docs/", "/data/", "*.log", "!keep.log"]
    assert pp.user_rules_excluding("docs/a/b.md", False, lines) == ["docs/"]
    assert pp.user_rules_excluding("src/docs", True, lines) == ["docs/"]
    assert pp.user_rules_excluding("data/x.csv", False, lines) == ["/data/"]
    assert pp.user_rules_excluding("src/data/x.csv", False, lines) == []
    assert pp.user_rules_excluding("logs/run.log", False, lines) == ["*.log"]
    assert pp.user_rules_excluding("src/main.py", False, lines) == []


def test_user_includes_matching():
    lines = ["!/a/b.txt", "!*.zip", "x/"]
    assert pp.user_includes_matching("a/b.txt", lines) == ["/a/b.txt"]
    assert pp.user_includes_matching("deep/p.zip", lines) == ["*.zip"]
    assert pp.user_includes_matching("c/b.txt", lines) == []


def test_suggested_patterns_are_anchored_and_round_trip(tmp_path):
    proj = make(tmp_path, {"src/config.json": "", "tests/config.json": ""})
    s = pp.suggest_patterns("src/config.json", False)
    assert s == {"exclude_this": "/src/config.json", "exclude_ext": "*.json",
                 "include_this": "!/src/config.json"}
    assert included(proj, ignore_lines=[s["exclude_this"]]) == {"tests/config.json"}
    assert pp.suggest_patterns(".env", False).get("exclude_ext") is None
    assert pp.suggest_patterns("a/b", True)["exclude_named"] == "b/"


# -- preview parity -----------------------------------------------------------------

def test_preview_matches_package_dry_run(tmp_path, capsys):
    proj = make(tmp_path, {"a.py": "", "b.bak": "", "__pycache__/x.pyc": "",
                           "docs/d.md": "", "keep/k.zip": ""})
    (proj / ".packagerignore").write_text("docs/\n!keep/k.zip\n", encoding="utf-8")
    code = pp.main(["package", str(proj), "--dry-run", "--list-included"])
    assert code == 0
    out = capsys.readouterr().out
    cli = {line.strip()[2:] for line in out.splitlines() if line.startswith("  + ")}
    assert cli == included(proj)


def test_preview_with_unsaved_lines_does_not_touch_disk(tmp_path):
    proj = make(tmp_path, {"a.py": "", "b.py": ""})
    included(proj, ignore_lines=["b.py"])
    assert not (proj / ".packagerignore").exists()


# -- CLI routing --------------------------------------------------------------------

def test_gui_flag_routes_to_gui(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(pp, "cmd_gui", lambda args: seen.append(args.project) or 0)
    assert pp.main(["--gui", str(tmp_path)]) == 0
    assert pp.main(["gui"]) == 0
    assert pp.main(["-gui"]) == 0
    assert seen == [str(tmp_path), ".", "."]


def test_gui_flag_refuses_other_options(capsys):
    assert pp.main(["--gui", "--profile", "release"]) == pp.EXIT_PROBLEMS
    assert "--gui takes only" in capsys.readouterr().err


# -- Tk smoke test ------------------------------------------------------------------

def _tk_available() -> bool:
    try:
        import tkinter
        root = tkinter.Tk()
        root.destroy()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _tk_available(), reason="no tkinter or no display")
def test_gui_toggle_save_round_trip(tmp_path):
    proj = make(tmp_path, {"a.py": "", "notes/todo.md": "", "old.zip": ""})
    app = pp.PackagerGUI(proj)
    try:
        def pump(cond, limit=200):
            for _ in range(limit):
                app.root.update()
                if cond():
                    return True
                app.root.after(20)
                import time; time.sleep(0.02)
            return False

        app.refresh_now()
        assert pump(lambda: "a.py" in app.records)
        assert app.records["old.zip"]["status"] == "excluded"

        app.toggle("a.py")                     # exclude an included file
        app.toggle("old.zip")                  # force-include a built-in exclusion
        assert app.ignore.patterns() == ["/a.py", "!/old.zip"]
        assert app.is_dirty()
        app.refresh_now()
        assert pump(lambda: app.records.get("a.py", {}).get("status") == "excluded")
        assert app.records["old.zip"]["status"] == "forced"

        app.toggle("old.zip")                  # toggling back removes the exact rule
        app.undo()                             # ...and undo restores it
        assert app.ignore.patterns() == ["/a.py", "!/old.zip"]

        assert app.save_rules()
        assert pp.load_ignore_file(proj)[0] == ["/a.py", "!/old.zip"]
        assert not app.is_dirty()
    finally:
        app.root.destroy()


@pytest.mark.skipif(not _tk_available(), reason="no tkinter or no display")
def test_gui_disables_editing_for_unreadable_ignore_file(tmp_path):
    proj = make(tmp_path, {"a.py": ""})
    bad = b"secrets/\n\xff\n"
    (proj / ".packagerignore").write_bytes(bad)
    app = pp.PackagerGUI(proj)
    try:
        app.root.update()
        assert app.ignore is None and app.ignore_error
        import tkinter.messagebox as mb
        orig = mb.showerror
        mb.showerror = lambda *a, **k: None
        try:
            assert app.save_rules() is False
        finally:
            mb.showerror = orig
        assert (proj / ".packagerignore").read_bytes() == bad
    finally:
        app.root.destroy()
