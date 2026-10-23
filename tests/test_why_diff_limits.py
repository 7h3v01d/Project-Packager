# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest / 7h3v01d
"""Tests for `why`, `diff`, [limits], the inline allow-secret marker, and the
per-user GUI settings store."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if "pp" in sys.modules:
    pp = sys.modules["pp"]
else:
    spec = importlib.util.spec_from_file_location("pp", ROOT / "project_packager.py")
    pp = importlib.util.module_from_spec(spec)
    sys.modules["pp"] = pp
    spec.loader.exec_module(pp)

FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"   # split so this file never trips a scanner


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("PROJECT_PACKAGER_CONFIG_DIR", str(tmp_path / "_cfg"))


def make(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    proj = tmp_path / name
    proj.mkdir(exist_ok=True)
    for rel, body in files.items():
        p = proj / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return proj


def run(capsys, *argv) -> tuple[int, str, str]:
    code = pp.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


# -- allow-secret marker --------------------------------------------------------

def test_marker_moves_finding_to_allowed(tmp_path):
    proj = make(tmp_path, {
        "fixture.py": f'KEY = "{FAKE_KEY}"  # packager: allow-secret\n',
        "real.py": f'KEY = "{FAKE_KEY}"\n',
    })
    res = pp.scan_for_secrets(proj, [proj / "fixture.py", proj / "real.py"])
    assert [pp.normalise_rel(f.rel_path) for f in res.findings] == ["real.py"]
    assert [pp.normalise_rel(f.rel_path) for f in res.allowed] == ["fixture.py"]


def test_marker_only_covers_its_own_line(tmp_path):
    proj = make(tmp_path, {
        "a.py": f"# packager: allow-secret\nKEY = '{FAKE_KEY}'\n",
    })
    res = pp.scan_for_secrets(proj, [proj / "a.py"])
    assert len(res.findings) == 1 and not res.allowed


def test_release_passes_with_marker_and_lists_it(tmp_path, capsys):
    proj = make(tmp_path, {"t.py": f'K = "{FAKE_KEY}"  # packager: allow-secret\n'})
    code, out, _ = run(capsys, "package", str(proj), "--profile", "release", "--dry-run")
    assert code == pp.EXIT_OK
    assert "ALLOWED by inline" in out and "t.py:1" in out


def test_release_still_blocks_unmarked(tmp_path, capsys):
    proj = make(tmp_path, {"t.py": f'K = "{FAKE_KEY}"\n'})
    code, _, _ = run(capsys, "package", str(proj), "--profile", "release", "--dry-run")
    assert code == pp.EXIT_SECRETS


def test_check_warns_about_allowed(tmp_path, capsys):
    proj = make(tmp_path, {"t.py": f'K = "{FAKE_KEY}"  # packager: allow-secret\n'})
    code, out, _ = run(capsys, "check", str(proj))
    assert "WARN  No secret matches allowed" in out
    assert "OK    No likely secrets" in out


# -- [limits] -----------------------------------------------------------------------

LIMITS = 'schema_version = 1\n[limits]\nmax_file_mb = 0.001\nmax_files = 2\n'


def test_limits_schema_rejects_bad_values(tmp_path):
    proj = make(tmp_path, {"release_check.toml": "[limits]\nmax_file_mb = -1\n"})
    with pytest.raises(pp.ConfigError):
        pp.load_check_config(proj)
    proj2 = make(tmp_path, {"release_check.toml": "[limits]\nmax_files = true\n"}, "p2")
    with pytest.raises(pp.ConfigError):
        pp.load_check_config(proj2)


def test_check_reports_limits(tmp_path, capsys):
    proj = make(tmp_path, {"release_check.toml": LIMITS, "big.txt": "x" * 4000,
                           "a.py": "", "b.py": ""})
    code, out, _ = run(capsys, "check", str(proj))
    assert code == pp.EXIT_PROBLEMS
    assert "FAIL  No single file over 0.001 MB: big.txt" in out
    assert "FAIL  At most 2 files" in out


def test_release_package_blocks_on_limits_without_mutating(tmp_path, capsys):
    proj = make(tmp_path, {"release_check.toml": "schema_version = 1\n[limits]\nmax_file_mb = 0.001\n",
                           "big.txt": "x" * 4000, "__pycache__/c.pyc": ""})
    out_dir = tmp_path / "out"
    code, _, err = run(capsys, "package", str(proj), "--profile", "release",
                       "--output", str(out_dir))
    # Pre-checks skip limits; the package gate catches them on the real file set.
    assert code == pp.EXIT_CHECKS_FAILED
    assert "big.txt" in err and "[limits]" in err
    assert (proj / "__pycache__").exists(), "a refused package must not clean"
    assert not out_dir.exists() or not list(out_dir.iterdir())


def test_share_package_ignores_limits(tmp_path, capsys):
    proj = make(tmp_path, {"release_check.toml": LIMITS, "big.txt": "x" * 4000})
    code, _, _ = run(capsys, "package", str(proj), "--dry-run")
    assert code == pp.EXIT_OK


def test_force_overrides_limits(tmp_path, capsys):
    proj = make(tmp_path, {"release_check.toml": "schema_version = 1\n[limits]\nmax_file_mb = 0.001\n",
                           "big.txt": "x" * 4000})
    code, _, _ = run(capsys, "package", str(proj), "--profile", "release", "--dry-run", "--force")
    assert code == pp.EXIT_OK


# -- why ------------------------------------------------------------------------------

def test_why_cites_user_rule_with_line_number(tmp_path, capsys):
    proj = make(tmp_path, {"data/raw/big.csv": "", "data/raw/keep.csv": "",
                           ".packagerignore": "# c\ndata/raw/\n!data/raw/keep.csv\n"})
    code, out, _ = run(capsys, "why", "data/raw/big.csv", "data/raw/keep.csv", "-p", str(proj))
    assert code == pp.EXIT_OK
    assert "EXCLUDED  data/raw/big.csv" in out
    assert "data/raw/   (.packagerignore line 2)" in out
    assert "INCLUDED  data/raw/keep.csv   (force-included)" in out
    assert "!data/raw/keep.csv   (.packagerignore line 3)" in out


def test_why_names_builtin_and_strict_sources(tmp_path, capsys):
    proj = make(tmp_path, {".venv/x.py": "", "n.bak": "", ".env": ""})
    _, out, _ = run(capsys, "why", ".venv/x.py", "n.bak", "-p", str(proj))
    assert "inside excluded folder .venv/" in out and "built-in default" in out
    assert "session debris" in out
    _, out, _ = run(capsys, "why", ".env", "-p", str(proj), "--profile", "release")
    assert "strict privacy set" in out
    _, out, _ = run(capsys, "why", ".env", "-p", str(proj))
    assert "INCLUDED  .env" in out


def test_why_missing_path_exits_1(tmp_path, capsys):
    proj = make(tmp_path, {"a.py": ""})
    code, out, _ = run(capsys, "why", "nope.py", "-p", str(proj))
    assert code == pp.EXIT_PROBLEMS and "NOT FOUND" in out


def test_why_symlink(tmp_path, capsys, needs_symlinks):
    proj = make(tmp_path, {"a.py": ""})
    target = tmp_path / "outside.txt"
    target.write_text("x", encoding="utf-8")
    os.symlink(target, proj / "link.txt")
    _, out, _ = run(capsys, "why", "link.txt", "-p", str(proj))
    assert "SKIPPED" in out and "cannot be overridden" in out


# -- diff ------------------------------------------------------------------------------

def package(proj: Path, out: Path, name: str, capsys) -> Path:
    code, _, err = run(capsys, "package", str(proj), "--output", str(out), "--name", name)
    assert code == 0, err
    return next(out.glob(f"{name}_*.zip"))


def test_diff_two_packages(tmp_path, capsys):
    proj = make(tmp_path, {"a.py": "1", "b.py": "2", "c.py": "3"})
    out = tmp_path / "out"
    z1 = package(proj, out, "one", capsys)
    (proj / "a.py").write_text("changed", encoding="utf-8")
    (proj / "b.py").unlink()
    (proj / "d.py").write_text("new", encoding="utf-8")
    z2 = package(proj, out, "two", capsys)
    code, text, _ = run(capsys, "diff", str(z1), str(z2), "--json")
    assert code == pp.EXIT_PROBLEMS
    data = json.loads(text)
    assert [x["path"] for x in data["added"]] == ["d.py"]
    assert [x["path"] for x in data["removed"]] == ["b.py"]
    assert [x["path"] for x in data["changed"]] == ["a.py"]
    assert data["unchanged_count"] == 1


def test_diff_identical_exits_0(tmp_path, capsys):
    proj = make(tmp_path, {"a.py": "1"})
    z = package(proj, tmp_path / "out", "x", capsys)
    code, _, _ = run(capsys, "diff", str(z), str(z))
    assert code == pp.EXIT_OK


def test_diff_zip_against_tree_uses_package_rules(tmp_path, capsys):
    proj = make(tmp_path, {"a.py": "1"})
    z = package(proj, tmp_path / "out", "x", capsys)
    (proj / "junk.bak").write_text("j", encoding="utf-8")     # excluded: not a change
    (proj / "new.py").write_text("n", encoding="utf-8")
    code, text, _ = run(capsys, "diff", str(z), str(proj), "--json")
    data = json.loads(text)
    assert [x["path"] for x in data["added"]] == ["new.py"]


def test_diff_zip_without_manifest_hashes_members(tmp_path, capsys):
    proj = make(tmp_path, {"a.py": "1"})
    z = tmp_path / "plain.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.py", "1")
    code, text, _ = run(capsys, "diff", str(z), str(proj), "--json")
    data = json.loads(text)
    assert code == pp.EXIT_OK and data["old"]["source"].startswith("hashed members")


def test_diff_bad_inputs(tmp_path, capsys):
    bad = tmp_path / "bad.zip"
    bad.write_text("not a zip", encoding="utf-8")
    assert run(capsys, "diff", str(bad), str(bad))[0] == pp.EXIT_OS_ERROR
    assert run(capsys, "diff", str(tmp_path / "nope.zip"), str(bad))[0] == pp.EXIT_BAD_PROJECT


# -- GUI settings store ---------------------------------------------------------

def test_settings_round_trip_and_recent_order(tmp_path):
    path = tmp_path / "cfg" / "gui.json"
    st = pp.GuiSettings(path)
    st.remember(Path("/a"), {"profile": "release", "name": "x", "junk": 1})
    st.remember(Path("/b"), {"profile": "share"})
    st.remember(Path("/a"), {"profile": "backup"})
    assert st.save()
    again = pp.GuiSettings(path)
    assert again.recent() == [str(Path("/a")), str(Path("/b"))]
    assert again.for_project(Path("/a")) == {"profile": "backup"}


def test_settings_never_overwrites_unreadable_file(tmp_path):
    path = tmp_path / "gui.json"
    path.write_text("{ not json", encoding="utf-8")
    st = pp.GuiSettings(path)
    st.remember(Path("/a"), {"profile": "share"})
    assert st.save() is False
    assert path.read_text(encoding="utf-8") == "{ not json"


def test_settings_live_outside_the_project(tmp_path, monkeypatch):
    monkeypatch.delenv("PROJECT_PACKAGER_CONFIG_DIR")
    assert ".config" in str(pp.GuiSettings.default_path()) or "APPDATA" in os.environ


def _tk_available() -> bool:
    try:
        import tkinter
        root = tkinter.Tk()
        root.destroy()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _tk_available(), reason="no tkinter or no display")
def test_gui_remembers_per_project_choices(tmp_path):
    proj = make(tmp_path, {"a.py": ""})
    app = pp.PackagerGUI(proj)
    try:
        app.var_profile.set("release")
        app.var_name.set("handoff")
        app.on_close()
    except Exception:
        app.root.destroy()
        raise
    app2 = pp.PackagerGUI(proj)
    try:
        assert app2.var_profile.get() == "release"
        assert app2.var_name.get() == "handoff"
        assert str(proj.resolve()) in app2.settings.recent()
        assert not (proj / "gui.json").exists()
    finally:
        app2.root.destroy()


# -- check is read-only, even when it builds a wheel ------------------------------

def test_wheel_check_never_writes_into_the_project(tmp_path, capsys, monkeypatch):
    """setuptools builds in place (build/, *.egg-info). `check` promises never
    to modify the project, so the wheel must be built from a copy.

    pip is faked so the test needs no network: it behaves like setuptools,
    writing build debris into its working directory and a wheel into -w.
    """
    proj = make(tmp_path, {
        "release_check.toml": '[wheel]\nbuild = true\nmust_contain = ["mod.py"]\n',
        "pyproject.toml": "[project]\nname='m'\n", "mod.py": "",
    })
    before = sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*"))
    seen = {}

    class Done:
        returncode, stdout, stderr = 0, "", ""

    def fake_run(cmd, cwd=None, **kwargs):
        seen["cwd"] = Path(cwd)
        (Path(cwd) / "build").mkdir()
        (Path(cwd) / "m.egg-info").mkdir()
        out = Path(cmd[cmd.index("-w") + 1])
        out.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out / "m-0-py3-none-any.whl", "w") as zf:
            zf.writestr("mod.py", "")
        return Done()

    monkeypatch.setattr(pp.subprocess, "run", fake_run)
    code, out, _ = run(capsys, "check", str(proj))
    assert "OK    Wheel builds successfully" in out
    assert "OK    Wheel contains mod.py" in out
    assert seen["cwd"].resolve() != proj.resolve()
    after = sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*"))
    assert after == before, f"check modified the project: {set(after) ^ set(before)}"
