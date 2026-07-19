"""Packaging tests: archive creation, manifests, atomicity, and collisions."""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from conftest import DEFECT_REASON
from conftest import members, pkg, sole_zip, write

# --------------------------------------------------------------------------
# Normal packaging
# --------------------------------------------------------------------------


def test_package_creates_zip_and_sidecar(demo_project: Path, out_dir: Path) -> None:
    code = pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 0

    zip_path = sole_zip(out_dir)
    assert zip_path.name.startswith("demo_")
    sidecar = zip_path.with_name(zip_path.name + ".sha256")
    assert sidecar.is_file()

    digest, name = sidecar.read_text(encoding="utf-8").split()
    assert name == zip_path.name
    assert digest == pkg.sha256_of_file(zip_path)


def test_package_contents_match_the_scan_contract(demo_project: Path, out_dir: Path) -> None:
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    names = members(sole_zip(out_dir))

    assert "README.md" in names
    assert "main.py" in names
    assert "test_main.py" in names
    assert "src/app/core.py" in names
    assert "run.log" in names

    assert "data.db" not in names
    assert "scratch.tmp" not in names
    assert "old.zip" not in names
    assert ".git/config" not in names
    assert ".vscode/settings.json" not in names
    assert "node_modules/package.js" not in names
    assert "__pycache__/main.cpython-311.pyc" not in names
    assert ".venv/pyvenv.cfg" not in names


def test_manifest_describes_exactly_the_archive_members(demo_project: Path, out_dir: Path) -> None:
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    zip_path = sole_zip(out_dir)

    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read(pkg.MANIFEST_ARCNAME))
        names = {n for n in zf.namelist() if n != pkg.MANIFEST_ARCNAME and not n.endswith("/")}

    manifest_paths = {entry["path"] for entry in manifest["files"]}
    assert manifest_paths == names
    assert manifest["file_count"] == len(manifest["files"])
    assert manifest["total_bytes"] == sum(e["size"] for e in manifest["files"])
    assert manifest["tool"] == pkg.TOOL_NAME


def test_fresh_package_verifies_successfully(demo_project: Path, out_dir: Path) -> None:
    """The acceptance gate's most basic requirement."""
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    assert pkg.main(["verify", str(sole_zip(out_dir))]) == 0


def test_dry_run_writes_nothing(demo_project: Path, out_dir: Path) -> None:
    code = pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--dry-run"]
    )
    assert code == 0
    assert list(out_dir.iterdir()) == []


def test_project_is_never_modified_without_clean(demo_project: Path, out_dir: Path) -> None:
    before = {p.relative_to(demo_project).as_posix() for p in demo_project.rglob("*")}
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    after = {p.relative_to(demo_project).as_posix() for p in demo_project.rglob("*")}
    assert before == after


# --------------------------------------------------------------------------
# Overwrite handling
# --------------------------------------------------------------------------


def test_existing_output_without_overwrite_is_refused(demo_project: Path, out_dir: Path) -> None:
    name = pkg.build_zip_name(demo_project, "demo")
    (out_dir / name).write_bytes(b"previous archive")

    code = pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 3
    assert (out_dir / name).read_bytes() == b"previous archive"


def test_overwrite_replaces_the_archive(demo_project: Path, out_dir: Path) -> None:
    name = pkg.build_zip_name(demo_project, "demo")
    (out_dir / name).write_bytes(b"previous archive")

    code = pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo", "--overwrite"]
    )
    assert code == 0
    assert zipfile.is_zipfile(out_dir / name)


# --------------------------------------------------------------------------
# Reserved manifest name (report P0 #5)
# --------------------------------------------------------------------------


def test_project_owned_manifest_name_is_rejected(demo_project: Path, out_dir: Path) -> None:
    """A project shipping its own PACKAGE_MANIFEST.json must abort the run,
    not silently produce a duplicate-named member."""
    write(demo_project / pkg.MANIFEST_ARCNAME, '{"mine": true}\n')

    code = pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    assert code != 0, "collision with the reserved manifest name must fail the run"
    assert list(out_dir.glob("*.zip")) == [], "no archive should be left behind"


def test_manifest_collision_never_produces_duplicate_members(
    demo_project: Path, out_dir: Path
) -> None:
    write(demo_project / pkg.MANIFEST_ARCNAME, '{"mine": true}\n')
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])

    for zip_path in out_dir.glob("*.zip"):
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        assert len(names) == len(set(names)), "duplicate archive member names"


# --------------------------------------------------------------------------
# Symlinks must not be archived (report P0 #1)
# --------------------------------------------------------------------------


def test_external_symlink_contents_never_reach_the_archive(
    demo_project: Path, tmp_path: Path, out_dir: Path, needs_symlinks
) -> None:
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("PRIVATE-CANARY-VALUE\n", encoding="utf-8")
    os.symlink(secret, demo_project / "innocent_notes.txt")

    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])

    zip_path = sole_zip(out_dir)
    assert "innocent_notes.txt" not in members(zip_path)
    assert b"PRIVATE-CANARY-VALUE" not in zip_path.read_bytes()


# --------------------------------------------------------------------------
# Manifest reporting (report P1)
# --------------------------------------------------------------------------


def test_no_manifest_is_reported_accurately(demo_project: Path, out_dir: Path, capsys) -> None:
    """v3.0.0 printed 'Manifest embedded: PACKAGE_MANIFEST.json' regardless."""
    pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo", "--no-manifest"]
    )
    output = capsys.readouterr().out

    assert pkg.MANIFEST_ARCNAME not in members(sole_zip(out_dir))
    assert f"Manifest embedded:       {pkg.MANIFEST_ARCNAME}" not in output
    assert "disabled" in output.lower()


def test_manifest_disabled_archive_verifies_as_partial(demo_project: Path, out_dir: Path) -> None:
    """Report: a valid sidecar with no member manifest needs its own status."""
    pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo", "--no-manifest"]
    )
    code = pkg.main(["verify", str(sole_zip(out_dir))])
    assert code not in (0, 1), "partial verification needs a distinct exit status"


# --------------------------------------------------------------------------
# Snapshot consistency (report P1)
# --------------------------------------------------------------------------


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_missing_file_fails_the_manifest_instead_of_vanishing(
    demo_project: Path, out_dir: Path
) -> None:
    """v3.0.0's build_manifest swallows OSError and drops the entry."""
    included = [demo_project / "README.md", demo_project / "gone.py"]
    with pytest.raises(OSError):
        pkg.build_manifest(demo_project, included)


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_file_changed_during_packaging_fails_the_run(
    demo_project: Path, out_dir: Path, monkeypatch
) -> None:
    """The manifest must describe the exact bytes written to the archive."""
    target = demo_project / "main.py"
    original_write = zipfile.ZipFile.write
    tripped = {"done": False}

    def mutating_write(self, filename, arcname=None, *args, **kwargs):
        if not tripped["done"] and Path(filename) == target:
            tripped["done"] = True
            target.write_text("print('changed mid-flight')\n" * 20, encoding="utf-8")
        return original_write(self, filename, arcname, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "write", mutating_write)

    code = pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    if code == 0:
        assert pkg.main(["verify", str(sole_zip(out_dir))]) == 0, (
            "a package that reports success must verify against its own manifest"
        )


# --------------------------------------------------------------------------
# Atomic archive creation (report P1)
# --------------------------------------------------------------------------


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_failed_write_leaves_no_partial_archive(
    demo_project: Path, out_dir: Path, monkeypatch
) -> None:
    original_write = zipfile.ZipFile.write
    calls = {"n": 0}

    def failing_write(self, filename, arcname=None, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 2:
            raise OSError("simulated disk failure")
        return original_write(self, filename, arcname, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "write", failing_write)

    code = pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 4
    assert list(out_dir.glob("*.zip")) == [], "a failed run must leave no final archive"
    assert list(out_dir.glob("*.sha256")) == []


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_failed_overwrite_preserves_the_existing_archive(
    demo_project: Path, out_dir: Path, monkeypatch
) -> None:
    name = pkg.build_zip_name(demo_project, "demo")
    existing = out_dir / name
    existing.write_bytes(b"a valid previous archive")

    original_write = zipfile.ZipFile.write
    calls = {"n": 0}

    def failing_write(self, filename, arcname=None, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 2:
            raise OSError("simulated disk failure")
        return original_write(self, filename, arcname, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "write", failing_write)

    pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo", "--overwrite"]
    )
    assert existing.read_bytes() == b"a valid previous archive"


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_temporary_files_are_cleaned_up_after_failure(
    demo_project: Path, out_dir: Path, monkeypatch
) -> None:
    original_write = zipfile.ZipFile.write
    calls = {"n": 0}

    def failing_write(self, filename, arcname=None, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 2:
            raise OSError("simulated disk failure")
        return original_write(self, filename, arcname, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "write", failing_write)
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])

    leftovers = [p.name for p in out_dir.iterdir()]
    assert leftovers == [], f"temporary output material left behind: {leftovers}"


# --------------------------------------------------------------------------
# Output in the project root (report P0 #3)
# --------------------------------------------------------------------------


def test_output_in_project_root_produces_a_complete_package(demo_project: Path) -> None:
    code = pkg.main(["package", str(demo_project), "--output", str(demo_project), "--name", "demo"])
    assert code == 0

    # Not sole_zip(): when the output directory is the project root, the
    # project's own old.zip sits alongside the archive being written.
    produced = sorted(demo_project.glob("demo_*.zip"))
    assert len(produced) == 1, f"expected one produced archive, found {produced}"
    zip_path = produced[0]

    names = members(zip_path)
    assert "README.md" in names
    assert "main.py" in names
    assert names != {pkg.MANIFEST_ARCNAME}
    assert zip_path.name not in names, "the archive must not contain itself"
    assert f"{zip_path.name}.sha256" not in names, "nor its own sidecar"


# --------------------------------------------------------------------------
# Reserved name is unconditional (external review, v3.0.1-rc1)
# --------------------------------------------------------------------------


def test_reserved_manifest_name_is_rejected_even_with_no_manifest(
    demo_project: Path, out_dir: Path
) -> None:
    """The name belongs to the verification protocol, not to the writing path.

    v3.0.1-rc1 only checked for a collision when it was about to write its own
    manifest, so --no-manifest let a project's own PACKAGE_MANIFEST.json into
    the archive, where verify then mistook it for the internal one.
    """
    write(demo_project / pkg.MANIFEST_ARCNAME, '{"mine": true}\n')

    code = pkg.main(
        ["package", str(demo_project), "--output", str(out_dir),
         "--name", "demo", "--no-manifest"]
    )
    assert code != 0, "reserved name must be refused regardless of --no-manifest"
    assert list(out_dir.glob("*.zip")) == []


def test_sidecar_failure_is_reported_not_claimed(
    demo_project: Path, out_dir: Path, monkeypatch, capsys
) -> None:
    """The summary must not print a sidecar filename it failed to write."""
    original_write_text = Path.write_text

    def refuse_sidecar(self, *args, **kwargs):
        if self.name.endswith(".sha256"):
            raise OSError("simulated sidecar write failure")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", refuse_sidecar)
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])

    output = capsys.readouterr().out
    assert "Hash sidecar:            demo" not in output, (
        "summary claimed a sidecar that was never written"
    )
    assert "not written" in output.lower()


def test_sidecar_failure_fails_release_mode(
    clean_project: Path, out_dir: Path, monkeypatch
) -> None:
    """A release package without its sidecar has no trusted hash to verify against."""
    original_write_text = Path.write_text

    def refuse_sidecar(self, *args, **kwargs):
        if self.name.endswith(".sha256"):
            raise OSError("simulated sidecar write failure")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", refuse_sidecar)
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code != 0


def test_no_manifest_and_no_sidecar_fails_the_package(
    demo_project: Path, out_dir: Path, monkeypatch
) -> None:
    """An archive with neither carries no verification evidence at all."""
    original_write_text = Path.write_text

    def refuse_sidecar(self, *args, **kwargs):
        if self.name.endswith(".sha256"):
            raise OSError("simulated sidecar write failure")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", refuse_sidecar)
    code = pkg.main(
        ["package", str(demo_project), "--output", str(out_dir),
         "--name", "demo", "--no-manifest"]
    )
    assert code != 0


def test_no_manifest_summary_reflects_sidecar_failure(
    demo_project: Path, out_dir: Path, monkeypatch, capsys
) -> None:
    original_write_text = Path.write_text

    def refuse_sidecar(self, *args, **kwargs):
        if self.name.endswith(".sha256"):
            raise OSError("simulated sidecar write failure")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", refuse_sidecar)
    pkg.main(
        ["package", str(demo_project), "--output", str(out_dir),
         "--name", "demo", "--no-manifest"]
    )
    output = capsys.readouterr().out.lower()
    assert "sidecar hash only" not in output, "claimed partial verification with no sidecar"
    assert "no verification evidence" in output


def test_overwrite_is_refused_in_release_mode_until_atomic(
    clean_project: Path, out_dir: Path
) -> None:
    """Replacement is not atomic yet, so --overwrite can destroy a good archive.

    Refused in strict/release, where that matters most, until v3.1.0 lands
    atomic replacement. Overridable with --force.
    """
    (out_dir / pkg.build_zip_name(clean_project, "rel")).write_bytes(b"previous release")

    code = pkg.main(
        ["package", str(clean_project), "--profile", "release", "--output", str(out_dir),
         "--name", "rel", "--overwrite"]
    )
    assert code != 0
    assert (out_dir / pkg.build_zip_name(clean_project, "rel")).read_bytes() == b"previous release"


def test_overwrite_in_release_is_permitted_with_force(clean_project: Path, out_dir: Path) -> None:
    (out_dir / pkg.build_zip_name(clean_project, "rel")).write_bytes(b"previous release")
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release", "--output", str(out_dir),
         "--name", "rel", "--overwrite", "--force"]
    )
    assert code == 0


def test_overwrite_still_works_in_share_mode(demo_project: Path, out_dir: Path) -> None:
    (out_dir / pkg.build_zip_name(demo_project, "demo")).write_bytes(b"previous")
    code = pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo", "--overwrite"]
    )
    assert code == 0
