"""Archive verification tests.

The verifier must treat an archive as untrusted input: hostile member names,
metadata disagreement, and resource-exhaustion hints all have to fail.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from conftest import DEFECT_REASON
from conftest import assert_failure_line, failure_lines, pkg, sole_zip


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def build_package(project: Path, out_dir: Path) -> Path:
    assert pkg.main(["package", str(project), "--output", str(out_dir), "--name", "demo"]) == 0
    return sole_zip(out_dir)


def resign(zip_path: Path) -> None:
    """Rewrite the sidecar so sidecar failures don't mask manifest failures."""
    sidecar = zip_path.with_name(zip_path.name + ".sha256")
    sidecar.write_text(
        f"{pkg.sha256_of_file(zip_path)}  {zip_path.name}\n", encoding="utf-8"
    )


def rebuild_with(zip_path: Path, mutate) -> None:
    """Rewrite an archive through a mutation callback, then refresh the sidecar."""
    with zipfile.ZipFile(zip_path) as zf:
        payload = [(item, zf.read(item.filename)) for item in zf.infolist()]

    zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        mutate(zf, payload)
    resign(zip_path)


def load_manifest(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read(pkg.MANIFEST_ARCNAME))


def rewrite_manifest(zip_path: Path, manifest: dict) -> None:
    def mutate(zf, payload):
        for item, data in payload:
            if item.filename == pkg.MANIFEST_ARCNAME:
                data = json.dumps(manifest, indent=2).encode("utf-8")
            zf.writestr(item.filename, data)

    rebuild_with(zip_path, mutate)


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------


def test_correct_archive_verifies(demo_project: Path, out_dir: Path) -> None:
    assert pkg.verify_archive(build_package(demo_project, out_dir)) == 0


def test_missing_path_is_reported(tmp_path: Path) -> None:
    assert pkg.verify_archive(tmp_path / "nothing.zip") == 1


# --------------------------------------------------------------------------
# Member tampering
# --------------------------------------------------------------------------


def test_modified_member_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)

    def mutate(zf, payload):
        for item, data in payload:
            if item.filename == "main.py":
                data = b"print('tampered')\n"
            zf.writestr(item.filename, data)

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) == 1


def test_missing_member_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)

    def mutate(zf, payload):
        for item, data in payload:
            if item.filename == "main.py":
                continue
            zf.writestr(item.filename, data)

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) == 1


def test_added_member_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)

    def mutate(zf, payload):
        for item, data in payload:
            zf.writestr(item.filename, data)
        zf.writestr("smuggled.py", b"import os\n")

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) == 1


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_duplicate_member_fails(demo_project: Path, out_dir: Path, capsys) -> None:
    """v3.0.0 happens to fail this via a hash mismatch, because ZipFile.read
    returns the last member of that name. That is an accident of the stdlib,
    not detection: the verifier must name the duplicate."""
    zip_path = build_package(demo_project, out_dir)

    def mutate(zf, payload):
        for item, data in payload:
            zf.writestr(item.filename, data)
            if item.filename == "main.py":
                zf.writestr("main.py", b"print('shadow copy')\n")

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) == 1
    assert_failure_line(capsys, "duplicate")


# --------------------------------------------------------------------------
# Hostile member names
# --------------------------------------------------------------------------


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def write_member_verbatim(zf, name: str, data: bytes) -> None:
    """Write a member under exactly this name, bypassing normalisation.

    ZipInfo.__init__ replaces os.sep with "/", so on Windows a backslash name
    silently becomes a forward-slash one. That normalisation is what made two
    of these cases pass on Windows — the rewritten member no longer matched the
    manifest entry, so verification failed as "missing from archive" rather
    than because any unsafe-path guard existed. Setting filename afterwards
    puts the hostile name in the archive on every platform.
    """
    info = zipfile.ZipInfo("placeholder")
    info.filename = name
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
@pytest.mark.parametrize(
    "hostile_name",
    [
        "/etc/passwd",
        "../../escaped.py",
        "docs/../../escaped.py",
        "C:/Windows/System32/evil.dll",
        "C:\\Windows\\System32\\evil.dll",
        "\\\\server\\share\\evil.dll",
    ],
)
def test_unsafe_member_paths_fail(
    demo_project: Path, out_dir: Path, hostile_name: str, capsys
) -> None:
    """Absolute, drive-qualified, UNC, and traversal names must be rejected
    whether or not they appear in the manifest.

    The manifest lists the hostile name too, so the archive is internally
    consistent: the only thing that can fail it is a guard that objects to the
    name itself. Asserting the stated reason keeps this honest across
    platforms — otherwise Windows path normalisation makes two of these cases
    pass for reasons unrelated to safety.
    """
    zip_path = build_package(demo_project, out_dir)
    manifest = load_manifest(zip_path)
    manifest["files"].append(
        {"path": hostile_name, "size": 3, "sha256": pkg.hashlib.sha256(b"bad").hexdigest()}
    )
    manifest["file_count"] = len(manifest["files"])

    def mutate(zf, payload):
        for item, data in payload:
            if item.filename == pkg.MANIFEST_ARCNAME:
                data = json.dumps(manifest, indent=2).encode("utf-8")
            zf.writestr(item.filename, data)
        write_member_verbatim(zf, hostile_name, b"bad")

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) == 1
    assert_failure_line(capsys, "unsafe")


# --------------------------------------------------------------------------
# Archive-level corruption
# --------------------------------------------------------------------------


def test_corrupt_zip_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)
    zip_path.write_bytes(b"this is not a zip file at all")
    resign(zip_path)
    assert pkg.verify_archive(zip_path) == 1


def test_crc_failure_fails(demo_project: Path, out_dir: Path) -> None:
    """Flip stored bytes in place, leaving the central directory intact."""
    zip_path = build_package(demo_project, out_dir)

    with zipfile.ZipFile(zip_path) as zf:
        info = zf.getinfo("main.py")
        data_start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra or b"")

    raw = bytearray(zip_path.read_bytes())
    target = data_start + max(0, info.compress_size // 2)
    raw[target] ^= 0xFF
    zip_path.write_bytes(bytes(raw))
    resign(zip_path)

    assert pkg.verify_archive(zip_path) == 1


# --------------------------------------------------------------------------
# Sidecar
# --------------------------------------------------------------------------


def test_sidecar_hash_mismatch_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)
    sidecar = zip_path.with_name(zip_path.name + ".sha256")
    sidecar.write_text(f"{'0' * 64}  {zip_path.name}\n", encoding="utf-8")
    assert pkg.verify_archive(zip_path) == 1


def test_missing_sidecar_still_verifies_the_manifest(demo_project: Path, out_dir: Path, capsys) -> None:
    zip_path = build_package(demo_project, out_dir)
    zip_path.with_name(zip_path.name + ".sha256").unlink()

    code = pkg.verify_archive(zip_path)
    assert "sidecar" in capsys.readouterr().out.lower()
    assert code == 0


def test_malformed_sidecar_is_reported(demo_project: Path, out_dir: Path, capsys) -> None:
    zip_path = build_package(demo_project, out_dir)
    zip_path.with_name(zip_path.name + ".sha256").write_text("", encoding="utf-8")

    pkg.verify_archive(zip_path)
    assert "sidecar" in capsys.readouterr().out.lower()


# --------------------------------------------------------------------------
# Manifest structure
# --------------------------------------------------------------------------


def test_malformed_manifest_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)

    def mutate(zf, payload):
        for item, data in payload:
            if item.filename == pkg.MANIFEST_ARCNAME:
                data = b"{ this is not json"
            zf.writestr(item.filename, data)

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) == 1


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
@pytest.mark.parametrize(
    "broken",
    [
        {"files": "not-a-list"},
        {"files": [{"path": 42, "size": 1, "sha256": "x"}]},
        {"files": [{"path": "main.py", "size": "big", "sha256": "x"}]},
        {"files": [{"size": 1, "sha256": "x"}]},
        {},
    ],
)
def test_manifest_with_wrong_types_fails(
    demo_project: Path, out_dir: Path, broken: dict, capsys
) -> None:
    """Most of these already exit 1, but only because every real member then
    looks like it is "not in manifest". The verifier must reject the manifest
    structure itself."""
    zip_path = build_package(demo_project, out_dir)
    rewrite_manifest(zip_path, broken)
    assert pkg.verify_archive(zip_path) == 1

    lines = failure_lines(capsys)
    assert any("manifest" in line.lower() for line in lines), (
        "the manifest itself must be rejected as malformed"
    )
    assert not any("not in manifest" in line.lower() for line in lines), (
        "a structurally invalid manifest must not be reported as hundreds of "
        "individually unlisted members"
    )


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_file_count_disagreement_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)
    manifest = load_manifest(zip_path)
    manifest["file_count"] = len(manifest["files"]) + 7
    rewrite_manifest(zip_path, manifest)
    assert pkg.verify_archive(zip_path) == 1


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_total_bytes_disagreement_fails(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)
    manifest = load_manifest(zip_path)
    manifest["total_bytes"] = manifest["total_bytes"] + 100_000
    rewrite_manifest(zip_path, manifest)
    assert pkg.verify_archive(zip_path) == 1


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_per_file_size_disagreement_fails(demo_project: Path, out_dir: Path) -> None:
    """Content hash can match while the declared size lies."""
    zip_path = build_package(demo_project, out_dir)
    manifest = load_manifest(zip_path)
    for entry in manifest["files"]:
        if entry["path"] == "main.py":
            entry["size"] = entry["size"] + 999
    rewrite_manifest(zip_path, manifest)
    assert pkg.verify_archive(zip_path) == 1


def test_missing_manifest_is_a_distinct_partial_result(demo_project: Path, out_dir: Path) -> None:
    """Report: define a distinct status for valid sidecar, no member manifest."""
    zip_path = build_package(demo_project, out_dir)

    def mutate(zf, payload):
        for item, data in payload:
            if item.filename == pkg.MANIFEST_ARCNAME:
                continue
            zf.writestr(item.filename, data)

    rebuild_with(zip_path, mutate)
    assert pkg.verify_archive(zip_path) not in (0, 1)


# --------------------------------------------------------------------------
# Resource exhaustion
# --------------------------------------------------------------------------


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_absurd_member_count_is_refused(demo_project: Path, out_dir: Path) -> None:
    zip_path = build_package(demo_project, out_dir)
    manifest = load_manifest(zip_path)
    manifest["file_count"] = 50_000_000
    manifest["files"] = manifest["files"] * 1
    rewrite_manifest(zip_path, manifest)
    assert pkg.verify_archive(zip_path) == 1


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_implausible_declared_size_is_refused(demo_project: Path, out_dir: Path) -> None:
    """A declared expansion far beyond the archive size is a zip-bomb hint."""
    zip_path = build_package(demo_project, out_dir)
    manifest = load_manifest(zip_path)
    for entry in manifest["files"]:
        entry["size"] = 10 * 1024 ** 4
    manifest["total_bytes"] = sum(e["size"] for e in manifest["files"])
    rewrite_manifest(zip_path, manifest)
    assert pkg.verify_archive(zip_path) == 1


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_verification_streams_members(demo_project: Path, out_dir: Path, monkeypatch) -> None:
    """Report: hash members as streams, never whole-file reads."""
    zip_path = build_package(demo_project, out_dir)

    def refuse_whole_read(self, name, pwd=None):
        if name != pkg.MANIFEST_ARCNAME:
            raise AssertionError(f"whole-file read of archive member: {name}")
        return original_read(self, name, pwd)

    original_read = zipfile.ZipFile.read
    monkeypatch.setattr(zipfile.ZipFile, "read", refuse_whole_read)
    assert pkg.verify_archive(zip_path) == 0


# --------------------------------------------------------------------------
# Positive evidence (external review, v3.0.1-rc1)
# --------------------------------------------------------------------------


def test_no_sidecar_and_no_manifest_fails(demo_project: Path, out_dir: Path, capsys) -> None:
    """Nothing was verified, so the result cannot be PARTIAL.

    v3.0.1-rc1 counted detected failures rather than tracking positive
    evidence, so an archive with no trusted hash and no manifest — nothing
    checked at all — was reported as "archive intact, contents unverified".
    """
    assert pkg.main(
        ["package", str(demo_project), "--output", str(out_dir),
         "--name", "demo", "--no-manifest"]
    ) == 0
    zip_path = sole_zip(out_dir)
    zip_path.with_name(zip_path.name + ".sha256").unlink()

    code = pkg.verify_archive(zip_path)
    output = capsys.readouterr().out.lower()

    assert code == 1, "no evidence of any kind must fail, not report PARTIAL"
    assert "intact" not in output, "must not claim intactness it cannot support"


def test_sidecar_only_is_partial(demo_project: Path, out_dir: Path) -> None:
    assert pkg.main(
        ["package", str(demo_project), "--output", str(out_dir),
         "--name", "demo", "--no-manifest"]
    ) == 0
    assert pkg.verify_archive(sole_zip(out_dir)) == 7


def test_manifest_without_sidecar_is_described_as_self_consistent(
    demo_project: Path, out_dir: Path, capsys
) -> None:
    """A manifest verifies the archive against itself, nothing more."""
    zip_path = build_package(demo_project, out_dir)
    zip_path.with_name(zip_path.name + ".sha256").unlink()

    code = pkg.verify_archive(zip_path)
    output = capsys.readouterr().out.lower()

    assert code == 0
    assert "self-consistent" in output or "internally consistent" in output
