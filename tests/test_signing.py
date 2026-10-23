# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest / 7h3v01d
"""Optional minisign signatures: `package --sign`, `verify --pubkey`.

Needs minisign on PATH. Without it these skip — or fail, with
PP_REQUIRE_MINISIGN=1, mirroring PP_REQUIRE_SYMLINKS.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from conftest import pkg, sole_zip, write


@pytest.fixture()
def keys(tmp_path: Path) -> dict[str, Path]:
    exe = shutil.which("minisign")
    if not exe:
        if os.environ.get("PP_REQUIRE_MINISIGN") == "1":
            pytest.fail("minisign not on PATH and PP_REQUIRE_MINISIGN=1 is set")
        pytest.skip("minisign not installed — signing tests did not run")
    out: dict[str, Path] = {}
    for name in ("me", "other"):
        pub, sec = tmp_path / f"{name}.pub", tmp_path / f"{name}.key"
        subprocess.run([exe, "-G", "-W", "-f", "-p", str(pub), "-s", str(sec)],
                       check=True, capture_output=True)
        out[name + "_pub"], out[name + "_key"] = pub, sec
    return out


def signed_package(project: Path, out_dir: Path, key: Path) -> Path:
    code = pkg.main(["package", str(project), "--output", str(out_dir), "--name", "s",
                     "--sign", "--sign-key", str(key)])
    assert code == 0
    return sole_zip(out_dir)


def test_sign_writes_signature_and_verify_accepts_it(clean_project, out_dir, keys, capsys):
    zip_path = signed_package(clean_project, out_dir, keys["me_key"])
    assert zip_path.with_name(zip_path.name + ".minisig").is_file()
    assert sorted(p.name for p in out_dir.iterdir()) == sorted(
        [zip_path.name, zip_path.name + ".sha256", zip_path.name + ".minisig"])
    capsys.readouterr()
    assert pkg.main(["verify", str(zip_path), "--pubkey", str(keys["me_pub"])]) == 0
    out = capsys.readouterr().out
    assert "signature verified" in out
    assert f"sha256:{pkg.sha256_of_file(zip_path)}" in out, "trusted comment carries the hash"


def test_wrong_key_fails(clean_project, out_dir, keys):
    zip_path = signed_package(clean_project, out_dir, keys["me_key"])
    assert pkg.main(["verify", str(zip_path), "--pubkey", str(keys["other_pub"])]) == 1


def test_inline_pubkey_string_works(clean_project, out_dir, keys):
    zip_path = signed_package(clean_project, out_dir, keys["me_key"])
    key_line = keys["me_pub"].read_text(encoding="utf-8").splitlines()[1].strip()
    assert pkg.main(["verify", str(zip_path), "--pubkey-string", key_line]) == 0


def test_attacker_who_rewrites_archive_and_sidecar_is_caught(clean_project, out_dir, keys, capsys):
    """The point of signing: sidecar + manifest can be forged together; the
    signature cannot without the secret key."""
    zip_path = signed_package(clean_project, out_dir, keys["me_key"])
    with zipfile.ZipFile(zip_path, "a") as zf:
        zf.writestr("payload.py", "import os\n")
    zip_path.with_name(zip_path.name + ".sha256").write_text(
        f"{pkg.sha256_of_file(zip_path)}  {zip_path.name}\n", encoding="utf-8")
    capsys.readouterr()
    assert pkg.main(["verify", str(zip_path), "--pubkey", str(keys["me_pub"])]) == 1
    assert "FAIL  signature" in capsys.readouterr().out


def test_unsigned_archive_fails_when_a_key_is_given(clean_project, out_dir, keys, capsys):
    assert pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "u"]) == 0
    capsys.readouterr()
    assert pkg.main(["verify", str(sole_zip(out_dir)), "--pubkey", str(keys["me_pub"])]) == 1
    assert "unsigned" in capsys.readouterr().out


def test_signature_present_but_unchecked_is_warned(clean_project, out_dir, keys, capsys):
    zip_path = signed_package(clean_project, out_dir, keys["me_key"])
    capsys.readouterr()
    assert pkg.main(["verify", str(zip_path)]) == 0
    assert "present but not checked" in capsys.readouterr().out


def test_overwrite_removes_the_stale_signature(clean_project, out_dir, keys):
    zip_path = signed_package(clean_project, out_dir, keys["me_key"])
    write(clean_project / "new.py", "x = 1\n")
    assert pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "s",
                     "--overwrite"]) == 0
    assert not zip_path.with_name(zip_path.name + ".minisig").exists(), (
        "a signature for the replaced archive must not survive the overwrite")


def test_missing_minisign_is_refused_before_anything_is_written(
        clean_project, out_dir, monkeypatch, capsys):
    cache = clean_project / "__pycache__"
    cache.mkdir()
    (cache / "a.pyc").write_bytes(b"c")
    monkeypatch.setattr(pkg, "find_minisign", lambda: None)
    code = pkg.main(["package", str(clean_project), "--profile", "release",
                     "--output", str(out_dir), "--name", "r", "--sign"])
    assert code == pkg.EXIT_OS_ERROR
    assert "needs minisign" in capsys.readouterr().err
    assert list(out_dir.iterdir()) == []
    assert cache.is_dir(), "a refused run must not clean"


def test_missing_key_is_refused_before_anything_is_written(clean_project, out_dir, keys, tmp_path):
    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "r",
                     "--sign", "--sign-key", str(tmp_path / "nope.key")])
    assert code == pkg.EXIT_OS_ERROR
    assert list(out_dir.iterdir()) == []


def test_signing_failure_after_write_keeps_archive_but_exits_4(
        clean_project, out_dir, keys, monkeypatch, capsys):
    def boom(*a, **k):
        raise pkg.SigningError("simulated")
    monkeypatch.setattr(pkg, "sign_archive", boom)
    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "r",
                     "--sign", "--sign-key", str(keys["me_key"])])
    assert code == pkg.EXIT_OS_ERROR
    assert "NOT signed" in capsys.readouterr().err
    assert not list(out_dir.glob("*.minisig*"))
    assert pkg.verify_archive(sole_zip(out_dir)) == 0


def test_signature_is_never_packaged(clean_project, keys):
    """Output in the project root: the archive's own .minisig is reserved."""
    assert pkg.main(["package", str(clean_project), "--output", str(clean_project),
                     "--name", "self", "--sign", "--sign-key", str(keys["me_key"])]) == 0
    first = next(clean_project.glob("self_*.zip"))
    reserved = pkg.reserved_output_paths(first)
    assert first.with_name(first.name + ".minisig").resolve() in reserved
