"""CLI surface and documented exit codes.

Every code in the README table needs a test, because the exit code is the
only part of this tool a CI pipeline actually reads.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from conftest import pkg, sole_zip, write

FAKE_AWS_KEY = "AKIA" + "R" * 16


# --------------------------------------------------------------------------
# 0 — success
# --------------------------------------------------------------------------


def test_exit_0_on_successful_package(demo_project: Path, out_dir: Path) -> None:
    assert pkg.main(["package", str(demo_project), "--output", str(out_dir)]) == 0


def test_exit_0_on_passing_check(clean_project: Path) -> None:
    assert pkg.main(["check", str(clean_project)]) == 0


def test_exit_0_on_verified_archive(demo_project: Path, out_dir: Path) -> None:
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    assert pkg.main(["verify", str(sole_zip(out_dir))]) == 0


# --------------------------------------------------------------------------
# 1 — check failures / verify problems
# --------------------------------------------------------------------------


def test_exit_1_on_failing_check(demo_project: Path) -> None:
    assert pkg.main(["check", str(demo_project)]) == 1


def test_exit_1_on_failed_verify(demo_project: Path, out_dir: Path) -> None:
    pkg.main(["package", str(demo_project), "--output", str(out_dir), "--name", "demo"])
    zip_path = sole_zip(out_dir)
    zip_path.write_bytes(b"corrupted")
    assert pkg.main(["verify", str(zip_path)]) == 1


# --------------------------------------------------------------------------
# 2 — bad project path
# --------------------------------------------------------------------------


def test_exit_2_when_project_missing(tmp_path: Path, out_dir: Path) -> None:
    assert pkg.main(["package", str(tmp_path / "nope"), "--output", str(out_dir)]) == 2


def test_exit_2_when_project_is_a_file(tmp_path: Path, out_dir: Path) -> None:
    target = tmp_path / "a_file.txt"
    target.write_text("not a directory\n", encoding="utf-8")
    assert pkg.main(["package", str(target), "--output", str(out_dir)]) == 2


def test_exit_2_when_check_target_is_not_a_directory(tmp_path: Path) -> None:
    target = tmp_path / "a_file.txt"
    target.write_text("not a directory\n", encoding="utf-8")
    assert pkg.main(["check", str(target)]) == 2


# --------------------------------------------------------------------------
# 3 — output exists
# --------------------------------------------------------------------------


def test_exit_3_when_output_exists(demo_project: Path, out_dir: Path) -> None:
    (out_dir / pkg.build_zip_name(demo_project, "demo")).write_bytes(b"existing")
    assert pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo"]
    ) == 3


# --------------------------------------------------------------------------
# 4 — OS error while writing
# --------------------------------------------------------------------------


def test_exit_4_on_write_failure(demo_project: Path, out_dir: Path, monkeypatch) -> None:
    def refuse(self, *args, **kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr(zipfile.ZipFile, "write", refuse)
    assert pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--name", "demo"]
    ) == 4


# --------------------------------------------------------------------------
# 5 — secrets in strict/release mode
# --------------------------------------------------------------------------


def test_exit_5_on_secrets_in_strict_mode(clean_project: Path, out_dir: Path) -> None:
    write(clean_project / "config.py", f'KEY = "{FAKE_AWS_KEY}"\n')
    assert pkg.main(
        ["package", str(clean_project), "--output", str(out_dir), "--strict"]
    ) == 5


# --------------------------------------------------------------------------
# 6 — pre-package checks failed
# --------------------------------------------------------------------------


def test_exit_6_when_pre_package_checks_fail(demo_project: Path, out_dir: Path) -> None:
    assert pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--check"]
    ) == 6


def test_force_overrides_failed_pre_package_checks(demo_project: Path, out_dir: Path) -> None:
    assert pkg.main(
        ["package", str(demo_project), "--output", str(out_dir), "--check", "--force"]
    ) == 0


# --------------------------------------------------------------------------
# Argument handling
# --------------------------------------------------------------------------


def test_bare_path_still_packages(demo_project: Path, out_dir: Path) -> None:
    """Backward compatibility promise from the module docstring."""
    assert pkg.main([str(demo_project), "--output", str(out_dir)]) == 0


def test_init_writes_starter_files(clean_project: Path) -> None:
    assert pkg.main(["init", str(clean_project)]) == 0
    assert (clean_project / pkg.CHECK_CONFIG_NAME).is_file()
    assert (clean_project / pkg.IGNORE_FILE_NAME).is_file()


def test_init_output_is_valid_toml(clean_project: Path) -> None:
    import tomllib

    pkg.main(["init", str(clean_project)])
    text = (clean_project / pkg.CHECK_CONFIG_NAME).read_text(encoding="utf-8")
    tomllib.loads(text)


def test_init_output_passes_its_own_checks(clean_project: Path) -> None:
    """A freshly initialised project must not be born failing."""
    pkg.main(["init", str(clean_project)])
    assert pkg.load_check_config(clean_project) is not None


def test_version_flag_reports_the_single_source_of_truth(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        pkg.main(["--version"])
    assert exc.value.code == 0
    assert pkg.TOOL_VERSION in capsys.readouterr().out


def test_mistyped_subcommand_falls_through_to_package() -> None:
    """Documents a consequence of the bare-path compatibility shim.

    main() prepends "package" to any first argument that is not a known
    subcommand and does not start with "-", so a typo like `chekc` is treated
    as a project path and exits 2 rather than producing a usage error. Worth
    revisiting in v3.1.0, but locking in the current behaviour so a rule-engine
    or CLI change does not alter it unnoticed.
    """
    assert pkg.main(["chekc"]) == 2


def test_flag_before_subcommand_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        pkg.main(["--not-a-flag"])
    assert exc.value.code != 0
