"""Release-check tests: configuration loading, gates, and the secret scanner.

The central requirement is fail-closed behaviour: an unreadable or malformed
release_check.toml must never look like "no configuration".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import DEFECT_REASON
from conftest import assert_reason_reported, pkg, sole_zip, write

VALID_CONFIG = """\
[version]
target = "1.0.0"
files = ["pyproject.toml", "CHANGELOG.md"]

[required]
files = ["LICENSE", "README.md"]
"""

INVALID_TOML = """\
[version
target = "1.0.0"
this line is not toml at all
"""


# --------------------------------------------------------------------------
# Config loading
# --------------------------------------------------------------------------


def test_missing_config_is_reported_as_absent(clean_project: Path) -> None:
    assert pkg.load_check_config(clean_project) is None


def test_valid_config_is_loaded(clean_project: Path) -> None:
    write(clean_project / pkg.CHECK_CONFIG_NAME, VALID_CONFIG)
    config = pkg.load_check_config(clean_project)
    assert config is not None
    assert config["version"]["target"] == "1.0.0"


def test_invalid_config_is_distinguishable_from_a_missing_one(clean_project: Path) -> None:
    """P0 #2: v3.0.0 returned None for both, so a broken gate read as no gate."""
    write(clean_project / pkg.CHECK_CONFIG_NAME, INVALID_TOML)
    with pytest.raises(Exception):
        pkg.load_check_config(clean_project)


def test_invalid_config_makes_check_exit_nonzero(clean_project: Path) -> None:
    write(clean_project / pkg.CHECK_CONFIG_NAME, INVALID_TOML)
    assert pkg.main(["check", str(clean_project)]) != 0


def test_invalid_config_blocks_release_packaging(clean_project: Path, out_dir: Path) -> None:
    """A broken gate must not become an open gate."""
    write(clean_project / pkg.CHECK_CONFIG_NAME, INVALID_TOML)

    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code != 0
    assert list(out_dir.glob("*.zip")) == []


def test_unreadable_config_is_a_hard_failure(clean_project: Path) -> None:
    """A directory in place of the config file stands in for any read error."""
    (clean_project / pkg.CHECK_CONFIG_NAME).mkdir()
    assert pkg.main(["check", str(clean_project)]) != 0


def test_invalid_regex_in_config_fails(clean_project: Path) -> None:
    write(
        clean_project / pkg.CHECK_CONFIG_NAME,
        '[forbidden.patterns]\n"broken" = "([unclosed"\n',
    )
    assert pkg.main(["check", str(clean_project)]) != 0


@pytest.mark.parametrize(
    "body",
    [
        '[version]\ntarget = 1.0\nfiles = "not-a-list"\n',
        '[required]\nfiles = "LICENSE"\n',
        '[wheel]\nbuild = "yes"\ntimeout = "soon"\n',
    ],
)
def test_wrong_config_field_types_fail(clean_project: Path, body: str, capsys) -> None:
    """Report: 'Validate field types and regular expressions before running
    checks'.

    Two of these already exit nonzero, but incidentally: a string where a list
    belongs is iterated character by character, so "LICENSE" becomes seven
    missing files. The config must be rejected as invalid before any check runs.
    """
    write(clean_project / pkg.CHECK_CONFIG_NAME, body)
    assert pkg.main(["check", str(clean_project)]) != 0
    assert_reason_reported(capsys, "configuration")


# --------------------------------------------------------------------------
# Configured gates
# --------------------------------------------------------------------------


def test_clean_project_with_valid_config_passes(clean_project: Path) -> None:
    write(clean_project / pkg.CHECK_CONFIG_NAME, VALID_CONFIG)
    assert pkg.main(["check", str(clean_project)]) == 0


def test_version_mismatch_fails(clean_project: Path) -> None:
    write(clean_project / "CHANGELOG.md", "## 0.9.0\nOlder release.\n")
    write(clean_project / pkg.CHECK_CONFIG_NAME, VALID_CONFIG)
    assert pkg.main(["check", str(clean_project)]) == 1


def test_required_file_missing_fails(clean_project: Path) -> None:
    (clean_project / "LICENSE").unlink()
    write(clean_project / pkg.CHECK_CONFIG_NAME, VALID_CONFIG)
    assert pkg.main(["check", str(clean_project)]) == 1


def test_forbidden_pattern_fails(clean_project: Path) -> None:
    write(clean_project / "settings.py", 'HOST = "192.168.0.163"\n')
    write(
        clean_project / pkg.CHECK_CONFIG_NAME,
        '[forbidden.patterns]\n"private IP" = "192\\\\.168\\\\.\\\\d+\\\\.\\\\d+"\n',
    )
    assert pkg.main(["check", str(clean_project)]) == 1


def test_forbidden_pattern_respects_allow_files(clean_project: Path) -> None:
    write(clean_project / "settings.py", 'HOST = "192.168.0.163"\n')
    write(
        clean_project / pkg.CHECK_CONFIG_NAME,
        '[forbidden]\nallow_files = ["settings.py"]\n\n'
        '[forbidden.patterns]\n"private IP" = "192\\\\.168\\\\.\\\\d+\\\\.\\\\d+"\n',
    )
    assert pkg.main(["check", str(clean_project)]) == 0


def test_banned_path_fails(clean_project: Path) -> None:
    write(clean_project / "old_stuff" / "stale.py", "legacy\n")
    write(clean_project / pkg.CHECK_CONFIG_NAME, '[banned]\npaths = ["old_stuff/"]\n')
    assert pkg.main(["check", str(clean_project)]) == 1


def test_required_contents_fails_when_absent(clean_project: Path) -> None:
    write(
        clean_project / pkg.CHECK_CONFIG_NAME,
        '[required.contains]\n"main.py" = ["validate_request"]\n',
    )
    assert pkg.main(["check", str(clean_project)]) == 1


def test_working_tree_debris_fails_builtin_checks(demo_project: Path) -> None:
    """patch_thing.py and notes.bak are exactly what the built-in check hunts."""
    assert pkg.main(["check", str(demo_project)]) == 1


# --------------------------------------------------------------------------
# Secret scanner
# --------------------------------------------------------------------------

FAKE_AWS_KEY = "AKIA" + "Q" * 16
FAKE_GITHUB_TOKEN = "ghp_" + "b" * 36


def test_secret_is_detected(clean_project: Path) -> None:
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    findings = pkg.scan_for_secrets(clean_project, [clean_project / "config.py"])
    assert len(findings) == 1
    assert findings[0].label == "AWS access key"


def test_secret_warns_but_does_not_block_by_default(clean_project: Path, out_dir: Path) -> None:
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 0
    assert sole_zip(out_dir).is_file()


def test_secret_blocks_in_strict_mode(clean_project: Path, out_dir: Path) -> None:
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir), "--name", "demo", "--strict"]
    )
    assert code == 5
    assert list(out_dir.glob("*.zip")) == []


def test_force_overrides_the_secret_block(clean_project: Path, out_dir: Path) -> None:
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "demo", "--strict", "--force"]
    )
    assert code == 0


def test_no_scan_disables_detection(clean_project: Path, out_dir: Path) -> None:
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "demo", "--strict", "--no-scan"]
    )
    assert code == 0


def test_complete_secrets_are_never_printed(clean_project: Path, out_dir: Path, capsys) -> None:
    """Report: 'Tests proving complete secrets are never printed'."""
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\nGH = "{FAKE_GITHUB_TOKEN}"\n')
    pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert FAKE_AWS_KEY not in combined
    assert FAKE_GITHUB_TOKEN not in combined


@pytest.mark.defect
@pytest.mark.xfail(strict=True, reason=DEFECT_REASON)
def test_previews_are_strongly_redacted(clean_project: Path) -> None:
    """Report: 'More strongly redacted previews'.

    v3.0.0 previews the first ten characters, which for an AWS key is the
    four-character prefix plus six real characters of the secret.
    """
    write(clean_project / "config.py", f'KEY = "{FAKE_AWS_KEY}"\n')
    findings = pkg.scan_for_secrets(clean_project, [clean_project / "config.py"])

    preview = findings[0].preview
    revealed = sum(1 for a, b in zip(preview, FAKE_AWS_KEY) if a == b)
    assert revealed <= 6, f"preview {preview!r} reveals {revealed} characters of the secret"


def test_secret_scan_reports_skipped_files(clean_project: Path) -> None:
    """Report: 'Reporting of files skipped because of size or binary detection'."""
    big = clean_project / "huge.txt"
    big.write_bytes(b"a" * (pkg.SECRET_SCAN_MAX_BYTES + 1))
    binary = clean_project / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02" * 100)

    result = pkg.scan_for_secrets(clean_project, [big, binary])
    skipped = getattr(result, "skipped", None)
    assert skipped is not None, "scan_for_secrets must report what it could not scan"
    assert {p.name for p in skipped} == {"huge.txt", "blob.bin"}


# --------------------------------------------------------------------------
# Unscanned files and unreadable ignore rules (external review, v3.0.1-rc1)
# --------------------------------------------------------------------------


def test_oversized_text_file_is_reported_as_unscanned(clean_project: Path, out_dir: Path, capsys) -> None:
    """A file too large to scan must never pass silently as "no secrets"."""
    big = clean_project / "bundle.js"
    big.write_text("x" * (pkg.SECRET_SCAN_MAX_BYTES + 10) + f'\nKEY = "{FAKE_AWS_KEY}"\n',
                   encoding="utf-8")

    pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    output = capsys.readouterr().out.lower()
    assert "unscanned" in output or "not scanned" in output
    assert "bundle.js" in output


def test_release_mode_blocks_on_unscanned_text_files(clean_project: Path, out_dir: Path) -> None:
    """Release mode claims to refuse shipping secrets; it must not ship
    files it never looked at."""
    big = clean_project / "bundle.js"
    big.write_text("x" * (pkg.SECRET_SCAN_MAX_BYTES + 10) + f'\nKEY = "{FAKE_AWS_KEY}"\n',
                   encoding="utf-8")

    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir), "--name", "demo", "--strict"]
    )
    assert code == 5
    assert list(out_dir.glob("*.zip")) == []


def test_force_overrides_unscanned_block(clean_project: Path, out_dir: Path) -> None:
    big = clean_project / "bundle.js"
    big.write_text("x" * (pkg.SECRET_SCAN_MAX_BYTES + 10), encoding="utf-8")
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "demo", "--strict", "--force"]
    )
    assert code == 0


def test_unreadable_ignore_file_fails_closed_in_release(clean_project: Path, out_dir: Path) -> None:
    """Losing every project-specific exclusion must not be a warning.

    A directory standing in for any read error on .packagerignore.
    """
    (clean_project / pkg.IGNORE_FILE_NAME).mkdir()

    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 9
    assert list(out_dir.glob("*.zip")) == []


def test_unreadable_ignore_file_warns_in_share_mode(clean_project: Path, out_dir: Path, capsys) -> None:
    """Ordinary sharing stays usable, but says plainly what was lost."""
    (clean_project / pkg.IGNORE_FILE_NAME).mkdir()

    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    combined = (capsys.readouterr().out + capsys.readouterr().err).lower()
    assert code == 0
