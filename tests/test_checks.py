"""Release-check tests: configuration loading, gates, and the secret scanner.

The central requirement is fail-closed behaviour: an unreadable or malformed
release_check.toml must never look like "no configuration".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import DEFECT_REASON
from conftest import assert_reason_reported, members, pkg, sole_zip, write

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
    """--no-scan skips the gate, but strict mode now requires --force with it.

    Contract changed after external review: silently disabling the gate that
    strict mode exists to enforce was judged a trap. Outside strict mode,
    --no-scan alone is still enough.
    """
    write(clean_project / "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    assert pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "share", "--no-scan"]
    ) == 0
    assert pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "demo", "--strict", "--no-scan", "--force"]
    ) == 0


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


def test_absent_ignore_file_is_not_an_error(clean_project: Path, out_dir: Path) -> None:
    """No ignore file means no exclusions were asked for, which is fine.

    Replaces an earlier test asserting that an *unreadable* ignore file merely
    warned in share mode. External review rejected that split, correctly: an
    unusable ignore file is evidence exclusions were intended, and share mode
    is where losing them leaks something.
    """
    assert not (clean_project / pkg.IGNORE_FILE_NAME).exists()
    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 0


# --------------------------------------------------------------------------
# Unscanned classification and gate consolidation (external review, rc2)
# --------------------------------------------------------------------------


def make_large_binary(path: Path) -> Path:
    """A binary asset comfortably over the scan limit."""
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x01\x02\x03" * (pkg.SECRET_SCAN_MAX_BYTES // 2))
    return path


def make_large_text(path: Path, secret: str = "") -> Path:
    path.write_text("x" * (pkg.SECRET_SCAN_MAX_BYTES + 10) + f'\nKEY = "{secret}"\n',
                    encoding="utf-8")
    return path


def test_large_binary_asset_does_not_block_release(clean_project: Path, out_dir: Path) -> None:
    """Size must not be mistaken for textiness.

    Classifying by size before sampling content made every image, PDF, wheel,
    or media file over 1 MiB block strict/release packaging.
    """
    make_large_binary(clean_project / "logo.png")
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir), "--name", "demo", "--strict"]
    )
    assert code == 0, "a large binary asset is not an unscanned text file"


def test_large_binary_is_reported_as_binary_not_text(clean_project: Path) -> None:
    big = make_large_binary(clean_project / "logo.png")
    result = pkg.scan_for_secrets(clean_project, [big])

    assert result.unscanned, "the skip should still be recorded"
    assert result.unscanned_text_files() == [], "but not as a text file"
    kinds = {entry.kind for entry in result.unscanned}
    assert "binary" in kinds


def test_large_text_still_blocks_release(clean_project: Path, out_dir: Path) -> None:
    make_large_text(clean_project / "bundle.js", FAKE_AWS_KEY)
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 5, "unscannable text blocks with the secret code, in every profile"


def test_unknown_suffix_is_treated_conservatively_as_text(clean_project: Path) -> None:
    """Anything not demonstrably binary is assumed to be text-like."""
    odd = clean_project / "data.weirdext"
    odd.write_text("y" * (pkg.SECRET_SCAN_MAX_BYTES + 10), encoding="utf-8")
    result = pkg.scan_for_secrets(clean_project, [odd])
    assert [entry.path.name for entry in result.unscanned_text_files()] == ["data.weirdext"]


def test_secret_in_included_file_exits_5_in_release_mode(clean_project: Path, out_dir: Path) -> None:
    """One gate, one code. Release used to exit 6 via the pre-check scanner."""
    write(clean_project / "config.py", f'KEY = "{FAKE_AWS_KEY}"\n')
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 5
    assert list(out_dir.glob("*.zip")) == []


def test_secret_in_excluded_file_does_not_block_release(clean_project: Path, out_dir: Path) -> None:
    """What blocks the package must match what the package contains.

    Release mode excludes .env from the archive, so a key there is not shipped
    and must not fail the run.
    """
    write(clean_project / ".env", f'AWS_KEY = "{FAKE_AWS_KEY}"\n')
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 0
    assert ".env" not in members(sole_zip(out_dir))


def test_exit_6_still_covers_non_secret_check_failures(clean_project: Path, out_dir: Path) -> None:
    write(clean_project / "patch_thing.py", "# session debris\n")
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 6


def test_no_scan_is_refused_in_strict_mode_without_force(clean_project: Path, out_dir: Path) -> None:
    """Silently disabling the gate in the mode that exists to enforce it is a trap."""
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "demo", "--strict", "--no-scan"]
    )
    assert code != 0


def test_no_scan_with_force_is_permitted_in_strict_mode(clean_project: Path, out_dir: Path) -> None:
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir),
         "--name", "demo", "--strict", "--no-scan", "--force"]
    )
    assert code == 0


def test_unreadable_ignore_file_fails_closed_in_share_mode(clean_project: Path, out_dir: Path) -> None:
    """An unusable ignore file is evidence exclusions were intended.

    Share mode is exactly where people rely on .packagerignore to keep private
    notes and local config out of an archive they are about to send someone.
    """
    (clean_project / pkg.IGNORE_FILE_NAME).mkdir()
    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 9
    assert list(out_dir.glob("*.zip")) == []


def test_force_does_not_bypass_ignore_file_failure(clean_project: Path, out_dir: Path) -> None:
    (clean_project / pkg.IGNORE_FILE_NAME).mkdir()
    code = pkg.main(
        ["package", str(clean_project), "--output", str(out_dir), "--name", "demo", "--force"]
    )
    assert code == 9, "--force is for judgement calls, not for unusable configuration"


# --------------------------------------------------------------------------
# Config schema version (raised in both external reviews)
# --------------------------------------------------------------------------


def test_schema_version_is_accepted(clean_project: Path) -> None:
    write(clean_project / pkg.CHECK_CONFIG_NAME, "schema_version = 1\n\n" + VALID_CONFIG)
    config = pkg.load_check_config(clean_project)
    assert config is not None


def test_config_without_schema_version_still_loads(clean_project: Path) -> None:
    """Existing configurations must keep working; the field is optional."""
    write(clean_project / pkg.CHECK_CONFIG_NAME, VALID_CONFIG)
    assert pkg.load_check_config(clean_project) is not None


def test_future_schema_version_fails_closed(clean_project: Path) -> None:
    """A newer format this build cannot interpret must not be half-applied.

    Without a declared version, a future release that changes field meanings
    would be silently misread by an older build — the gate would run, and run
    wrong.
    """
    write(
        clean_project / pkg.CHECK_CONFIG_NAME,
        f"schema_version = {pkg.CHECK_CONFIG_SCHEMA_VERSION + 1}\n\n" + VALID_CONFIG,
    )
    with pytest.raises(pkg.ConfigError):
        pkg.load_check_config(clean_project)
    assert pkg.main(["check", str(clean_project)]) == 9


def test_non_integer_schema_version_fails(clean_project: Path) -> None:
    write(clean_project / pkg.CHECK_CONFIG_NAME, 'schema_version = "one"\n\n' + VALID_CONFIG)
    assert pkg.main(["check", str(clean_project)]) == 9


def test_init_template_declares_a_schema_version(clean_project: Path) -> None:
    pkg.main(["init", str(clean_project)])
    text = (clean_project / pkg.CHECK_CONFIG_NAME).read_text(encoding="utf-8")
    assert "schema_version" in text
    assert pkg.load_check_config(clean_project) is not None


# --------------------------------------------------------------------------
# Typed unscanned classification
# --------------------------------------------------------------------------


def test_unscanned_kind_is_typed_not_stringly(clean_project: Path) -> None:
    """Policy is driven by an enum, not by the wording of a reason string."""
    make_large_binary(clean_project / "logo.png")
    make_large_text(clean_project / "bundle.js")

    result = pkg.scan_for_secrets(
        clean_project, [clean_project / "logo.png", clean_project / "bundle.js"]
    )
    kinds = {entry.path.name: entry.kind for entry in result.unscanned}

    assert kinds["logo.png"] is pkg.UnscannedKind.BINARY
    assert kinds["bundle.js"] is pkg.UnscannedKind.TEXT_LIKE
    assert all(isinstance(entry.kind, pkg.UnscannedKind) for entry in result.unscanned)


# --------------------------------------------------------------------------
# Classification must follow content, not filename (external review, rc3)
# --------------------------------------------------------------------------

PRINTABLE_FILLER = "Lorem ipsum printable text. "


def make_oversized_printable(path: Path, secret: str = "") -> Path:
    """Entirely printable text, comfortably over the scan limit."""
    body = PRINTABLE_FILLER * ((pkg.SECRET_SCAN_MAX_BYTES // len(PRINTABLE_FILLER)) + 100)
    path.write_text(body + f'\nKEY = "{secret}"\n', encoding="utf-8")
    return path


@pytest.mark.parametrize("filename", ["report.pdf", "data.bin", "archive.zip", "lib.so"])
def test_printable_text_with_a_binary_extension_is_not_trusted(
    clean_project: Path, filename: str
) -> None:
    """A filename does not demonstrate anything about contents.

    Trusting the suffix let an oversized printable file named report.pdf be
    classified as "binary content, not scanned by design", so a key inside it
    shipped in a release with exit 0.
    """
    target = make_oversized_printable(clean_project / filename, FAKE_AWS_KEY)
    result = pkg.scan_for_secrets(clean_project, [target])

    assert result.unscanned[0].kind is pkg.UnscannedKind.TEXT_LIKE
    assert [e.path.name for e in result.unscanned_text_files()] == [filename]


def test_printable_text_with_a_binary_extension_blocks_release(
    clean_project: Path, out_dir: Path
) -> None:
    make_oversized_printable(clean_project / "report.pdf", FAKE_AWS_KEY)
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 5
    assert list(out_dir.glob("*.zip")) == []


@pytest.mark.parametrize(
    ("filename", "magic"),
    [
        ("logo.png", b"\x89PNG\r\n\x1a\n"),
        ("scan.pdf", b"%PDF-1.7\n"),
        ("photo.jpg", b"\xff\xd8\xff\xe0"),
        ("bundle.gz", b"\x1f\x8b\x08"),
        ("mystery.unknownext", b"\x00\x01\x02\x03"),
    ],
)
def test_genuine_binary_content_is_recognised(
    clean_project: Path, filename: str, magic: bytes
) -> None:
    """Real binaries are identified by their contents, extension or not."""
    target = clean_project / filename
    target.write_bytes(magic + bytes(range(256)) * 5000)
    result = pkg.scan_for_secrets(clean_project, [target])

    assert result.unscanned[0].kind is pkg.UnscannedKind.BINARY
    assert result.unscanned_text_files() == []


def test_genuine_binary_does_not_block_release(clean_project: Path, out_dir: Path) -> None:
    (clean_project / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 5000)
    code = pkg.main(
        ["package", str(clean_project), "--profile", "release",
         "--output", str(out_dir), "--name", "rel"]
    )
    assert code == 0


# --------------------------------------------------------------------------
# Ignore-file decoding (external review, rc3)
# --------------------------------------------------------------------------


def test_invalid_utf8_ignore_file_fails_closed(clean_project: Path, out_dir: Path) -> None:
    """errors="replace" silently rewrote patterns, so exclusions stopped matching.

    A safety configuration file is the last place to guess at damaged bytes.
    """
    (clean_project / pkg.IGNORE_FILE_NAME).write_bytes(b"secret\xff.txt\n")
    write(clean_project / "secret.txt", "private\n")

    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 9
    assert list(out_dir.glob("*.zip")) == []


def test_utf8_bom_ignore_file_is_accepted(clean_project: Path, out_dir: Path) -> None:
    """Windows editors write a BOM; that is ordinary, not corruption."""
    (clean_project / pkg.IGNORE_FILE_NAME).write_bytes(b"\xef\xbb\xbfsecret.txt\n")
    write(clean_project / "secret.txt", "private\n")

    code = pkg.main(["package", str(clean_project), "--output", str(out_dir), "--name", "demo"])
    assert code == 0
    assert "secret.txt" not in members(sole_zip(out_dir))


def test_invalid_utf8_release_config_fails_closed(clean_project: Path) -> None:
    """UnicodeDecodeError is a ValueError, not an OSError — it was uncaught."""
    (clean_project / pkg.CHECK_CONFIG_NAME).write_bytes(b'[version]\ntarget = "1.\xff0"\n')
    with pytest.raises(pkg.ConfigError):
        pkg.load_check_config(clean_project)
    assert pkg.main(["check", str(clean_project)]) == 9


def test_utf8_bom_release_config_is_accepted(clean_project: Path) -> None:
    (clean_project / pkg.CHECK_CONFIG_NAME).write_bytes(
        b"\xef\xbb\xbf" + VALID_CONFIG.encode("utf-8")
    )
    assert pkg.load_check_config(clean_project) is not None
