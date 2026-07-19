# Project Packager regression suite

Written against the **target behaviour** described in the remediation report
rather than against whatever the tool currently does. The v3.0.1 hardening pass
is complete; tests carrying the `defect` marker encode work still outstanding
for the **v3.1.0 consolidation release**.

Outstanding work is marked both `defect` (for filtering) and
`xfail(strict=True)` (for clean pytest semantics), so a normal run is green:

```bash
pytest                    # 191 passed, 27 xfailed — the expected release state
pytest -m "not defect"    # 191 passed — baseline only
pytest -m defect          # the v3.1.0 work list, as XFAIL
pytest -rx                # list the outstanding items with their reasons
```

`strict=True` matters: if an xfailed test starts passing, it is reported as a
**failure**, not a quiet XPASS. That already caught one item during the v3.0.1
review pass — `test_secret_scan_reports_skipped_files` was fixed as a side
effect of other work and would otherwise have sat marked as outstanding.

If your run does not match the line below, you are looking at a different build
than the one documented here — check before reporting the difference as a
regression.

Current state:

| Selection | v3.0.0 | v3.0.1 |
|-----------|--------|--------|
| baseline | 85 passed | **191 passed** |
| outstanding | 55 | 27 |

As each defect is fixed, delete both its `@pytest.mark.defect` and
`@pytest.mark.xfail` decorators. When the
marker is gone from every test and `pytest` is fully green, the hardened-release
acceptance gate in the report is satisfied.

### What v3.0.1 closed

All six P0 items: symlink escape, fail-closed configuration, output-to-project-root,
include reopening (plus Windows separator normalisation), reserved manifest name,
and manifest-disabled reporting.

### What remains for v3.1.0

Atomic archive creation, snapshot-consistent manifests, hardened and streaming
verification, cleaning revalidation, later-rule
precedence in the ordered rule engine, and secret-scanner improvements.

## Layout

| File | Covers |
|------|--------|
| `conftest.py` | Module loading, project fixtures, scan/archive helpers, output assertions |
| `test_scanner.py` | Rule engine, includes, symlinks, output protection, profiles |
| `test_packaging.py` | Archive creation, manifests, atomicity, name collisions |
| `test_verify.py` | Verification against hostile and malformed archives |
| `test_checks.py` | Release config loading, gates, secret scanner |
| `test_cleaning.py` | `--clean` blast radius and containment |
| `test_exit_codes.py` | Every code in the README table, plus CLI surface |

## Ported pysharepack tests

All ten legacy regression tests are carried over, adapted to Project Packager's
rule API and default profile. Two behaviours differ deliberately and the
adapted tests record the difference:

- **Nested archives.** pysharepack included `old.zip`; Project Packager excludes
  `*.zip` by default and documents `--include "*.zip"` as the escape hatch. Both
  halves are tested.
- **Config source.** pysharepack read `.pysharepack.toml` via its own minimal
  TOML parser; Project Packager reads `.packagerignore` plus `release_check.toml`
  through `tomllib`. The legacy parser is not ported — 3.11+ makes it dead weight.

## Report coverage

| Report item | Tests |
|-------------|-------|
| P0 #1 symlink escape | `test_scanner.py` symlink group, `test_packaging.py::test_external_symlink_contents_never_reach_the_archive` |
| P0 #2 fail-closed config | `test_checks.py` config-loading group |
| P0 #3 output-to-project-root | `test_output_dir_equal_to_project_root_still_packages_project`, `test_exact_output_zip_is_excluded_but_siblings_survive`, `test_output_in_project_root_produces_a_complete_package` |
| P0 #4 force-include | `test_include_can_reopen_excluded_directory`, `test_include_reopens_only_the_named_branch` |
| P0 #5 reserved manifest name | `test_project_owned_manifest_name_is_rejected`, `test_manifest_collision_never_produces_duplicate_members` |
| P0 #6 regression suite | this directory |
| P1 atomic archive creation | `test_failed_write_leaves_no_partial_archive`, `test_failed_overwrite_preserves_the_existing_archive`, `test_temporary_files_are_cleaned_up_after_failure` |
| P1 snapshot-consistent manifests | `test_missing_file_fails_the_manifest_instead_of_vanishing`, `test_file_changed_during_packaging_fails_the_run` |
| P1 hardened verification | `test_verify.py` hostile-name, structure, and resource-exhaustion groups |
| P1 revalidate before cleaning | `test_cleaning_refuses_a_target_that_moved_outside_the_project`, `test_cleaning_refuses_a_target_with_an_unapproved_name` |
| P1 `--no-manifest` reporting | `test_no_manifest_is_reported_accurately`, `test_manifest_disabled_archive_verifies_as_partial` |
| Rule-engine consolidation | `test_later_rules_override_earlier_rules`, `test_path_patterns_are_root_anchored`, `test_windows_style_separators_are_normalised`, `test_every_decision_carries_a_reason` |
| Secret scanner improvements | `test_previews_are_strongly_redacted`, `test_secret_scan_reports_skipped_files` |

## Two notes on how these tests are written

**Incidental passes are treated as failures.** Several v3.0.0 behaviours produce
the right exit code for the wrong reason, and would silently regress the moment
an implementation detail changed:

- A duplicate archive member fails verification only because `ZipFile.read`
  returns the last member of that name, so the hash mismatches. The "Duplicate
  name" text in the output is Python's own warning, not detection.
- A malformed `release_check.toml` with a string where a list belongs exits
  nonzero only because the string is iterated character by character, turning
  `"LICENSE"` into seven missing files.
- A `__pycache__` symlink pointing outside the project survives cleaning only
  because `shutil.rmtree` refuses to act on a symlink and the error is caught.

Where the report asks for a specific guard, the test asserts the tool named that
guard (`assert_failure_line`), not merely that something went wrong.

**The suite survives the v3.1.0 restructure.** `conftest.py` imports
`project_packager` from `src/` if that directory exists and falls back to the
single-file module otherwise, so the same tests can run against both forms — which
is also how the report's requirement that the installed and standalone forms share
one implementation gets enforced.

## Findings beyond the report

**Pattern anchoring.** Building the suite surfaced that `--exclude "docs/"` was
matched against the bare directory name at any depth, and an early version of
this suite asserted that a trailing slash alone should make a pattern
root-only. External review rejected that as a surprising contract: under
gitignore conventions `docs/` legitimately means a directory named `docs`
anywhere. Redesigning the test around three explicit cases then exposed a worse
problem — `/docs/` was being *silently discarded*, so a user who wrote it got no
exclusion and no warning. All three cases are now implemented and covered by
baseline tests:

| Pattern | Meaning |
|---------|---------|
| `docs/` | a directory named `docs` at any depth |
| `/docs/` | the project-root `docs` directory only |
| `src/docs/` | that specific relative subtree |

Worth recording because the sequence is instructive: a test can be red for the
wrong reason, and a wrong specification is more dangerous than a missing one.

`test_mistyped_subcommand_falls_through_to_package` records a consequence of the
backward-compatibility shim rather than a defect: `main()` prepends `package` to
any first argument that is not a known subcommand and does not start with `-`,
so `chekc` is read as a project path and exits 2 instead of producing a usage
error. Locked in as-is so a CLI change does not alter it unnoticed; worth
revisiting in v3.1.0.
