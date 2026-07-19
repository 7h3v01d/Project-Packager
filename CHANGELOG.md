# Changelog

All notable changes to Project Packager are recorded here.

## 3.0.1 — Safety hotfix

### Corrections following external review of 3.0.1-rc1

- **`PACKAGE_MANIFEST.json` is now reserved unconditionally.** The collision
  check previously ran only when a manifest was being written, so
  `--no-manifest` let a project's own file of that name into the archive, where
  `verify` then read it as the internal manifest and failed.
- **Verification tracks positive evidence.** An archive with neither a valid
  sidecar nor an embedded manifest was reported as `PARTIAL — archive intact`
  when in fact nothing had been checked at all. Outcomes are now: sidecar only →
  `PARTIAL` (exit 7); manifest only → `OK`, described explicitly as
  self-consistency rather than proof of provenance; neither → `FAIL` (exit 1).
- **Unscanned files are reported and block release mode.** The secret scanner
  silently skipped files over 1 MiB, so a release could ship a token in a large
  text file while reporting no secrets. Skips are now listed with a reason
  (too large, binary, unreadable, not UTF-8) and block strict/release packaging
  unless `--force` is given.
- **Unreadable `.packagerignore` fails closed in strict/release mode** with exit
  9, instead of warning and continuing with every project exclusion lost.
- **Sidecar write failure is reported honestly.** The summary no longer prints a
  sidecar filename it failed to write, and a release without its sidecar fails.
- `ContainmentError` now has its own exit code (10) instead of borrowing the
  reserved-name code.
- Source header no longer carries a duplicated version string.
- README describes integrity checking rather than proof: a new section
  distinguishes corruption detection, self-consistency, and tamper evidence
  relative to a trusted hash from authenticated signing.
- Outstanding v3.1.0 tests are marked `xfail(strict=True)`, so a normal `pytest`
  run is green and a fixed-but-still-marked test fails loudly. This immediately
  caught one item that had been fixed as a side effect.


A focused hardening pass. No new features; every change closes a correctness
or privacy defect found during the v3.0.0 review.

### Fixed

- **Symlinks are never followed.** v3.0.0 packaged the *target* of a symlinked
  file, so a link inside the project could silently pull material from outside
  it into the archive. Symlinked files and directories are now skipped, counted
  in the summary, and cannot be forced in with `--include`. Every source is
  rechecked for symlink status and project containment immediately before it is
  written, not only when it was scanned.
- **Invalid release configuration now fails closed.** A malformed or unreadable
  `release_check.toml` used to print a parse error, fall back to built-in checks
  only, and exit 0 — a broken release gate read as an absent one. Configuration
  problems are now distinct from a missing file, are validated for field types
  and regex compilation before any check runs, exit 9, and prevent the release
  profile from packaging.
- **`--output .` produces a complete package.** Using the project directory as
  the output directory previously pruned the entire project, producing an
  archive containing nothing but a manifest. The root is no longer pruned when
  output and project directories are the same; only the exact output ZIP, its
  sidecar, and its temporary forms are excluded. A separate output subdirectory
  inside the project is still pruned whole.
- **`--include` reaches beneath excluded directories.** Path-style include
  patterns now reopen the specific directory branch they target, so
  `--include ".vscode/settings.json"` works as documented. Reopening a branch
  does not readmit anything else inside it.
- **Windows-style patterns are normalised.** `--exclude "data\some\file.csv"`
  now means the same thing as its forward-slash form.
- **`PACKAGE_MANIFEST.json` is reserved.** A project shipping its own file of
  that name used to produce an archive with two members of the same name that
  immediately failed its own verification. The run now aborts with exit 8
  before anything is written.
- **`--no-manifest` is reported honestly.** The summary no longer claims a
  manifest was embedded when it was not, and states that verification will be
  partial.

### Added

- Distinct exit codes: `7` partial verification (valid sidecar, no embedded
  manifest), `8` reserved-name collision, `9` invalid release configuration.
- `verify` reports a `PARTIAL` result rather than `OK` when an archive has no
  embedded manifest to check its contents against.
- Skipped-symlink count in the packaging summary.
- Distinct exit code 10 for containment failures.
- A 151-test regression suite (`tests/`). The included CI workflow targets
  Windows and Linux on Python 3.11–3.13; verified locally on Linux only.

### Known limitations

Carried forward to v3.1.0, and covered by tests currently marked `defect`:

- Archive creation is not yet atomic; a failed write can leave a partial file,
  and `--overwrite` can destroy a valid previous archive.
- Manifests are not yet snapshot-consistent: a file changed between hashing and
  writing produces an archive that fails its own verification, and an unreadable
  file is dropped from the manifest rather than failing the run.
- Large text files are refused in release mode rather than scanned
  incrementally; streaming the scanner is v3.1.0 work.
- Verification does not yet reject duplicate members, unsafe member paths,
  malformed manifest structure, or metadata disagreement, and reads members
  whole rather than streaming them.
- Cleaning does not yet revalidate containment immediately before deletion.
- Exclusion patterns are matched by directory name at any depth rather than
  being root-anchored, so `--exclude "docs/"` also excludes `src/docs/`.
- Documentation still describes integrity verification in terms that could be
  read as authenticated signing.

## 3.0.0

- Initial consolidated release: `package`, `check`, `verify`, and `init`
  subcommands; embedded SHA-256 manifest and sidecar; secret scanning;
  `release_check.toml` release gates.
