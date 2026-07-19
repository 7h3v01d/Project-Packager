# Changelog

All notable changes to Project Packager are recorded here.

## 3.0.1 — Safety hotfix

### Corrections following external review of 3.0.1-rc3

- **Binary classification no longer trusts the filename.** A file was treated as
  binary if its *extension* was known-binary, so an oversized printable file
  named `report.pdf` was recorded as "binary content, not scanned by design" and
  a key inside it shipped in a release with exit 0. Classification is now by
  magic-byte signature and content inspection; the extension only annotates the
  reason text, and a printable file with a binary-looking name is called out
  explicitly. This was the most serious remaining privacy defect.
- **Configuration files are decoded strictly.** `.packagerignore` was read with
  `errors="replace"`, so invalid UTF-8 silently rewrote patterns — an exclusion
  stopped matching and the file it named shipped. Both `.packagerignore` and
  `release_check.toml` now decode as `utf-8-sig` (so a Windows BOM is fine) and
  raise a configuration error on invalid UTF-8. `release_check.toml` previously
  surfaced this as an uncaught traceback, since `UnicodeDecodeError` is a
  `ValueError` rather than an `OSError`.
- **A refused package no longer mutates the project.** Release mode cleans
  automatically, and cleaning ran *before* the `--no-scan`, secret, and
  non-atomic-overwrite refusals — so a command that packaged nothing still
  deleted cache directories. Cleaning now happens only after every blocking
  condition has passed, immediately before the archive is written.

### Corrections following external review of 3.0.1-rc2

- **`release_check.toml` may declare `schema_version`.** Optional for backwards
  compatibility; a version newer than the build understands is refused rather
  than half-interpreted. `init` writes it by default. Raised in two successive
  reviews.
- **Unscanned-file classification is typed.** `UnscannedKind` is a `StrEnum`
  (`BINARY`, `TEXT_LIKE`, `UNREADABLE`) rather than a bare string, so blocking
  policy cannot drift back to being derived from the wording of a reason string.


- **Unscanned files are classified by content, not size.** Sampling happened
  after the size check, and any oversized file was then treated as text, so a
  1 MiB PNG blocked strict/release packaging and was described as an unscanned
  text file. Classification now samples first and records a structured
  `UnscannedFile(path, reason, kind)`; binary assets are noted but do not block,
  and anything not demonstrably binary is treated conservatively as text.
- **One secret gate, one exit code.** Release packaging previously scanned twice
  — once over the whole working tree during pre-checks, once over the inclusion
  set during packaging — returning `6` in release and `5` under `--strict` for
  the same problem, ignoring `--no-scan` in the first pass, and blocking on
  secrets in files the release profile excludes anyway. Packaging now runs the
  non-secret release checks, then scans exactly the files that will ship. Exit
  `5` covers secrets and unscannable text in both modes; exit `6` is reserved
  for non-secret check failures. `check` still scans the broader tree.
- **`--no-scan` requires `--force` in strict/release mode.**
- **`.packagerignore` fails closed in every profile**, not just strict/release.
  An unusable ignore file is evidence that exclusions were intended, and share
  mode is where losing them leaks something. Not overridable with `--force`.
- **Leading-slash patterns are honoured.** `/docs/` was silently discarded — it
  could never match, so the user got no exclusion and no warning. Anchoring now
  follows gitignore conventions: `docs/` matches at any depth, `/docs/` matches
  the project-root directory only, `src/docs/` matches that subtree.
- **No manifest and no sidecar now fails the package**, in any profile, and the
  summary no longer claims partial verification when no sidecar was written.
- **`--overwrite` is refused in strict/release mode** until atomic replacement
  lands in v3.1.0, since a failed write can destroy the existing archive.
  Overridable with `--force`.
- Exit codes are centralised in an `Exit` IntEnum and documented as part of the
  CLI contract; code `10` added to the README table.
- CI now runs the full documented `pytest` on every matrix entry. The previous
  advisory job used `continue-on-error`, so CI could stay green while the
  documented command failed or an xfail marker went stale. A self-package job
  packages and verifies the repository end to end.
- README gained a Current Limitations section covering non-atomic replacement,
  unhardened cleaning, and the verifier's non-adversarial scope.

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
- A 170-test regression suite (`tests/`). The included CI workflow runs the
  full suite on Windows and Linux across Python 3.11–3.13 and packages the
  repository as an end-to-end check.

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
- Documentation still describes integrity verification in terms that could be
  read as authenticated signing.

## 3.0.0

- Initial consolidated release: `package`, `check`, `verify`, and `init`
  subcommands; embedded SHA-256 manifest and sidecar; secret scanning;
  `release_check.toml` release gates.
