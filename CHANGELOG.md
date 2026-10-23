# Changelog

All notable changes to Project Packager are recorded here.

## 3.1.0 — Consolidation

Every outstanding `defect` test is fixed and its markers removed: the full
suite is green with no xfails, which is the acceptance gate in
`tests/README.md`. Each fix was confirmed to fail against the previous build.

### Signing, installation, and polish

- **Optional minisign signatures.** `package --sign [--sign-key FILE]` writes
  `<zip>.minisig` with a signed comment recording tool version, file name and
  SHA-256. Preflighted before anything is written or cleaned. `verify --pubkey
  FILE` / `--pubkey-string KEY` checks it; an unchecked signature is warned
  about, never silently trusted. Overwriting removes a stale signature. This
  closes the "who made it" gap the README previously listed as out of scope.
  `tests/test_signing.py` (11 tests); `PP_REQUIRE_MINISIGN=1` turns skips into
  failures, and CI sets it on Linux.
- **pip-installable**: `pyproject.toml` installs the single file as a module
  with a `project-packager` command. Version comes from `TOOL_VERSION`.
- **The project gates its own releases**: `release_check.toml` checks version
  alignment, forbids the retired brand and personal LAN IPs, requires the
  licence header, bans a `src/` tree, sets size limits, and builds the wheel.
  CI installs with pip, runs `check`, then packages itself in release mode,
  signed, and verifies the signature.
- **`check` no longer writes into the project when building a wheel.**
  setuptools builds in place, so `[wheel] build = true` left `build/` and
  `*.egg-info/` in the source tree, breaking the documented promise that
  `check` never modifies anything. The wheel is now built from a temporary
  copy (VCS, venvs, caches and build output skipped; links copied as links).
  Found when this project's own `release_check.toml` turned the gate on.
- **Typo hint**: `chekc` now says *Did you mean 'check'?* (still exit 2). A
  real folder with that name is still packaged.
- **`package.bat` found Python incorrectly** when the `py` launcher was
  present: `PYTHON` became `py -3`, and every `"%PYTHON%"` call then looked
  for a program literally named `py -3`. It now resolves the interpreter's full
  path (preferring `python`), and refuses anything older than 3.11.
- The expected zipfile "Duplicate name" warning in
  `test_duplicate_member_fails` is filtered on that test only: the suite runs
  with no warnings.

### Atomic, snapshot-consistent archives

- **Archives are written atomically.** Everything goes to `<zip>.part` and is
  swapped in with `os.replace` only when complete. A failed run leaves no
  partial archive and no temporary files, and a failed `--overwrite` leaves the
  previous archive byte-for-byte intact. The sidecar is written to a temporary
  name first and swapped in straight after the archive; if it can't be, any
  stale sidecar from an overwritten archive is removed rather than left to
  describe the wrong file.
- **`--overwrite` is no longer refused in strict/release mode.** The refusal
  was explicitly a stopgap until replacement was atomic. Two baseline tests
  encoded the stopgap itself and were rewritten to test the guarantee it stood
  in for: `test_overwrite_in_release_replaces_atomically` and
  `test_refused_overwrite_does_not_clean_the_project` (now: a release refused
  for a secret, with `--overwrite`, cleans nothing and keeps the old archive).
- **Manifests are snapshot-consistent.** Before the manifest is embedded,
  every member is streamed back out of the temporary archive and checked
  against it. A file that changes, appears or disappears mid-package fails the
  run with exit 4 and a clear message, instead of shipping an archive that
  fails its own verification.
- **`build_manifest` no longer silently drops a file it cannot read.**

### Hardened verification

- One streaming core, `inspect_archive()`, used by `verify`, by `check`'s
  latest-package inspection, and (manifest validation) by `diff`.
- Refused before decompression: more than 200,000 members; members or a
  manifest declaring expansion beyond 1000× the archive size (above 256 MB);
  a manifest over 64 MB.
- Duplicate member names are named as duplicates, not detected by accident
  via a hash mismatch.
- Unsafe member names — absolute, drive-qualified, UNC, backslashed, NUL,
  `..` traversal — fail by name, whether or not the manifest lists them.
- Manifest structure is validated first (types, required fields, digest
  format, duplicate paths, `file_count`, `total_bytes`). A malformed manifest is
  one clear failure, not every member reported "not in manifest".
- Per-file declared size must match both the central directory and the bytes
  actually streamed.
- Members are hashed as streams; no member is ever read whole.

### Cleaning and scanning

- **Cleaning revalidates every target immediately before deleting it**:
  inside the project root recorded at scan time, an approved cache name, the
  expected type, and not a symlink. Paths collected at scan time are no longer
  trusted at deletion time.
- **Secret previews are strongly redacted**: at most the four-character type
  prefix plus the token length (`AKIA…[20 chars redacted]`). v3.0.0 showed ten
  characters — six of them real secret material.

### Ordered rule precedence

- **The last matching rule wins**, as in gitignore: built-in rules, then
  `.packagerignore` top to bottom, then `--exclude`, then `--include`. So
  `*.log` then `!run.log` ships `run.log`, and `!run.log` then `*.log` does not.
  An earlier draft of the `!` feature below made `!` always win, which let
  `test_later_rules_override_earlier_rules` pass for the wrong reason; the
  test now asserts both orders. The GUI's "add rule" moves an existing rule to
  the end so it becomes the winning line.


### Added — GUI and tooling

- **`--gui` / `gui` subcommand: a visual include/exclude editor.** Tree preview
  of the whole project with per-file status and reason, toggle in/out by
  double-click or Space, context-menu rule actions, live preview of unsaved
  edits, undo, and buttons that run package / dry run / check / verify / init
  through the CLI itself. Standard library only (tkinter), imported lazily so
  the CLI still runs on a Python built without Tk.
- **`!pattern` lines in `.packagerignore` force-include**, with exactly the
  power of `--include`, so includes no longer have to be retyped on every run.
  `\!` escapes a literal `!`. Old builds read a `!` line as a literal
  exclusion that matches nothing they would otherwise have shipped, so a file
  written for this version fails safe on an older one.
- **`why PATH...`** explains each path's fate: included, force-included,
  excluded or skipped symlink; the rule responsible; whether it is built-in,
  from the strict set, or yours (with its `.packagerignore` line number); and
  the exact line that would override it.
- **`diff OLD NEW`** compares two packages, or a package with a project
  folder (using the same rules `package` would). Added / removed / changed with
  size deltas, `--json`, exit 0 identical / 1 different.
- **`[limits]` in `release_check.toml`** — `max_file_mb`, `max_total_mb`,
  `max_files`. `check` reports them against the release file set; release
  packaging (or `--check`) refuses with exit 6 against the real file set,
  before anything is cleaned. `--force` overrides. Share packaging ignores them.
- **Inline `packager: allow-secret` marker** for known false positives. Same
  line only. Allowed matches don't block but are listed in every package
  summary, warned about by `check`, and shown amber in the GUI.
- **GUI:** Compare… (diff an earlier ZIP against the project now), Why? on
  the context menu, allowed-secret status, and per-user memory of profile,
  name, output and options per project plus a recent-projects list. Stored in
  the user config folder, never in the project; the CLI never reads it.
- `preview_package()`, `IgnoreFile`, `user_rules_excluding()`,
  `user_includes_matching()` and `suggest_patterns()` — the read-only engine
  pieces the GUI is built on, usable from tests and scripts.

### Fixed

- **Anchored force-includes were silently ignored.** `--include "/notes.txt"`
  was matched verbatim against relative paths, which never begin with `/`, so
  it did nothing and gave no warning — the same defect fixed for exclusions in
  3.0.1. Leading-slash includes now anchor to the project root, both for
  matching and for reopening an excluded directory.
  Revert-proven: `tests/test_gui_rules.py::test_anchored_include_*`.

## 3.0.1 — Safety hotfix

### Test-infrastructure corrections

- **Symlink coverage can now be required rather than hoped for.**
  `PP_REQUIRE_SYMLINKS=1` turns the skip into a failure, and CI sets it. The
  workflow previously ran `git config core.symlinks true` and claimed this made
  the containment tests execute on Windows runners; that setting affects git
  checkout, not `os.symlink`, so it did nothing and the claim was unverified.
  CI now probes the privilege explicitly and reports it.

### Corrections following external review of 3.0.1-rc5

- **Two unsafe-member tests were passing on Windows for the wrong reason.**
  `ZipInfo.__init__` rewrites `os.sep` to `/`, so backslash and UNC member names
  were normalised before being written; the rewritten member then failed to
  match its manifest entry and verification failed as "missing from archive",
  not because any unsafe-path guard exists. Strict xfail surfaced this as an
  XPASS on Windows. The hostile name is now written verbatim and the test
  asserts the guard is named, so it means the same thing on every platform.

- **Binary detection uses control-byte density, not NUL presence.** A single
  NUL in an otherwise printable file was enough to label it "binary content —
  not scanned by design", so a key beside it shipped with exit 0. One NUL is
  damage or noise — from generated config, a truncated write, or deliberate
  disguise — not proof of binary content. Files are now judged on the
  proportion of unexpected control bytes, with recognised magic bytes remaining
  the strongest signal.
- **Reserved-name collisions are refused before cleaning.** The collision is
  known immediately after scanning, but was raised inside `create_zip()`, so a
  run that correctly exited 8 had already deleted cache directories.

### Corrections following external review of 3.0.1-rc4

- **Unicode text is decoded before binary classification.** `looks_binary` was
  `b"\x00" in sample`, and UTF-16 encodes ASCII as alternating NULs — so a
  UTF-16LE PowerShell script holding an AWS key was reported as "binary content,
  not scanned by design" and shipped in a release with exit 0. Detection now
  tries a Unicode BOM (UTF-8/16/32), then a BOM-less UTF-16 alternating-NUL
  signature, then strict UTF-8, and only consults the NUL heuristic for data
  none of those resolve. UTF-16 is ordinary on Windows and in PowerShell
  workflows, so this was a routine case rather than an exotic one.
- **Text decoding is strict.** `read_text_safe` used `errors="ignore"`, so a
  malformed file counted as successfully scanned with bytes silently discarded.
  Undecodable files are now reported as unscanned text-like and block
  strict/release packaging.
- **An existing output ZIP no longer causes cleaning.** Output existence was
  checked inside `create_zip()`, which runs after cleaning, so the most common
  refusal of all — packaging twice without `--overwrite` — still deleted cache
  directories. It is now checked before anything mutates the project, with the
  original check retained as defence in depth against a race.

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
