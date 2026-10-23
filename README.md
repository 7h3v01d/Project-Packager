# Project Packager

A small, safe, audit-friendly project packaging and release-checking CLI.

Check a project against universal and per-project release rules, package it into a clean **verifiable** ZIP with an embedded SHA-256 manifest, and later check that archive against the hash it was distributed with — all from one file.

**Standard library only. Single file. No dependencies. Windows-friendly.**

```
python project_packager.py check .                       # release sanity checks
python project_packager.py package . --profile release   # gated, verified build
python project_packager.py verify mypkg_2026-07-03.zip   # check it against its hash
```

---

## Why

Zipping a project folder by hand ships everything: `__pycache__`, `.git`, virtualenvs, old ZIPs nested inside new ZIPs, `.bak` debris, stray patch scripts — and occasionally an API key. And even a clean-looking ZIP can hide stale files, wrong version banners, or forgotten internal hostnames.

Project Packager runs the release checklist for you, produces a clean archive, embeds a per-file SHA-256 record of exactly what's inside it, and blocks failed checks and detected secrets in release mode.

## The pipeline

| Command   | What it does                                                             |
|-----------|--------------------------------------------------------------------------|
| `init`    | Drop starter `release_check.toml` + `.packagerignore` into a project     |
| `check`   | Universal checks + your per-project rules; exit 0/1                      |
| `package` | Clean ZIP with embedded SHA-256 manifest + `.sha256` sidecar             |
| `verify`  | Re-hash every archive member against the manifest; detect corruption     |
| `gui`     | Visual include/exclude editor and runner (also `--gui`)                  |
| `why`     | Explain why a path is in or out, citing the exact rule and line          |
| `diff`    | Compare two packages, or a package against the project as it is now      |

**Backward compatible:** `python project_packager.py .` (no subcommand) still packages.

## Current limitations

Please read these before relying on the tool for anything important.

- **`verify` defends against hostile archives, but it is not a sandbox.** It
  rejects duplicate and unsafe member names, malformed manifests, size
  disagreements and implausible expansion, and streams every member. It never
  extracts anything. It does not make an archive *trustworthy*, only
  *consistent*: see the next section.
- **Packaging reads every file twice.** Once to hash it for the manifest, and
  once more from the temporary archive to prove the bytes written match. That is
  what makes the manifest snapshot-consistent; on very large projects it costs
  time.
- **Atomicity is per file system.** The archive is written beside its final
  name and swapped in with `os.replace`. A failure leaves the previous archive
  untouched, but a power cut mid-swap is up to your file system.
- **Secret scanning is heuristic and cannot prove a project is secret-free.**
  See the note at the end of the next section.

## What verification does and does not show

Project Packager provides **integrity checking**, not authenticated signing. The
distinction matters when you decide how much to rely on a `verify` result.

It does show:

- **Corruption detection.** A truncated download, a bad disk, or a partial copy
  changes hashes and is caught.
- **Self-consistency.** Archive members currently match the manifest embedded in
  that same archive.
- **Tamper evidence relative to a trusted hash.** If you obtained the expected
  SHA-256 through a channel you trust — a signed release page, a message from
  the author, your own records — a match shows you have that exact archive.

It does not show:

- **Authorship or origin.** Nothing here proves who built the archive.
- **Resistance to a substituting attacker.** Anyone who can replace the ZIP can
  also replace its `.sha256` sidecar and rewrite the embedded manifest to match.
  Verification against a hash you fetched from the same place as the archive
  proves only that the two agree with each other.

For origin and substitution resistance you need a detached signature. Project
Packager supports [minisign](https://jedisct1.github.io/minisign/) as an
optional extra — see [Signing](#signing--who-made-this-archive).

### `--no-scan` and unscanned files

`--no-scan` disables secret scanning entirely. In strict or release mode it must
be paired with `--force`, because silently disabling the gate that those modes
exist to enforce is a trap rather than a convenience.

Files the scanner cannot read are reported rather than skipped quietly, and are
classified by content, not size:

- **Binary assets** — images, PDFs, wheels, media — are recorded as
  intentionally unscanned and do not block a release.
- **Text files it could not read** — over the 1 MiB limit, not decodable as
  supported Unicode text, or unreadable — block strict and release packaging
  unless you add `--force`, because they ship unexamined.

Supported text encodings are UTF-8, UTF-8 with BOM, UTF-16LE/BE (with or
without a BOM), and UTF-32. Classification follows content, never the filename:
a printable file named `report.pdf` is scanned, and a real PNG is not.

**False positives** — test fixtures, documentation examples — can be allowed with an inline marker on the *same line* as the match:

```python
EXAMPLE_KEY = "AKIA................"  # packager: allow-secret
```

Allowed matches never block, but they are never hidden either: `package` lists them under *ALLOWED by inline marker* in every summary, `check` reports them as a warning, and the GUI shows them in amber. A marker on a line of its own covers nothing.

Likewise, the secret scanner is heuristic. It detects known token shapes in
files it can read, reports files it could not scan, and blocks release mode on
both. It cannot prove a project is secret-free, and it supplements rather than
replaces provider-side secret revocation, repository scanning, and human review.

### Configuration format version

`release_check.toml` may declare `schema_version = 1` at the top level. It is
optional, so existing files keep working, but declaring it means a future
release that changes field meanings will be refused by an older build rather
than half-interpreted. `init` writes it by default.

Unknown sections and keys are rejected outright. A misspelled gate such as
`[requred]` that silently does nothing is more dangerous than a stale
configuration that fails visibly.

## Requirements

Python 3.11+ (uses `tomllib`). No third-party packages.

## Installation

It's one file. Copy `project_packager.py` anywhere on your path, or run it in place.

Or install it as a command (still the same single file underneath):

```bash
pip install .                     # from a checkout
project-packager --version
project-packager package . --profile release
```

`pyproject.toml` reads the version from `TOOL_VERSION` in the script, so there is one place to bump it.

---

## `check` — release sanity checks

```bash
python project_packager.py check C:\path\to\myproject
```

### Built-in checks (no config needed)

- **Working-tree debris** — `patch_*` / `fix_*` / `add_*` scripts, `*.bak`, `*.tmp`, `*.old`, `*.orig`, "New Text Document" files anywhere in the tree; warns on a lingering `scripts/` session folder
- **Secret scan** — tracked text files scanned for AWS, Anthropic, OpenAI, GitHub, Slack, and Google credentials plus private-key blocks
- **Latest package inspection** — finds the newest ZIP in `../packaged` or the project root, checks it for debris entries, and **re-verifies every file hash** against the embedded manifest

### Per-project checks — `release_check.toml`

Run `init` to generate a commented starter, or see `release_check.example.toml` for a fully-loaded example. All sections are optional.

```toml
[version]
# Every listed file must contain the target version string.
target = "3.2.2"
files = ["config.py", "pyproject.toml", "CHANGELOG.md"]

[forbidden]
# Filenames exempt from the forbidden-pattern scan.
allow_files = ["CHANGELOG.md"]

[forbidden.patterns]
# label = regex. Must not appear in any tracked text file.
"personal LAN IP" = "192\\.168\\.\\d{1,3}\\.\\d{1,3}"
"legacy brand"    = "(?i)old_brand_name"

[forbidden.contains]
# Per-file substrings that must NOT appear.
"app.py" = ["My Project v2"]

[required]
files = ["LICENSE", "README.md", "SECURITY.md"]

[required.contains]
# Per-file substrings that MUST appear.
# Join alternative files with | — contents are concatenated, useful when a
# refactor moved a symbol across files.
"tools.py"                  = ["_safe_path", "relative_to"]
"web_app.py|routes/chat.py" = ["prepare_tool_calls"]

[banned]
# Paths that must not exist in the working tree.
paths = ["tests/stale_copy.py", "old_stuff/"]

[requirements]
# Heavy optional deps that belong in extras, not the base install.
file = "requirements.txt"
forbidden = ["faster-whisper", "pytesseract"]

[wheel]
# Actually build the wheel (pip wheel . --no-deps) and verify that critical
# modules and static assets survive packaging.
build = true
timeout = 300
must_contain = ["app.py", "static/app.css", "static/js/core.js"]

[limits]
# Size gates on what a release package would contain. `check` reports them
# against the release-profile file set; `package --profile release` (or
# --check) refuses with exit 6 if the real file set exceeds them.
max_file_mb = 25
max_total_mb = 200
max_files = 5000
```

The checker prints `OK` / `FAIL` / `WARN` per item and exits 1 if anything failed — ready for batch files and CI.

---

## `package` — clean, verifiable ZIPs

```bash
# Preview — writes and deletes nothing
python project_packager.py package . --dry-run

# Standard package (ZIP lands in ..\packaged\ beside the project)
python project_packager.py package .

# Full release gate: checks first, strict exclusions, cache clean,
# fails on secrets or failed checks
python project_packager.py package . --profile release
```

Output filename is timestamped automatically: `myproject_2026-07-03_1430.zip`.

### What every package gets

- **Embedded manifest** — `PACKAGE_MANIFEST.json` inside the ZIP with per-file SHA-256 hashes and sizes
- **Hash sidecar** — a `sha256sum`-compatible `<zip>.sha256` beside the archive
- **Sensible exclusions** — caches, VCS folders, virtualenvs, build output, editor folders, session debris, and existing `*.zip` files (no packages-inside-packages)
- **Secret scan** — warns by default; blocks in `--strict` / release profile

### Profiles

| Profile   | Exclusions                     | Clean  | Checks first | Secret scan |
|-----------|--------------------------------|--------|--------------|-------------|
| `share`   | Standard (default)             | opt-in | opt-in       | Warns       |
| `release` | Standard + strict privacy set  | yes    | yes          | **Blocks**  |
| `backup`  | Minimal (`.git`, caches only)  | opt-in | opt-in       | Off         |

`--strict` (usable with any profile) additionally excludes `.env`, `.env.*`, `*.key`, `*.pem`, `credentials.json`, `id_rsa*`, `secrets/` directories, and similar.

### Options

```
project                Project directory to package (default: .)
--profile {share,release,backup}
--output, -o PATH      Output folder (default: ./packaged beside the project)
--name, -n NAME        Custom base name; timestamp is still appended
--dry-run              Show the plan; write and delete nothing
--clean                Delete only safe cache junk before packaging
--strict               Extra privacy exclusions + secrets block packaging
--check                Run release checks first; abort if any fail
--exclude PATTERN      Extra exclusion (repeatable; '/' in pattern = path match)
--include PATTERN      Force-include (repeatable; beats all exclusions)
--no-scan              Disable the secret scanner
--no-manifest          Skip embedding PACKAGE_MANIFEST.json
--force                Package anyway despite secret findings or failed checks
--overwrite            Allow overwriting an existing ZIP of the same name
--sign                 Write a minisign signature (<zip>.minisig); checked up front
--sign-key FILE        minisign secret key (default ~/.minisign/minisign.key)
--open                 Open the output folder when done
--list-included        Print every included file
--list-excluded        Print every excluded item with its reason
```

### `.packagerignore`

Per-project exclusions, gitignore-lite. One pattern per line:

```
# comments allowed
*.log
docs/
data/raw/
notes/scratch_*.md
```

Trailing `/` marks a directory pattern; patterns containing `/` match against the relative POSIX path (and everything beneath it); plain patterns match file *and* directory names. A leading `/` anchors to the project root.

A leading `!` force-includes, with the same power as `--include`: it overrides every exclusion — built-in, strict, or yours — but never a symlink or the archive being written, and force-included files are still secret-scanned (and block release mode like any other). `\!` escapes a literal leading `!`. `--exclude` values on the command line are never reinterpreted this way.

```
data/raw/
!data/raw/sample.csv
!/old_release.zip
```

---

## `gui` — pick includes and excludes visually

```bash
python project_packager.py --gui              # current folder
python project_packager.py gui C:\path\to\proj
```

Uses `tkinter` from the standard library, so the tool stays dependency-free. (On Windows it's part of the normal Python install; on Debian/Ubuntu it's `sudo apt install python3-tk`.)

- **Tree preview** of the project with each file marked *included*, *excluded*, *force-included*, *possible secret*, *not scannable*, or *symlink (skipped)*, plus the rule or reason. Folders show `N in · M out` and turn amber when something inside needs attention.
- **Toggle** a file with double-click, or anything (folders too) with Space/Enter. Toggling writes the narrowest rule that does the job — `/src/config.json`, not `config.json` — and toggling back removes that exact rule.
- **Right-click** for: exclude this, exclude every `*.ext`, exclude every folder with this name, force-include, remove the rule(s) that excluded this, copy path, show in file manager. Excluded folders can be expanded to rescue a single file from inside them.
- **Rule lists** for exclusions and force-includes; select a rule to highlight what it matches. Undo (Ctrl+Z), Revert, Save (Ctrl+S).
- **Filter** by All / Included / Excluded / Attention, and find by name.
- **Package, Dry run, Run checks, Verify, Compare, Init** run this same script as a subprocess, so gates and exit codes are identical to the CLI. A successful package is verified automatically. **Compare…** diffs an earlier ZIP against the project as it is now; **Why?** on the right-click menu prints the `why` explanation into the log.
- **Remembers** your profile, name, output folder and checkboxes per project, plus a recent-projects list. That lives in your user config (`%APPDATA%\project_packager\gui.json` on Windows, `~/.config/project_packager/gui.json` elsewhere), never in the project, so a cloned repo can't change how your packaging behaves. The CLI never reads it.

Safety properties:

- The preview is computed by the same `build_rules` / `scan_project` / `scan_for_secrets` path as `package`. The GUI has no matching logic of its own.
- Nothing is written until Save. Saving is atomic (temp file + replace) and keeps your comments and line order.
- If `.packagerignore` exists but can't be read, editing is disabled — saving a blank list over it would silently drop exclusions you meant to keep.

---

## `why` — which rule decided this?

```bash
python project_packager.py why data/raw/big.csv .venv/lib/x.py .env --profile release
```

```
EXCLUDED  data/raw/big.csv
  path pattern: data/raw
  from your rule(s):
    data/raw/   (.packagerignore line 3)
  Remove the rule, or force-include with:  !/data/raw/big.csv

EXCLUDED  .env
  file pattern: .env
  source: strict privacy set (--strict / release profile)
```

Reports included / force-included / excluded / skipped symlink, the matching rule, whether it is built-in, strict, or yours (with its line number), and the exact line that would override it. Uses the same scan as `package`. Exit 0, or 1 if a path doesn't exist. Options: `--project/-p`, `--profile`, `--strict`.

---

## `diff` — what changed between releases?

```bash
python project_packager.py diff packaged\app_2026-09-01_1200.zip packaged\app_2026-10-24_0900.zip
python project_packager.py diff packaged\app_2026-09-01_1200.zip .     # vs. what you'd ship now
```

Lists added (`+`), removed (`-`) and changed (`~`, with size delta) files. A ZIP side uses its embedded manifest (or hashes members if it has none); a folder side uses exactly what `package` would include under `--profile` / `--strict` — so excluded junk never shows up as a change, but a file that newly *would* ship does. `--json` for scripts. Exit 0 identical, 1 different, 2 path missing, 4 unreadable archive, 9 bad `.packagerignore`.

`diff` compares manifests as recorded; it does not re-hash archive members. Run `verify` to confirm an archive still matches its own manifest.

---

## `verify` — check an archive against its manifest and hash

```bash
python project_packager.py verify packaged\myproject_2026-07-03_1430.zip
```

Verifies the ZIP against its `.sha256` sidecar, then re-hashes **every member** against the embedded manifest. Any modified file, any missing file, and any file added to the archive that isn't in the manifest is reported as a `FAIL`. Exit 0 = intact, 1 = problems.

The archive is treated as untrusted input. Before anything is decompressed it is refused for: more than 200,000 members, duplicate member names, unsafe member names (absolute, drive-qualified, UNC, backslashed, or `..` traversal), a manifest over 64 MB, or members or a manifest declaring an expansion beyond 1000× the archive size (above 256 MB). A manifest of the wrong shape is reported as malformed, once, rather than as every member being "not in manifest". `file_count`, `total_bytes` and each per-file `size` must agree with what is actually there. Members are hashed as streams, never read whole, and nothing is extracted.

The manifest can also be inspected or verified with standard tools — it's plain JSON, and the sidecar works with `sha256sum -c`.

---

## Signing — who made this archive?

The sidecar hash and manifest prove an archive is *intact*. They can't prove who made it, because anyone who can replace the ZIP can replace those too. A signature can: only the holder of your secret key can produce one.

Signing is optional and uses [minisign](https://jedisct1.github.io/minisign/), a small, well-regarded external tool. Nothing changes unless you ask for it.

```bash
# once: install minisign and make a key pair
winget install jedisct1.minisign            # or: scoop install minisign / apt install minisign
minisign -G                                  # ~/.minisign/minisign.key + minisign.pub

# sign while packaging (prompts for your key password)
python project_packager.py package . --profile release --sign

# recipients verify with your PUBLIC key
python project_packager.py verify app_2026-10-24_0900.zip --pubkey minisign.pub
python project_packager.py verify app_2026-10-24_0900.zip --pubkey-string RWQ...
```

- `--sign` checks that minisign and the key exist **before** anything is written or cleaned.
- The signature goes to `<zip>.minisig`, written atomically. Its trusted (signed) comment records the tool version, file name and SHA-256.
- If signing fails after the archive is written, the archive stays (it's complete and verified) but the run exits 4 and says it is **not signed**.
- `--overwrite` deletes the old archive's `.minisig`, which would otherwise describe different bytes.
- `verify --pubkey` fails if the signature is missing, invalid, or made by another key. Without `--pubkey`, a present `.minisig` is reported as *present but not checked* rather than silently trusted.
- Publish your **public** key somewhere recipients already trust (your GitHub profile, a README, a release page). A public key fetched from the same place as the archive proves only that the two agree.
- The GUI doesn't sign: minisign needs to prompt for your key password in a terminal.

---

## Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Success / all checks passed / archive verified                 |
| 1    | `check` failures or `verify` problems                          |
| 2    | Project path missing or not a directory                        |
| 3    | Output ZIP already exists (use `--overwrite`)                  |
| 4    | OS error, file changed mid-package, or signing failed          |
| 5    | Secrets found in strict/release mode (`--force` to override)   |
| 6    | Pre-package release checks failed (`--force` to override)      |
| 7    | Archive verified only partially (valid sidecar, no manifest)   |
| 8    | Project file collides with a reserved internal name            |
| 9    | `release_check.toml` or `.packagerignore` present but unusable |
| 10   | A source path escaped the project between scanning and writing |

`--gui` exits 1 if given any option other than a project folder, and 4 if tkinter is unavailable.

## What `--clean` will and won't touch

**Will delete:** `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `*.pyc`, `*.pyo`

**Will never delete:** virtualenvs, `build/`, `dist/`, logs, databases, ZIPs, or anything else. Cleaning is deliberately conservative — everything else is only *excluded from the archive*, never removed from disk. The `check` command never modifies anything at all.

## License

Apache License 2.0 — Copyright 2026 Leon Priest ([7h3v01d](https://github.com/7h3v01d))
