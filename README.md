# Project Packager v3.0.0

A small, safe, audit-friendly project packaging and release-checking CLI.

Check a project against universal and per-project release rules, package it into a clean **verifiable** ZIP with an embedded SHA-256 manifest, and later prove the archive hasn't been tampered with — all from one file.

**Standard library only. Single file. No dependencies. Windows-friendly.**

```
python project_packager.py check .                       # release sanity checks
python project_packager.py package . --profile release   # gated, verified build
python project_packager.py verify mypkg_2026-07-03.zip   # prove it's intact
```

---

## Why

Zipping a project folder by hand ships everything: `__pycache__`, `.git`, virtualenvs, old ZIPs nested inside new ZIPs, `.bak` debris, stray patch scripts — and occasionally an API key. And even a clean-looking ZIP can hide stale files, wrong version banners, or forgotten internal hostnames.

Project Packager runs the release checklist for you, produces a clean archive, embeds cryptographic proof of exactly what's inside it, and refuses to ship secrets or failed checks in release mode.

## The pipeline

| Command   | What it does                                                             |
|-----------|--------------------------------------------------------------------------|
| `init`    | Drop starter `release_check.toml` + `.packagerignore` into a project     |
| `check`   | Universal checks + your per-project rules; exit 0/1                      |
| `package` | Clean ZIP with embedded SHA-256 manifest + `.sha256` sidecar             |
| `verify`  | Re-hash every archive member against the manifest; detect any tampering  |

**Backward compatible:** `python project_packager.py .` (no subcommand) still packages.

## Requirements

Python 3.11+ (uses `tomllib`). No third-party packages.

## Installation

It's one file. Copy `project_packager.py` anywhere on your path, or run it in place.

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

Trailing `/` marks a directory pattern; patterns containing `/` match against the relative POSIX path (and everything beneath it); plain patterns match file *and* directory names.

---

## `verify` — prove an archive is intact

```bash
python project_packager.py verify packaged\myproject_2026-07-03_1430.zip
```

Verifies the ZIP against its `.sha256` sidecar, then re-hashes **every member** against the embedded manifest. Any modified file, any missing file, and any file added to the archive that isn't in the manifest is reported as a `FAIL`. Exit 0 = intact, 1 = problems.

The manifest can also be inspected or verified with standard tools — it's plain JSON, and the sidecar works with `sha256sum -c`.

---

## Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Success / all checks passed / archive verified                 |
| 1    | `check` failures or `verify` problems                          |
| 2    | Project path missing or not a directory                        |
| 3    | Output ZIP already exists (use `--overwrite`)                  |
| 4    | OS error while writing                                         |
| 5    | Secrets found in strict/release mode (`--force` to override)   |
| 6    | Pre-package release checks failed (`--force` to override)      |

## What `--clean` will and won't touch

**Will delete:** `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `*.pyc`, `*.pyo`

**Will never delete:** virtualenvs, `build/`, `dist/`, logs, databases, ZIPs, or anything else. Cleaning is deliberately conservative — everything else is only *excluded from the archive*, never removed from disk. The `check` command never modifies anything at all.

## License

Apache License 2.0 — Copyright 2026 Leon Priest ([7h3v01d](https://github.com/7h3v01d))
