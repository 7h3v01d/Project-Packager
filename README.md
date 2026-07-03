# Project Packager

A small, safe, audit-friendly Python project packaging CLI.

Create a clean, **verifiable** ZIP of a Python project for sharing, uploading, or archiving — with an embedded SHA-256 manifest, a hash sidecar, and a built-in secret scanner so credentials never leave your machine by accident.

**Standard library only. Single file. No dependencies. Windows-friendly.**

---

## Why

Zipping a project folder by hand ships everything: `__pycache__`, `.git`, virtualenvs, old ZIPs nested inside new ZIPs, `.bak` debris, stray patch scripts — and occasionally an API key. Project Packager produces a clean archive by default, proves exactly what's inside it, and refuses to ship secrets in release mode.

## Features

- **Safe by default** — never deletes or modifies your project unless you explicitly pass `--clean` (and even then, only disposable cache junk: `__pycache__`, `.pytest_cache`, `*.pyc`, etc.)
- **Sensible exclusions** — caches, VCS folders, virtualenvs, build output, editor folders, session debris (`*.bak`, `*.tmp`, `patch_*.py`, …), and existing `*.zip` files
- **Embedded manifest** — every ZIP contains `PACKAGE_MANIFEST.json` with per-file SHA-256 hashes and sizes
- **Hash sidecar** — a `sha256sum`-compatible `<zip>.sha256` file is written beside the archive
- **Secret scanner** — included text files are scanned for AWS, Anthropic, OpenAI, GitHub, Slack, and Google keys plus private-key blocks; warns by default, **blocks packaging** in release/strict mode
- **Profiles** — `share` (default), `release` (strict + clean + fail-on-secrets), `backup` (keep almost everything)
- **`.packagerignore`** — per-project exclusion rules, gitignore-lite syntax
- **Path-aware patterns** — any pattern containing `/` matches against the relative path (e.g. `tests/web_app.py`, `data/raw/`)
- **Force-include** — `--include` overrides every exclusion when you need to rescue something
- **Clear reporting** — exclusions grouped by reason, top-5 largest included files, large-file warnings, ZIP hash

## Requirements

Python 3.10+ (uses modern type syntax). No third-party packages.

## Installation

It's one file. Copy `project_packager.py` anywhere on your path, or run it in place:

```bash
python project_packager.py --help
```

## Quick start

```bash
# Preview what would be packaged — writes and deletes nothing
python project_packager.py C:\path\to\myproject --dry-run

# Package it (ZIP lands in ..\packaged\ beside the project)
python project_packager.py C:\path\to\myproject

# Shippable build: strict exclusions, cache cleanup, fails if secrets found
python project_packager.py C:\path\to\myproject --profile release

# Full snapshot, minimal exclusions, no secret scan
python project_packager.py C:\path\to\myproject --profile backup
```

Output filename is timestamped automatically: `myproject_2026-07-03_1430.zip`.

## Profiles

| Profile   | Exclusions                          | Clean | Secret scan            |
|-----------|-------------------------------------|-------|------------------------|
| `share`   | Standard (default)                  | opt-in| Warns                  |
| `release` | Standard + strict privacy set       | yes   | **Blocks** (see below) |
| `backup`  | Minimal (`.git`, caches only)       | opt-in| Off                    |

`release` implies `--strict --clean` and exits with code `5` if possible secrets are found in included files. Fix the findings, exclude the files, or override with `--force`.

`--strict` (usable with any profile) additionally excludes `.env`, `.env.*`, `*.key`, `*.pem`, `*.crt`, `credentials.json`, `id_rsa*`, `secrets/` directories, and similar.

## Options

```
project                Project directory to package (default: .)
--profile {share,release,backup}
--output, -o PATH      Output folder (default: ./packaged beside the project)
--name, -n NAME        Custom base name; timestamp is still appended
--dry-run              Show the plan; write and delete nothing
--clean                Delete only safe cache junk before packaging
--strict               Extra privacy exclusions + secrets block packaging
--exclude PATTERN      Extra exclusion (repeatable; '/' in pattern = path match)
--include PATTERN      Force-include (repeatable; beats all exclusions)
--no-scan              Disable the secret scanner
--no-manifest          Skip embedding PACKAGE_MANIFEST.json
--force                Package anyway despite secret findings
--overwrite            Allow overwriting an existing ZIP of the same name
--open                 Open the output folder when done
--list-included        Print every included file
--list-excluded        Print every excluded item with its reason
```

## `.packagerignore`

Drop a `.packagerignore` file in the project root. One pattern per line:

```
# comments allowed
*.log
docs/
data/raw/
notes/scratch_*.md
```

- Trailing `/` marks a directory pattern
- Patterns containing `/` match against the relative POSIX path (and everything beneath it)
- Plain patterns match file *and* directory names

## Verifying a package

Every archive can be independently verified:

```bash
# 1. Verify the ZIP itself against the sidecar
sha256sum -c myproject_2026-07-03_1430.zip.sha256

# 2. Inspect the embedded manifest
python -c "import zipfile, json; print(json.dumps(json.loads(zipfile.ZipFile('myproject_2026-07-03_1430.zip').read('PACKAGE_MANIFEST.json')), indent=2))"
```

The manifest records the tool version, UTC creation time, file count, total bytes, and a SHA-256 hash for every file in the archive.

## Secret scanner

Included text files up to 1 MB are scanned for high-confidence credential patterns:

- AWS access keys (`AKIA…`)
- Anthropic API keys (`sk-ant-…`)
- OpenAI-style keys (`sk-…`)
- GitHub tokens (`ghp_…`, `github_pat_…`)
- Slack tokens (`xox…`)
- Google API keys (`AIza…`)
- `-----BEGIN PRIVATE KEY-----` blocks

Findings are reported with file, line number, and a redacted preview. Binary files are skipped automatically. The scanner is read-only and never modifies your files.

## Exit codes

| Code | Meaning                                           |
|------|---------------------------------------------------|
| 0    | Success                                           |
| 2    | Project path missing or not a directory           |
| 3    | Output ZIP already exists (use `--overwrite`)     |
| 4    | OS error while writing the ZIP                    |
| 5    | Secrets found in strict/release mode (`--force` to override) |

Non-zero codes make it easy to wire into batch files and CI steps.

## What `--clean` will and won't touch

**Will delete:** `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `*.pyc`, `*.pyo`

**Will never delete:** virtualenvs, `build/`, `dist/`, logs, databases, ZIPs, or anything else. Cleaning is deliberately conservative — everything else is only *excluded from the archive*, never removed from disk.

## License

Apache License 2.0 — Copyright 2026 Leon Priest ([7h3v01d](https://github.com/7h3v01d))
