# Project Packager — Quick Start

One file, no dependencies, Python 3.11+. Copy `project_packager.py` anywhere and run it.

```bash
python project_packager.py package .
```

That's the whole thing. It scans the current directory, drops caches, virtualenvs,
VCS metadata, build output and session debris, writes a timestamped ZIP into
`../packaged/`, embeds a per-file SHA-256 manifest, and writes a `.sha256`
sidecar next to it.

---

## The four commands

| Command | What it does |
|---------|--------------|
| `package` | Build a clean ZIP of your project |
| `verify` | Check an archive against its manifest and hash |
| `check` | Run release gates without packaging |
| `init` | Write starter `release_check.toml` + `.packagerignore` |

---

## Sending someone your code

```bash
python project_packager.py package . --name myproject
```

Look at the summary before you send it. The two lines that matter:

```text
Included files:          42
Excluded items:          18
```

Not sure what went in? Ask:

```bash
python project_packager.py package . --dry-run --list-included
```

`--dry-run` writes nothing and deletes nothing, so it's always safe to run first.

**Recipients verify it like this:**

```bash
python project_packager.py verify myproject_2026-07-19_1430.zip
```

---

## Cutting a release

```bash
python project_packager.py package . --profile release
```

Release mode is deliberately strict. It runs your release checks first, cleans
cache junk, applies extra privacy exclusions (`.env` and friends), and **refuses
to package** if it finds a secret or a text file it couldn't scan.

Expect it to say no the first few times. That's the point.

---

## The three profiles

| Profile | Use it for | Behaviour |
|---------|-----------|-----------|
| `share` *(default)* | Sending code to someone | Excludes junk, warns about secrets |
| `release` | Publishing | Adds checks, cleaning, strict exclusions; blocks on secrets |
| `backup` | Archiving your own work | Keeps almost everything, including `.venv` and `build/` |

---

## Controlling what goes in

**One-off, on the command line:**

```bash
python project_packager.py package . --exclude "notes/" --include "*.zip"
```

Both are repeatable. `--include` overrides exclusions, including inside an
excluded directory — so `--include ".vscode/settings.json"` works even though
`.vscode/` is excluded by default.

**Persistent, in `.packagerignore`:**

```text
# One pattern per line
notes/              a directory named notes, at any depth
/scratch/           only the scratch directory at the project root
data/raw/           that specific subtree
*.csv               any CSV file
```

Windows-style backslashes are fine — `data\raw\` means the same thing.

If `.packagerignore` exists but can't be read, packaging **fails** rather than
carrying on without your exclusions. That's on purpose: an unreadable ignore
file means you meant to exclude something.

---

## Release checks

```bash
python project_packager.py init .     # writes the starter config
python project_packager.py check .    # run the gates
```

`release_check.toml` is where per-project rules live:

```toml
schema_version = 1

[version]
target = "1.2.0"
files = ["pyproject.toml", "CHANGELOG.md"]   # all must contain the version

[required]
files = ["LICENSE", "README.md"]

[forbidden.patterns]
"private IP" = "192\\.168\\.\\d+\\.\\d+"
```

Unknown sections and typos are rejected outright — a misspelled `[requred]` that
silently does nothing is worse than one that fails visibly.

Run checks as part of packaging with `--check`, or use `--profile release`,
which includes them.

---

## Exit codes

Worth knowing if you script this.

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Checks failed, or verification found a problem |
| 2 | Project path missing or not a directory |
| 3 | Output ZIP already exists (use `--overwrite`) |
| 4 | Write error, or an archive with no verification evidence |
| 5 | Secrets, or unscannable text, in strict/release mode |
| 6 | Non-secret release checks failed |
| 7 | Partial verification — sidecar matched, no manifest to check against |
| 8 | A project file collides with the reserved `PACKAGE_MANIFEST.json` |
| 9 | `release_check.toml` or `.packagerignore` present but unusable |
| 10 | A source path escaped the project between scanning and writing |

---

## Things that will surprise you

**It refuses more than you expect, and that's deliberate.** A refused command
never modifies your project — no cleaning, no partial archives, nothing.

**Symlinks are never followed.** Not even with `--include`. A link pointing
outside the project is skipped and counted in the summary. This is the main
thing standing between you and accidentally packaging your home directory.

**`--force` is for judgement calls, not broken config.** It overrides secret
findings and failed checks. It will not override an unusable `.packagerignore`,
because that isn't a judgement call.

**`--clean` only ever deletes cache junk** — `__pycache__`, `.pytest_cache`,
`*.pyc`. It will not touch `.venv`, `build/`, `dist/`, logs, or databases.
Release mode enables it automatically.

**A secret in an excluded file won't block you.** Release mode scans exactly
what's going into the archive, so a key in `.env` is fine when `.env` isn't
being shipped.

---

## Current limitations

Read these before relying on it for anything important.

- **Replacement is not atomic.** A failed write can leave a partial file, and
  `--overwrite` can destroy a good archive. That's why `--overwrite` is refused
  in release mode unless you add `--force`. Fixed in v3.1.0.
- **`verify` is a corruption detector, not a hostile-archive verifier.** It
  doesn't yet reject duplicate members, unsafe member paths, or malformed
  manifest structure.
- **The secret scanner is heuristic.** It finds known token shapes in files it
  can read, and reports the files it couldn't. It cannot prove your project is
  secret-free — it supplements provider-side revocation and human review rather
  than replacing them.
- **Verification is integrity checking, not signing.** It detects corruption and
  confirms the archive matches its own manifest. Anyone who can replace the ZIP
  can also replace the sidecar, so a hash match only proves authenticity if you
  got the expected hash from somewhere you trust.

---

## Cheat sheet

```bash
# See what would happen, change nothing
python project_packager.py package . --dry-run --list-excluded

# Share with someone
python project_packager.py package . --name handoff

# Publish
python project_packager.py package . --profile release

# Back up everything, junk included
python project_packager.py package . --profile backup

# Check an archive you were sent
python project_packager.py verify handoff_2026-07-19_1430.zip

# Gates only, no packaging
python project_packager.py check .

# Rescue something the defaults dropped
python project_packager.py package . --include "docs/diagrams/*.png"
```

Full detail in `README.md`. Version history and known issues in `CHANGELOG.md`.
