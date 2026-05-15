# snitch

> Scan locally-installed tools and packages for known-malicious or suspicious code.

`snitch` is a defensive CLI that inventories every package, tool, extension, and
binary you've installed and cross-references each one against advisory
databases, IOC feeds, heuristic rules, and static-analysis checks. It runs
locally, caches its intel, and produces a ranked report so you can decide what
to remove.

## Status

Alpha. The MVP scans `pip`, `npm`, Homebrew, Go binaries, Cursor/VS Code
extensions, GitHub-cloned repos, and arbitrary binaries on `$PATH`.

## Install

```bash
pipx install .
# or, for development
uv pip install -e ".[dev,ast]"
```

## Quickstart

```bash
snitch update              # refresh advisory + malicious-package mirrors
snitch scan                # scan every supported ecosystem
snitch scan --ecosystem pip,npm --deep
snitch inspect pip:requests@2.31.0
snitch report --format md --out report.md
```

## What it checks

- **Advisories** — OSV.dev (covers GHSA, PyPA, npm, Go, RubyGems, crates.io).
- **Known malicious packages** — local mirror of [`ossf/malicious-packages`](https://github.com/ossf/malicious-packages).
- **Heuristics** — install/postinstall scripts, recent publishes, sole-maintainer flips, repo-URL mismatches, typosquats.
- **Static analysis** — JS (tree-sitter) and Python (`ast`) rules for `eval`, `child_process`, `subprocess`, base64+exec, dynamic require/import, etc.
- **Binaries** — SHA-256 + codesign + (opt-in) VirusTotal hash lookup. No file uploads.

## Configuration

`snitch` keeps all its data in a single hidden directory so multiple checkouts
can't poison each other. Each run it picks the best location automatically:

1. **App-local (default)** — `<project_root>/.snitch/`, next to the
   `pyproject.toml` of the installed snitch package. Used when that directory
   is discoverable and writable. The `.snitch/` dir is `.gitignore`'d.
2. **XDG fallback** — `~/Library/Caches/snitch/` and
   `~/Library/Application Support/snitch/` on macOS (or `$XDG_CACHE_HOME` /
   `$XDG_CONFIG_HOME` on Linux). Used when there's no project root —
   typically a `pipx install snitch` into site-packages.

Inside the chosen directory:

- `snitch.db` — SQLite cache (advisories, malicious-package index, VT hashes,
  scan history).
- `malicious-packages/` — local clone of
  [`ossf/malicious-packages`](https://github.com/ossf/malicious-packages).
- `ignore.toml` — your allow-list.

If you previously ran an older snitch and have data in XDG, the first run
after this change migrates it automatically into the app-local directory so
you don't have to re-download the 200k-entry mirror.

```bash
snitch where        # print the resolved data dir and whether legacy data exists
snitch migrate      # explicitly move XDG data into the app-local directory
snitch ignore path  # print the allow-list path
```

Optional environment variables:

- `SNITCH_VT_API_KEY` — VirusTotal API key for binary hash lookups.

## Adding a heuristic

Drop a new rule in `src/snitch/heuristics/` that returns `Finding`s. Register
it in the orchestrator. See `heuristics/npm_rules.py` for examples.

## License

MIT
