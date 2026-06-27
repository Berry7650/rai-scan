# rai-scan — Linux AI CLI Agent Scanner & Safe Cleanup Tool

`rai-scan` detects known AI CLI agents and leftover files from tools such as Codex, Claude, Gemini, OpenAI CLI tools, Copilot-related CLIs, npm packages, pipx apps, cargo binaries, shell startup lines, cache directories, config directories, and systemd units.

It is built for safe cleanup: removals use preview mode, explicit confirmation, recoverable trash, rollback journals, and root-execution refusal.

`rai-scan` finds known AI CLI agents, estimates their disk usage, and can remove
their files through recoverable trash.

Current release: **0.1.0**

The scanner recognizes binaries, package-manager installations, configuration
and cache directories, shell startup lines, and systemd units. Low-confidence
AI-related data is reported separately and is never automatically removed.

## Important safety boundary

`rai-scan` is designed for normal-user cleanup. It refuses to perform
installation, removal, rollback, or uninstallation while running as root.

The `--root` option means “include and explicitly approve system-scoped
findings.” It does not grant privileges, invoke `sudo`, or bypass operating
system permissions. A normal user generally cannot modify root-owned files or
services, even with `--root`.

## Requirements

- Linux
- Python 3.8 or newer
- Optional package managers (`pipx`, `npm`, and `cargo`) for detecting and
  removing packages installed by those tools

## Install

From the project directory:

```sh
./install.sh
```

The installer creates an isolated `.venv` and a launcher at
`~/.local/bin/rai-scan`. If isolated build tooling is unavailable, it prints a
warning and falls back to a virtual environment that can see system-site build
packages; the rai-scan runtime itself has no third-party dependencies.

For development:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## Usage

Open the guided interface:

```sh
rai-scan
```

List detected agents using a fresh scan:

```sh
rai-scan list --no-cache --verbose
```

Export machine-readable results:

```sh
rai-scan list --json
rai-scan list --md
rai-scan list --html
```

Preview removal without changing anything:

```sh
rai-scan remove claude --dry-run --no-cache
```

Remove an agent after an explicit confirmation:

```sh
rai-scan remove claude
```

Removal always performs a fresh scan. The command prints every planned
operation and requires typing `YES`.

System-scoped findings require expanded scanning and a second confirmation:

```sh
rai-scan remove example-agent --root
```

When system-level operations are present, the command requires both `YES` and
`SYSTEM`. It still runs with the current user's permissions.

Undo the latest removal session:

```sh
rai-scan rollback
```

Only the latest removal session can be rolled back. A partial rollback can be
retried; already restored packages and daemons are not repeated.

### Commands

| Command | Purpose |
|---|---|
| `rai-scan` or `rai-scan menu` | Open the guided interface |
| `rai-scan list` | List detected agents |
| `rai-scan remove NAME` | Preview and remove one or more agents |
| `rai-scan rollback` | Restore the latest recorded removal |
| `rai-scan add-sig ...` | Add or replace a local signature |
| `rai-scan reset-sig` | Delete local signature overrides |

Common options:

- `--dry-run`: preview removal without changing anything.
- `--no-cache`: force a fresh scan for listing or reporting.
- `--root`: include system paths and permit system-scoped attempts.
- `--verbose`: display matched artifact paths.
- `--json`, `--md`, `--html`: select report output.

## Safety model

- Known signatures and low-confidence heuristic findings are kept separate.
- Every CLI removal prints a preview and requires typing `YES`.
- System-scoped removal requires a second `SYSTEM` confirmation.
- Removal always performs a fresh scan rather than trusting a cached manifest.
- Files are moved to `~/.rai-scan/trash`; they are not immediately deleted.
- File, unit, and shell changes use a write-ahead rollback journal.
- State directories are owner-only (`0700`) and state files are `0600`.
- Rollback records are integrity-signed and confined to rai-scan trash paths.
- Paths are revalidated immediately before removal.
- Device, inode, type, owner, size, and modification time are checked where available.
- Symlinked state, journal, and shell startup files are rejected.
- Shell lines are changed only if their content still matches the scan.
- File moves must be atomic and remain on one filesystem.
- Concurrent removal and rollback operations are blocked with a file lock.
- Scan caches expire after five minutes and are tied to scan scope and the
  active signature catalog.
- Custom signature paths are confined to the current user's home and cannot
  target sensitive directories such as `.ssh`, `.gnupg`, or rai-scan state.
- Package names, versions, and systemd unit names are validated before being
  passed to external tools.
- Protected operating-system trees are denied even during `--root` operations.

Rollback restores moved files and shell lines, then attempts to reinstall
removed packages and re-enable disabled daemons. External package managers or
system services can still fail; such failures are reported as a partial
rollback.

### Safety limitations

- Detection is signature-based and may produce false positives. Always inspect
  the preview.
- Package reinstalls depend on external registries, package availability, and
  package-manager state.
- Daemon restoration depends on a working systemd user or system service.
- Recoverable file moves must remain on the same filesystem as
  `~/.rai-scan/trash`; cross-filesystem moves are refused.
- `--root` does not make root-owned operations succeed.
- Rollback journals without a valid integrity signature are rejected.

See [SECURITY.md](SECURITY.md) for the trust model and vulnerability-reporting
guidance.

## Custom signatures

Add a local signature override:

```sh
rai-scan add-sig \
  --name example-agent \
  --bin example-agent \
  --config ~/.config/example-agent \
  --cache ~/.cache/example-agent
```

Custom overrides are stored in `~/.rai-scan/signatures.json`. Reset them with:

```sh
rai-scan reset-sig
```

Custom signature restrictions:

- Paths must remain inside the current user's home.
- The home directory itself cannot be targeted.
- `.ssh`, `.gnupg`, and rai-scan state cannot be targeted.
- Binary entries must be plain command names, not paths.
- Low-confidence heuristic findings cannot be converted into automatic removal
  candidates without an explicit signature.

## State and recovery files

By default, state is stored under `~/.rai-scan`:

| Path | Contents |
|---|---|
| `last_scan.json` | Short-lived scan cache |
| `signatures.json` | Local signature overrides |
| `rollback.log` | Signed removal and rollback journal |
| `.journal.key` | Private journal-integrity key |
| `trash/` | Recoverable moved files and units |

The state directory is forced to mode `0700`; state files and integrity keys
are forced to `0600`. Set `RAI_SCAN_HOME` to an absolute path to relocate this
state.

Do not edit `rollback.log`, `.journal.key`, or files under `trash/`. Journal
tampering intentionally causes rollback to fail closed.

## Development

Run tests and lint checks:

```sh
.venv/bin/python -m pytest
.venv/bin/ruff check .
```

Build a wheel:

```sh
.venv/bin/python -m pip wheel . --no-build-isolation --no-deps --wheel-dir dist
```

The runtime has no third-party Python dependencies.

## Uninstall

```sh
./uninstall.sh
```

To also permanently remove recoverable trash and rollback history:

```sh
./uninstall.sh --purge-state
```

Preview either operation safely:

```sh
./uninstall.sh --dry-run
./uninstall.sh --dry-run --purge-state
```

Uninstall refuses root execution, symlinked state directories, and unsafe
canonical state paths.

## Release history

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
