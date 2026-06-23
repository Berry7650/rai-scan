# Changelog

All notable project changes are documented here.

## 0.1.0 — 2026-06-23

Initial public release.

### Features

- Signature-based discovery of AI CLI binaries, packages, configuration,
  caches, shell lines, and systemd units.
- Conservative low-confidence reporting for other AI-related data.
- Terminal, JSON, Markdown, and HTML reports.
- Guided menu and command-line removal workflow.
- Recoverable trash and rollback support.
- Custom user signature overrides.
- Bundled AI-agent signature catalog.

### Safety

- Owner-only state directories and files.
- Signed rollback journals with a private integrity key.
- Rollback schema, source-confinement, and destination validation.
- Artifact identity checks using device, inode, mode, owner, size, and mtime.
- Package scope detection and explicit system-operation confirmation.
- Protected system-tree and sensitive user-path denylists.
- Safe custom-signature validation.
- Collision-resistant trash paths.
- Atomic shell-file replacement with non-UTF-8 byte preservation.
- Root execution refusal for installation, removal, rollback, and uninstall.
- Fresh scans before CLI and guided removals.
- Same-filesystem atomic file removal and restoration.
- Package and systemd identifier validation before subprocess execution.
- Daemon rollback that restores recorded enabled and running state.
- Fail-closed handling of incomplete package and daemon operations.

### Project

- Dependency-free Python runtime.
- Automated tests and Ruff linting.
- GitHub Actions across supported Python versions.
- MIT license, security policy, and installation documentation.
