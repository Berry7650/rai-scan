# Security policy

## Supported version

Security fixes are currently applied to the latest release:

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Trust model

`rai-scan` treats filesystem paths, local signature overrides, scan caches,
rollback records, package-manager output, shell startup files, and systemd
units as potentially unsafe input.

Mutating operations are designed to fail closed:

- Root execution is refused.
- State files must be regular files owned by the current user.
- Symlinked state, journal, and shell startup files are rejected.
- Removal uses a fresh scan and validates artifact identity before mutation.
- Protected system and sensitive user paths are denied.
- System findings require `--root` scope and explicit `SYSTEM` confirmation.
- Rollback records use an owner-only HMAC key and are validated before use.
- Rollback sources must stay under rai-scan trash.
- Non-atomic cross-filesystem moves are refused.
- External command arguments are validated before package or daemon actions.

The `--root` flag does not elevate privileges. The program never calls `sudo`
and intentionally refuses to run as root.

## Sensitive data

Scan caches and rollback records can contain:

- user paths;
- agent configuration locations;
- matched shell startup lines;
- package names and versions;
- service names.

The state directory is restricted to mode `0700`, and state files are
restricted to `0600`. Do not publish the contents of `~/.rai-scan` when filing
a report without reviewing and redacting them.

## Reporting a vulnerability

This workspace does not currently declare a public security contact or issue
tracker. Report vulnerabilities privately to the project maintainer and
include:

- the affected version;
- the exact command or workflow;
- expected and observed behavior;
- a minimal reproduction using temporary files where possible;
- whether root-owned files, credentials, or another user's data could be
  affected.

Do not include real credentials, private shell configuration, journal keys, or
unredacted rollback logs.

## Out of scope

The following are operational limitations rather than security guarantees:

- inaccurate third-party signatures;
- unavailable package versions during rollback;
- package-manager or systemd failures;
- modifications made directly to rai-scan trash outside the program;
- elevated execution achieved by modifying or removing the root refusal in
  the source code.
