import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rai_scan.config import ensure_state_dir, state_dir
from rai_scan.models import unique_non_overlapping
from rai_scan.safety import (
    atomic_write_bytes,
    atomic_write_text,
    refuse_root,
    reject_symlink_components,
    secure_directory,
    secure_existing_file,
    secure_open,
    secure_private_file,
)


PROTECTED_PATHS = {
    Path("/"),
    Path("/bin"),
    Path("/boot"),
    Path("/dev"),
    Path("/etc"),
    Path("/home"),
    Path("/lib"),
    Path("/lib64"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sbin"),
    Path("/sys"),
    Path("/tmp"),
    Path("/usr"),
    Path("/usr/bin"),
    Path("/usr/lib"),
    Path("/usr/local"),
    Path("/usr/local/bin"),
    Path("/var"),
}

PROTECTED_TREES = {
    Path("/boot"),
    Path("/dev"),
    Path("/etc"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sys"),
    Path("/var"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/usr/lib"),
}


def _inside_home(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(Path.home().resolve())
        return True
    except ValueError:
        return False


def _artifact_paths(agent: Dict[str, Any]) -> List[Path]:
    paths = [item["path"] for item in agent.get("artifacts", [])]
    return [Path(p) for p in unique_non_overlapping(paths)]


def _revalidate_paths(agent: Dict[str, Any]) -> List[str]:
    errors = []
    for item in agent.get("artifacts", []):
        path = Path(item["path"])
        if not path.exists() and not path.is_symlink():
            errors.append("path no longer exists: {}".format(item["path"]))
            continue
        try:
            reject_symlink_components(path.parent, "artifact path")
        except PermissionError as exc:
            errors.append(str(exc))
            continue
        resolved = path.resolve(strict=False)
        if path.is_symlink() and not resolved.exists():
            errors.append("dangling symlink: {}".format(item["path"]))
            continue
        try:
            info = path.lstat()
        except OSError as exc:
            errors.append("could not inspect {}: {}".format(path, exc))
            continue
        expected = {
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": info.st_mode,
            "uid": info.st_uid,
            "lstat_size": info.st_size,
        }
        for field, actual in expected.items():
            recorded = item.get(field)
            if recorded is not None and recorded != actual:
                errors.append("{} changed since scan: {}".format(field, path))
        recorded_mtime = item.get("mtime")
        if recorded_mtime is not None and recorded_mtime != info.st_mtime:
            errors.append("mtime changed since scan: {}".format(path))
    return errors


def preview(agents: List[Dict[str, Any]]) -> str:
    lines = []
    for agent in agents:
        lines.append("{}:".format(agent["display_name"]))
        lines.extend("  move {}".format(path) for path in _artifact_paths(agent))
        lines.extend(
            "  uninstall {}{} package {}".format(
                "system " if item.get("scope") == "system" else "",
                item["manager"],
                item["name"],
            )
            for item in agent.get("packages", [])
        )
        lines.extend(
            "  comment {}:{}".format(item["file"], item["line_number"])
            for item in agent.get("shell_lines", [])
        )
        for item in agent.get("daemons", []):
            label = "system " if item.get("scope") == "system" else ""
            lines.append("  disable {}{} unit {}".format(label, item.get("type", ""), item["name"]))
    return "\n".join(lines)


def _trash_destination(agent_id: str, source: Path, session: str) -> Path:
    digest = hashlib.sha256(os.fsencode(str(source))).hexdigest()[:20]
    safe_name = source.name or "root"
    safe_agent = re.sub(r"[^a-zA-Z0-9_.-]+", "_", agent_id).strip("._") or "unknown"
    return (
        ensure_state_dir()
        / "trash"
        / "{}_{}".format(safe_agent, session)
        / "{}_{}".format(digest, safe_name)
    )


def _validate_removal_path(source: Path, include_root: bool) -> None:
    resolved = source.resolve(strict=False)
    if resolved in PROTECTED_PATHS:
        raise PermissionError("refusing protected path: {}".format(source))
    if any(root == resolved or root in resolved.parents for root in PROTECTED_TREES):
        raise PermissionError("refusing protected system tree: {}".format(source))
    home = Path.home().resolve()
    if resolved == home:
        raise PermissionError("refusing home directory itself: {}".format(source))
    sensitive_user_trees = (home / ".ssh", home / ".gnupg", ensure_state_dir())
    if any(
        root.resolve(strict=False) == resolved
        or root.resolve(strict=False) in resolved.parents
        for root in sensitive_user_trees
    ):
        raise PermissionError("refusing sensitive user path: {}".format(source))
    if not include_root and not _inside_home(source):
        raise PermissionError("refusing system path without --root: {}".format(source))


def _move_artifacts(
    agent: Dict[str, Any],
    session: str,
    include_root: bool,
    record: Dict[str, Any],
) -> List[Dict[str, str]]:
    moved = []
    for source in _artifact_paths(agent):
        _validate_removal_path(source, include_root)
        if not (source.exists() or source.is_symlink()):
            continue
        destination = _trash_destination(agent["id"], source, session)
        secure_directory(destination.parent, "trash directory")
        entry = {"original": str(source), "trash": str(destination)}
        record["files_moved_to_trash"].append(entry)
        _update_last_record(record)
        try:
            os.rename(str(source), str(destination))
        except OSError as exc:
            if exc.errno == getattr(os, "EXDEV", 18):
                raise RuntimeError(
                    "refusing non-atomic cross-filesystem move: {}".format(source)
                )
            raise
        moved.append(entry)
    return moved


def _uninstall(package: Dict[str, Any]) -> None:
    _validate_package(package)
    executable = package.get("executable")
    if package["manager"] == "pip":
        if executable:
            command = [executable, "uninstall", "-y", package["name"]]
        else:
            command = [sys.executable, "-m", "pip", "uninstall", "-y", package["name"]]
    elif package["manager"] == "pipx":
        command = [executable or "pipx", "uninstall", package["name"]]
    elif package["manager"] == "npm":
        command = [executable or "npm", "uninstall", "-g", package["name"]]
    elif package["manager"] == "cargo":
        command = [executable or "cargo", "uninstall", package["name"]]
    else:
        raise RuntimeError("unsupported package manager: {}".format(package["manager"]))
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "package uninstall failed")


def _validate_package(package: Dict[str, Any]) -> None:
    manager = package.get("manager")
    name = package.get("name")
    patterns = {
        "pip": r"[A-Za-z0-9][A-Za-z0-9_.-]*",
        "pipx": r"[A-Za-z0-9][A-Za-z0-9_.-]*",
        "npm": r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]*",
        "cargo": r"[A-Za-z0-9][A-Za-z0-9_.-]*",
    }
    pattern = patterns.get(manager)
    if not pattern or not isinstance(name, str) or not re.fullmatch(pattern, name):
        raise PermissionError("refusing unsafe package identity: {} {}".format(manager, name))
    version = package.get("version", "")
    if version and (
        not isinstance(version, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*", version)
    ):
        raise PermissionError("refusing unsafe package version: {}".format(version))


def _disable_daemon(daemon: Dict[str, Any]) -> None:
    if daemon.get("type") != "systemd":
        return
    scope = daemon.get("scope", "user")
    name = daemon.get("name", "")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.(?:service|timer)", name):
        raise PermissionError("refusing unsafe daemon name: {}".format(name))
    cmd = [daemon.get("executable") or "systemctl"]
    if scope == "user":
        cmd.append("--user")
    cmd.extend(["disable", "--now", name])
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "could not disable daemon")


def _trash_daemon_unit(
    daemon: Dict[str, Any], session: str, record: Dict[str, Any]
) -> Dict[str, str]:
    unit_path = Path(daemon.get("path", ""))
    if not unit_path.is_file():
        return {}
    secure_existing_file(unit_path, "systemd unit")
    expected_parent = (
        Path("/etc/systemd/system")
        if daemon.get("scope") == "system"
        else Path.home() / ".config/systemd/user"
    )
    if unit_path.parent.resolve(strict=False) != expected_parent.resolve(strict=False):
        raise PermissionError("refusing unexpected systemd unit path: {}".format(unit_path))
    destination = _trash_destination(
        daemon.get("agent_hint", "unknown"), unit_path, session
    )
    secure_directory(destination.parent, "trash directory")
    entry = {"original": str(unit_path), "trash": str(destination)}
    record["daemons_trashed"].append(entry)
    _update_last_record(record)
    try:
        os.rename(str(unit_path), str(destination))
    except OSError as exc:
        if exc.errno == getattr(os, "EXDEV", 18):
            raise RuntimeError(
                "refusing non-atomic cross-filesystem move: {}".format(unit_path)
            )
        raise
    return entry


def _comment_shell_lines(
    lines: List[Dict[str, Any]], stamp: str, record: Dict[str, Any]
) -> List[Dict[str, Any]]:
    changed = []
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for line in lines:
        by_file.setdefault(line["file"], []).append(line)
    for filename, matches in by_file.items():
        path = Path(filename)
        if not _inside_home(path):
            raise PermissionError("refusing shell file outside home: {}".format(path))
        secure_existing_file(path, "shell startup file")
        if path.is_symlink():
            raise PermissionError("refusing symlinked shell startup file: {}".format(path))
        info = path.stat()
        original = path.read_bytes().splitlines(keepends=True)
        expected = {item["line_number"]: item["content"] for item in matches}
        for number, content in expected.items():
            index = number - 1
            actual = (
                original[index]
                .rstrip(b"\r\n")
                .decode("utf-8", errors="surrogateescape")
                if index < len(original)
                else None
            )
            if actual != content:
                raise RuntimeError("shell file changed since scan: {}:{}".format(path, number))
        for item in matches:
            for field, actual in (
                ("device", info.st_dev),
                ("inode", info.st_ino),
                ("mode", info.st_mode),
                ("uid", info.st_uid),
            ):
                if item.get(field) is not None and item[field] != actual:
                    raise RuntimeError(
                        "shell file {} changed since scan: {}".format(field, path)
                    )
        for number in sorted(expected, reverse=True):
            index = number - 1
            newline = b"\n" if original[index].endswith(b"\n") else b""
            content = original[index].rstrip(b"\r\n")
            original[index] = (
                "# rai-scan disabled {}: ".format(stamp).encode("utf-8")
                + content
                + newline
            )
            changed.append(
                {"file": filename, "line_number": number, "content": expected[number]}
            )
        record["shell_lines_commented"].extend(
            item for item in changed if item["file"] == filename
        )
        _update_last_record(record)
        atomic_write_bytes(
            path,
            b"".join(original),
            "shell startup file",
            stat.S_IMODE(info.st_mode),
        )
    return changed


def _acquire_lock(lock_path: Path):
    fd = secure_open(
        lock_path,
        os.O_RDWR | os.O_CREAT,
        "removal lock",
        encoding="utf-8",
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.close()
        raise RuntimeError(
            "another rai-scan removal or rollback is in progress; "
            "check ~/.rai-scan for stale lock files"
        )
    return fd


def _release_lock(fd) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
    except OSError:
        pass


def remove_agents(
    agents: List[Dict[str, Any]], include_root: bool = False
) -> Tuple[Dict[str, Any], List[str]]:
    refuse_root("remove agents")
    ensure_state_dir()
    now = datetime.now(timezone.utc).astimezone()
    session = now.strftime("%Y%m%dT%H%M%S.%f%z")
    lock_fd = _acquire_lock(state_dir() / ".removal.lock")
    try:
        record: Dict[str, Any] = {
            "session_id": now.isoformat(timespec="seconds"),
            "state": "started",
            "include_root": include_root,
            "agents_removed": [],
            "files_moved_to_trash": [],
            "packages_uninstalled": [],
            "shell_lines_commented": [],
            "daemons_disabled": [],
            "daemons_trashed": [],
            "errors": [],
        }
        from rai_scan.removal.rollback import append_record

        append_record(record)
        errors = []
        for agent in agents:
            validation_errors = _revalidate_paths(agent)
            if validation_errors:
                for err in validation_errors:
                    message = "{}: {}".format(agent["id"], err)
                    record["errors"].append(message)
                    errors.append(message)
                continue
            try:
                _move_artifacts(agent, session, include_root, record)
                for package in agent.get("packages", []):
                    if package.get("scope", "user") == "system" and not include_root:
                        raise PermissionError(
                            "refusing system package without --root: {} {}".format(
                                package["manager"], package["name"]
                            )
                        )
                    planned = dict(package)
                    planned["journal_state"] = "planned"
                    record["packages_uninstalled"].append(planned)
                    _update_last_record(record)
                    planned["journal_state"] = "attempted"
                    _update_last_record(record)
                    try:
                        _uninstall(package)
                    except Exception:
                        planned["journal_state"] = "failed"
                        _update_last_record(record)
                        raise
                    planned["journal_state"] = "complete"
                    _update_last_record(record)
                for daemon in agent.get("daemons", []):
                    if daemon.get("scope") == "system" and not include_root:
                        raise PermissionError(
                            "refusing system daemon without --root: {}".format(
                                daemon["name"]
                            )
                        )
                    planned_daemon = dict(daemon)
                    planned_daemon["journal_state"] = "planned"
                    record["daemons_disabled"].append(planned_daemon)
                    _update_last_record(record)
                    planned_daemon["journal_state"] = "attempted"
                    _update_last_record(record)
                    try:
                        _disable_daemon(daemon)
                    except Exception:
                        planned_daemon["journal_state"] = "failed"
                        _update_last_record(record)
                        raise
                    planned_daemon["journal_state"] = "complete"
                    _update_last_record(record)
                    _trash_daemon_unit(daemon, session, record)
                _comment_shell_lines(
                    agent.get("shell_lines", []), now.date().isoformat(), record
                )
                record["agents_removed"].append(agent["id"])
                _update_last_record(record)
            except Exception as exc:
                message = "{}: {} ({})".format(agent["id"], type(exc).__name__, exc)
                record["errors"].append(message)
                errors.append(message)
        record["state"] = "complete" if not errors else "partial"
        _update_last_record(record)
        return record, errors
    finally:
        _release_lock(lock_fd)


def _update_last_record(record: Dict[str, Any]) -> None:
    path = state_dir() / "rollback.log"
    if not path.is_file():
        return
    secure_private_file(path, "rollback journal")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return
    existing = json.loads(lines[-1])
    from rai_scan.removal.rollback import _sign_record, _verify_record

    _verify_record(existing)
    if existing.get("session_id") != record.get("session_id"):
        raise RuntimeError("rollback journal changed during removal")
    signed = _sign_record(record)
    record["journal_hmac"] = signed["journal_hmac"]
    lines[-1] = json.dumps(signed)
    atomic_write_text(
        path, "\n".join(lines) + "\n", "rollback journal"
    )
