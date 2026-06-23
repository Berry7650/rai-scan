import fcntl
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from rai_scan.config import ensure_state_dir, state_dir
from rai_scan.safety import (
    atomic_write_bytes,
    atomic_write_text,
    refuse_root,
    secure_existing_file,
    secure_open,
    secure_private_file,
)


def log_path() -> Path:
    return state_dir() / "rollback.log"


def _key_path() -> Path:
    return state_dir() / ".journal.key"


def _journal_key() -> bytes:
    path = _key_path()
    ensure_state_dir()
    if path.is_file():
        secure_private_file(path, "rollback journal key")
        return path.read_bytes()
    key = os.urandom(32)
    descriptor = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return key


def _sign_record(record: Dict[str, Any]) -> Dict[str, Any]:
    signed = dict(record)
    signed.pop("journal_hmac", None)
    payload = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed["journal_hmac"] = hmac.new(_journal_key(), payload, hashlib.sha256).hexdigest()
    return signed


def _verify_record(record: Dict[str, Any]) -> None:
    signature = record.get("journal_hmac")
    if not isinstance(signature, str):
        raise RuntimeError("rollback journal record is unsigned")
    expected = _sign_record(record)["journal_hmac"]
    if not hmac.compare_digest(signature, expected):
        raise RuntimeError("rollback journal record failed integrity validation")
    required = {
        "session_id": str,
        "state": str,
        "files_moved_to_trash": list,
        "packages_uninstalled": list,
        "shell_lines_commented": list,
        "daemons_disabled": list,
        "daemons_trashed": list,
    }
    for field, expected_type in required.items():
        if not isinstance(record.get(field), expected_type):
            raise RuntimeError("invalid rollback journal field: {}".format(field))


def append_record(record: Dict[str, Any]) -> None:
    path = ensure_state_dir() / "rollback.log"
    signed = _sign_record(record)
    record["journal_hmac"] = signed["journal_hmac"]
    with secure_open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        "rollback journal",
    ) as handle:
        handle.write(json.dumps(signed) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _restore_shell(entry: Dict[str, Any]) -> None:
    path = Path(entry["file"])
    try:
        path.resolve(strict=False).relative_to(Path.home().resolve())
    except ValueError:
        raise PermissionError("refusing shell restore outside home: {}".format(path))
    secure_existing_file(path, "shell startup file")
    lines = path.read_bytes().splitlines(keepends=True)
    index = entry["line_number"] - 1
    expected_suffix = ": {}".format(entry["content"]).encode(
        "utf-8", errors="surrogateescape"
    )
    if (
        index >= len(lines)
        or not lines[index].startswith(b"# rai-scan disabled ")
        or not lines[index].rstrip(b"\r\n").endswith(expected_suffix)
    ):
        raise RuntimeError("shell line changed after removal: {}:{}".format(path, index + 1))
    newline = b"\n" if lines[index].endswith(b"\n") else b""
    lines[index] = entry["content"].encode("utf-8", errors="surrogateescape") + newline
    mode = path.stat().st_mode & 0o777
    atomic_write_bytes(path, b"".join(lines), "shell startup file", mode)


def _acquire_lock(lock_path: Path):
    fd = secure_open(
        lock_path,
        os.O_RDWR | os.O_CREAT,
        "removal lock",
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


def _update_record(record: Dict[str, Any]) -> None:
    path = log_path()
    if not path.is_file():
        return
    secure_private_file(path, "rollback journal")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return
    if json.loads(lines[-1]).get("session_id") != record.get("session_id"):
        raise RuntimeError("rollback journal changed during rollback")
    signed = _sign_record(record)
    record["journal_hmac"] = signed["journal_hmac"]
    lines[-1] = json.dumps(signed)
    atomic_write_text(path, "\n".join(lines) + "\n", "rollback journal")


def _confined_trash_source(value: str) -> Path:
    source = Path(value)
    trash = (ensure_state_dir() / "trash").resolve(strict=False)
    try:
        source.resolve(strict=False).relative_to(trash)
    except ValueError:
        raise PermissionError("rollback source is outside rai-scan trash: {}".format(source))
    return source


def _allowed_restore_destination(value: str, include_root: bool) -> Path:
    destination = Path(value)
    resolved = destination.resolve(strict=False)
    if not include_root:
        try:
            resolved.relative_to(Path.home().resolve())
        except ValueError:
            raise PermissionError(
                "rollback destination is outside home: {}".format(destination)
            )
    from rai_scan.removal.engine import PROTECTED_PATHS

    if resolved in PROTECTED_PATHS:
        raise PermissionError("refusing protected rollback destination: {}".format(destination))
    return destination


def _run(command: List[str], description: str) -> None:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "{} failed".format(description))


def _reinstall_package(package: Dict[str, Any]) -> None:
    from rai_scan.removal.engine import _validate_package

    _validate_package(package)
    name = package["name"]
    version = package.get("version", "")
    manager = package["manager"]
    if manager == "pip":
        requirement = "{}=={}".format(name, version) if version else name
        executable = package.get("executable")
        command = (
            [executable, "install", requirement]
            if executable
            else [sys.executable, "-m", "pip", "install", requirement]
        )
    elif manager == "pipx":
        requirement = "{}=={}".format(name, version) if version else name
        command = [package.get("executable") or "pipx", "install", requirement]
    elif manager == "npm":
        requirement = "{}@{}".format(name, version) if version else name
        command = [package.get("executable") or "npm", "install", "-g", requirement]
    elif manager == "cargo":
        command = [package.get("executable") or "cargo", "install", name]
        if version:
            command.extend(["--version", version])
    else:
        raise RuntimeError("unsupported package manager: {}".format(manager))
    _run(command, "package reinstall")


def _restore_daemon_state(daemon: Dict[str, Any]) -> None:
    if daemon.get("type") != "systemd":
        return
    name = daemon.get("name", "")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.(?:service|timer)", name):
        raise PermissionError("refusing unsafe daemon name: {}".format(name))
    command = [daemon.get("executable") or "systemctl"]
    if daemon.get("scope", "user") == "user":
        command.append("--user")
    enabled = bool(daemon.get("enabled"))
    active = bool(daemon.get("active"))
    if enabled and active:
        _run(command + ["enable", "--now", name], "daemon enable and start")
    elif enabled:
        _run(command + ["enable", name], "daemon enable")
    elif active:
        _run(command + ["start", name], "daemon start")


def rollback_last() -> Dict[str, Any]:
    refuse_root("roll back removals")
    ensure_state_dir()
    path = log_path()
    if not path.is_file():
        raise RuntimeError("no rollback history found")
    secure_private_file(path, "rollback journal")
    lock_fd = _acquire_lock(state_dir() / ".removal.lock")
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        if not raw_lines:
            raise RuntimeError("no rollback history found")
        record = json.loads(raw_lines[-1])
        _verify_record(record)
        if record.get("state") == "rolled_back":
            raise RuntimeError("last removal session has already been rolled back")
        record["state"] = "rolling_back"
        record["rollback_errors"] = []
        record.setdefault("packages_reinstalled", [])
        record.setdefault("daemons_reenabled", [])
        _update_record(record)
        for item in reversed(record.get("files_moved_to_trash", [])):
            if not isinstance(item, dict):
                raise RuntimeError("invalid file restoration entry")
            source = _confined_trash_source(item["trash"])
            destination = _allowed_restore_destination(
                item["original"], bool(record.get("include_root"))
            )
            if not source.exists() and not source.is_symlink():
                if not destination.exists() and not destination.is_symlink():
                    record["rollback_errors"].append(
                        "file is missing from original and trash locations: {}".format(
                            destination
                        )
                    )
                    _update_record(record)
                continue
            if destination.exists() or destination.is_symlink():
                record["rollback_errors"].append(
                    "restore destination already exists: {}".format(destination)
                )
                _update_record(record)
                continue
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.rename(str(source), str(destination))
            except OSError as exc:
                record["rollback_errors"].append(
                    "could not restore {}: {}".format(destination, exc)
                )
                _update_record(record)
        for item in record.get("daemons_trashed", []):
            if not isinstance(item, dict):
                raise RuntimeError("invalid daemon restoration entry")
            source = _confined_trash_source(item["trash"])
            destination = _allowed_restore_destination(
                item["original"], bool(record.get("include_root"))
            )
            if not source.exists() and not source.is_symlink():
                if not destination.exists() and not destination.is_symlink():
                    record["rollback_errors"].append(
                        "daemon unit is missing from original and trash locations: {}".format(
                            destination
                        )
                    )
                    _update_record(record)
                continue
            if destination.exists() or destination.is_symlink():
                record["rollback_errors"].append(
                    "daemon restore destination already exists: {}".format(destination)
                )
                _update_record(record)
                continue
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.rename(str(source), str(destination))
            except (OSError, RuntimeError, PermissionError) as exc:
                record["rollback_errors"].append(
                    "could not restore daemon unit {}: {}".format(destination, exc)
                )
                _update_record(record)
        for item in record.get("shell_lines_commented", []):
            try:
                _restore_shell(item)
            except (OSError, RuntimeError, PermissionError) as exc:
                record["rollback_errors"].append(
                    "could not restore shell line {}:{}: {}".format(
                        item["file"], item["line_number"], exc
                    )
                )
                _update_record(record)
        for package in record.get("packages_uninstalled", []):
            state = package.get("journal_state", "complete")
            if state != "complete":
                if state in ("attempted", "failed"):
                    record["rollback_errors"].append(
                        "package operation state is uncertain; review manually: {} {}".format(
                            package.get("manager"), package.get("name")
                        )
                    )
                    _update_record(record)
                continue
            if package in record["packages_reinstalled"]:
                continue
            try:
                _reinstall_package(package)
                record["packages_reinstalled"].append(package)
                _update_record(record)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                record["rollback_errors"].append(
                    "could not reinstall {} {}: {}".format(
                        package["manager"], package["name"], exc
                    )
                )
                _update_record(record)
        for daemon in record.get("daemons_disabled", []):
            state = daemon.get("journal_state", "complete")
            if state != "complete":
                if state in ("attempted", "failed"):
                    record["rollback_errors"].append(
                        "daemon operation state is uncertain; review manually: {}".format(
                            daemon.get("name")
                        )
                    )
                    _update_record(record)
                continue
            if daemon in record["daemons_reenabled"]:
                continue
            try:
                _restore_daemon_state(daemon)
                record["daemons_reenabled"].append(daemon)
                _update_record(record)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                record["rollback_errors"].append(
                    "could not re-enable daemon {}: {}".format(daemon["name"], exc)
                )
                _update_record(record)
        record["state"] = "rolled_back" if not record["rollback_errors"] else "rollback_partial"
        _update_record(record)
        return record
    finally:
        _release_lock(lock_fd)
