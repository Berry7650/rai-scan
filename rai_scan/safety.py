import os
import stat
import tempfile
from pathlib import Path
from typing import Optional


def refuse_root(operation: str) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise PermissionError(
            "refusing to {} while running as root; run rai-scan as your normal user".format(
                operation
            )
        )


def _existing_components(path: Path):
    current = path.absolute()
    components = [current]
    components.extend(current.parents)
    for component in reversed(components):
        if component.exists() or component.is_symlink():
            yield component


def reject_symlink_components(path: Path, label: str) -> None:
    for component in _existing_components(path):
        if component.is_symlink():
            raise PermissionError("{} contains a symlink: {}".format(label, component))


def secure_directory(path: Path, label: str = "directory") -> Path:
    reject_symlink_components(path, label)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    reject_symlink_components(path, label)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise PermissionError("{} is not a directory: {}".format(label, path))
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise PermissionError("{} is not owned by the current user: {}".format(label, path))
    path.chmod(0o700)
    return path


def secure_existing_file(path: Path, label: str) -> None:
    reject_symlink_components(path, label)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError("{} is not a regular file: {}".format(label, path))
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise PermissionError("{} is not owned by the current user: {}".format(label, path))


def secure_private_file(path: Path, label: str) -> None:
    secure_existing_file(path, label)
    path.chmod(0o600)


def secure_open(
    path: Path,
    flags: int,
    label: str,
    mode: int = 0o600,
    encoding: Optional[str] = "utf-8",
):
    secure_directory(path.parent, "{} parent".format(label))
    reject_symlink_components(path, label)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags | nofollow, mode)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise PermissionError("{} is not a regular file: {}".format(label, path))
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        os.close(descriptor)
        raise PermissionError("{} is not owned by the current user: {}".format(label, path))
    os.fchmod(descriptor, mode)
    file_mode = "r"
    if flags & os.O_APPEND:
        file_mode = "a"
    elif flags & os.O_WRONLY or flags & os.O_RDWR:
        file_mode = "w"
    return os.fdopen(descriptor, file_mode, encoding=encoding)


def atomic_write_bytes(path: Path, content: bytes, label: str, mode: int = 0o600) -> None:
    parent = secure_directory(path.parent, "{} parent".format(label))
    if path.exists() or path.is_symlink():
        secure_existing_file(path, label)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".rai-scan-", dir=str(parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        directory_fd = os.open(str(parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: Path, content: str, label: str, mode: int = 0o600) -> None:
    atomic_write_bytes(path, content.encode("utf-8"), label, mode)
