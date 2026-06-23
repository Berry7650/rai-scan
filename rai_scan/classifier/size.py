import os
from pathlib import Path
from typing import Set


def disk_usage(path: Path) -> int:
    try:
        if path.is_symlink() or path.is_file():
            return path.lstat().st_size
    except OSError:
        return 0

    total = 0
    seen: Set[str] = set()
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            key = str(current.resolve())
            if key in seen:
                continue
            seen.add(key)
            with os.scandir(str(current)) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            total += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return "{:.0f} {}".format(value, unit) if unit == "B" else "{:.1f} {}".format(value, unit)
        value /= 1024
    return "{} B".format(size)
