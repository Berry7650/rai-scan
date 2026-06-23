import os
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from rai_scan.classifier.size import disk_usage
from rai_scan.models import Artifact


def _expand(relative: str) -> Path:
    path = Path(relative).expanduser()
    return path if path.is_absolute() else Path.home() / path


def _bin_dirs(include_root: bool) -> Iterable[Path]:
    home = Path.home()
    paths = [
        home / ".local/bin",
        home / "bin",
        home / ".cargo/bin",
        home / ".npm-global/bin",
    ]
    prefix = os.environ.get("PREFIX")
    if prefix:
        paths.append(Path(prefix) / "bin")
    if include_root:
        paths.extend([Path("/usr/local/bin"), Path("/usr/bin"), Path("/opt")])
    return paths


def scan(signatures: Dict[str, Any], include_root: bool = False) -> List[Artifact]:
    found: List[Artifact] = []
    seen: Set[str] = set()

    def add(path: Path, kind: str, hint: str) -> None:
        key = str(path)
        if key in seen or not (path.exists() or path.is_symlink()):
            return
        seen.add(key)
        try:
            stat = path.lstat()
            size = disk_usage(path)
            found.append(
                Artifact(
                    key,
                    kind,
                    size,
                    stat.st_mtime,
                    hint,
                    stat.st_dev,
                    stat.st_ino,
                    stat.st_mode,
                    stat.st_uid,
                    stat.st_size,
                )
            )
        except OSError:
            return

    for agent_id, signature in signatures["agents"].items():
        for binary in signature.get("binaries", []):
            resolved = shutil.which(binary)
            if resolved:
                add(Path(resolved), "binary", agent_id)
            for directory in _bin_dirs(include_root):
                add(directory / binary, "binary", agent_id)
        for relative in signature.get("binary_paths", []):
            add(_expand(relative), "binary", agent_id)
        for relative in signature.get("config_dirs", []):
            add(_expand(relative), "config", agent_id)
        for relative in signature.get("cache_dirs", []):
            add(_expand(relative), "cache", agent_id)
        for pattern in signature.get("config_globs", []):
            expanded = _expand(pattern)
            for path in expanded.parent.glob(expanded.name):
                add(path, "config", agent_id)
        for pattern in signature.get("cache_globs", []):
            expanded = _expand(pattern)
            for path in expanded.parent.glob(expanded.name):
                add(path, "cache", agent_id)
    return found


def broken_bin_symlinks(include_root: bool = False) -> List[Artifact]:
    result = []
    for directory in _bin_dirs(include_root):
        if not directory.is_dir():
            continue
        try:
            for path in directory.iterdir():
                if path.is_symlink() and not path.exists():
                    result.append(Artifact(str(path), "broken_symlink", 0, agent_hint=None))
        except OSError:
            continue
    return result
