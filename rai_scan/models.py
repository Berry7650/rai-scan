from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Artifact:
    path: str
    type: str
    size_bytes: int = 0
    mtime: Optional[float] = None
    agent_hint: Optional[str] = None
    device: Optional[int] = None
    inode: Optional[int] = None
    mode: Optional[int] = None
    uid: Optional[int] = None
    lstat_size: Optional[int] = None


@dataclass
class Package:
    manager: str
    name: str
    version: str = ""
    install_path: Optional[str] = None
    executable: Optional[str] = None
    scope: str = "user"


@dataclass
class ShellLine:
    file: str
    line_number: int
    content: str
    agent_hint: str
    device: Optional[int] = None
    inode: Optional[int] = None
    mode: Optional[int] = None
    uid: Optional[int] = None


@dataclass
class DaemonEntry:
    type: str
    name: str
    path: str
    enabled: bool = False
    agent_hint: Optional[str] = None
    scope: str = "user"
    active: bool = False
    executable: Optional[str] = None


@dataclass
class AgentBundle:
    id: str
    display_name: str
    version_detected: str = ""
    confidence: str = "medium"
    total_bytes: int = 0
    artifacts: List[Artifact] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)
    shell_lines: List[ShellLine] = field(default_factory=list)
    daemons: List[DaemonEntry] = field(default_factory=list)


def unique_non_overlapping(paths: List[str]) -> List[str]:
    sorted_paths = sorted(paths, key=lambda p: len(Path(p).parts))
    result: List[str] = []
    keep: List[Path] = []
    for p in sorted_paths:
        path = Path(p)
        if any(root == path or root in path.parents for root in keep):
            continue
        keep.append(path)
        result.append(p)
    return result


def to_dict(value: Any) -> Dict[str, Any]:
    return asdict(value)
