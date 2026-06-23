from pathlib import Path
from typing import List

from rai_scan.models import Artifact
from rai_scan.probes.fs_probe import broken_bin_symlinks


def find_orphans(include_root: bool = False) -> List[Artifact]:
    orphans = broken_bin_symlinks(include_root)
    for item in orphans:
        item.agent_hint = "broken_symlink"
        if not Path(item.path).is_symlink():
            item.agent_hint = "unknown"
    return orphans
