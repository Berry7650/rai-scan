import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from rai_scan.models import DaemonEntry


def _systemctl_state(name: str, scope: str, executable: str) -> tuple:
    base = [executable]
    if scope == "user":
        base.append("--user")

    def check(command: str) -> bool:
        try:
            result = subprocess.run(
                base + [command, name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    return check("is-enabled"), check("is-active")


def scan(signatures: Dict[str, Any], include_root: bool = False) -> List[DaemonEntry]:
    if os.environ.get("TERMUX_VERSION") or Path("/data/data/com.termux").exists():
        return []
    directories = [(Path.home() / ".config/systemd/user", "user")]
    if include_root:
        directories.append((Path("/etc/systemd/system"), "system"))
    result = []
    systemctl = shutil.which("systemctl")
    for directory, scope in directories:
        if not directory.is_dir():
            continue
        for path in list(directory.glob("*.service")) + list(directory.glob("*.timer")):
            lowered = path.name.lower()
            for agent_id, signature in signatures["agents"].items():
                if any(
                    re.search(
                        r"(^|[^a-z0-9]){}([^a-z0-9]|$)".format(
                            re.escape(pattern.lower())
                        ),
                        lowered,
                    )
                    for pattern in signature.get("systemd_patterns", [])
                ):
                    enabled, active = (
                        _systemctl_state(path.name, scope, systemctl)
                        if systemctl
                        else (False, False)
                    )
                    result.append(
                        DaemonEntry(
                            "systemd",
                            path.name,
                            str(path),
                            enabled,
                            agent_id,
                            scope,
                            active,
                            systemctl,
                        )
                    )
                    break
    return result
