import re
from pathlib import Path
from typing import Any, Dict, List

from rai_scan.models import ShellLine


SHELL_FILES = (
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".config/fish/config.fish",
)


def scan(signatures: Dict[str, Any]) -> List[ShellLine]:
    result = []
    for relative in SHELL_FILES:
        path = Path.home() / relative
        if not path.is_file():
            continue
        try:
            if path.is_symlink():
                continue
            stat = path.stat()
            lines = [
                line.decode("utf-8", errors="surrogateescape").rstrip("\r\n")
                for line in path.read_bytes().splitlines(keepends=True)
            ]
        except OSError:
            continue
        for number, content in enumerate(lines, 1):
            if content.lstrip().startswith("# rai-scan disabled"):
                continue
            for agent_id, signature in signatures["agents"].items():
                patterns = signature.get("shell_patterns", [])
                if any(
                    re.search(
                        r"(?<![\w-]){}(?![\w-])".format(re.escape(pattern)),
                        content,
                        re.IGNORECASE,
                    )
                    for pattern in patterns
                ):
                    result.append(
                        ShellLine(
                            str(path),
                            number,
                            content,
                            agent_id,
                            stat.st_dev,
                            stat.st_ino,
                            stat.st_mode,
                            stat.st_uid,
                        )
                    )
                    break
    return result
