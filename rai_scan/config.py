import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict

from rai_scan.safety import secure_directory, secure_private_file


def state_dir() -> Path:
    override = os.environ.get("RAI_SCAN_HOME")
    path = Path(override).expanduser() if override else Path.home() / ".rai-scan"
    if not path.is_absolute():
        raise ValueError("RAI_SCAN_HOME must be an absolute path")
    return path


def ensure_state_dir() -> Path:
    return secure_directory(state_dir(), "rai-scan state directory")


def bundled_signatures_path() -> Path:
    return Path(__file__).with_name("signatures.json")


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_custom_signatures(data: Dict[str, Any]) -> None:
    agents = data.get("agents")
    if not isinstance(agents, dict):
        raise ValueError("custom signatures must contain an 'agents' object")
    home = Path.home().resolve()
    sensitive = [home / ".ssh", home / ".gnupg", home / ".rai-scan"]
    path_fields = ("binary_paths", "config_dirs", "cache_dirs")
    glob_fields = ("config_globs", "cache_globs")
    string_list_fields = (
        "binaries",
        "pip_packages",
        "npm_packages",
        "cargo_packages",
        "shell_patterns",
        "systemd_patterns",
    )
    for agent_id, signature in agents.items():
        if not isinstance(agent_id, str) or not isinstance(signature, dict):
            raise ValueError("custom signature entries must be objects")
        for field in string_list_fields:
            values = signature.get(field, [])
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value for value in values
            ):
                raise ValueError("{} must be a list of non-empty strings".format(field))
        for field in path_fields + glob_fields:
            values = signature.get(field, [])
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError("{} must be a list of paths".format(field))
            for value in values:
                expanded = Path(value).expanduser()
                expanded = expanded if expanded.is_absolute() else home / expanded
                parent = expanded.parent if field in glob_fields else expanded
                resolved = parent.resolve(strict=False)
                try:
                    resolved.relative_to(home)
                except ValueError:
                    raise ValueError(
                        "custom signature paths must stay inside home: {}".format(value)
                    )
                if resolved == home or any(
                    root == resolved or root in resolved.parents for root in sensitive
                ):
                    raise ValueError("refusing sensitive custom signature path: {}".format(value))
        binaries = signature.get("binaries", [])
        if not isinstance(binaries, list) or any(
            not isinstance(value, str)
            or not value
            or Path(value).name != value
            for value in binaries
        ):
            raise ValueError("custom signature binaries must be command names")
        package_patterns = {
            "pip_packages": r"[A-Za-z0-9][A-Za-z0-9_.-]*",
            "npm_packages": r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]*",
            "cargo_packages": r"[A-Za-z0-9][A-Za-z0-9_.-]*",
        }
        for field, pattern in package_patterns.items():
            if any(not re.fullmatch(pattern, value) for value in signature.get(field, [])):
                raise ValueError("unsafe package name in {}".format(field))


def load_signatures() -> Dict[str, Any]:
    bundled = _load_json(bundled_signatures_path())
    if not isinstance(bundled.get("agents"), dict):
        raise ValueError("bundled signatures.json must contain an 'agents' object")
    user_path = state_dir() / "signatures.json"
    if not user_path.is_file():
        return bundled
    try:
        secure_private_file(user_path, "custom signatures")
        user_data = _load_json(user_path)
        _validate_custom_signatures(user_data)
    except (json.JSONDecodeError, OSError, PermissionError, ValueError) as exc:
        print(
            "Warning: ignoring invalid user signatures ({}): {}".format(user_path, exc),
            file=sys.stderr,
        )
        return bundled
    if not isinstance(user_data.get("agents"), dict):
        print(
            "Warning: ignoring user signatures without 'agents' object: {}".format(user_path),
            file=sys.stderr,
        )
        return bundled
    merged = dict(bundled)
    merged["agents"] = dict(bundled["agents"])
    merged["agents"].update(user_data["agents"])
    return merged
