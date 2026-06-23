import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set

from rai_scan.models import Package


def _run(command: List[str]) -> str:
    if not shutil.which(command[0]):
        return ""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=20, check=False
        )
        return result.stdout if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _wanted(signatures: Dict[str, Any], field: str) -> Set[str]:
    return {
        name.lower()
        for signature in signatures["agents"].values()
        for name in signature.get(field, [])
    }


def _scope_for_path(value: str) -> str:
    try:
        Path(value).resolve().relative_to(Path.home().resolve())
        return "user"
    except ValueError:
        return "system"


def _scan_pip(signatures: Dict[str, Any]) -> List[Package]:
    packages: List[Package] = []
    seen = set()
    executables = []
    for exe in ("pip", "pip3"):
        resolved = shutil.which(exe)
        if resolved and resolved not in executables:
            executables.append(resolved)
    for executable in executables:
        output = _run([executable, "list", "--format=json", "--disable-pip-version-check"])
        if not output:
            continue
        try:
            rows = json.loads(output)
        except json.JSONDecodeError:
            continue
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name", ""))
            key = ("pip", name.lower())
            if name.lower() in _wanted(signatures, "pip_packages") and key not in seen:
                seen.add(key)
                packages.append(Package(
                    "pip",
                    name,
                    str(row.get("version", "")),
                    executable=executable,
                    scope=_scope_for_path(executable),
                ))
    return packages


def scan(signatures: Dict[str, Any]) -> List[Package]:
    packages: List[Package] = []
    packages.extend(_scan_pip(signatures))

    pipx = shutil.which("pipx")
    output = _run([pipx, "list", "--json"]) if pipx else ""
    if output:
        try:
            data = json.loads(output)
            for name, details in data.get("venvs", {}).items():
                if name.lower() in _wanted(signatures, "pip_packages"):
                    metadata = details.get("metadata", {})
                    packages.append(
                        Package(
                            "pipx",
                            name,
                            str(metadata.get("main_package", {}).get("package_version", "")),
                            details.get("venv_dir"),
                            pipx,
                            "user",
                        )
                    )
        except (AttributeError, json.JSONDecodeError):
            pass

    npm = shutil.which("npm")
    npm_root = _run([npm, "root", "-g"]).strip() if npm else ""
    npm_scope = _scope_for_path(npm_root) if npm_root else "system"
    output = _run([npm, "list", "-g", "--depth=0", "--json"]) if npm else ""
    if output:
        try:
            dependencies = json.loads(output).get("dependencies", {})
            for name, details in dependencies.items():
                if name.lower() in _wanted(signatures, "npm_packages"):
                    packages.append(
                        Package(
                            "npm",
                            name,
                            str(details.get("version", "")),
                            npm_root or None,
                            npm,
                            npm_scope,
                        )
                    )
        except (AttributeError, json.JSONDecodeError):
            pass

    cargo = shutil.which("cargo")
    output = _run([cargo, "install", "--list"]) if cargo else ""
    cargo_home = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    wanted = _wanted(signatures, "cargo_packages")
    for line in output.splitlines():
        if line and not line[0].isspace() and " v" in line:
            name, version = line.split(" v", 1)
            if name.lower() in wanted:
                packages.append(
                    Package(
                        "cargo",
                        name,
                        version.rstrip(":"),
                        cargo_home,
                        cargo,
                        _scope_for_path(cargo_home),
                    )
                )
    return packages
