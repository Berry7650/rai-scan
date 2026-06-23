import hashlib
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from rai_scan.classifier.matcher import classify
from rai_scan.classifier.orphan import find_orphans
from rai_scan.config import ensure_state_dir, load_signatures, state_dir
from rai_scan.models import to_dict, unique_non_overlapping
from rai_scan.probes import ai_related_probe, daemon_probe, fs_probe, pkg_probe, shell_probe
from rai_scan.safety import atomic_write_text, secure_private_file


CACHE_MAX_AGE_SECONDS = 300
SCHEMA_VERSION = 3


def cache_path() -> Path:
    return state_dir() / "last_scan.json"


def _signature_fingerprint(signatures: Dict[str, Any]) -> str:
    encoded = json.dumps(signatures, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def scan_system(include_root: bool = False, write_cache: bool = True) -> Dict[str, Any]:
    signatures = load_signatures()
    artifacts = fs_probe.scan(signatures, include_root)
    packages = pkg_probe.scan(signatures)
    shell_lines = shell_probe.scan(signatures)
    daemons = daemon_probe.scan(signatures, include_root)
    ai_related = ai_related_probe.scan(signatures, artifacts)
    artifacts.extend(find_orphans(include_root))
    agents, orphans = classify(signatures, artifacts, packages, shell_lines, daemons)
    all_artifact_paths = []
    for agent in agents:
        all_artifact_paths.extend(item.path for item in agent.artifacts)
    all_artifact_paths.extend(item.path for item in orphans)
    unique_paths = set(unique_non_overlapping(all_artifact_paths))
    path_to_size = {}
    for agent in agents:
        for item in agent.artifacts:
            if item.path in unique_paths:
                path_to_size[item.path] = item.size_bytes
    for item in orphans:
        if item.path in unique_paths:
            path_to_size[item.path] = item.size_bytes
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "scan_time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "system": platform.system().lower(),
        "include_root": include_root,
        "signature_fingerprint": _signature_fingerprint(signatures),
        "total_reclaimable_bytes": sum(path_to_size.values()),
        "agents": [to_dict(agent) for agent in agents],
        "possible_ai_related_bytes": sum(item.size_bytes for item in ai_related),
        "ai_related": [to_dict(item) for item in ai_related],
        "orphans": [to_dict(item) for item in orphans],
    }
    if write_cache:
        path = ensure_state_dir() / "last_scan.json"
        try:
            atomic_write_text(
                path, json.dumps(manifest, indent=2) + "\n", "scan cache"
            )
        except (OSError, PermissionError):
            # Scanning and report export remain useful in read-only environments.
            pass
    return manifest


def get_manifest(no_cache: bool = False, include_root: bool = False) -> Dict[str, Any]:
    path = cache_path()
    if not no_cache and path.is_file():
        try:
            secure_private_file(path, "scan cache")
            data = json.loads(path.read_text(encoding="utf-8"))
            age = time.time() - path.stat().st_mtime
            signatures = load_signatures()
            valid = (
                data.get("schema_version") == SCHEMA_VERSION
                and data.get("include_root") is include_root
                and data.get("signature_fingerprint") == _signature_fingerprint(signatures)
                and 0 <= age <= CACHE_MAX_AGE_SECONDS
            )
            if valid:
                return data
        except (OSError, PermissionError, json.JSONDecodeError):
            pass
    return scan_system(include_root)
