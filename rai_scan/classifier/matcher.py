from typing import Any, Dict, List, Tuple

from rai_scan.models import AgentBundle, Artifact, DaemonEntry, Package, ShellLine, unique_non_overlapping


def _unique_artifact_bytes(artifacts: List[Artifact]) -> int:
    paths = unique_non_overlapping([a.path for a in artifacts])
    path_set = set(paths)
    return sum(a.size_bytes for a in artifacts if a.path in path_set)


def classify(
    signatures: Dict[str, Any],
    artifacts: List[Artifact],
    packages: List[Package],
    shell_lines: List[ShellLine],
    daemons: List[DaemonEntry],
) -> Tuple[List[AgentBundle], List[Artifact]]:
    bundles = {
        agent_id: AgentBundle(agent_id, signature.get("display_name", agent_id))
        for agent_id, signature in signatures["agents"].items()
    }
    orphans = []

    for artifact in artifacts:
        if artifact.agent_hint in bundles:
            bundles[artifact.agent_hint].artifacts.append(artifact)
        else:
            orphans.append(artifact)

    package_fields = {
        "pip": "pip_packages",
        "pipx": "pip_packages",
        "npm": "npm_packages",
        "cargo": "cargo_packages",
    }
    for package in packages:
        field = package_fields.get(package.manager)
        matched = False
        for agent_id, signature in signatures["agents"].items():
            names = [str(value).lower() for value in signature.get(field or "", [])]
            if package.name.lower() in names:
                bundles[agent_id].packages.append(package)
                if not bundles[agent_id].version_detected:
                    bundles[agent_id].version_detected = package.version
                matched = True
                break
        if not matched:
            continue

    for line in shell_lines:
        if line.agent_hint in bundles:
            bundles[line.agent_hint].shell_lines.append(line)
    for daemon in daemons:
        if daemon.agent_hint in bundles:
            bundles[daemon.agent_hint].daemons.append(daemon)

    result = []
    for bundle in bundles.values():
        if bundle.artifacts or bundle.packages or bundle.shell_lines or bundle.daemons:
            bundle.total_bytes = _unique_artifact_bytes(bundle.artifacts)
            if bundle.packages or any(item.type == "binary" for item in bundle.artifacts):
                bundle.confidence = "high"
            elif bundle.shell_lines and not bundle.artifacts:
                bundle.confidence = "low"
            result.append(bundle)
    return sorted(result, key=lambda item: item.display_name.lower()), orphans
