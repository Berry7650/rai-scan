import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rai_scan.classifier.size import human_size
from rai_scan.color import danger, heading, info, muted, success, warning
from rai_scan.removal.engine import preview, remove_agents
from rai_scan.removal.rollback import rollback_last
from rai_scan.report import as_html, as_json, as_list, as_markdown, components
from rai_scan.scanner import scan_system


def recommendations(manifest: Dict[str, Any]) -> List[Tuple[str, str, bool]]:
    """Return agent id, explanation, and whether it is a likely leftover."""
    result = []
    for agent in manifest.get("agents", []):
        has_install = bool(agent.get("packages")) or any(
            item["type"] == "binary" for item in agent.get("artifacts", [])
        )
        reasons = []
        likely_leftover = not has_install
        if likely_leftover:
            reasons.append("no executable or installed package was found; may be leftover data")
        if agent.get("total_bytes", 0) >= 1024**3:
            reasons.append("large storage use: {}".format(human_size(agent["total_bytes"])))
        elif agent.get("total_bytes", 0) >= 500 * 1024**2:
            reasons.append("significant storage use: {}".format(human_size(agent["total_bytes"])))
        if any(_is_system_path(item["path"]) for item in agent.get("artifacts", [])):
            reasons.append("contains system-installed files; extra caution required")
        if not reasons:
            reasons.append("installed agent with modest storage use")
        result.append((agent["id"], "; ".join(reasons), likely_leftover))
    return result


def _is_system_path(value: str) -> bool:
    try:
        Path(value).resolve(strict=False).relative_to(Path.home().resolve())
        return False
    except ValueError:
        return True


def _agent_details(agent: Dict[str, Any], number: int) -> str:
    lines = [
        "{}. {} ({})".format(number, agent["display_name"], agent["id"]),
        "   Size: {} | Confidence: {} | Components: {}".format(
            human_size(agent["total_bytes"]), agent["confidence"], components(agent)
        ),
    ]
    lines.extend("   - {}".format(item["path"]) for item in agent.get("artifacts", []))
    for package in agent.get("packages", []):
        exe_note = " [{}]".format(package["executable"]) if package.get("executable") else ""
        lines.append(
            "   - {} package: {} {}{}".format(
                package["manager"], package["name"], package.get("version", ""), exe_note
            ).rstrip()
        )
    for daemon in agent.get("daemons", []):
        scope = " (system)" if daemon.get("scope") == "system" else ""
        lines.append("   - daemon: {}{} [{}]".format(daemon["name"], scope, daemon["type"]))
    return "\n".join(lines)


def _choose_agents(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    agents = manifest.get("agents", [])
    if not agents:
        print(warning("No confirmed AI agents were found."))
        return []
    print("\n" + heading("Choose agents"))
    for number, agent in enumerate(agents, 1):
        print(_agent_details(agent, number))

    suggested = {
        agent_id
        for agent_id, _reason, likely_leftover in recommendations(manifest)
        if likely_leftover
    }
    if suggested:
        print("\n" + warning("Auto-select is available for likely leftovers:"))
        for agent_id in sorted(suggested):
            print("  - {}".format(agent_id))
        prompt = "Enter numbers, 'a' for likely leftovers, or 'q' to cancel: "
    else:
        print("\n" + info("No safe automatic removal candidates were found."))
        print("Automatic selection only includes agents with no binary or installed package.")
        prompt = "Enter agent numbers separated by spaces, or 'q' to cancel: "

    answer = input(prompt).strip().lower()
    if not answer or answer == "q":
        return []
    if answer == "a" and suggested:
        return [agent for agent in agents if agent["id"] in suggested]

    selected = []
    for value in answer.replace(",", " ").split():
        try:
            index = int(value) - 1
        except ValueError:
            print("Invalid selection: {}".format(value))
            return []
        if index < 0 or index >= len(agents):
            print("Selection out of range: {}".format(value))
            return []
        if agents[index] not in selected:
            selected.append(agents[index])
    return selected


def _removal_wizard(manifest: Dict[str, Any]) -> None:
    print(info("Refreshing scan before removal..."))
    manifest = scan_system(include_root=bool(manifest.get("include_root")))
    selected = _choose_agents(manifest)
    if not selected:
        return
    print("\n" + heading("Removal preview — no changes have been made:"))
    print(preview(selected))
    print(
        "Total selected: {}".format(
            human_size(sum(agent["total_bytes"] for agent in selected))
        )
    )
    system_paths = [
        item["path"]
        for agent in selected
        for item in agent.get("artifacts", [])
        if _is_system_path(item["path"])
    ]
    system_packages = [
        "{} package {}".format(item["manager"], item["name"])
        for agent in selected
        for item in agent.get("packages", [])
        if item.get("scope") == "system"
    ]
    system_daemons = [
        item["name"]
        for agent in selected
        for item in agent.get("daemons", [])
        if item.get("scope") == "system"
    ]
    include_root = False
    if system_paths or system_packages or system_daemons:
        print("\n" + danger("System-level items are included:"))
        for path in system_paths:
            print("  - {}".format(path))
        for package in system_packages:
            print("  - {}".format(package))
        for name in system_daemons:
            print("  - systemd system unit: {}".format(name))
        include_root = input("Allow system paths for this removal? Type ROOT: ").strip() == "ROOT"
        if not include_root:
            print(warning("Cancelled because system paths were not approved."))
            return
    if input("\nType YES to move these files to recoverable trash: ").strip() != "YES":
        print(warning("Cancelled. No changes made."))
        return
    record, errors = remove_agents(selected, include_root)
    print(success("Removal session recorded: {}".format(record["session_id"])))
    if errors:
        print(danger("Some operations failed:"))
        for error in errors:
            print("  - {}".format(error))


def _show_recommendations(manifest: Dict[str, Any]) -> None:
    print("\n" + heading("Review recommendations"))
    for agent_id, reason, likely_leftover in recommendations(manifest):
        label = warning("LIKELY LEFTOVER") if likely_leftover else info("REVIEW")
        print("  [{}] {}: {}".format(label, agent_id, reason))
    if manifest.get("ai_related"):
        print(
            "\n"
            + warning("Possible AI-related data is informational and never auto-selected:")
        )
        for item in manifest["ai_related"]:
            print(
                "  - {} — {} ({})".format(
                    item["path"], human_size(item["size_bytes"]), item["agent_hint"]
                )
            )


def _export(manifest: Dict[str, Any]) -> None:
    print("\n" + heading("Export report"))
    print("1. JSON\n2. Markdown\n3. HTML\n0. Cancel")
    choice = input("Choose report format: ").strip()
    formats = {
        "1": ("json", as_json),
        "2": ("md", as_markdown),
        "3": ("html", as_html),
    }
    selected = formats.get(choice)
    if not selected:
        return
    extension, renderer = selected
    filename = "rai-scan-{}.{}".format(datetime.now().strftime("%Y%m%d-%H%M%S"), extension)
    path = Path.cwd() / filename
    path.write_text(renderer(manifest) + "\n", encoding="utf-8")
    print(success("Report saved to {}".format(path)))


def _rollback() -> None:
    if input("Restore the last removal session? Type YES: ").strip() != "YES":
        print(warning("Cancelled."))
        return
    try:
        record = rollback_last()
    except Exception as exc:
        print(danger("Rollback failed: {}".format(exc)))
        return
    print(success("Restored session {}.".format(record["session_id"])))
    if record.get("rollback_errors"):
        print(danger("Rollback was partial:"))
        for error in record["rollback_errors"]:
            print("  - {}".format(error))


def _uninstall() -> bool:
    project_dir = Path(__file__).resolve().parents[2]
    script = project_dir / "uninstall.sh"
    if not script.is_file():
        print(danger("Uninstall script not found: {}".format(script)))
        return False
    print("\nThis removes the rai-scan command and its private Python environment.")
    print("The project source directory will be kept: {}".format(project_dir))
    purge = input(
        "Also permanently delete ~/.rai-scan trash, cache, and rollback history? [y/N]: "
    ).strip().lower() == "y"
    print("\nPlanned uninstall:")
    command = [str(script), "--dry-run"]
    if purge:
        command.append("--purge-state")
    subprocess.run(command, check=False)
    if input("\nType UNINSTALL to continue: ").strip() != "UNINSTALL":
        print(warning("Cancelled. Nothing was removed."))
        return False
    command = [str(script)]
    if purge:
        command.append("--purge-state")
    result = subprocess.run(command, check=False)
    return result.returncode == 0


def run(manifest: Dict[str, Any]) -> int:
    while True:
        print("\n" + heading("=== rai-scan guided menu ==="))
        print("Confirmed agents: {} | Confirmed size: {}".format(
            len(manifest.get("agents", [])),
            human_size(manifest.get("total_reclaimable_bytes", 0)),
        ))
        print(
            "Possible AI-related data: {} | Size: {}".format(
                len(manifest.get("ai_related", [])),
                human_size(manifest.get("possible_ai_related_bytes", 0)),
            )
        )
        print(
            "\n1. Fresh scan\n"
            "2. Show simple results\n"
            "3. Show detailed results\n"
            "4. Recommendations and automatic review\n"
            "5. Safe removal wizard\n"
            "6. Export a report\n"
            "7. Roll back last removal\n"
            "8. Help and safety information\n"
            "9. Uninstall rai-scan\n"
            "0. Exit"
        )
        choice = input("Choose an option: ").strip()
        if choice == "1":
            print(info("Scanning..."))
            manifest = scan_system()
            print(success("Fresh scan complete."))
        elif choice == "2":
            print(as_list(manifest))
        elif choice == "3":
            print(as_list(manifest, verbose=True))
        elif choice == "4":
            _show_recommendations(manifest)
        elif choice == "5":
            _removal_wizard(manifest)
            manifest = scan_system()
        elif choice == "6":
            _export(manifest)
        elif choice == "7":
            _rollback()
            manifest = scan_system()
        elif choice == "8":
            print(
                "\nSafety rules:\n"
                "- Confirmed agents have known signatures.\n"
                "- Possible AI-related data is low confidence and is not auto-removed.\n"
                "- Automatic selection only chooses likely leftovers with no binary/package.\n"
                "- Every removal shows a preview and requires YES.\n"
                "- Removed files go to ~/.rai-scan/trash and can be rolled back."
            )
        elif choice == "9":
            if _uninstall():
                print(success("Uninstall complete. Exiting rai-scan."))
                return 0
        elif choice == "0":
            print(muted("Goodbye."))
            return 0
        else:
            print(warning("Invalid option. Choose 0 through 9."))
