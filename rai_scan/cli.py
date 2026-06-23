import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from rai_scan import __version__
from rai_scan.classifier.size import human_size
from rai_scan.config import (
    _validate_custom_signatures,
    bundled_signatures_path,
    ensure_state_dir,
    state_dir,
)
from rai_scan.removal.engine import preview, remove_agents
from rai_scan.removal.rollback import rollback_last
from rai_scan.report import as_html, as_json, as_list, as_markdown
from rai_scan.scanner import cache_path, get_manifest
from rai_scan.safety import atomic_write_text, secure_private_file
from rai_scan.tui.guided import run as run_guided


def _common_options(parser: argparse.ArgumentParser, suppress_defaults: bool = False) -> None:
    default = argparse.SUPPRESS if suppress_defaults else False
    parser.add_argument(
        "--dry-run", action="store_true", default=default, help="preview without making changes"
    )
    parser.add_argument(
        "--no-cache", action="store_true", default=default, help="force a fresh scan"
    )
    parser.add_argument(
        "--root", action="store_true", default=default, help="include system paths"
    )
    parser.add_argument(
        "--verbose", action="store_true", default=default, help="show matched artifact paths"
    )
    parser.add_argument("--json", action="store_true", default=default, dest="output_json")
    parser.add_argument("--html", action="store_true", default=default)
    parser.add_argument("--md", action="store_true", default=default)


def build_parser() -> argparse.ArgumentParser:
    subcommand_common = argparse.ArgumentParser(add_help=False)
    _common_options(subcommand_common, suppress_defaults=True)
    parser = argparse.ArgumentParser(
        prog="rai-scan",
        description="Find and safely remove installed AI CLI agents",
    )
    _common_options(parser)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", parents=[subcommand_common], help="print detected agents")
    subparsers.add_parser("menu", parents=[subcommand_common], help="open the guided menu")
    remove = subparsers.add_parser(
        "remove", parents=[subcommand_common], help="remove an agent"
    )
    remove.add_argument("name", nargs="+", help="agent id or display name")
    subparsers.add_parser("rollback", help="undo the last removal session")

    add = subparsers.add_parser("add-sig", help="add or replace a custom signature")
    add.add_argument("--name", required=True)
    add.add_argument("--display-name")
    add.add_argument("--bin", action="append", default=[])
    add.add_argument("--config", action="append", default=[])
    add.add_argument("--cache", action="append", default=[])
    add.add_argument("--pip", action="append", default=[])
    add.add_argument("--npm", action="append", default=[])
    add.add_argument("--cargo", action="append", default=[])
    subparsers.add_parser("reset-sig", help="remove custom signatures and use bundled defaults")
    return parser


def _format_output(manifest: Dict[str, Any], args: argparse.Namespace, verbose: bool = False) -> str:
    if getattr(args, "output_json", False):
        return as_json(manifest)
    if getattr(args, "html", False):
        return as_html(manifest)
    if getattr(args, "md", False):
        return as_markdown(manifest)
    return as_list(manifest, verbose)


def _find_agents(manifest: Dict[str, Any], names: List[str]) -> List[Dict[str, Any]]:
    wanted = {name.lower() for name in names}
    return [
        agent
        for agent in manifest.get("agents", [])
        if agent["id"].lower() in wanted or agent["display_name"].lower() in wanted
    ]


def _missing_names(agents: List[Dict[str, Any]], names: List[str]) -> List[str]:
    aliases = set()
    for agent in agents:
        aliases.add(agent["id"].lower())
        aliases.add(agent["display_name"].lower())
    return [name for name in names if name.lower() not in aliases]


def _confirm(agents: List[Dict[str, Any]]) -> bool:
    package_count = sum(len(agent.get("packages", [])) for agent in agents)
    shell_count = sum(len(agent.get("shell_lines", [])) for agent in agents)
    size = sum(agent["total_bytes"] for agent in agents)
    print(
        "Remove {} agent(s)? Move {} to trash, uninstall {} package(s), "
        "and comment {} shell line(s).".format(len(agents), human_size(size), package_count, shell_count)
    )
    if input("Type YES to confirm: ").strip() != "YES":
        return False
    home = Path.home().resolve()
    system_paths = []
    for agent in agents:
        for item in agent.get("artifacts", []):
            try:
                Path(item["path"]).resolve(strict=False).relative_to(home)
            except ValueError:
                system_paths.append(item["path"])
        system_paths.extend(
            "{} package {}".format(item["manager"], item["name"])
            for item in agent.get("packages", [])
            if item.get("scope") == "system"
        )
        system_paths.extend(
            "systemd unit {}".format(item["name"])
            for item in agent.get("daemons", [])
            if item.get("scope") == "system"
        )
    if system_paths:
        print("System-level operations require a second confirmation:")
        for item in system_paths:
            print("  - {}".format(item))
        return input("Type SYSTEM to approve these system operations: ").strip() == "SYSTEM"
    return True


def _remove(manifest: Dict[str, Any], names: List[str], dry_run: bool, root: bool) -> int:
    agents = _find_agents(manifest, names)
    missing = _missing_names(agents, names)
    if missing:
        print("Not found: {}".format(", ".join(missing)), file=sys.stderr)
    if not agents:
        return 1
    print(preview(agents))
    if dry_run:
        print("Dry run: no changes made.")
        return 0
    if not _confirm(agents):
        print("Cancelled.")
        return 1
    record, errors = remove_agents(agents, root)
    print("Removal session {} recorded.".format(record["session_id"]))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


def _interactive(manifest: Dict[str, Any], args: argparse.Namespace) -> int:
    print(as_list(manifest, args.verbose))
    agents = manifest.get("agents", [])
    if not agents:
        return 0
    answer = input("Enter agent numbers to remove, separated by spaces (or q): ").strip()
    if not answer or answer.lower() == "q":
        return 0
    selected = []
    for value in answer.replace(",", " ").split():
        try:
            index = int(value) - 1
        except ValueError:
            print("Invalid selection: {}".format(value), file=sys.stderr)
            return 2
        if index < 0 or index >= len(agents):
            print("Selection out of range: {}".format(value), file=sys.stderr)
            return 2
        selected.append(agents[index]["id"])
    return _remove(manifest, selected, args.dry_run, args.root)


def _add_signature(args: argparse.Namespace) -> int:
    name = args.name.strip()
    if not name:
        print("Error: --name must not be empty.", file=sys.stderr)
        return 1
    if not (args.bin or args.config or args.cache or args.pip or args.npm or args.cargo):
        print(
            "Error: provide at least one artifact type (--bin, --config, --cache, --pip, --npm, --cargo).",
            file=sys.stderr,
        )
        return 1
    for label, paths in [("config", args.config), ("cache", args.cache)]:
        for item in paths:
            expanded = Path(item).expanduser()
            if not expanded.exists():
                print("Warning: {} path does not exist: {}".format(label, expanded))
    path = ensure_state_dir() / "signatures.json"
    bundled = json.loads(bundled_signatures_path().read_text(encoding="utf-8"))
    data = {"version": "custom-1", "agents": {}}
    if path.is_file():
        try:
            secure_private_file(path, "custom signatures")
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print("Error: existing custom signatures are invalid: {}".format(exc), file=sys.stderr)
            return 1
        if not isinstance(existing.get("agents"), dict):
            print("Error: existing custom signatures lack an 'agents' object.", file=sys.stderr)
            return 1
        data["agents"] = {
            key: value
            for key, value in existing["agents"].items()
            if key not in bundled["agents"] or value != bundled["agents"][key]
        }
    agent_id = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not agent_id:
        print("Error: --name must contain a letter or number.", file=sys.stderr)
        return 1
    data["agents"][agent_id] = {
        "display_name": args.display_name or name,
        "homepage": "",
        "binaries": args.bin,
        "pip_packages": args.pip,
        "npm_packages": args.npm,
        "cargo_packages": args.cargo,
        "config_dirs": [str(Path(item).expanduser()) for item in args.config],
        "cache_dirs": [str(Path(item).expanduser()) for item in args.cache],
        "config_globs": [],
        "cache_globs": [],
        "shell_patterns": [name] + args.bin,
        "systemd_patterns": args.bin,
    }
    try:
        _validate_custom_signatures(data)
    except ValueError as exc:
        print("Error: invalid custom signature: {}".format(exc), file=sys.stderr)
        return 1
    atomic_write_text(
        path, json.dumps(data, indent=2) + "\n", "custom signatures"
    )
    try:
        cache_path().unlink()
    except FileNotFoundError:
        pass
    print("Saved signature '{}' to {}".format(agent_id, path))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rollback":
        try:
            record = rollback_last()
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            print("Rollback failed: {}".format(exc), file=sys.stderr)
            return 1
        print("Restored removal session {}.".format(record["session_id"]))
        if record.get("rollback_errors"):
            print("\n".join(record["rollback_errors"]), file=sys.stderr)
            return 1
        return 0
    if args.command == "add-sig":
        return _add_signature(args)
    if args.command == "reset-sig":
        path = state_dir() / "signatures.json"
        if path.is_file():
            secure_private_file(path, "custom signatures")
            path.unlink()
            try:
                cache_path().unlink()
            except FileNotFoundError:
                pass
            print("Removed custom signatures. Using bundled defaults.")
        else:
            print("No custom signatures found. Already using bundled defaults.")
        return 0

    try:
        manifest = get_manifest(
            True if args.command == "remove" else args.no_cache,
            args.root,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Scan failed: {}".format(exc), file=sys.stderr)
        return 1

    if args.command == "remove":
        return _remove(manifest, args.name, args.dry_run, args.root)
    if args.command == "list":
        print(_format_output(manifest, args, args.verbose))
        return 0
    if args.command == "menu" or args.command is None:
        if sys.stdin.isatty():
            return run_guided(manifest)
        print(_format_output(manifest, args, args.verbose))
        return 0
    return _interactive(manifest, args)


if __name__ == "__main__":
    raise SystemExit(main())
