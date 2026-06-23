import html
import json
from typing import Any, Dict, List

from rai_scan.classifier.size import human_size
from rai_scan.color import BOLD, CYAN, GREEN, YELLOW, muted, paint


def components(agent: Dict[str, Any]) -> str:
    values = set()
    values.update(item["type"] for item in agent.get("artifacts", []))
    values.update(item["manager"] for item in agent.get("packages", []))
    if agent.get("shell_lines"):
        values.add("shell")
    if agent.get("daemons"):
        values.add("daemon")
    return ", ".join(sorted(values)) or "-"


def as_json(manifest: Dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2)


def as_markdown(manifest: Dict[str, Any]) -> str:
    lines: List[str] = [
        "## rai-scan report — {}".format(manifest["scan_time"]),
        "",
        "| # | Agent | Components | Size | Confidence |",
        "|---:|---|---|---:|---|",
    ]
    for number, agent in enumerate(manifest.get("agents", []), 1):
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                number,
                agent["display_name"].replace("|", "\\|"),
                components(agent).replace("|", "\\|"),
                human_size(agent["total_bytes"]),
                agent["confidence"],
            )
        )
    lines.extend(
        ["", "**Total reclaimable: {}**".format(human_size(manifest["total_reclaimable_bytes"]))]
    )
    if manifest.get("ai_related"):
        lines.extend(["", "### Possible AI-related data (low confidence)", ""])
        for item in manifest["ai_related"]:
            lines.append(
                "- `{}` — {} ({})".format(
                    item["path"], human_size(item["size_bytes"]), item.get("agent_hint", "heuristic")
                )
            )
    return "\n".join(lines)


def as_html(manifest: Dict[str, Any]) -> str:
    cards = []
    for agent in manifest.get("agents", []):
        items = "".join(
            "<li><code>{}</code> — {}</li>".format(
                html.escape(item["path"]), human_size(item["size_bytes"])
            )
            for item in agent.get("artifacts", [])
        )
        cards.append(
            "<section><h2>{}</h2><p>{} · {} · confidence: {}</p><ul>{}</ul></section>".format(
                html.escape(agent["display_name"]),
                html.escape(components(agent)),
                human_size(agent["total_bytes"]),
                html.escape(agent["confidence"]),
                items,
            )
        )
    if manifest.get("ai_related"):
        items = "".join(
            "<li><code>{}</code> — {} ({})</li>".format(
                html.escape(item["path"]),
                human_size(item["size_bytes"]),
                html.escape(item.get("agent_hint", "heuristic")),
            )
            for item in manifest["ai_related"]
        )
        cards.append(
            "<section><h2>Possible AI-related data</h2>"
            "<p>Low-confidence heuristic findings; not included in automatic removal.</p>"
            "<ul>{}</ul></section>".format(items)
        )
    return """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>rai-scan report</title>
<style>body{{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#18212b}}
section{{border:1px solid #ccd5df;border-radius:8px;padding:1rem;margin:1rem 0}}
code{{overflow-wrap:anywhere}}h1,h2{{margin-top:0}}</style>
<h1>rai-scan report</h1><p>{count} agents · {size} · {time}</p>{cards}</html>""".format(
        count=len(manifest.get("agents", [])),
        size=human_size(manifest["total_reclaimable_bytes"]),
        time=html.escape(manifest["scan_time"]),
        cards="".join(cards),
    )


def as_list(manifest: Dict[str, Any], verbose: bool = False) -> str:
    lines = []
    for number, agent in enumerate(manifest.get("agents", []), 1):
        lines.append(
            "{} {:<20} {:<28} {}".format(
                paint("#{}".format(number), BOLD, CYAN),
                agent["display_name"],
                components(agent),
                paint("{:>10}".format(human_size(agent["total_bytes"])), GREEN),
            )
        )
        if verbose:
            lines.extend(
                "      {}".format(muted(item["path"])) for item in agent.get("artifacts", [])
            )
    if not lines:
        lines.append("No known AI CLI agents found.")
    if manifest.get("orphans"):
        lines.append(
            "#{}   [orphans] {:>44}".format(
                len(manifest.get("agents", [])) + 1,
                human_size(sum(item["size_bytes"] for item in manifest["orphans"])),
            )
        )
    if manifest.get("ai_related"):
        lines.append("")
        lines.append(
            paint(
                "Possible AI-related data (low confidence; not auto-removable):",
                BOLD,
                YELLOW,
            )
        )
        for item in manifest["ai_related"]:
            lines.append(
                "  {:<54} {:>10}  {}".format(
                    item["path"],
                    human_size(item["size_bytes"]),
                    item.get("agent_hint", "heuristic"),
                )
            )
        lines.append(
            "Possible AI-related total: {}".format(
                human_size(manifest.get("possible_ai_related_bytes", 0))
            )
        )
    lines.append(
        "{} {}".format(
            paint("Total reclaimable:", BOLD),
            paint(human_size(manifest["total_reclaimable_bytes"]), BOLD, GREEN),
        )
    )
    return "\n".join(lines)
