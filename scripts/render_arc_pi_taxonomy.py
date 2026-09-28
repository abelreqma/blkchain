#!/usr/bin/env python3
"""Render the Arcanum Prompt Injection Taxonomy JSON into one markdown file so
it can be chunked by the standard markdown ingest path (one heading per node).

Reproducible corpus-prep: re-run after updating the arc_pi_taxonomy clone. Paths
derive from blkchain.config (no hardcoded absolute paths).

    .venv/bin/python scripts/render_arc_pi_taxonomy.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# import the project config for the corpus root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from blkchain import config  # noqa: E402

SRC = config.SOURCES_DIR / "arc_pi_taxonomy" / "docs" / "data" / "taxonomy.json"
OUT = config.SOURCES_DIR / "arc_pi_taxonomy" / "taxonomy_nodes.md"

PILLARS = {
    "intents": "Intent",
    "techniques": "Technique",
    "evasions": "Evasion",
    "inputs": "Input Surface",
}


def render() -> str:
    data = json.loads(SRC.read_text())
    lines: list[str] = ["# Arcanum Prompt Injection Taxonomy (nodes)\n"]
    for key, label in PILLARS.items():
        nodes = data.get(key, [])
        lines.append(f"\n## Pillar: {label} ({len(nodes)} nodes)\n")
        for n in nodes:
            code = n.get("code", "")
            title = n.get("title", "")
            lines.append(f"\n### {code} {title}  (pillar: {label}, delivery: {n.get('delivery', 'n/a')})\n")
            if n.get("description"):
                lines.append(n["description"] + "\n")
            if n.get("ideas"):
                lines.append("Example techniques / ideas:\n" + "\n".join(f"- {i}" for i in n["ideas"]) + "\n")
            if n.get("aliases"):
                lines.append("Also known as (other frameworks): " + "; ".join(n["aliases"]) + "\n")
    return "\n".join(lines)


def main() -> int:
    if not SRC.exists():
        print(f"taxonomy JSON not found at {SRC}", file=sys.stderr)
        return 1
    OUT.write_text(render())
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
