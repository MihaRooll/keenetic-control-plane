"""Add or update one entry in docs/docs-map.json, preserving file formatting.

Main-orchestrator helper for the docs lifecycle rule: every new or materially
changed doc needs a map entry, and hand-editing a 95-entry JSON invites
accidental reformatting of unrelated records.

Usage: py -3.11 scripts/main-add-docs-map-entry.py <entry_json_file>
"""

from __future__ import annotations

import json
import pathlib
import sys

MAP_PATH = pathlib.Path("docs/docs-map.json")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    entry = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    document = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    entries = document["entries"]

    for index, existing in enumerate(entries):
        if existing.get("path") == entry["path"]:
            entries[index] = entry
            action = "updated"
            break
    else:
        entries.append(entry)
        entries.sort(key=lambda item: item.get("path", ""))
        action = "added"

    MAP_PATH.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"{action}: {entry['path']} (entries: {len(entries)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
