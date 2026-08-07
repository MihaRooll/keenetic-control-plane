"""Replace the `next_task` action/note lines in docs/STATUS.yaml in place.

Line-surgical on purpose: rewriting the whole YAML would reformat a 100k+
character SSOT file and bury the real change in noise.

Usage: py -3.11 scripts/main-set-next-task.py <action_file> <note_file> <task_id>
"""

from __future__ import annotations

import json
import pathlib
import sys

STATUS = pathlib.Path("docs/STATUS.yaml")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    action = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
    note = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
    task_id = sys.argv[3]

    lines = STATUS.read_text(encoding="utf-8").splitlines(keepends=True)
    in_next_task = False
    replaced = {"id": False, "action": False, "note": False}
    out: list[str] = []
    for line in lines:
        if line.startswith("next_task:"):
            in_next_task = True
            out.append(line)
            continue
        if in_next_task and line and not line.startswith((" ", "\t")):
            in_next_task = False
        if in_next_task:
            if line.startswith("  id:"):
                out.append(f"  id: {json.dumps(task_id, ensure_ascii=False)}\n")
                replaced["id"] = True
                continue
            if line.startswith("  action:"):
                out.append(f"  action: {json.dumps(action, ensure_ascii=False)}\n")
                replaced["action"] = True
                continue
            if line.startswith("  note:"):
                out.append(f"  note: {json.dumps(note, ensure_ascii=False)}\n")
                replaced["note"] = True
                continue
        out.append(line)

    if not all(replaced.values()):
        print("not all fields replaced:", replaced)
        return 1
    STATUS.write_text("".join(out), encoding="utf-8")
    print("next_task updated:", replaced)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
