"""Print the request schema for one API path from the exported OpenAPI document.

Main-orchestrator helper: the operator error surface deliberately never echoes
field names back, so the schema has to be read from the contract instead.

Usage: py -3.11 scripts/main-show-request-schema.py <path> [method]
"""

from __future__ import annotations

import json
import pathlib
import sys

SPEC = pathlib.Path("docs/contracts/openapi-v0.json")


def resolve(spec: dict, node: dict) -> dict:
    ref = node.get("$ref")
    if not ref:
        return node
    name = ref.split("/")[-1]
    return spec["components"]["schemas"][name]


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    method = (sys.argv[2] if len(sys.argv) > 2 else "post").lower()
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    if path not in spec["paths"]:
        matches = [p for p in spec["paths"] if path in p]
        print(f"path not found; candidates: {matches[:20]}")
        return 1
    operation = spec["paths"][path][method]
    body = operation.get("requestBody")
    if not body:
        print("no request body")
        return 0
    schema = resolve(spec, body["content"]["application/json"]["schema"])
    print("required:", schema.get("required"))
    print("additionalProperties:", schema.get("additionalProperties"))
    for name, prop in schema.get("properties", {}).items():
        prop = resolve(spec, prop)
        kind = prop.get("type") or prop.get("anyOf") or prop.get("allOf") or "?"
        print(f"  {name}: {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
