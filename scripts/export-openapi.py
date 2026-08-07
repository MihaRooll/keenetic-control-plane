"""Export OpenAPI schema from FastAPI host app."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "docs" / "contracts" / "openapi-v0.json"


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT))
    from router_control_host.app import create_app

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "openapi-export.sqlite3"
        app = create_app(db_path=db_path)
        schema = app.openapi()
        app.state.host.runtime.store._conn.close()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
