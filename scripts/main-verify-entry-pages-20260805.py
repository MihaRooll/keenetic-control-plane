"""Main-only live verification: entry-pages create->draft->publish->self-check flow."""

from __future__ import annotations

import json

import requests
from hub_admin_password import require_hub_admin_password

BASE = "http://127.0.0.1:8787"
API = f"{BASE}/api/router-control/v1"


def main() -> int:
    password = require_hub_admin_password()
    sess = requests.Session()
    sess.headers.update({"Origin": BASE})
    sess.post(f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15)

    create = sess.post(f"{API}/entry-pages", json={"audience": "guest"}, timeout=15)
    print(json.dumps({"step": "create", "status": create.status_code}))
    if create.status_code >= 400:
        print(create.text[:1500])
        return 1
    page = create.json()
    page_id = page.get("page_id") or page.get("id")
    print(json.dumps({"page_id": page_id, "keys": sorted(page.keys())}))

    draft_doc = {
        "title": "Проверка Main",
        "button_label": "Отправить",
        "submissions_enabled": True,
        "fields": [
            {"name": "guest_name", "label": "Имя", "kind": "text", "required": True},
        ],
    }
    draft = sess.put(f"{API}/entry-pages/{page_id}/draft", json={"document": draft_doc}, timeout=15)
    print(json.dumps({"step": "draft", "status": draft.status_code}))
    if draft.status_code >= 400:
        print(draft.text[:1500])
        return 1
    draft_body = draft.json()
    revision_id = draft_body.get("revision_id")
    print(json.dumps({"revision_id": revision_id}))

    publish = sess.post(f"{API}/entry-pages/{page_id}/publish", json={"revision_id": revision_id}, timeout=15)
    print(json.dumps({"step": "publish", "status": publish.status_code}))
    print(publish.text[:1500])

    self_check = sess.post(f"{API}/entry-pages/{page_id}/self-check", json={}, timeout=15)
    print(json.dumps({"step": "self_check", "status": self_check.status_code}))
    print(self_check.text[:2000])

    preview = sess.get(f"{API}/entry-pages/{page_id}/draft-preview", timeout=15)
    print(json.dumps({"step": "draft_preview", "status": preview.status_code, "len": len(preview.text)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
