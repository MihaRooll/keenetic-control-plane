"""Entry page catalog: operator-authored landing pages with immutable revisions."""

from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from router_control.domain.errors import EntryPageConflict
from router_control.domain.network_intents import canonical_dumps
from router_control.persistence.errors import NotFoundError
from router_control.persistence.store import PersistenceStore
from router_control.ports.clock import ClockPort

_FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_FIELD_KINDS = frozenset({"text", "phone", "email", "select"})
_DOCUMENT_KEYS = frozenset(
    {"title", "intro", "button_label", "fields", "submissions_enabled"}
)
_STAFF_DOCUMENT_KEYS = _DOCUMENT_KEYS | {"roles"}
_FIELD_ITEM_KEYS = frozenset({"name", "label", "kind", "required"})
_FIELD_ITEM_KEYS_WITH_OPTIONS = _FIELD_ITEM_KEYS | {"options"}
_SLUG_COLLISION_RETRIES = 16
_STYLESHEET_PATH = "/p/_assets/entry-page.css"

_STATIC_HTML: tuple[str, ...] = (
    "<!doctype html>",
    '<html lang="ru">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>",
    "</title>",
    "</head>",
    "<body>",
    "<h1>",
    "</h1>",
    "<p>",
    "</p>",
    "<label>",
    "Роль",
    '<select name="role" required>',
    "</select>",
    "</label>",
    "<option value=\"",
    "\">",
    "</option>",
    '<select name="',
    '" id="',
    '">',
    '<input type="',
    '" name="',
    '" id="',
    '">',
    '<button type="submit">',
    "</button>",
    "</form>",
    "</body>",
    "</html>",
)


class PublicHtmlBuilder:
    """Guest HTML builder: dynamic text/attrs are escaped; static scaffold is constant-only."""

    __slots__ = ("_parts",)

    def __init__(self) -> None:
        self._parts: list[str] = []

    def _static(self, fragment: str) -> None:
        if fragment not in _STATIC_HTML:
            msg = "public HTML scaffold accepts module-level constants only"
            raise ValueError(msg)
        self._parts.append(fragment)

    def text(self, value: str, *, quote: bool = False) -> None:
        self._parts.append(html.escape(str(value), quote=quote))

    def attr(self, value: str) -> str:
        return html.escape(str(value), quote=True)

    def build(self) -> str:
        return "\n".join(self._parts)


class EntryPageNotFound(Exception):
    def __init__(self, message: str, *, code: str = "entry.page_not_found") -> None:
        super().__init__(message)
        self.code = code


class EntryPageValidationError(ValueError):
    def __init__(self, message: str, *, code: str, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field


def _reject_html(value: str, field_path: str) -> None:
    if "<" in value or ">" in value:
        raise EntryPageValidationError(
            "HTML markup is not allowed",
            code="entry.html_not_allowed",
            field=field_path,
        )


def _validate_string_length(
    value: str,
    *,
    field_path: str,
    min_len: int,
    max_len: int,
) -> str:
    stripped = value.strip()
    if len(stripped) < min_len or len(stripped) > max_len:
        raise EntryPageValidationError(
            f"invalid length for {field_path}",
            code="entry.validation_failed",
            field=field_path,
        )
    _reject_html(stripped, field_path)
    return stripped


def _validate_field_item(raw: Any, index: int) -> dict[str, Any]:
    field_path = f"fields[{index}]"
    if not isinstance(raw, dict):
        raise EntryPageValidationError(
            "field must be an object",
            code="entry.validation_failed",
            field=field_path,
        )
    unknown = set(raw) - _FIELD_ITEM_KEYS_WITH_OPTIONS
    if unknown:
        raise EntryPageValidationError(
            "unknown field keys",
            code="entry.validation_failed",
            field=field_path,
        )
    if "options" in raw and raw.get("kind") != "select":
        raise EntryPageValidationError(
            "options only allowed for select fields",
            code="entry.validation_failed",
            field=f"{field_path}.options",
        )
    name = _validate_string_length(
        str(raw["name"]),
        field_path=f"{field_path}.name",
        min_len=1,
        max_len=32,
    )
    if not _FIELD_NAME_RE.fullmatch(name):
        raise EntryPageValidationError(
            "invalid field name",
            code="entry.validation_failed",
            field=f"{field_path}.name",
        )
    label = _validate_string_length(
        str(raw["label"]),
        field_path=f"{field_path}.label",
        min_len=1,
        max_len=60,
    )
    kind = str(raw["kind"])
    if kind not in _FIELD_KINDS:
        raise EntryPageValidationError(
            "invalid field kind",
            code="entry.validation_failed",
            field=f"{field_path}.kind",
        )
    if not isinstance(raw["required"], bool):
        raise EntryPageValidationError(
            "required must be boolean",
            code="entry.validation_failed",
            field=f"{field_path}.required",
        )
    item: dict[str, Any] = {
        "name": name,
        "label": label,
        "kind": kind,
        "required": raw["required"],
    }
    if kind == "select":
        if "options" not in raw:
            raise EntryPageValidationError(
                "select field requires options",
                code="entry.validation_failed",
                field=f"{field_path}.options",
            )
        options_raw = raw["options"]
        if not isinstance(options_raw, list):
            raise EntryPageValidationError(
                "options must be a list",
                code="entry.validation_failed",
                field=f"{field_path}.options",
            )
        if len(options_raw) < 1 or len(options_raw) > 12:
            raise EntryPageValidationError(
                "invalid options count",
                code="entry.validation_failed",
                field=f"{field_path}.options",
            )
        options: list[str] = []
        for opt_index, opt_raw in enumerate(options_raw):
            opt_path = f"{field_path}.options[{opt_index}]"
            opt = _validate_string_length(
                str(opt_raw),
                field_path=opt_path,
                min_len=1,
                max_len=60,
            )
            options.append(opt)
        item["options"] = options
    elif "options" in raw:
        raise EntryPageValidationError(
            "options only allowed for select fields",
            code="entry.validation_failed",
            field=f"{field_path}.options",
        )
    return item


def validate_and_canonicalize_entry_document(
    document: dict[str, Any],
    *,
    audience: str,
) -> tuple[dict[str, Any], str, str]:
    if not isinstance(document, dict):
        raise EntryPageValidationError(
            "document must be an object",
            code="entry.validation_failed",
            field="document",
        )
    if audience == "guest" and "roles" in document:
        raise EntryPageValidationError(
            "roles not allowed for guest pages",
            code="entry.validation_failed",
            field="roles",
        )
    allowed_keys = _STAFF_DOCUMENT_KEYS if audience == "staff" else _DOCUMENT_KEYS
    unknown_top = set(document) - allowed_keys
    if unknown_top:
        raise EntryPageValidationError(
            "unknown document keys",
            code="entry.validation_failed",
            field="document",
        )
    title = _validate_string_length(
        str(document["title"]),
        field_path="title",
        min_len=1,
        max_len=120,
    )
    intro = _validate_string_length(
        str(document.get("intro", "")),
        field_path="intro",
        min_len=0,
        max_len=400,
    )
    button_label = _validate_string_length(
        str(document["button_label"]),
        field_path="button_label",
        min_len=1,
        max_len=60,
    )
    fields_raw = document["fields"]
    if not isinstance(fields_raw, list):
        raise EntryPageValidationError(
            "fields must be a list",
            code="entry.validation_failed",
            field="fields",
        )
    if len(fields_raw) > 8:
        raise EntryPageValidationError(
            "too many fields",
            code="entry.validation_failed",
            field="fields",
        )
    fields: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for index, field_raw in enumerate(fields_raw):
        field = _validate_field_item(field_raw, index)
        if field["name"] in seen_names:
            raise EntryPageValidationError(
                "duplicate field name",
                code="entry.validation_failed",
                field=f"fields[{index}].name",
            )
        seen_names.add(field["name"])
        fields.append(field)
    if not isinstance(document["submissions_enabled"], bool):
        raise EntryPageValidationError(
            "submissions_enabled must be boolean",
            code="entry.validation_failed",
            field="submissions_enabled",
        )
    canonical: dict[str, Any] = {
        "title": title,
        "intro": intro,
        "button_label": button_label,
        "fields": fields,
        "submissions_enabled": document["submissions_enabled"],
    }
    if audience == "staff":
        roles_raw = document.get("roles")
        if roles_raw is None:
            raise EntryPageValidationError(
                "roles required for staff pages",
                code="entry.validation_failed",
                field="roles",
            )
        if not isinstance(roles_raw, list):
            raise EntryPageValidationError(
                "roles must be a list",
                code="entry.validation_failed",
                field="roles",
            )
        if len(roles_raw) < 1 or len(roles_raw) > 12:
            raise EntryPageValidationError(
                "invalid roles count",
                code="entry.validation_failed",
                field="roles",
            )
        roles: list[str] = []
        for index, role_raw in enumerate(roles_raw):
            role = _validate_string_length(
                str(role_raw),
                field_path=f"roles[{index}]",
                min_len=1,
                max_len=40,
            )
            roles.append(role)
        canonical["roles"] = roles
    canonical_json = canonical_dumps(canonical)
    content_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return canonical, canonical_json, content_sha256


def render_public_html(
    document: dict[str, Any],
    *,
    audience: str,
    slug: str,
    submit_path: str,
) -> str:
    _ = slug
    builder = PublicHtmlBuilder()
    builder._static("<!doctype html>")
    builder._static('<html lang="ru">')
    builder._static("<head>")
    builder._static('<meta charset="utf-8">')
    builder._static('<meta name="viewport" content="width=device-width, initial-scale=1">')
    builder._static("<title>")
    builder.text(str(document["title"]), quote=True)
    builder._static("</title>")
    builder._parts.append(
        f'<link rel="stylesheet" href="{builder.attr(_STYLESHEET_PATH)}">'
    )
    builder._static("</head>")
    builder._static("<body>")
    builder._static("<h1>")
    builder.text(str(document["title"]), quote=True)
    builder._static("</h1>")
    intro = str(document.get("intro", ""))
    if intro:
        builder._static("<p>")
        builder.text(intro, quote=True)
        builder._static("</p>")
    if bool(document["submissions_enabled"]):
        builder._parts.append(
            f'<form method="post" action="{builder.attr(submit_path)}">'
        )
        if audience == "staff":
            roles = document.get("roles") or []
            builder._static("<label>")
            builder._static("Роль")
            builder._static('<select name="role" required>')
            for role in roles:
                escaped_role = builder.attr(str(role))
                builder._parts.append(f'<option value="{escaped_role}">')
                builder.text(str(role), quote=True)
                builder._static("</option>")
            builder._static("</select>")
            builder._static("</label>")
        for field in document.get("fields") or []:
            name = builder.attr(str(field["name"]))
            builder._static("<label>")
            builder.text(str(field["label"]), quote=True)
            kind = str(field["kind"])
            required_attr = " required" if field.get("required") else ""
            if kind == "select":
                builder._parts.append(f'<select name="{name}" id="{name}"{required_attr}>')
                for option in field.get("options") or []:
                    escaped_option = builder.attr(str(option))
                    builder._parts.append(f'<option value="{escaped_option}">')
                    builder.text(str(option), quote=True)
                    builder._static("</option>")
                builder._static("</select>")
            else:
                input_type = {
                    "text": "text",
                    "phone": "tel",
                    "email": "email",
                }[kind]
                builder._parts.append(
                    f'<input type="{input_type}" name="{name}" id="{name}"{required_attr}>'
                )
            builder._static("</label>")
        builder._static('<button type="submit">')
        builder.text(str(document["button_label"]), quote=True)
        builder._static("</button>")
        builder._static("</form>")
    builder._static("</body>")
    builder._static("</html>")
    return builder.build()


@dataclass
class EntryPageService:
    store: PersistenceStore
    clock: ClockPort

    def list_pages(self, site_id: str) -> list[dict[str, Any]]:
        return [self._public_page(row) for row in self.store.list_entry_pages(site_id)]

    def ensure_page(self, site_id: str, audience: str) -> dict[str, Any]:
        existing = self.store.find_entry_page_by_audience(site_id, audience)
        if existing is not None:
            return self._public_page(existing)
        for _ in range(_SLUG_COLLISION_RETRIES):
            slug = secrets.token_urlsafe(9)
            if self.store.get_entry_page_by_slug(slug) is not None:
                continue
            try:
                page_id = self.store.create_entry_page_resolving_conflict(
                    site_id=site_id,
                    audience=audience,
                    slug=slug,
                    now=self.clock.now(),
                )
            except EntryPageConflict:
                raced = self.store.find_entry_page_by_audience(site_id, audience)
                if raced is not None:
                    return self._public_page(raced)
                continue
            row = self.store.get_entry_page(page_id)
            if row is None:
                msg = "entry page missing after create"
                raise EntryPageValidationError(
                    msg,
                    code="entry.page_not_found",
                    field="page_id",
                )
            return self._public_page(row)
        msg = "unable to allocate unique entry page slug"
        raise EntryPageValidationError(msg, code="entry.validation_failed", field="slug")

    def get_page(self, page_id: str) -> dict[str, Any]:
        row = self.store.get_entry_page(page_id)
        if row is None:
            raise EntryPageNotFound("entry page not found")
        return self._public_page(row)

    def get_page_by_slug(self, slug: str) -> dict[str, Any]:
        row = self.store.get_entry_page_by_slug(slug)
        if row is None:
            raise EntryPageNotFound("entry page not found")
        return self._public_page(row)

    def save_draft(self, page_id: str, document: dict[str, Any]) -> dict[str, Any]:
        page = self.store.get_entry_page(page_id)
        if page is None:
            raise EntryPageNotFound("entry page not found")
        audience = str(page["audience"])
        _canonical, canonical_json, content_sha256 = validate_and_canonicalize_entry_document(
            document,
            audience=audience,
        )
        revision = self.store.append_entry_page_revision(
            page_id=page_id,
            canonical_json=canonical_json,
            content_sha256=content_sha256,
            now=self.clock.now(),
        )
        updated = self.store.get_entry_page(page_id)
        assert updated is not None
        return {
            **self._public_page(updated),
            "revision": self._public_revision(revision),
        }

    def publish(self, page_id: str, revision_id: str) -> dict[str, Any]:
        try:
            self.store.set_entry_page_published_revision(
                page_id=page_id,
                revision_id=revision_id,
                now=self.clock.now(),
            )
        except NotFoundError as exc:
            if "revision" in str(exc):
                raise EntryPageNotFound(
                    "revision not found for entry page",
                    code="entry.revision_not_found",
                ) from exc
            raise EntryPageNotFound("entry page not found") from exc
        row = self.store.get_entry_page(page_id)
        assert row is not None
        return self._public_page(row)

    def unpublish(self, page_id: str) -> dict[str, Any]:
        try:
            self.store.clear_entry_page_published_revision(
                page_id=page_id,
                now=self.clock.now(),
            )
        except NotFoundError as exc:
            raise EntryPageNotFound("entry page not found") from exc
        row = self.store.get_entry_page(page_id)
        assert row is not None
        return self._public_page(row)

    def get_revision(self, page_id: str, revision_id: str) -> dict[str, Any]:
        revision = self.store.get_entry_page_revision(page_id, revision_id)
        if revision is None:
            raise EntryPageNotFound(
                "revision not found for entry page",
                code="entry.revision_not_found",
            )
        body = self._public_revision(revision)
        body["document"] = json.loads(revision["canonical_json"])
        return body

    def render_document_for_page(
        self,
        page_id: str,
        *,
        published_only: bool,
    ) -> tuple[str | None, str]:
        page = self.store.get_entry_page(page_id)
        if page is None:
            raise EntryPageNotFound("entry page not found")
        revision_id = (
            page["published_revision_id"]
            if published_only
            else page["current_revision_id"]
        )
        if revision_id is None:
            reason = (
                "entry.not_published"
                if published_only
                else "entry.no_draft"
            )
            return None, reason
        revision = self.store.get_entry_page_revision(page_id, str(revision_id))
        if revision is None:
            return None, "entry.revision_not_found"
        document = json.loads(revision["canonical_json"])
        submit_path = f"/p/{page['slug']}/submit"
        html_body = render_public_html(
            document,
            audience=str(page["audience"]),
            slug=str(page["slug"]),
            submit_path=submit_path,
        )
        return html_body, "entry.render_ok"

    def _public_page(self, row: dict[str, Any]) -> dict[str, Any]:
        title: str | None = None
        current_revision_id = row.get("current_revision_id")
        if current_revision_id:
            revision = self.store.get_entry_page_revision(
                str(row["page_id"]),
                str(current_revision_id),
            )
            if revision is not None:
                document = json.loads(revision["canonical_json"])
                title = str(document.get("title"))
        return {
            "page_id": row["page_id"],
            "site_id": row["site_id"],
            "audience": row["audience"],
            "slug": row["slug"],
            "title": title,
            "has_draft": current_revision_id is not None,
            "current_revision_id": current_revision_id,
            "published_revision_id": row.get("published_revision_id"),
            "public_path": f"/p/{row['slug']}",
            "created_at_epoch": row["created_at_epoch"],
            "updated_at_epoch": row["updated_at_epoch"],
        }

    def _public_revision(self, revision: dict[str, Any]) -> dict[str, Any]:
        return {
            "revision_id": revision["revision_id"],
            "page_id": revision["page_id"],
            "revision_number": revision["revision_number"],
            "content_sha256": revision["content_sha256"],
            "created_at_epoch": revision["created_at_epoch"],
        }
