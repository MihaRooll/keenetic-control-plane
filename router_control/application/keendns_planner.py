"""Offline KeenDNS/CrazeDNS sealed preview descriptor compiler (docs-sourced grammar only)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast

from router_control.application.grammar_doc_refs import build_planner_op_notes

_KEENDNS_FAMILY = "keendns"
_DISCOVERY_DOC = "docs/OPERATOR_KEENDNS_DISCOVERY.md"
_VERIFICATION_STATUS = "documentation_sourced_unconfirmed"

KeenDnsIntentKind = Literal["book", "drop"]
KeenDnsAccessMode = Literal["auto", "cloud", "direct"]

KEENDNS_ALLOWED_DOMAINS = frozenset(
    {
        "keenetic.pro",
        "keenetic.name",
        "keenetic.link",
        "netcraze.pro",
        "netcraze.link",
        "netcraze.club",
        "crazedns.ru",
    }
)
_ALLOWED_DOMAINS = KEENDNS_ALLOWED_DOMAINS
_MAX_NAME_LEN = 63
_DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class KeenDnsPlannerError(ValueError):
    """Fail-closed KeenDNS preview planner error."""


@dataclass(frozen=True, slots=True)
class KeenDnsSealedOpDescriptor:
    operation: str
    command_text: str
    name: str | None = None
    domain: str | None = None
    mode: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class KeenDnsPreviewPlan:
    intent_kind: str
    name: str
    domain: str
    mode: str | None
    preview_ops: tuple[KeenDnsSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...]


def normalize_keendns_name(raw: str) -> str:
    """Strip + ASCII lower — shared SSOT with UI and allowlist."""
    return raw.strip().lower()


def validate_keendns_dns_label(name: str) -> str:
    """Return normalized DNS label or raise KeenDnsPlannerError."""
    normalized = normalize_keendns_name(name)
    if not normalized or len(normalized) > _MAX_NAME_LEN:
        raise KeenDnsPlannerError("name must be a DNS label of length 1-63")
    if not _DNS_LABEL_RE.fullmatch(normalized):
        raise KeenDnsPlannerError(
            "name must match DNS label grammar (a-z0-9 with internal hyphens only)"
        )
    return normalized


def _validate_name(raw: Any) -> str:
    if not isinstance(raw, str):
        raise KeenDnsPlannerError("name must be a non-empty string")
    return validate_keendns_dns_label(raw)


def _validate_domain(raw: Any) -> str:
    if not isinstance(raw, str):
        raise KeenDnsPlannerError("domain must be a non-empty string")
    domain = raw.strip().lower()
    if domain not in _ALLOWED_DOMAINS:
        raise KeenDnsPlannerError(
            f"domain must be one of docs-sourced accept-list ({_DISCOVERY_DOC} §3)"
        )
    return domain


def _validate_mode(raw: Any) -> KeenDnsAccessMode:
    if raw not in ("auto", "cloud", "direct"):
        raise KeenDnsPlannerError("mode must be auto, cloud, or direct (docs-sourced labels)")
    return cast(KeenDnsAccessMode, raw)


def _book_command(name: str, domain: str, mode: str) -> str:
    return f"ndns book-name {name} {domain} {mode}"


def _drop_command(name: str, domain: str) -> str:
    return f"ndns drop-name {name} {domain}"


def compile_keendns_book_preview(
    name: str, domain: str, mode: KeenDnsAccessMode
) -> KeenDnsPreviewPlan:
    validated_name = _validate_name(name)
    validated_domain = _validate_domain(domain)
    validated_mode = _validate_mode(mode)
    command = _book_command(validated_name, validated_domain, validated_mode)
    notes = build_planner_op_notes(
        _KEENDNS_FAMILY,
        "keendns_book_name",
        sealed_template=command,
        extra=(
            f"documentation_sourced_unconfirmed; candidate CLI from {_DISCOVERY_DOC} §3",
            "standing authorized expendable lab 2026-08-08; cloud registration not auto-proven",
            "not device-observed in lab",
        ),
    )
    op = KeenDnsSealedOpDescriptor(
        operation="keendns_book_name",
        command_text=command,
        name=validated_name,
        domain=validated_domain,
        mode=validated_mode,
        notes=notes,
    )
    plan_notes = (
        f"sealed descriptor; verification_status={_VERIFICATION_STATUS}",
        f"grammar docs-sourced ({_DISCOVERY_DOC} §3); not device-certified",
        "apply path shipped offline; live cloud registration not verified by host",
    )
    return KeenDnsPreviewPlan(
        intent_kind="book",
        name=validated_name,
        domain=validated_domain,
        mode=validated_mode,
        preview_ops=(op,),
        verification_status=_VERIFICATION_STATUS,
        notes=plan_notes,
    )


def compile_keendns_drop_preview(name: str, domain: str) -> KeenDnsPreviewPlan:
    validated_name = _validate_name(name)
    validated_domain = _validate_domain(domain)
    command = _drop_command(validated_name, validated_domain)
    notes = build_planner_op_notes(
        _KEENDNS_FAMILY,
        "keendns_drop_name",
        sealed_template=command,
        extra=(
            f"documentation_sourced_unconfirmed; candidate CLI from {_DISCOVERY_DOC} §3",
            "standing authorized expendable lab 2026-08-08; cloud registration not auto-proven",
            "not device-observed in lab",
        ),
    )
    op = KeenDnsSealedOpDescriptor(
        operation="keendns_drop_name",
        command_text=command,
        name=validated_name,
        domain=validated_domain,
        notes=notes,
    )
    plan_notes = (
        f"sealed descriptor; verification_status={_VERIFICATION_STATUS}",
        f"grammar docs-sourced ({_DISCOVERY_DOC} §3); not device-certified",
        "apply path shipped offline; live cloud registration not verified by host",
    )
    return KeenDnsPreviewPlan(
        intent_kind="drop",
        name=validated_name,
        domain=validated_domain,
        mode=None,
        preview_ops=(op,),
        verification_status=_VERIFICATION_STATUS,
        notes=plan_notes,
    )


def compile_keendns_preview_intent(intent: Mapping[str, Any]) -> KeenDnsPreviewPlan:
    kind = intent.get("intent_kind")
    if kind not in ("book", "drop"):
        raise KeenDnsPlannerError("intent_kind must be book or drop")
    name = _validate_name(intent.get("name"))
    domain = _validate_domain(intent.get("domain"))
    if kind == "book":
        mode = _validate_mode(intent.get("mode"))
        return compile_keendns_book_preview(name, domain, mode)
    return compile_keendns_drop_preview(name, domain)


def plan_to_preview_dict(plan: KeenDnsPreviewPlan) -> dict[str, object]:
    return {
        "intent_kind": plan.intent_kind,
        "name": plan.name,
        "domain": plan.domain,
        "mode": plan.mode,
        "verification_status": plan.verification_status,
        "notes": list(plan.notes),
        "preview_ops": [
            {
                "operation": op.operation,
                "command_text": op.command_text,
                "name": op.name,
                "domain": op.domain,
                "mode": op.mode,
                "notes": list(op.notes),
            }
            for op in plan.preview_ops
        ],
    }


def compile_keendns_apply_intent(intent: Mapping[str, Any]) -> KeenDnsPreviewPlan:
    """Compile sealed book/drop ops for apply dispatch (same validation as preview)."""
    return compile_keendns_preview_intent(intent)


__all__ = [
    "KEENDNS_ALLOWED_DOMAINS",
    "KeenDnsPlannerError",
    "KeenDnsPreviewPlan",
    "KeenDnsSealedOpDescriptor",
    "compile_keendns_apply_intent",
    "compile_keendns_book_preview",
    "compile_keendns_drop_preview",
    "compile_keendns_preview_intent",
    "normalize_keendns_name",
    "plan_to_preview_dict",
    "validate_keendns_dns_label",
]
