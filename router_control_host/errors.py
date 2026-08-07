"""HTTP error helpers."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from router_control.application.wifi_observation_helpers import scrub_error_message
from starlette.exceptions import HTTPException as StarletteHTTPException

_SAFE_VALIDATION_CTX_KEYS = frozenset({"expected", "expected_values", "ge", "le", "gt", "lt"})
_UNRECOGNIZED_FIELD_LOC_PLACEHOLDER = "[unrecognized_field]"

_OPERATOR_REASON_TEMPLATES: dict[str, str] = {
    "unknown_fields": "{context}: unrecognized field(s)",
    "invalid_fqdn": "Field '{field}' has invalid FQDN format",
    "not_allowlisted": "Field '{field}' is not in the allowed set",
    "out_of_range": "Field '{field}' is out of allowed range",
    "invalid_format": "Field '{field}' has invalid format",
    "invalid_value": "Field '{field}' has invalid value",
    "secret_shaped_field": "{context}: secret-shaped field rejected",
    "preview_failed": "Preview compilation failed",
    "apply_failed": "Wi-Fi apply failed",
    "wireguard_apply_failed": "WireGuard apply failed",
    "wireguard_preview_failed": "WireGuard preview failed",
    "observed_state_failed": "Wi-Fi observed state read failed",
    "site_survey_failed": "Wi-Fi site survey failed",
    "live_backup_unavailable": "Startup-config backup unavailable for live apply",
    "trail_begin_failed": "Sealed apply trail begin failed",
    "profile_validation_failed": "VPN profile validation failed",
    "credential_ref_required": "Field '{field}' is required for secured Wi-Fi intent",
    "incomplete": "Live connection incomplete: missing {context}",
    "credential_unusable": "Credential reference is not usable",
    "credential_not_found": "Credential reference not found",
    "credential_kind_invalid": "Credential reference kind is not valid for Wi-Fi apply",
}

_INTENT_CODE_TO_REASON: dict[str, str] = {
    "unknown_fields": "unknown_fields",
    "invalid_fqdn": "invalid_fqdn",
    "secret_shaped_field": "secret_shaped_field",
    "not_allowlisted": "not_allowlisted",
    "invalid_format": "invalid_format",
    "out_of_range": "out_of_range",
    "invalid_value": "invalid_value",
    "invalid_document": "invalid_value",
    "missing_field": "invalid_value",
    "invalid_shape": "invalid_format",
    "unknown_kind": "invalid_value",
}

_RCI_CODE_TO_REASON: dict[str, str] = {
    "not_allowlisted": "not_allowlisted",
    "invalid_fqdn": "invalid_fqdn",
    "invalid_format": "invalid_format",
    "out_of_range": "out_of_range",
    "invalid_value": "invalid_value",
}

_HTTP_STATUS_MESSAGES: dict[int, tuple[str, str]] = {
    400: ("request.validation_failed", "Bad request"),
    401: ("auth.required", "Authentication required"),
    403: ("auth.forbidden", "Forbidden"),
    404: ("resource.not_found", "Resource not found"),
    405: ("http.method_not_allowed", "Method not allowed"),
    409: ("resource.conflict", "Conflict"),
    412: ("resource.precondition_failed", "Precondition failed"),
    422: ("request.validation_failed", "Request validation failed"),
    503: ("service.unavailable", "Service unavailable"),
}

_CONSTRAINT_TYPE_BASES = (
    "int_type",
    "bool_type",
    "float_type",
    "string_type",
    "greater_than_equal",
    "less_than_equal",
    "greater_than",
    "less_than",
    "string_too_short",
    "string_too_long",
)

_STRUCTURAL_TYPE_BASES = (
    "literal_error",
    "missing",
    "extra_forbidden",
    "model_type",
    "dict_type",
)

_PASCAL_CASE_MODEL_TAG = re.compile(r"^[A-Z][A-Za-z0-9]*$")
_LITERAL_BRANCH = re.compile(r"^literal\[(.+)\]$")


def synthesize_operator_message(
    *,
    code: str,
    reason: str,
    field: str | None = None,
    expected: str | None = None,
    context: str | None = None,
) -> str:
    """Build operator-facing message from allowlisted reason templates only."""
    _ = code
    template = _OPERATOR_REASON_TEMPLATES.get(reason)
    if template is None:
        return "Request validation failed"
    ctx = context or field or "request"
    message = template.format(field=field or "request", context=ctx)
    if expected:
        message = f"{message} (expected {expected})"
    return message


def intent_code_to_reason(code: str) -> str:
    return _INTENT_CODE_TO_REASON.get(code, "invalid_value")


def rci_code_to_reason(code: str) -> str:
    return _RCI_CODE_TO_REASON.get(code, "invalid_value")


def operator_structured_error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    reason: str,
    field: str | None = None,
    expected: str | None = None,
    details: list[dict[str, Any]] | None = None,
    context: str | None = None,
) -> JSONResponse:
    message = synthesize_operator_message(
        code=code,
        reason=reason,
        field=field,
        expected=expected,
        context=context,
    )
    detail_items = list(details) if details else []
    if not detail_items and (field or reason):
        item: dict[str, Any] = {"reason": reason}
        if field:
            item["field"] = field
        if expected:
            item["expected"] = expected
        detail_items = [item]
    return error_response(
        request,
        status_code=status_code,
        code=code,
        message=message,
        details=detail_items,
    )


def starlette_http_error_response(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """Map StarletteHTTPException to error envelope without echoing exc.detail."""
    status = exc.status_code
    error_code, message = _HTTP_STATUS_MESSAGES.get(
        status,
        (f"http.{status}", "Request failed"),
    )
    return error_response(
        request,
        status_code=status,
        code=error_code,
        message=message,
        details=[],
    )


def _type_matches_base(error_type: str, bases: tuple[str, ...]) -> bool:
    return error_type in bases or any(error_type.endswith(f".{base}") for base in bases)


def _is_constraint_type(error_type: str) -> bool:
    return _type_matches_base(error_type, _CONSTRAINT_TYPE_BASES)


def _is_structural_type(error_type: str) -> bool:
    return _type_matches_base(error_type, _STRUCTURAL_TYPE_BASES)


def _is_model_type(error_type: str) -> bool:
    return _type_matches_base(error_type, ("model_type",))


def _resolve_pydantic_model_by_name(class_name: str) -> type[BaseModel] | None:
    for module in sys.modules.values():
        if module is None:
            continue
        candidate = getattr(module, class_name, None)
        if (
            isinstance(candidate, type)
            and issubclass(candidate, BaseModel)
            and candidate.__name__ == class_name
        ):
            return candidate
    return None


def _add_forms_from_model_class(
    class_name: str,
    *,
    add_form: Any,
) -> None:
    model_cls = _resolve_pydantic_model_by_name(class_name)
    if model_cls is None:
        return
    for field_name in model_cls.model_fields:
        add_form(f"object with '{field_name}'")


def _is_unrecognized_field_error(error_type: str) -> bool:
    return error_type == "extra_forbidden" or error_type.endswith(".extra_forbidden")


def _loc_segments_after_body(loc: Sequence[Any]) -> list[str]:
    segments: list[str] = []
    for item in loc:
        if item == "body":
            continue
        segments.append(str(item))
    return segments


def _is_pascal_case_model_tag(segment: str) -> bool:
    return bool(_PASCAL_CASE_MODEL_TAG.fullmatch(segment))


def _is_literal_branch(segment: str) -> bool:
    return segment.startswith("literal[")


def _literal_branch_form(segment: str) -> str | None:
    match = _LITERAL_BRANCH.fullmatch(segment)
    if not match:
        return None
    return match.group(1)


def _extract_root_field(loc: Sequence[Any]) -> str | None:
    segments = _loc_segments_after_body(loc)
    return segments[0] if segments else None


def _extract_nested_field_from_loc(loc: Sequence[Any]) -> str | None:
    segments = _loc_segments_after_body(loc)
    if len(segments) < 2:
        return None
    candidates: list[str] = []
    for segment in segments[1:]:
        if segment == _UNRECOGNIZED_FIELD_LOC_PLACEHOLDER:
            continue
        if _is_pascal_case_model_tag(segment) or _is_literal_branch(segment):
            continue
        candidates.append(segment)
    return candidates[-1] if candidates else None


def _loc_has_union_indicator(loc: Sequence[Any]) -> bool:
    segments = _loc_segments_after_body(loc)
    return any(
        _is_literal_branch(segment) or _is_pascal_case_model_tag(segment)
        for segment in segments
    )


def _group_errors_by_root(errors: Sequence[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in errors:
        root = _extract_root_field(item.get("loc", ()))
        if root is not None:
            grouped[root].append(item)
    return grouped


def _is_union_cluster(cluster: Sequence[dict[str, Any]]) -> bool:
    if len(cluster) < 2:
        return False
    for item in cluster:
        if str(item.get("type", "")) == "literal_error":
            return True
        if _loc_has_union_indicator(item.get("loc", ())):
            return True
    return False


def _find_union_cluster_for_first_error(
    errors: Sequence[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    if not errors:
        return None
    grouped = _group_errors_by_root(errors)
    first_root = _extract_root_field(errors[0].get("loc", ()))
    if first_root is None:
        return None
    cluster = grouped.get(first_root, [])
    if _is_union_cluster(cluster):
        return cluster
    return None


def _sanitize_validation_loc(loc: Sequence[Any], *, error_type: str) -> list[Any]:
    loc_list = list(loc) if isinstance(loc, Sequence) else [loc]
    if not _is_unrecognized_field_error(error_type) or not loc_list:
        return loc_list
    sanitized = list(loc_list)
    sanitized[-1] = _UNRECOGNIZED_FIELD_LOC_PLACEHOLDER
    return sanitized


def _format_validation_loc(loc: Sequence[Any], *, error_type: str = "") -> str:
    if _is_unrecognized_field_error(error_type):
        return _UNRECOGNIZED_FIELD_LOC_PLACEHOLDER
    parts: list[str] = []
    for item in loc:
        if item == "body":
            continue
        parts.append(str(item))
    return ".".join(parts) if parts else "request"


def _safe_validation_ctx(ctx: dict[str, Any] | None) -> dict[str, Any] | None:
    if not ctx:
        return None
    safe = {str(key): value for key, value in ctx.items() if key in _SAFE_VALIDATION_CTX_KEYS}
    return safe or None


def _format_bounds_from_ctx(ctx: dict[str, Any] | None) -> str:
    if not ctx:
        return ""
    if "expected" in ctx:
        return f"(expected {ctx['expected']})"
    if "expected_values" in ctx:
        return f"(expected one of: {ctx['expected_values']})"
    if "ge" in ctx and "le" in ctx:
        return f"(expected >= {ctx['ge']} and <= {ctx['le']})"
    if "ge" in ctx:
        return f"(expected >= {ctx['ge']})"
    if "le" in ctx:
        return f"(expected <= {ctx['le']})"
    if "gt" in ctx:
        return f"(expected > {ctx['gt']})"
    if "lt" in ctx:
        return f"(expected < {ctx['lt']})"
    return ""


def _synthesize_validation_item_message(
    *,
    loc_path: str,
    error_type: str,
    ctx: dict[str, Any] | None,
) -> str:
    if _is_unrecognized_field_error(error_type):
        message = f"Unrecognized field in request: {error_type}"
    else:
        message = f"Invalid value for {loc_path}: {error_type}"
    bounds = _format_bounds_from_ctx(ctx)
    if bounds:
        message = f"{message} {bounds}"
    return message


def _collect_union_allowed_forms(cluster: Sequence[dict[str, Any]]) -> list[str]:
    forms: list[str] = []
    seen: set[str] = set()

    def add_form(form: str) -> None:
        if form not in seen:
            seen.add(form)
            forms.append(form)

    for item in cluster:
        loc = item.get("loc", ())
        error_type = str(item.get("type", ""))
        segments = _loc_segments_after_body(loc if isinstance(loc, Sequence) else (loc,))
        ctx_raw = item.get("ctx")
        ctx = ctx_raw if isinstance(ctx_raw, dict) else None

        for segment in segments:
            if _is_literal_branch(segment):
                if ctx and "expected" in ctx:
                    add_form(str(ctx["expected"]))
                else:
                    literal_form = _literal_branch_form(segment)
                    if literal_form is not None:
                        add_form(literal_form)

        for idx, segment in enumerate(segments):
            if _is_pascal_case_model_tag(segment):
                if _is_unrecognized_field_error(error_type) and idx == len(segments) - 1:
                    continue
                _add_forms_from_model_class(segment, add_form=add_form)

        if _is_model_type(error_type) and ctx and "class_name" in ctx:
            _add_forms_from_model_class(str(ctx["class_name"]), add_form=add_form)

        if _is_unrecognized_field_error(error_type):
            continue

        nested = _extract_nested_field_from_loc(loc if isinstance(loc, Sequence) else (loc,))
        if nested and any(_is_pascal_case_model_tag(segment) for segment in segments):
            add_form(f"object with '{nested}'")
        elif nested and error_type == "missing":
            add_form(f"object with '{nested}'")

    return forms


def _synthesize_union_cluster_summary(cluster: Sequence[dict[str, Any]]) -> str:
    root = _extract_root_field(cluster[0].get("loc", ()))
    if root is None:
        return "Request validation failed"

    constraint_errors = [
        item for item in cluster if _is_constraint_type(str(item.get("type", "")))
    ]
    nested_fields = {
        nested
        for item in constraint_errors
        if (nested := _extract_nested_field_from_loc(item.get("loc", ()))) is not None
    }
    non_constraint_errors = [
        item for item in cluster if not _is_constraint_type(str(item.get("type", "")))
    ]
    siblings_only_structural = all(
        _is_structural_type(str(item.get("type", ""))) for item in non_constraint_errors
    )

    if len(nested_fields) == 1 and siblings_only_structural and constraint_errors:
        nested = next(iter(nested_fields))
        winner = next(
            item
            for item in constraint_errors
            if _extract_nested_field_from_loc(item.get("loc", ())) == nested
        )
        error_type = str(winner.get("type", "validation_error"))
        ctx = _safe_validation_ctx(
            winner.get("ctx") if isinstance(winner.get("ctx"), dict) else None
        )
        return _synthesize_validation_item_message(
            loc_path=f"{root}.{nested}",
            error_type=error_type,
            ctx=ctx,
        )

    allowed_forms = _collect_union_allowed_forms(cluster)
    allowed_text = ", ".join(allowed_forms) if allowed_forms else "see details"
    return (
        f"Invalid value for {root}: does not match any allowed form "
        f"(allowed: {allowed_text})"
    )


def _synthesize_validation_summary(errors: Sequence[dict[str, Any]]) -> str:
    if not errors:
        return "Request validation failed"

    union_cluster = _find_union_cluster_for_first_error(errors)
    if union_cluster is not None:
        return _synthesize_union_cluster_summary(union_cluster)

    first = errors[0]
    first_loc = first.get("loc", ())
    first_type = str(first.get("type", "validation_error"))
    first_ctx = _safe_validation_ctx(
        first.get("ctx") if isinstance(first.get("ctx"), dict) else None
    )
    return _synthesize_validation_item_message(
        loc_path=_format_validation_loc(
            first_loc if isinstance(first_loc, Sequence) else (),
            error_type=first_type,
        ),
        error_type=first_type,
        ctx=first_ctx,
    )


def build_validation_error_details(
    errors: Sequence[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """Rebuild Pydantic validation errors without echoing user input or raw msg."""
    details: list[dict[str, Any]] = []
    for item in errors:
        loc = item.get("loc", ())
        error_type = str(item.get("type", "validation_error"))
        ctx_raw = item.get("ctx")
        safe_ctx = _safe_validation_ctx(ctx_raw if isinstance(ctx_raw, dict) else None)
        sanitized_loc = _sanitize_validation_loc(
            loc if isinstance(loc, Sequence) else (loc,),
            error_type=error_type,
        )
        detail: dict[str, Any] = {
            "loc": sanitized_loc,
            "type": error_type,
        }
        if safe_ctx is not None:
            detail["ctx"] = safe_ctx
        details.append(detail)

    if not details:
        return "Request validation failed", []

    summary = _synthesize_validation_summary(errors)
    if len(details) > 1:
        summary = f"{summary} (+{len(details) - 1} more)"
    return summary, details


def validation_error_response(request: Request, exc: RequestValidationError) -> JSONResponse:
    message, details = build_validation_error_details(exc.errors())
    return error_response(
        request,
        status_code=422,
        code="request.validation_failed",
        message=message,
        details=details,
    )


def _scrub_error_value(value: Any) -> Any:
    """Recursively scrub string leaves in nested error detail structures (F-2)."""
    if isinstance(value, str):
        return scrub_error_message(value)
    if isinstance(value, dict):
        return {str(key): _scrub_error_value(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_scrub_error_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_error_value(item) for item in value)
    return value


def _scrub_error_details(details: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not details:
        return []
    scrubbed: list[dict[str, Any]] = []
    for item in details:
        clean: dict[str, Any] = {}
        for key, value in item.items():
            clean[str(key)] = _scrub_error_value(value)
        scrubbed.append(clean)
    return scrubbed


def error_body(
    *,
    code: str,
    message: str,
    request_id: str,
    correlation_id: str,
    details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": scrub_error_message(message),
            "details": _scrub_error_details(details),
            "request_id": request_id,
            "correlation_id": correlation_id,
        }
    }


def error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "req_unknown")
    correlation_id = getattr(request.state, "correlation_id", request_id)
    return JSONResponse(
        status_code=status_code,
        content=error_body(
            code=code,
            message=message,
            request_id=request_id,
            correlation_id=correlation_id,
            details=details,
        ),
        headers={
            "X-Request-Id": request_id,
            "X-Correlation-Id": correlation_id,
        },
    )


def sealed_apply_trail_begin_error_response(
    request: Request, exc: Exception
) -> JSONResponse:
    _ = exc
    return error_response(
        request,
        status_code=503,
        code="sealed_apply.trail_begin_failed",
        message=synthesize_operator_message(
            code="sealed_apply.trail_begin_failed",
            reason="trail_begin_failed",
        ),
    )
