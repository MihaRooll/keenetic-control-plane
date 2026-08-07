"""Typed operation codecs — deterministic encode/decode, secret slots, fail-closed."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from router_control.adapters.netcraze.operation_spec import (
    OperationSpec,
    OperationSpecError,
    TransportKind,
    UnknownFieldPolicy,
)

_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SECRET_LIKE = frozenset(
    {"password", "privatekey", "presharedkey", "secret", "token", "private_key"}
)
_REDACTED = "[REDACTED]"


class CodecError(OperationSpecError):
    """Codec encode/decode failure."""


class SecretSlotKind(StrEnum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    PRESHARED_KEY = "preshared_key"


@dataclass(frozen=True, slots=True)
class SecretSlot:
    field_name: str
    kind: SecretSlotKind
    credential_ref_id: str

    def __repr__(self) -> str:
        return (
            f"SecretSlot(field_name={self.field_name!r}, "
            f"kind={self.kind.value!r}, credential_ref_id=<redacted>)"
        )


class SecretResolver(Protocol):
    def resolve(self, credential_ref_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class TypedIntent:
    operation_spec_digest: str
    fields: dict[str, Any]
    secret_slots: tuple[SecretSlot, ...] = ()

    def __post_init__(self) -> None:
        forbidden = {"path", "command", "raw_json", "method", "endpoint"}
        for key in self.fields:
            normalized = key.strip().lower().replace("-", "_")
            if normalized in forbidden or normalized in _SECRET_LIKE:
                raise CodecError("intent fields must not include path/command/raw JSON or secrets")
        for slot in self.secret_slots:
            if slot.field_name not in self.fields:
                raise CodecError(f"secret slot references missing field: {slot.field_name}")


@dataclass(frozen=True, slots=True)
class WireRequest:
    transport_kind: TransportKind
    method: str
    endpoint_identifier: str
    body: bytes
    body_field_keys: tuple[str, ...]
    secret_slot_count: int

    def __repr__(self) -> str:
        sanitized = self.sanitized_dict()
        return (
            f"WireRequest(transport_kind={self.transport_kind.value!r}, "
            f"method={self.method!r}, endpoint_identifier={self.endpoint_identifier!r}, "
            f"body_sha256={sanitized['body_sha256']!r}, "
            f"body_field_keys={list(self.body_field_keys)!r}, "
            f"secret_slot_count={self.secret_slot_count})"
        )

    __str__ = __repr__

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "transport_kind": self.transport_kind.value,
            "method": self.method,
            "endpoint_identifier": self.endpoint_identifier,
            "body_sha256": f"sha256:{hashlib.sha256(self.body).hexdigest()}",
            "body_field_keys": list(self.body_field_keys),
            "secret_slot_count": self.secret_slot_count,
        }


@dataclass(frozen=True, slots=True)
class ContinuationToken:
    token: str
    poll_spec_id: str
    round_index: int


@dataclass(frozen=True, slots=True)
class TypedOutcome:
    status: str
    fields: dict[str, Any]
    continuation: ContinuationToken | None = None

    def sanitized_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "fields": _redact_mapping(self.fields),
        }
        if self.continuation is not None:
            payload["continuation"] = {
                "poll_spec_id": self.continuation.poll_spec_id,
                "round_index": self.continuation.round_index,
            }
        return payload


@dataclass(frozen=True, slots=True)
class NormalizedError:
    error_code: str
    message: str
    fail_closed: bool = True

    def sanitized_dict(self) -> dict[str, str | bool]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "fail_closed": self.fail_closed,
        }


@dataclass(frozen=True, slots=True)
class HttpExchange:
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class SealedCliExchange:
    exit_status: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    ack_matched: bool | None = None
    stdout_byte_count: int | None = None
    stderr_byte_count: int | None = None

    def __repr__(self) -> str:
        stdout_digest = (
            self.stdout_sha256
            if self.stdout_sha256 is not None
            else f"sha256:{hashlib.sha256(self.stdout).hexdigest()}"
            if self.stdout
            else None
        )
        stderr_digest = (
            self.stderr_sha256
            if self.stderr_sha256 is not None
            else f"sha256:{hashlib.sha256(self.stderr).hexdigest()}"
            if self.stderr
            else None
        )
        return (
            f"SealedCliExchange(exit_status={self.exit_status!r}, "
            f"stdout_sha256={stdout_digest!r}, stderr_sha256={stderr_digest!r}, "
            f"ack_matched={self.ack_matched!r}, "
            f"stdout_byte_count={self.stdout_byte_count!r}, "
            f"stderr_byte_count={self.stderr_byte_count!r})"
        )

    __str__ = __repr__


Exchange = HttpExchange | SealedCliExchange


def _redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        normalized = key.strip().lower().replace("-", "_")
        if normalized in _SECRET_LIKE or "secret" in normalized or "password" in normalized:
            redacted[key] = _REDACTED
        elif isinstance(value, dict):
            redacted[key] = _redact_mapping(value)
        else:
            redacted[key] = value
    return redacted


def _reject_unknown_fields(data: dict[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(set(data.keys()) - allowed)
    if unknown:
        raise CodecError(f"unknown response fields: {unknown}")


@dataclass(frozen=True, slots=True)
class OperationCodec:
    spec: OperationSpec

    @property
    def digest(self) -> str:
        return self.spec.codec_digest

    def encode(self, intent: TypedIntent, secret_resolver: SecretResolver) -> WireRequest:
        if intent.operation_spec_digest != self.spec.spec_digest:
            raise CodecError("intent operation_spec_digest mismatch")
        allowed_fields = frozenset(self.spec.body_field_keys)
        if set(intent.fields.keys()) - allowed_fields:
            raise CodecError("intent contains fields outside spec body_field_keys")
        for key in self.spec.body_field_keys:
            if key not in intent.fields:
                raise CodecError(f"missing required body field: {key}")

        body_payload: dict[str, Any] = {}
        for key, value in intent.fields.items():
            body_payload[key] = value
        for slot in intent.secret_slots:
            secret_value = secret_resolver.resolve(slot.credential_ref_id)
            if not secret_value:
                raise CodecError(f"secret slot unresolved: {slot.field_name}")
            body_payload[slot.field_name] = secret_value

        body = json.dumps(body_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return WireRequest(
            transport_kind=self.spec.transport_kind,
            method=self.spec.http_method.upper(),
            endpoint_identifier=self.spec.endpoint_identifier,
            body=body,
            body_field_keys=self.spec.body_field_keys,
            secret_slot_count=len(intent.secret_slots),
        )

    def decode(self, exchange: Exchange) -> TypedOutcome | NormalizedError:
        if isinstance(exchange, HttpExchange):
            return self._decode_http(exchange)
        return self._decode_sealed_cli(exchange)

    def decode_continuation(
        self,
        exchange: Exchange,
        *,
        prior_token: ContinuationToken,
    ) -> TypedOutcome | NormalizedError:
        if prior_token.round_index < 0:
            raise CodecError("invalid continuation round index")
        outcome = self.decode(exchange)
        if isinstance(outcome, NormalizedError):
            return outcome
        if outcome.continuation is None:
            return outcome
        return TypedOutcome(
            status=outcome.status,
            fields=outcome.fields,
            continuation=ContinuationToken(
                token=outcome.continuation.token,
                poll_spec_id=prior_token.poll_spec_id,
                round_index=prior_token.round_index + 1,
            ),
        )

    def _decode_http(self, exchange: HttpExchange) -> TypedOutcome | NormalizedError:
        if exchange.status >= 500:
            return NormalizedError(
                error_code="transport_error",
                message=f"HTTP {exchange.status}",
            )
        if exchange.status in {408, 504}:
            return NormalizedError(error_code="timeout", message="request timed out")
        if exchange.status == 401:
            return NormalizedError(error_code="session_loss", message="HTTP 401 unauthorized")
        if exchange.status == 403:
            return NormalizedError(error_code="forbidden", message="HTTP 403 forbidden")
        if not 200 <= exchange.status < 300:
            return NormalizedError(
                error_code="transport_error",
                message=f"HTTP {exchange.status}",
            )
        try:
            payload = json.loads(exchange.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return NormalizedError(error_code="incomplete_payload", message="invalid JSON body")
        if not isinstance(payload, dict):
            return NormalizedError(
                error_code="incomplete_payload",
                message="response must be object",
            )

        if payload.get("continued") is True:
            token_raw = str(payload.get("continuation_token", "")).strip()
            if not token_raw:
                return NormalizedError(
                    error_code="continuation_unknown",
                    message="continued response missing token",
                )
            poll_spec = self.spec.continuation_poll_spec_id or "continuation:unknown"
            return TypedOutcome(
                status="continued",
                fields={"continued": True},
                continuation=ContinuationToken(
                    token=token_raw,
                    poll_spec_id=poll_spec,
                    round_index=0,
                ),
            )

        if payload.get("error") is not None:
            return NormalizedError(
                error_code="command_level_error",
                message=str(payload.get("error", "command failed")),
            )

        if self.spec.unknown_field_policy == UnknownFieldPolicy.REJECT:
            allowed = frozenset({"status", "result", "fields", "continued", "continuation_token"})
            unknown = sorted(set(payload.keys()) - allowed)
            if unknown:
                return NormalizedError(
                    error_code="unknown_fields",
                    message=f"unknown response fields: {unknown}",
                )

        if "status" not in payload:
            return NormalizedError(
                error_code="incomplete_payload",
                message="response missing status",
            )
        status = str(payload["status"]).strip()
        if not status:
            return NormalizedError(
                error_code="incomplete_payload",
                message="response status must not be empty",
            )
        fields_raw = payload.get("fields") or payload.get("result") or {}
        if not isinstance(fields_raw, dict):
            fields_raw = {"value": fields_raw}
        return TypedOutcome(status=status, fields=_redact_mapping(dict(fields_raw)))

    def _normalize_sha256_field(self, value: str) -> str:
        text = value.strip().lower()
        if _SHA256_PREFIX_RE.match(text):
            return text
        if re.fullmatch(r"[a-f0-9]{64}", text):
            return f"sha256:{text}"
        raise CodecError("trusted prehash must be sha256:<64-hex>")

    def _decode_sealed_cli(self, exchange: SealedCliExchange) -> TypedOutcome | NormalizedError:
        if exchange.exit_status != 0:
            return NormalizedError(
                error_code="cli_non_zero_exit",
                message=f"sealed CLI exit status {exchange.exit_status}",
            )
        has_prehash = (
            exchange.stdout_sha256 is not None
            and exchange.stderr_sha256 is not None
            and exchange.ack_matched is not None
        )
        if has_prehash:
            stdout_prehash = exchange.stdout_sha256
            stderr_prehash = exchange.stderr_sha256
            ack_matched = exchange.ack_matched
            if stdout_prehash is None or stderr_prehash is None or ack_matched is None:
                return NormalizedError(
                    error_code="cli_provenance_invalid",
                    message="sealed CLI prehash fields incomplete",
                )
            if exchange.stdout or exchange.stderr:
                return NormalizedError(
                    error_code="cli_provenance_conflict",
                    message="sealed CLI prehash path forbids raw stdout/stderr payload",
                )
            if not ack_matched:
                return NormalizedError(
                    error_code="cli_ack_unverified",
                    message="sealed CLI ack not matched",
                )
            try:
                stdout_digest = self._normalize_sha256_field(stdout_prehash)
                stderr_digest = self._normalize_sha256_field(stderr_prehash)
            except CodecError as exc:
                return NormalizedError(
                    error_code="cli_provenance_invalid",
                    message=str(exc),
                )
            fields: dict[str, Any] = {
                "stdout_sha256": stdout_digest,
                "stderr_sha256": stderr_digest,
                "ack_matched": True,
            }
            if exchange.stdout_byte_count is not None:
                fields["stdout_byte_count"] = exchange.stdout_byte_count
            if exchange.stderr_byte_count is not None:
                fields["stderr_byte_count"] = exchange.stderr_byte_count
            return TypedOutcome(status="executed", fields=fields)

        if exchange.ack_matched is None:
            return NormalizedError(
                error_code="cli_ack_unverified",
                message="sealed CLI ack not verified",
            )
        if not exchange.ack_matched:
            return NormalizedError(
                error_code="cli_ack_unverified",
                message="sealed CLI ack not matched",
            )
        return TypedOutcome(
            status="executed",
            fields={
                "stdout_sha256": f"sha256:{hashlib.sha256(exchange.stdout).hexdigest()}",
                "stderr_sha256": f"sha256:{hashlib.sha256(exchange.stderr).hexdigest()}",
                "ack_matched": True,
            },
        )


@dataclass
class InMemorySecretResolver:
    _secrets: dict[str, str] = field(default_factory=dict)

    def store(self, credential_ref_id: str, secret: str) -> None:
        self._secrets[credential_ref_id] = secret

    def resolve(self, credential_ref_id: str) -> str:
        try:
            return self._secrets[credential_ref_id]
        except KeyError as exc:
            raise CodecError(f"unknown credential_ref_id: {credential_ref_id}") from exc


def codec_for_spec(spec: OperationSpec) -> OperationCodec:
    return OperationCodec(spec=spec)


__all__ = [
    "CodecError",
    "ContinuationToken",
    "Exchange",
    "HttpExchange",
    "InMemorySecretResolver",
    "NormalizedError",
    "OperationCodec",
    "SecretResolver",
    "SecretSlot",
    "SecretSlotKind",
    "SealedCliExchange",
    "TypedIntent",
    "TypedOutcome",
    "WireRequest",
    "codec_for_spec",
]
