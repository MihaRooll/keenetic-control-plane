"""Typed codec encode/decode tests."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.codec import (
    CodecError,
    HttpExchange,
    InMemorySecretResolver,
    NormalizedError,
    SecretSlot,
    SecretSlotKind,
    TypedIntent,
    codec_for_spec,
)
from router_control.adapters.netcraze.operation_spec import SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN


def test_encode_rejects_path_in_intent_fields() -> None:
    with pytest.raises(CodecError, match="path"):
        TypedIntent(
            operation_spec_digest=SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.spec_digest,
            fields={"path": "/evil", "mode": "on"},
        )


def test_encode_resolves_secret_slots() -> None:
    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN)
    resolver = InMemorySecretResolver()
    intent = TypedIntent(
        operation_spec_digest=SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.spec_digest,
        fields={"mode": "on"},
        secret_slots=(),
    )
    wire = codec.encode(intent, resolver)
    assert wire.endpoint_identifier == SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.endpoint_identifier
    assert "password" not in wire.sanitized_dict().__str__().lower()


def test_decode_command_level_error_fail_closed() -> None:
    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN)
    exchange = HttpExchange(
        status=200,
        headers={},
        body=json.dumps({"error": "command rejected"}).encode("utf-8"),
    )
    outcome = codec.decode(exchange)
    assert isinstance(outcome, NormalizedError)
    assert outcome.error_code == "command_level_error"


def test_decode_unknown_fields_rejected() -> None:
    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN)
    exchange = HttpExchange(
        status=200,
        headers={},
        body=json.dumps({"status": "ok", "unexpected": True}).encode("utf-8"),
    )
    outcome = codec.decode(exchange)
    assert isinstance(outcome, NormalizedError)


def test_secret_slot_not_in_repr() -> None:
    slot = SecretSlot(
        field_name="mode",
        kind=SecretSlotKind.PASSWORD,
        credential_ref_id="cred-001",
    )
    assert "cred-001" not in repr(slot)


def test_wire_request_repr_is_secret_safe() -> None:
    from router_control.adapters.netcraze.codec import WireRequest
    from router_control.adapters.netcraze.operation_spec import TransportKind

    wire = WireRequest(
        transport_kind=TransportKind.RCI_HTTP,
        method="POST",
        endpoint_identifier="/rci/fail-safe/begin",
        body=b'{"mode":"on","password":"super-secret-password"}',
        body_field_keys=("mode", "password"),
        secret_slot_count=1,
    )
    rendered = repr(wire)
    assert "super-secret-password" not in rendered
    assert "body_sha256=" in rendered


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (401, {"status": "ok"}),
        (403, {"status": "ok"}),
        (200, {}),
        (200, {"fields": {}}),
    ],
)
def test_decode_http_fail_closed_on_bad_status_or_payload(status: int, body: dict) -> None:
    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN)
    exchange = HttpExchange(
        status=status,
        headers={},
        body=json.dumps(body).encode("utf-8"),
    )
    outcome = codec.decode(exchange)
    assert isinstance(outcome, NormalizedError)


def test_decode_sealed_cli_prehash_path_requires_ack_and_empty_raw() -> None:
    from router_control.adapters.netcraze.codec import SealedCliExchange, codec_for_spec
    from router_control.adapters.netcraze.operation_spec import (
        SYNTHETIC_RECORDED_FAIL_SAFE_TIMER,
    )

    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_TIMER)
    exchange = SealedCliExchange(
        exit_status=0,
        stdout=b"",
        stderr=b"",
        stdout_sha256="sha256:" + "a" * 64,
        stderr_sha256="sha256:" + "b" * 64,
        ack_matched=True,
        stdout_byte_count=10,
        stderr_byte_count=0,
    )
    outcome = codec.decode(exchange)
    assert not isinstance(outcome, NormalizedError)
    assert outcome.status == "executed"
    assert outcome.fields["stdout_sha256"] == "sha256:" + "a" * 64


def test_decode_sealed_cli_rejects_raw_with_prehash() -> None:
    from router_control.adapters.netcraze.codec import SealedCliExchange, codec_for_spec
    from router_control.adapters.netcraze.operation_spec import (
        SYNTHETIC_RECORDED_FAIL_SAFE_TIMER,
    )

    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_TIMER)
    exchange = SealedCliExchange(
        exit_status=0,
        stdout=b"raw",
        stderr=b"",
        stdout_sha256="sha256:" + "a" * 64,
        stderr_sha256="sha256:" + "b" * 64,
        ack_matched=True,
    )
    outcome = codec.decode(exchange)
    assert isinstance(outcome, NormalizedError)
    assert outcome.error_code == "cli_provenance_conflict"


def test_decode_sealed_cli_bytes_path_requires_ack() -> None:
    from router_control.adapters.netcraze.codec import SealedCliExchange, codec_for_spec
    from router_control.adapters.netcraze.operation_spec import (
        SYNTHETIC_RECORDED_FAIL_SAFE_TIMER,
    )

    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_TIMER)
    exchange = SealedCliExchange(exit_status=0, stdout=b"ok", stderr=b"")
    outcome = codec.decode(exchange)
    assert isinstance(outcome, NormalizedError)
    assert outcome.error_code == "cli_ack_unverified"


def test_sealed_cli_exchange_repr_redacts_raw_bytes() -> None:
    from router_control.adapters.netcraze.codec import SealedCliExchange

    exchange = SealedCliExchange(0, b"raw-cli-secret", b"stderr-secret", ack_matched=True)
    rendered = repr(exchange)
    assert "raw-cli-secret" not in rendered
    assert "stderr-secret" not in rendered
    assert "stdout_sha256=" in rendered
