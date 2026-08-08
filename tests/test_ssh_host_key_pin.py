"""Offline tests for SSH host-key learn/confirm/pin application service."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.errors import SshHostKeyMissing
from router_control.adapters.netcraze.transport import normalize_management_host
from router_control.application.ssh_host_key_pin import (
    LearnCandidateResult,
    PendingLearnRegistry,
    SshHostKeyPinConflict,
    confirm_pin,
    learn_candidate,
    record_pending_learn,
    resolve_identity_router_id_for_host,
    resolve_ssh_host_key_sha256,
)
from router_control.persistence.connection import open_database
from router_control.persistence.errors import PreconditionFailed
from router_control.persistence.store import PersistenceStore
from router_control_host.wifi_live_transport import (
    connection_params_from_fields,
    missing_connection_fields,
)


class _FakeKey:
    def __init__(self, key_type: str, key_bytes: bytes) -> None:
        self._key_type = key_type
        self._key_bytes = key_bytes

    def get_name(self) -> str:
        return self._key_type

    def asbytes(self) -> bytes:
        return self._key_bytes


def _fingerprint_for(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def _record_pending(
    pending_registry: PendingLearnRegistry,
    router_id: str,
    pin: str,
    *,
    algorithm: str = "ssh-ed25519",
) -> None:
    record_pending_learn(
        pending_registry,
        router_id,
        LearnCandidateResult(
            fingerprint_sha256=pin,
            algorithm=algorithm,
            warning="test pending",
        ),
    )


@pytest.fixture
def store(tmp_path) -> PersistenceStore:
    conn = open_database(tmp_path / "ssh-pin.sqlite3")
    return PersistenceStore(conn)


@pytest.fixture
def pending_registry() -> PendingLearnRegistry:
    return PendingLearnRegistry()


def _seed_router(store: PersistenceStore) -> str:
    site = store.create_site(display_name="Lab", now=datetime(2026, 7, 31, tzinfo=UTC))
    return store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:1",
        host="192.168.1.1",
        source_address="192.168.2.10",
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )


def test_store_ssh_host_key_round_trip(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    pin = _fingerprint_for(b"host-key-bytes")
    store.set_endpoint_ssh_host_key(
        router_id,
        pin,
        "ssh-ed25519",
        "operator_supplied",
        pinned_at="2026-07-31T00:00:00Z",
    )
    loaded = store.get_endpoint_ssh_host_key(router_id)
    assert loaded is not None
    assert loaded.fingerprint_sha256 == pin
    assert loaded.algorithm == "ssh-ed25519"
    assert loaded.provenance == "operator_supplied"
    assert loaded.pinned_at == "2026-07-31T00:00:00Z"


def test_store_rejects_malformed_fingerprint(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    with pytest.raises(PreconditionFailed, match="invalid ssh host key fingerprint"):
        store.set_endpoint_ssh_host_key(router_id, "", "ssh-ed25519", "operator_supplied")
    with pytest.raises(PreconditionFailed, match="invalid ssh host key fingerprint"):
        store.set_endpoint_ssh_host_key(
            router_id,
            "!!!not-base64!!!",
            "ssh-ed25519",
            "operator_supplied",
        )


def test_store_rejects_invalid_provenance(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    with pytest.raises(PreconditionFailed, match="provenance"):
        store.set_endpoint_ssh_host_key(
            router_id,
            _fingerprint_for(b"x"),
            "ssh-ed25519",
            "blind_accept",
        )


def test_learn_candidate_mock_transport_no_auth() -> None:
    key_bytes = b"learn-key-material"
    fingerprint = _fingerprint_for(key_bytes)
    fake_key = _FakeKey("ssh-ed25519", key_bytes)
    transport = MagicMock()
    transport.get_remote_server_key.return_value = fake_key

    def factory(**_kwargs: object) -> Any:
        return transport

    result = learn_candidate(
        "192.168.1.1",
        transport_factory=factory,
    )
    assert result.fingerprint_sha256 == fingerprint
    assert result.algorithm == "ssh-ed25519"
    assert "out-of-band" in result.warning.lower()
    transport.start_client.assert_called_once()
    transport.get_remote_server_key.assert_called_once()
    transport.auth_password.assert_not_called()
    transport.auth_none.assert_not_called()
    transport.close.assert_called_once()


def test_confirm_pin_exact_echo(
    store: PersistenceStore,
    pending_registry: PendingLearnRegistry,
) -> None:
    router_id = _seed_router(store)
    pin = _fingerprint_for(b"confirm-me")
    _record_pending(pending_registry, router_id, pin)
    pinned = confirm_pin(
        store,
        router_id,
        pin,
        "ssh-ed25519",
        pending_registry=pending_registry,
    )
    assert pinned.fingerprint_sha256 == pin
    assert pinned.provenance == "learned_confirmed"
    assert pending_registry.get(router_id) is None


def test_confirm_pin_without_prior_learn_rejects(
    store: PersistenceStore,
    pending_registry: PendingLearnRegistry,
) -> None:
    router_id = _seed_router(store)
    pin = _fingerprint_for(b"no-pending")
    with pytest.raises(PreconditionFailed, match="no pending ssh host key learn"):
        confirm_pin(
            store,
            router_id,
            pin,
            "ssh-ed25519",
            pending_registry=pending_registry,
        )


def test_confirm_pin_wrong_echo_rejects(
    store: PersistenceStore,
    pending_registry: PendingLearnRegistry,
) -> None:
    router_id = _seed_router(store)
    learned = _fingerprint_for(b"learned-key")
    wrong = _fingerprint_for(b"wrong-echo")
    _record_pending(pending_registry, router_id, learned)
    with pytest.raises(PreconditionFailed, match="does not match pending learn"):
        confirm_pin(
            store,
            router_id,
            wrong,
            "ssh-ed25519",
            pending_registry=pending_registry,
        )


def test_confirm_pin_conflict_without_overwrite(
    store: PersistenceStore,
    pending_registry: PendingLearnRegistry,
) -> None:
    router_id = _seed_router(store)
    existing = _fingerprint_for(b"existing")
    candidate = _fingerprint_for(b"candidate")
    store.set_endpoint_ssh_host_key(
        router_id,
        existing,
        "ssh-ed25519",
        "operator_supplied",
    )
    _record_pending(pending_registry, router_id, candidate)
    with pytest.raises(SshHostKeyPinConflict) as exc_info:
        confirm_pin(
            store,
            router_id,
            candidate,
            "ssh-ed25519",
            pending_registry=pending_registry,
        )
    assert exc_info.value.existing.fingerprint_sha256 == existing
    assert exc_info.value.candidate_fingerprint_sha256 == candidate


def test_confirm_pin_overwrite(
    store: PersistenceStore,
    pending_registry: PendingLearnRegistry,
) -> None:
    router_id = _seed_router(store)
    existing = _fingerprint_for(b"old")
    candidate = _fingerprint_for(b"new")
    store.set_endpoint_ssh_host_key(
        router_id,
        existing,
        "ssh-ed25519",
        "operator_supplied",
    )
    _record_pending(pending_registry, router_id, candidate)
    pinned = confirm_pin(
        store,
        router_id,
        candidate,
        "ssh-ed25519",
        pending_registry=pending_registry,
        allow_overwrite=True,
    )
    assert pinned.fingerprint_sha256 == candidate
    assert pinned.provenance == "learned_confirmed"


def test_resolve_matching_explicit_returns_stored_pin(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    resolved = resolve_ssh_host_key_sha256(
        explicit=stored,
        router_id=router_id,
        store=store,
    )
    assert resolved == stored


def test_resolve_explicit_mismatch_raises(store: PersistenceStore) -> None:
    from router_control.adapters.netcraze.errors import SshHostKeyMismatch

    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored")
    explicit = _fingerprint_for(b"explicit")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    with pytest.raises(SshHostKeyMismatch, match="does not match stored confirmed pin"):
        resolve_ssh_host_key_sha256(
            explicit=explicit,
            router_id=router_id,
            store=store,
        )


def test_resolve_rejects_explicit_without_stored_pin(store: PersistenceStore) -> None:
    """Attack I-1: stale client-supplied pin must not substitute missing stored pin."""
    router_id = _seed_router(store)
    stale = _fingerprint_for(b"stale-session-pin")
    with pytest.raises(SshHostKeyMissing, match="stored confirmed SSH host key pin") as exc_info:
        resolve_ssh_host_key_sha256(
            explicit=stale,
            router_id=router_id,
            store=store,
        )
    assert stale not in str(exc_info.value)


def test_connection_params_rejects_stale_explicit_without_stored_pin(
    store: PersistenceStore,
) -> None:
    """Live path must refuse when router has no confirmed pin but client echoes stale pin."""
    router_id = _seed_router(store)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-attack",
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )
    store.set_router_credential_ref(router_id, cred_id, now=datetime(2026, 7, 31, tzinfo=UTC))
    store.set_endpoint_management_username(router_id, "admin")
    stale = _fingerprint_for(b"stale-session-pin")
    params = connection_params_from_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id=cred_id,
        ssh_host_key_sha256=stale,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert params is None
    missing = missing_connection_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id=cred_id,
        ssh_host_key_sha256=stale,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert "ssh_host_key_sha256" in missing


def test_resolve_uses_stored_when_no_explicit(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored-only")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    resolved = resolve_ssh_host_key_sha256(
        explicit=None,
        router_id=router_id,
        store=store,
    )
    assert resolved == stored


def test_resolve_fail_closed_when_missing(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    with pytest.raises(SshHostKeyMissing):
        resolve_ssh_host_key_sha256(
            explicit=None,
            router_id=router_id,
            store=store,
        )


def test_connection_params_resolve_stored_pin(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored-for-live")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    params = connection_params_from_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=None,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert params is not None
    assert params.ssh_host_key_sha256 == stored


def test_connection_params_resolve_stored_username(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored-for-live")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    store.set_endpoint_management_username(router_id, "stored-mgmt-user")
    params = connection_params_from_fields(
        host="192.168.1.1",
        username=None,
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=None,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert params is not None
    assert params.username == "stored-mgmt-user"
    assert params.ssh_host_key_sha256 == stored


def test_connection_params_missing_when_no_stored_username(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"pin-only")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    params = connection_params_from_fields(
        host="192.168.1.1",
        username=None,
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=None,
        router_id=router_id,
        store=store,
    )
    assert params is None


def test_connection_params_missing_when_no_stored_pin_with_username_and_cred(
    store: PersistenceStore,
) -> None:
    """Fail-closed: host + username + credential ref without stored pin → None."""
    router_id = _seed_router(store)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-no-pin",
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )
    store.set_router_credential_ref(router_id, cred_id, now=datetime(2026, 7, 31, tzinfo=UTC))
    store.set_endpoint_management_username(router_id, "synthetic-mgmt-user")
    missing = missing_connection_fields(
        host="192.168.1.1",
        username=None,
        router_credential_ref_id=cred_id,
        ssh_host_key_sha256=None,
        router_id=router_id,
        store=store,
    )
    assert "ssh_host_key_sha256" in missing
    params = connection_params_from_fields(
        host="192.168.1.1",
        username=None,
        router_credential_ref_id=cred_id,
        ssh_host_key_sha256=None,
        router_id=router_id,
        store=store,
    )
    assert params is None


def test_connection_params_matching_explicit_uses_stored_pin(
    store: PersistenceStore,
) -> None:
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    params = connection_params_from_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=stored,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert params is not None
    assert params.ssh_host_key_sha256 == stored


def test_connection_params_resolves_host_from_store_not_client(
    store: PersistenceStore,
) -> None:
    """Pin for 192.168.1.1 must not authorize connection to client-supplied 10.0.0.99."""
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"bound-host-pin")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    store.set_endpoint_management_username(router_id, "synthetic-mgmt-user")
    params = connection_params_from_fields(
        host="10.0.0.99",
        username=None,
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=None,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert params is not None
    assert params.host == "192.168.1.1"
    assert params.ssh_host_key_sha256 == stored
    assert params.username == "synthetic-mgmt-user"


def _insert_secondary_endpoint(
    store: PersistenceStore,
    router_id: str,
    *,
    host: str,
    priority: int,
) -> str:
    from router_control.persistence.ids import new_id

    endpoint_id = new_id("ep")
    ts = "2026-08-03T12:00:00Z"
    store._conn.execute(
        "INSERT INTO router_endpoints("
        "endpoint_id, router_id, kind, host, port, priority, is_enabled, "
        "source_address, created_at, updated_at"
        ") VALUES (?, ?, 'management_https', ?, 443, ?, 1, NULL, ?, ?)",
        (endpoint_id, router_id, host, priority, ts, ts),
    )
    return endpoint_id


def test_multi_endpoint_pin_and_username_same_binding_row(
    store: PersistenceStore,
) -> None:
    router_id = _seed_router(store)
    original_ep = store.get_connection_binding_endpoint(router_id)
    assert original_ep is not None
    original_ep_id = str(original_ep["endpoint_id"])
    pin = _fingerprint_for(b"multi-ep-pin")
    store.set_endpoint_ssh_host_key(
        router_id,
        pin,
        "ssh-ed25519",
        "operator_supplied",
    )
    store.set_endpoint_management_username(router_id, "synthetic-bound-user")
    _insert_secondary_endpoint(
        store,
        router_id,
        host="10.0.0.99",
        priority=-1,
    )
    assert store.get_primary_endpoint(router_id) is not None
    assert str(store.get_primary_endpoint(router_id)["host"]) == "10.0.0.99"
    binding = store.get_connection_binding_endpoint(router_id)
    assert binding is not None
    assert str(binding["endpoint_id"]) == original_ep_id
    assert store.get_endpoint_ssh_host_key(router_id) is not None
    assert store.get_endpoint_ssh_host_key(router_id).fingerprint_sha256 == pin
    assert store.get_endpoint_management_username(router_id) == "synthetic-bound-user"
    params = connection_params_from_fields(
        host="10.0.0.99",
        username=None,
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=None,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert params is not None
    assert params.host == "192.168.1.1"
    assert params.username == "synthetic-bound-user"


def test_connection_params_attack_bypass_closed_when_router_id_omitted(
    store: PersistenceStore,
) -> None:
    """Attack L-1: omitting router_id must not accept arbitrary pin for known host."""
    _seed_router(store)
    arbitrary = _fingerprint_for(b"attacker-chosen-pin")
    params_bypass = connection_params_from_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=arbitrary,
        source_address="192.168.2.10",
        router_id=None,
        store=None,
    )
    assert params_bypass is not None
    assert params_bypass.ssh_host_key_sha256 == arbitrary

    params_fixed = connection_params_from_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=arbitrary,
        source_address="192.168.2.10",
        router_id=None,
        store=store,
    )
    assert params_fixed is None
    missing = missing_connection_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=arbitrary,
        source_address="192.168.2.10",
        router_id=None,
        store=store,
    )
    assert "ssh_host_key_sha256" in missing


def test_connection_params_bootstrap_unknown_host_still_works(
    store: PersistenceStore,
) -> None:
    """First-contact bootstrap: unknown host may use explicit fingerprint."""
    bootstrap_pin = _fingerprint_for(b"first-contact-key")
    params = connection_params_from_fields(
        host="10.0.0.99",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=bootstrap_pin,
        source_address="192.168.2.10",
        router_id=None,
        store=store,
    )
    assert params is not None
    assert params.host == "10.0.0.99"
    assert params.source_address == "192.168.2.10"
    assert params.ssh_host_key_sha256 == bootstrap_pin


def test_connection_params_omitted_router_id_honours_explicit_host_and_source(
    store: PersistenceStore,
) -> None:
    """Store consults identity/pin only; caller host/source are not overridden."""
    router_id = _seed_router(store)
    stored = _fingerprint_for(b"stored-pin")
    store.set_endpoint_ssh_host_key(
        router_id,
        stored,
        "ssh-ed25519",
        "operator_supplied",
    )
    params = connection_params_from_fields(
        host="192.168.1.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=stored,
        source_address="192.168.2.10",
        router_id=None,
        store=store,
    )
    assert params is not None
    assert params.host == "192.168.1.1"
    assert params.source_address == "192.168.2.10"
    assert params.ssh_host_key_sha256 == stored


def _seed_live_shape_store(store: PersistenceStore) -> str:
    """Mirror live 192.168.2.1: genuine enrolled without pin + pinned drafts."""
    import base64
    import hashlib

    from router_control.application.router_discovery import (
        ENROLLMENT_DRAFT_LIFECYCLE,
        ENROLLMENT_DRAFT_MODEL,
    )

    def _pin_for(key_bytes: bytes) -> str:
        digest = hashlib.sha256(key_bytes).digest()
        return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"

    base = datetime(2026, 8, 3, 10, 0, tzinfo=UTC)
    site = store.create_site(display_name="Lab", now=base)
    host = "192.168.2.1"

    for index in range(3):
        created = base + timedelta(minutes=index)
        draft_id = store.enroll_router(
            site_id=site,
            display_name=f"Draft {index}",
            vendor="Netcraze",
            model=ENROLLMENT_DRAFT_MODEL,
            identity_fingerprint=f"digest:draft:{index}",
            host=host,
            port=443,
            kind="management_https",
            source_address=None,
            now=created,
        )
        store._conn.execute(
            "UPDATE routers SET lifecycle_status = ? WHERE router_id = ?",
            (ENROLLMENT_DRAFT_LIFECYCLE, draft_id),
        )
        store.set_endpoint_ssh_host_key(
            draft_id,
            _pin_for(f"draft-pin-{index}".encode()),
            "ssh-ed25519",
            "learned_confirmed",
            pinned_at=created.isoformat().replace("+00:00", "Z"),
        )

    genuine_id = store.enroll_router(
        site_id=site,
        display_name="Lab NC-1812",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lab:enrolled",
        host=host,
        port=22,
        kind="ssh_tunnel",
        source_address="192.168.2.10",
        now=base - timedelta(hours=1),
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (genuine_id,),
    )
    genuine_cred = store.insert_credential_ref(
        router_id=genuine_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-genuine",
        now=base,
    )
    store.set_router_credential_ref(genuine_id, genuine_cred, now=base)
    return genuine_id


def test_resolve_identity_router_id_prefers_genuine_enrolled_over_draft_pins(
    store: PersistenceStore,
) -> None:
    genuine_id = _seed_live_shape_store(store)
    resolved = resolve_identity_router_id_for_host(store, "192.168.2.1")
    assert resolved == genuine_id


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.2.1", "192.168.2.1"),
        ("192.168.2.1:443", "192.168.2.1"),
        ("[fd00::1]:22", "fd00::1"),
        ("user:pass@192.168.2.1:8080", "192.168.2.1"),
        ("https://user:pass@192.168.2.1:8443/path", "192.168.2.1"),
        ("", ""),
    ],
)
def test_normalize_management_host(raw: str, expected: str) -> None:
    assert normalize_management_host(raw) == expected


def test_main_observed_state_shape_refused_without_stored_pin(
    store: PersistenceStore,
) -> None:
    """Main POST /wifi/observed-state without router_id against live-shaped store."""
    _seed_live_shape_store(store)
    main_pin = _fingerprint_for(b"main-session-pin")
    params = connection_params_from_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:router-admin",
        ssh_host_key_sha256=main_pin,
        source_address="192.168.2.10",
        router_id=None,
        store=store,
    )
    assert params is None
    missing = missing_connection_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:router-admin",
        ssh_host_key_sha256=main_pin,
        source_address="192.168.2.10",
        router_id=None,
        store=store,
    )
    assert missing == ["ssh_host_key_sha256"]
