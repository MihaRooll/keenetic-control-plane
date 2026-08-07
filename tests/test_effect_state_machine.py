"""P1-A external effect state machine — immutable events, no adapter calls."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.domain.enums import EffectState, can_transition_effect
from router_control.persistence.connection import open_database
from router_control.persistence.errors import EffectTransitionError, StaleFenceError
from router_control.persistence.store import PersistenceStore


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "fx.sqlite3"))


def _seed(store: PersistenceStore) -> str:
    site = store.create_site(display_name="Lab", now=datetime(2026, 7, 22, tzinfo=UTC))
    return store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:1",
        host="127.0.0.1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )


def _fenced_job(store: PersistenceStore, router_id: str) -> tuple[str, str]:
    out = store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key="fx-fence",
        request_digest="sha256:fx-fence",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=300, now_epoch=100)
    assert claim is not None
    store.acquire_router_execution_fence(
        router_id=router_id,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=300,
        active_job_id=out.job_id,
        os_mutex_held=True,
        now_epoch=100,
    )
    return out.job_id, claim.lease_owner


def test_effect_happy_path_transitions(store: PersistenceStore) -> None:
    rid = _seed(store)
    job_id, lease_owner = _fenced_job(store, rid)
    effect_id = store.create_external_effect(
        router_id=rid,
        effect_key="apply:vpn:primary",
        job_id=job_id,
        lease_owner=lease_owner,
    )
    for state in (
        EffectState.DISPATCHING,
        EffectState.ACKNOWLEDGED,
        EffectState.OBSERVED_APPLIED,
    ):
        store.transition_external_effect(
            effect_id=effect_id,
            to_state=state.value,
            job_id=job_id,
            lease_owner=lease_owner,
        )
    row = store.get_external_effect(effect_id)
    assert row is not None
    assert row["current_state"] == EffectState.OBSERVED_APPLIED.value
    events = store.list_external_effect_events(effect_id)
    assert len(events) == 4
    assert events[0]["from_state"] is None


def test_invalid_transition_rejected(store: PersistenceStore) -> None:
    rid = _seed(store)
    job_id, lease_owner = _fenced_job(store, rid)
    effect_id = store.create_external_effect(
        router_id=rid,
        effect_key="k1",
        job_id=job_id,
        lease_owner=lease_owner,
    )
    with pytest.raises(EffectTransitionError):
        store.transition_external_effect(
            effect_id=effect_id,
            to_state=EffectState.OBSERVED_APPLIED.value,
            job_id=job_id,
            lease_owner=lease_owner,
        )


def test_stable_effect_key_unique(store: PersistenceStore) -> None:
    rid = _seed(store)
    job_id, lease_owner = _fenced_job(store, rid)
    store.create_external_effect(
        router_id=rid,
        effect_key="stable-key",
        job_id=job_id,
        lease_owner=lease_owner,
    )
    with pytest.raises(sqlite3.IntegrityError):
        store.create_external_effect(
            router_id=rid,
            effect_key="stable-key",
            job_id=job_id,
            lease_owner=lease_owner,
        )


def test_unfenced_effect_create_rejected(store: PersistenceStore) -> None:
    rid = _seed(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="unfenced",
        request_digest="sha256:unfenced",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    with pytest.raises(StaleFenceError):
        store.create_external_effect(
            router_id=rid,
            effect_key="unfenced-key",
            job_id=out.job_id,
            lease_owner="w1",
        )


def test_unfenced_effect_continuation_upsert_rejected(store: PersistenceStore) -> None:
    rid = _seed(store)
    job_id, lease_owner = _fenced_job(store, rid)
    effect_id = store.create_external_effect(
        router_id=rid,
        effect_key="cont-fence",
        job_id=job_id,
        lease_owner=lease_owner,
    )
    store.reap_expired_router_execution_fences(now_epoch=9999999999)
    with pytest.raises(StaleFenceError):
        store.upsert_effect_continuation(
            effect_id=effect_id,
            continuation_key="tok:1",
            state="Pending",
            job_id=job_id,
            lease_owner=lease_owner,
        )


def test_can_transition_matrix() -> None:
    assert can_transition_effect(EffectState.PREPARED, EffectState.DISPATCHING)
    assert not can_transition_effect(EffectState.OBSERVED_APPLIED, EffectState.UNKNOWN)


def test_effect_events_immutable(store: PersistenceStore) -> None:
    rid = _seed(store)
    job_id, lease_owner = _fenced_job(store, rid)
    effect_id = store.create_external_effect(
        router_id=rid,
        effect_key="imm",
        job_id=job_id,
        lease_owner=lease_owner,
    )
    events = store.list_external_effect_events(effect_id)
    event_id = str(events[0]["event_id"])
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store.conn.execute(
            "UPDATE external_effect_events SET to_state = 'Hacked' WHERE event_id = ?",
            (event_id,),
        )
