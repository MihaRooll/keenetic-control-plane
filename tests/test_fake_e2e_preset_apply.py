"""Fake E2E preset deployment path smoke (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control.composition import create_offline_runtime
from router_control.domain.enums import EffectState
from router_control.persistence.connection import open_database
from router_control.persistence.errors import ConflictError
from router_control.persistence.store import PersistenceStore, etag_for_revision
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

from tests.test_deployment_cas_session import FIXED, _seed_p2_plan


def test_offline_runtime_has_deployment_planner(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "e2e.sqlite3")
    assert runtime.deployment_planner is not None


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(
        db_path=tmp_path / "e2e-host.sqlite3",
        enable_worker=False,
        allow_fake_mutations=True,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_revision_state_endpoint(client) -> None:
    host = client.app.state.host
    site_id = host.ensure_default_site()
    router_id = host.runtime.store.enroll_router(
        site_id=site_id,
        display_name="E2E",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:e2e",
        host="127.0.0.1",
        now=host.runtime.clock.now(),
    )
    r = client.get(f"/api/router-control/v1/routers/{router_id}/revision-state")
    assert r.status_code == 404 or r.status_code == 200


def _acknowledge_effect(store: PersistenceStore, *, effect_id: str, job_id: str, rid: str) -> None:
    store.transition_external_effect(
        effect_id=effect_id,
        to_state=EffectState.DISPATCHING.value,
        job_id=job_id,
        lease_owner="worker-1",
        now=FIXED,
    )
    store.transition_external_effect(
        effect_id=effect_id,
        to_state=EffectState.ACKNOWLEDGED.value,
        job_id=job_id,
        lease_owner="worker-1",
        now=FIXED,
    )


def test_finalize_verify_success_atomic(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "finalize.sqlite3")
    store = PersistenceStore(conn)
    rid, plan_id, _digest, _etag = _seed_p2_plan(store)
    rev_id = store.get_plan(plan_id)["revision_id"]
    store._conn.execute(
        "UPDATE change_plans SET confirmation_state = 'Confirmed' WHERE plan_id = ?",
        (plan_id,),
    )
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="job-k",
        request_digest="sha256:job",
        plan_id=plan_id,
        initial_job_status="Running",
        now=FIXED,
    )
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="worker-1",
        mutex_holder_id="worker-1",
        lease_seconds=300,
        active_job_id=out.job_id,
        os_mutex_held=True,
        now=FIXED,
    )
    effect_id = store.create_external_effect(
        router_id=rid,
        job_id=out.job_id,
        effect_key=f"plan:{plan_id}",
        lease_owner="worker-1",
        now=FIXED,
    )
    _acknowledge_effect(store, effect_id=effect_id, job_id=out.job_id, rid=rid)
    overall = store.finalize_verify_success(
        plan_id=plan_id,
        job_id=out.job_id,
        lease_owner="worker-1",
        effect_id=effect_id,
        readback_identity_fingerprint="digest:fp",
        readback_resource_version="rv:2",
        readback_state_digest="state:2",
        verify_digest="sha256:verify",
        checks_json='{"postconditions_met":true}',
        revision_id=str(rev_id),
        router_id=rid,
        now=FIXED,
    )
    assert overall == "pass"
    report = store.get_plan_verify_report(plan_id, out.job_id)
    assert report is not None
    assert report["overall_status"] == "pass"
    assert str(report["observation_id"]) != store.get_plan(plan_id)["observation_id"]
    assert store.get_latest_evidence_revision(rid, "runtime_applied") is not None
    events = store._conn.execute(
        "SELECT * FROM managed_resource_ownership_events WHERE plan_id = ?", (plan_id,)
    ).fetchall()
    assert events
    fx = store.get_external_effect(effect_id)
    assert fx is not None
    assert str(fx["current_state"]) == EffectState.OBSERVED_APPLIED.value
    assert (
        store.finalize_verify_success(
            plan_id=plan_id,
            job_id=out.job_id,
            lease_owner="worker-1",
            effect_id=effect_id,
            readback_identity_fingerprint="digest:fp",
            readback_resource_version="rv:2",
            readback_state_digest="state:2",
            verify_digest="sha256:verify",
            checks_json='{"postconditions_met":true}',
            revision_id=str(rev_id),
            router_id=rid,
            now=FIXED,
        )
        == "pass"
    )


def test_finalize_drifted_skips_applied(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "drifted-finalize.sqlite3")
    store = PersistenceStore(conn)
    rid, plan_id, _digest, _etag = _seed_p2_plan(store)
    plan_row = store.get_plan(plan_id)
    assert plan_row is not None
    rev = store.get_desired_revision(rid)
    assert rev is not None
    store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:desired:new",
        based_on_observation_id=str(plan_row["observation_id"]),
        if_match=etag_for_revision(str(rev["revision_id"]), str(rev["canonical_digest"])),
        now=FIXED,
    )
    store._conn.execute(
        "UPDATE change_plans SET confirmation_state = 'Confirmed' WHERE plan_id = ?",
        (plan_id,),
    )
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="job-drift",
        request_digest="sha256:job",
        plan_id=plan_id,
        initial_job_status="Running",
        now=FIXED,
    )
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="worker-1",
        mutex_holder_id="worker-1",
        lease_seconds=300,
        active_job_id=out.job_id,
        os_mutex_held=True,
        now=FIXED,
    )
    overall = store.finalize_verify_success(
        plan_id=plan_id,
        job_id=out.job_id,
        lease_owner="worker-1",
        effect_id=None,
        readback_identity_fingerprint="digest:fp",
        readback_resource_version="rv:2",
        readback_state_digest="state:2",
        verify_digest="sha256:verify",
        checks_json='{"drifted":true}',
        revision_id=str(plan_row["revision_id"]),
        router_id=rid,
        now=FIXED,
    )
    assert overall == "drifted"
    assert store.get_latest_evidence_revision(rid, "runtime_applied") is None
    events = store._conn.execute(
        "SELECT * FROM managed_resource_ownership_events WHERE plan_id = ?", (plan_id,)
    ).fetchall()
    assert not events


def test_finalize_rejects_prepared_effect(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "prepared-finalize.sqlite3")
    store = PersistenceStore(conn)
    rid, plan_id, _digest, _etag = _seed_p2_plan(store)
    rev_id = store.get_plan(plan_id)["revision_id"]
    store._conn.execute(
        "UPDATE change_plans SET confirmation_state = 'Confirmed' WHERE plan_id = ?",
        (plan_id,),
    )
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="job-prepared",
        request_digest="sha256:job",
        plan_id=plan_id,
        initial_job_status="Running",
        now=FIXED,
    )
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="worker-1",
        mutex_holder_id="worker-1",
        lease_seconds=300,
        active_job_id=out.job_id,
        os_mutex_held=True,
        now=FIXED,
    )
    effect_id = store.create_external_effect(
        router_id=rid,
        job_id=out.job_id,
        effect_key=f"plan:{plan_id}",
        lease_owner="worker-1",
        now=FIXED,
    )
    with pytest.raises(ConflictError, match="effect not ready"):
        store.finalize_verify_success(
            plan_id=plan_id,
            job_id=out.job_id,
            lease_owner="worker-1",
            effect_id=effect_id,
            readback_identity_fingerprint="digest:fp",
            readback_resource_version="rv:2",
            readback_state_digest="state:2",
            verify_digest="sha256:verify",
            checks_json='{"postconditions_met":true}',
            revision_id=str(rev_id),
            router_id=rid,
            now=FIXED,
        )
    assert store.get_plan_verify_report(plan_id, out.job_id) is None
    assert store.get_latest_evidence_revision(rid, "runtime_applied") is None


def test_durable_finalize_survives_store_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "durable-e2e.sqlite3"
    conn = open_database(db_path)
    store = PersistenceStore(conn)
    rid, plan_id, _digest, _etag = _seed_p2_plan(store)
    rev_id = store.get_plan(plan_id)["revision_id"]
    store._conn.execute(
        "UPDATE change_plans SET confirmation_state = 'Confirmed' WHERE plan_id = ?",
        (plan_id,),
    )
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="job-durable",
        request_digest="sha256:job",
        plan_id=plan_id,
        initial_job_status="Running",
        now=FIXED,
    )
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="worker-1",
        mutex_holder_id="worker-1",
        lease_seconds=300,
        active_job_id=out.job_id,
        os_mutex_held=True,
        now=FIXED,
    )
    effect_id = store.create_external_effect(
        router_id=rid,
        job_id=out.job_id,
        effect_key=f"plan:{plan_id}",
        lease_owner="worker-1",
        now=FIXED,
    )
    _acknowledge_effect(store, effect_id=effect_id, job_id=out.job_id, rid=rid)
    assert (
        store.finalize_verify_success(
            plan_id=plan_id,
            job_id=out.job_id,
            lease_owner="worker-1",
            effect_id=effect_id,
            readback_identity_fingerprint="digest:fp",
            readback_resource_version="rv:2",
            readback_state_digest="state:2",
            verify_digest="sha256:verify-durable",
            checks_json='{"postconditions_met":true}',
            revision_id=str(rev_id),
            router_id=rid,
            now=FIXED,
        )
        == "pass"
    )
    store._conn.close()
    reopened = PersistenceStore(open_database(db_path))
    report = reopened.get_plan_verify_report(plan_id, out.job_id)
    assert report is not None
    assert report["overall_status"] == "pass"
    events = reopened._conn.execute(
        "SELECT * FROM managed_resource_ownership_events WHERE plan_id = ?", (plan_id,)
    ).fetchall()
    assert events
    state = reopened.get_revision_state(rid)
    assert state is not None
    assert state["runtime_applied_revision_id"] == str(rev_id)
    fx = reopened.get_external_effect(effect_id)
    assert fx is not None
    assert str(fx["current_state"]) == EffectState.OBSERVED_APPLIED.value
    reopened._conn.close()
