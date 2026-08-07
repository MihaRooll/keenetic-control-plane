"""P2 session binding and plan CAS."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.application.deployment_planner import (
    DEFAULT_REQUIRED_FAMILIES,
    DeploymentPlannerService,
)
from router_control.composition import FixedClock
from router_control.domain.event_preset import build_safe_default_document
from router_control.persistence.errors import PreconditionFailed
from router_control.persistence.store import PersistenceStore
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie, plan_session_binding_hmac

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


def _seed_family_certs(store: PersistenceStore, router_id: str) -> None:
    valid_until = (FIXED + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_from = FIXED.strftime("%Y-%m-%dT%H:%M:%SZ")
    for family in DEFAULT_REQUIRED_FAMILIES:
        store.upsert_family_certification(
            router_id=router_id,
            family=family,
            identity_tuple_digest="sha256:tuple:lab",
            shape_digest="sha256:shape",
            codec_digest="sha256:codec",
            executor_digest="sha256:executor",
            evidence_digest="sha256:evidence",
            certification_level="LabProven",
            valid_from=valid_from,
            valid_until=valid_until,
            now=FIXED,
        )


def _seed_p2_plan(
    store: PersistenceStore,
    *,
    session_hmac: str = "hmac:plan",
    with_credential: bool = False,
) -> tuple[str, str, str, str]:
    site = store.create_site(display_name="Lab", now=FIXED)
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
        now=FIXED,
    )
    cred_versions_json = "[]"
    if with_credential:
        cred_id = store.insert_credential_ref(
            router_id=rid,
            kind="management_password",
            provider="inline",
            provider_locator="vault:test",
            now=FIXED,
        )
        cred = store.get_credential_ref(cred_id)
        assert cred is not None
        cred_versions_json = json.dumps(
            [{"ref_id": cred_id, "version": str(cred["created_at"])}]
        )
    obs_id = store.insert_observation(
        router_id=rid,
        identity_fingerprint="digest:fp",
        resource_version="rv:1",
        state_digest="state:1",
        now=FIXED,
    )
    rev_id, rev_etag, _ = store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:desired:1",
        based_on_observation_id=obs_id,
        if_match="*",
        now=FIXED,
    )
    dep_id = "dep-p2"
    preset, revision, _ = store.create_event_preset(
        site_id=site,
        name="P2 Seed",
        canonical_json=json.dumps(build_safe_default_document().to_canonical()),
        canonical_digest="sha256:preset-doc",
        validation_status="ValidOffline",
        summary_redacted="seed",
        idempotency_key="seed-preset",
        request_digest="sha256:seed-preset",
        now=FIXED,
    )
    pub_row, _ = store.create_published_preset_idempotent(
        preset_id=str(preset["preset_id"]),
        source_revision_id=str(revision["revision_id"]),
        site_id=site,
        canonical_document_digest="sha256:preset-doc",
        schema_digest="sha256:schema",
        validation_digest="sha256:val",
        source_lineage_json="{}",
        publisher_session_binding_hmac="hmac:pub",
        idempotency_key="seed-pub",
        request_digest="sha256:seed-pub",
        now=FIXED,
    )
    store._conn.execute(
        "INSERT INTO router_deployment_revisions("
        "deployment_revision_id, published_preset_id, router_id, site_id, execution_target, "
        "identity_tuple_json, evidence_digest, required_families_json, "
        "credential_ref_versions_json, "
        "topology_bindings_json, canonical_desired_json, canonical_desired_digest, "
        "created_at, actor_session_binding_hmac"
        ") VALUES (?, ?, ?, ?, 'Lab', '{\"fingerprint\":\"digest:fp\"}', 'e', ?, ?, "
        "'{}', '{}', 'sha256:dep', ?, 'hmac')",
        (
            dep_id,
            pub_row["published_preset_id"],
            rid,
            site,
            json.dumps(list(DEFAULT_REQUIRED_FAMILIES)),
            cred_versions_json,
            FIXED.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    store._conn.execute(
        "UPDATE desired_revisions SET deployment_revision_id = ? WHERE revision_id = ?",
        (dep_id, rev_id),
    )
    _seed_family_certs(store, rid)
    planner = DeploymentPlannerService(store=store, clock=FixedClock(FIXED))
    doc = build_safe_default_document()
    topology = planner.build_topology_binding(doc)
    items = planner.compile_typed_plan_items(doc, topology=topology)
    payload = planner.build_change_plan_digest_payload(
        router_id=rid,
        deployment_revision_id=dep_id,
        deployment_digest="sha256:dep",
        desired_revision_id=rev_id,
        desired_digest="sha256:desired:1",
        observation_id=obs_id,
        observation_state_digest="state:1",
        observation_resource_version="rv:1",
        execution_target="Lab",
        family_cert_snapshots=store.build_family_cert_snapshots(
            rid, list(DEFAULT_REQUIRED_FAMILIES)
        ),
        items=items,
        risk_class="Medium",
        requires_backup=True,
        requires_fail_safe=True,
        expires_at=(FIXED + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        adopt_acknowledged=False,
    )
    plan_digest = planner.compute_change_plan_digest(payload)
    plan_id, plan_etag = store.create_p2_plan(
        router_id=rid,
        revision_id=rev_id,
        observation_id=obs_id,
        deployment_revision_id=dep_id,
        session_binding_hmac=session_hmac,
        plan_digest=plan_digest,
        items=items,
        if_match=rev_etag,
        now=FIXED,
    )
    return rid, plan_id, plan_digest, plan_etag


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "cas.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_sid_same_second_differ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "sid-test-password")
    t1 = mint_hub_admin_cookie(now=1_700_000_000)
    t2 = mint_hub_admin_cookie(now=1_700_000_000)
    sid1 = t1.split("|")[3].split(".")[0]
    sid2 = t2.split("|")[3].split(".")[0]
    assert sid1 != sid2
    assert plan_session_binding_hmac(sid1) != plan_session_binding_hmac(sid2)


def test_cross_session_bindings_differ(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    cookie_a = mint_hub_admin_cookie()
    cookie_b = mint_hub_admin_cookie()
    sid_a = cookie_a.split("|")[3].split(".")[0]
    sid_b = cookie_b.split("|")[3].split(".")[0]
    assert plan_session_binding_hmac(sid_a) != plan_session_binding_hmac(sid_b)


def test_cross_session_confirm_forbidden(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    cookie_a = mint_hub_admin_cookie()
    cookie_b = mint_hub_admin_cookie()
    sid_a = cookie_a.split("|")[3].split(".")[0]
    hmac_a = plan_session_binding_hmac(sid_a)
    _rid, plan_id, plan_digest, plan_etag = _seed_p2_plan(host.runtime.store, session_hmac=hmac_a)
    client.cookies.set("hub_admin", cookie_b)
    confirm = client.post(
        f"/api/router-control/v1/routers/{_rid}/plans/{plan_id}/confirm",
        json={"plan_digest": plan_digest},
        headers={"Idempotency-Key": "confirm-cross", "If-Match": plan_etag},
    )
    assert confirm.status_code == 403
    assert confirm.json()["error"]["code"] == "session_binding_mismatch"


def _confirm_p2(
    client, *, router_id: str, plan_id: str, plan_digest: str, plan_etag: str
) -> object:
    return client.post(
        f"/api/router-control/v1/routers/{router_id}/plans/{plan_id}/confirm",
        json={"plan_digest": plan_digest},
        headers={"Idempotency-Key": "confirm-stale", "If-Match": plan_etag},
    )


def test_confirm_rejects_stale_credential(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    cookie = mint_hub_admin_cookie()
    sid = cookie.split("|")[3].split(".")[0]
    hmac_a = plan_session_binding_hmac(sid)
    rid, plan_id, plan_digest, plan_etag = _seed_p2_plan(
        host.runtime.store, session_hmac=hmac_a, with_credential=True
    )
    dep_id = str(host.runtime.store.get_plan(plan_id)["deployment_revision_id"])
    dep = host.runtime.store.get_deployment_revision(dep_id)
    assert dep is not None
    cred_entry = json.loads(str(dep["credential_ref_versions_json"]))[0]
    host.runtime.store.mark_credential_revoked(str(cred_entry["ref_id"]), now=FIXED)
    client.cookies.set("hub_admin", cookie)
    confirm = _confirm_p2(
        client, router_id=rid, plan_id=plan_id, plan_digest=plan_digest, plan_etag=plan_etag
    )
    assert confirm.status_code == 422
    assert confirm.json()["error"]["code"] == "stale_credential"


def test_confirm_rejects_stale_certification(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    cookie = mint_hub_admin_cookie()
    sid = cookie.split("|")[3].split(".")[0]
    hmac_a = plan_session_binding_hmac(sid)
    rid, plan_id, plan_digest, plan_etag = _seed_p2_plan(host.runtime.store, session_hmac=hmac_a)
    certs = host.runtime.store.list_active_family_certifications(rid)
    assert certs
    host.runtime.store.revoke_family_certification(str(certs[0]["certification_id"]), now=FIXED)
    client.cookies.set("hub_admin", cookie)
    confirm = _confirm_p2(
        client, router_id=rid, plan_id=plan_id, plan_digest=plan_digest, plan_etag=plan_etag
    )
    assert confirm.status_code in (409, 422)
    assert confirm.json()["error"]["code"] in ("stale_certification", "digest_mismatch")


def test_apply_rejects_tuple_mismatch(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    cookie = mint_hub_admin_cookie()
    sid = cookie.split("|")[3].split(".")[0]
    hmac_a = plan_session_binding_hmac(sid)
    rid, plan_id, plan_digest, plan_etag = _seed_p2_plan(host.runtime.store, session_hmac=hmac_a)
    client.cookies.set("hub_admin", cookie)
    confirm = _confirm_p2(
        client, router_id=rid, plan_id=plan_id, plan_digest=plan_digest, plan_etag=plan_etag
    )
    assert confirm.status_code == 200
    plan = host.runtime.store.get_plan(plan_id)
    assert plan is not None
    from router_control.persistence.store import etag_for_plan_version

    apply_etag = etag_for_plan_version(plan_id, int(plan["plan_version"]))
    host.runtime.store._conn.execute(
        "UPDATE routers SET identity_fingerprint = ? WHERE router_id = ?",
        ("digest:tuple-changed", rid),
    )
    apply = client.post(
        f"/api/router-control/v1/routers/{rid}/plans/{plan_id}/apply",
        headers={"Idempotency-Key": "apply-tuple", "If-Match": apply_etag},
    )
    assert apply.status_code == 422
    assert apply.json()["error"]["code"] == "tuple_mismatch"


def test_assert_p2_plan_fresh_rejects_null_session_binding(tmp_path: Path) -> None:
    from router_control.persistence.connection import open_database

    conn = open_database(tmp_path / "null-hmac.sqlite3")
    store = PersistenceStore(conn)
    site = store.create_site(display_name="Lab", now=FIXED)
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
        now=FIXED,
    )
    obs_id = store.insert_observation(
        router_id=rid,
        identity_fingerprint="digest:fp",
        resource_version="rv:1",
        state_digest="state:1",
        now=FIXED,
    )
    rev_id, _, _ = store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:desired:1",
        based_on_observation_id=obs_id,
        if_match="*",
        now=FIXED,
    )
    plan_id = "plan-unbound-legacy"
    now_iso = FIXED.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (FIXED + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    store._conn.execute(
        "INSERT INTO change_plans("
        "plan_id, router_id, revision_id, observation_id, expected_desired_digest, "
        "observed_resource_version, observed_state_digest, plan_digest, risk_class, "
        "requires_backup, requires_fail_safe, expires_at, confirmation_state, "
        "actor_type, actor_id, created_at, session_binding_hmac, plan_version"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 'Draft', 'operator', ?, ?, NULL, 1)",
        (
            plan_id,
            rid,
            rev_id,
            obs_id,
            "sha256:desired:1",
            "rv:1",
            "state:1",
            "sha256:plan:legacy",
            "Medium",
            expires_at,
            "test",
            now_iso,
        ),
    )
    with pytest.raises(PreconditionFailed, match="unbound_plan_requires_recompile"):
        store.assert_p2_plan_fresh(plan_id, now=FIXED)


def _seed_legacy_unbound_plan(
    store: PersistenceStore,
    *,
    confirmation_state: str = "Draft",
) -> tuple[str, str, str, str]:
    site = store.create_site(display_name="Lab", now=FIXED)
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
        now=FIXED,
    )
    obs_id = store.insert_observation(
        router_id=rid,
        identity_fingerprint="digest:fp",
        resource_version="rv:1",
        state_digest="state:1",
        now=FIXED,
    )
    rev_id, rev_etag, _ = store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:desired:1",
        based_on_observation_id=obs_id,
        if_match="*",
        now=FIXED,
    )
    plan_id = "plan-unbound-http"
    now_iso = FIXED.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (FIXED + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    store._conn.execute(
        "INSERT INTO change_plans("
        "plan_id, router_id, revision_id, observation_id, expected_desired_digest, "
        "observed_resource_version, observed_state_digest, plan_digest, risk_class, "
        "requires_backup, requires_fail_safe, expires_at, confirmation_state, "
        "actor_type, actor_id, created_at, session_binding_hmac, plan_version"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, 'operator', ?, ?, NULL, 1)",
        (
            plan_id,
            rid,
            rev_id,
            obs_id,
            "sha256:desired:1",
            "rv:1",
            "state:1",
            "sha256:plan:legacy",
            "Medium",
            expires_at,
            confirmation_state,
            "test",
            now_iso,
        ),
    )
    from router_control.persistence.store import etag_for_plan_version

    plan_etag = etag_for_plan_version(plan_id, 1)
    return rid, plan_id, "sha256:plan:legacy", plan_etag


def test_legacy_unbound_confirm_rejects_412(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    rid, plan_id, plan_digest, plan_etag = _seed_legacy_unbound_plan(host.runtime.store)
    confirm = client.post(
        f"/api/router-control/v1/routers/{rid}/plans/{plan_id}/confirm",
        json={"plan_digest": plan_digest},
        headers={"Idempotency-Key": "confirm-unbound", "If-Match": plan_etag},
    )
    assert confirm.status_code == 412
    assert confirm.json()["error"]["code"] == "plan.unbound_requires_recompile"


def test_legacy_unbound_apply_rejects_412(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    rid, plan_id, _plan_digest, plan_etag = _seed_legacy_unbound_plan(
        host.runtime.store,
        confirmation_state="Confirmed",
    )
    apply = client.post(
        f"/api/router-control/v1/routers/{rid}/plans/{plan_id}/apply",
        headers={"Idempotency-Key": "apply-unbound", "If-Match": plan_etag},
    )
    assert apply.status_code == 412
    assert apply.json()["error"]["code"] == "plan.unbound_requires_recompile"


def test_cross_session_apply_forbidden(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    host = client.app.state.host
    host.allow_fake_mutations = True
    cookie_a = mint_hub_admin_cookie()
    cookie_b = mint_hub_admin_cookie()
    sid_a = cookie_a.split("|")[3].split(".")[0]
    hmac_a = plan_session_binding_hmac(sid_a)
    rid, plan_id, plan_digest, plan_etag = _seed_p2_plan(host.runtime.store, session_hmac=hmac_a)
    client.cookies.set("hub_admin", cookie_a)
    confirm = client.post(
        f"/api/router-control/v1/routers/{rid}/plans/{plan_id}/confirm",
        json={"plan_digest": plan_digest},
        headers={"Idempotency-Key": "confirm-apply-cross", "If-Match": plan_etag},
    )
    assert confirm.status_code == 200
    plan = host.runtime.store.get_plan(plan_id)
    assert plan is not None
    from router_control.persistence.store import etag_for_plan_version

    apply_etag = etag_for_plan_version(plan_id, int(plan["plan_version"]))
    client.cookies.set("hub_admin", cookie_b)
    apply = client.post(
        f"/api/router-control/v1/routers/{rid}/plans/{plan_id}/apply",
        headers={"Idempotency-Key": "apply-cross", "If-Match": apply_etag},
    )
    assert apply.status_code == 403
    assert apply.json()["error"]["code"] == "session_binding_mismatch"
