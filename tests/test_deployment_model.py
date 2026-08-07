"""P2 deployment model — canonical digests and compiler items."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from router_control.application.deployment_planner import DeploymentPlannerService
from router_control.composition import create_offline_runtime
from router_control.domain.event_preset import ValidationStatus, build_safe_default_document
from router_control.domain.network_intents import canonical_dumps, digest_canonical
from router_control.persistence.connection import open_database
from router_control.persistence.errors import PreconditionFailed
from router_control.persistence.store import PersistenceStore

from tests.test_deployment_cas_session import FIXED, _seed_p2_plan


def test_canonical_dumps_stable_utf8() -> None:
    payload = {"name": "café", "n": 1}
    raw = canonical_dumps(payload)
    assert raw == '{"n":1,"name":"café"}'
    assert digest_canonical("change_plan", payload).startswith("sha256:")


def test_digest_tamper_matrix() -> None:
    base = {"a": 1, "b": [2, 3]}
    d1 = digest_canonical("change_plan", base)
    tampered = {"a": 1, "b": [2, 4]}
    d2 = digest_canonical("change_plan", tampered)
    assert d1 != d2
    wrong_domain = digest_canonical("desired", base)
    assert d1 != wrong_domain


def test_compiler_emits_typed_items_with_explicit_gateway(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "deployment-compiler.sqlite3")
    planner = DeploymentPlannerService(store=runtime.store, clock=runtime.clock)
    doc = build_safe_default_document()
    topology = planner.build_topology_binding(doc)
    items = planner.compile_typed_plan_items(doc, topology=topology)
    kinds = {item["intent_kind"] for item in items}
    assert "vlan" in kinds
    assert "dhcp" in kinds
    assert "dns" in kinds
    assert "firewall" in kinds
    vlan = next(i for i in items if i["intent_kind"] == "vlan")
    assert "ipv4_gateway" in vlan["intent_json"]
    assert not str(vlan["intent_json"]["ipv4_gateway"]).endswith(".0")


def test_publication_digests_require_valid_offline(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "deployment-digest.sqlite3")
    planner = DeploymentPlannerService(store=runtime.store, clock=runtime.clock)
    doc = build_safe_default_document()
    canonical = doc.to_canonical()
    d1, _, v1 = planner.publication_digests(
        canonical_document=canonical,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    _, _, v2 = planner.publication_digests(
        canonical_document=canonical,
        validation_status=ValidationStatus.INVALID,
    )
    assert v1 != v2
    assert d1.startswith("sha256:")


def test_intent_digest_uses_change_plan_domain() -> None:
    intent = {"zone_id": "guest", "vlan_id": 10}
    d_item = digest_canonical("change_plan", {"intent_kind": "vlan", "intent": intent})
    d_legacy = digest_canonical("change_plan_item", intent)
    assert d_item != d_legacy
    assert d_item.startswith("sha256:")


def test_stale_observation_blocks_confirm(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "stale.sqlite3")
    store = PersistenceStore(conn)
    rid, plan_id, plan_digest, plan_etag = _seed_p2_plan(store)
    store._conn.execute(
        "UPDATE router_observations SET valid_until = ? WHERE router_id = ?",
        ((FIXED - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), rid),
    )
    with pytest.raises(PreconditionFailed, match="stale_observation"):
        store.confirm_p2_plan(
            plan_id=plan_id,
            plan_digest=plan_digest,
            if_match=plan_etag,
            session_binding_hmac="hmac:plan",
            adopt_acknowledged=False,
            actor_id="op",
            now=FIXED,
        )
