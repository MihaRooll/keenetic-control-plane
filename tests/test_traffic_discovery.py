"""SLICE-8 TrafficDiscovery proposals-only."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.application.traffic_discovery import AutoApplyBlocked, TrafficDiscoveryService
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore


class ApplySpy:
    def __init__(self) -> None:
        self.calls = 0

    def apply(self, *args: object, **kwargs: object) -> None:
        self.calls += 1


@pytest.fixture
def service(tmp_path: Path) -> tuple[TrafficDiscoveryService, ApplySpy, str]:
    conn = open_database(tmp_path / "t.sqlite3")
    store = PersistenceStore(conn)
    site = store.create_site(display_name="S", now=datetime(2026, 7, 21, tzinfo=UTC))
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:t",
        host="127.0.0.1",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    spy = ApplySpy()
    svc = TrafficDiscoveryService(store=store, apply_port=spy)
    return svc, spy, rid


def test_proposal_created(service: tuple[TrafficDiscoveryService, ApplySpy, str]) -> None:
    svc, spy, rid = service
    obs = svc.record_observation(
        router_id=rid,
        evidence={"dst": "10.0.0.1", "proto": "tcp"},
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    prop = svc.create_proposal(
        observation=obs,
        route_intent={"prefix": "10.0.0.0/24"},
        confidence=0.8,
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    assert prop.status == "Proposed"
    assert prop.auto_apply_blocked is True
    assert spy.calls == 0
    row = svc.store.get_route_proposal(prop.proposal_id)
    assert row is not None
    assert int(row["auto_apply_blocked"]) == 1


def test_untrusted_auto_apply_blocked(
    service: tuple[TrafficDiscoveryService, ApplySpy, str],
) -> None:
    svc, spy, rid = service
    obs = svc.record_observation(
        router_id=rid,
        evidence={"x": 1},
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    prop = svc.create_proposal(
        observation=obs,
        route_intent={"prefix": "0.0.0.0/0"},
        confidence=0.9,
        trusted_policy=False,
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    with pytest.raises(AutoApplyBlocked):
        svc.try_auto_apply(prop)
    assert spy.calls == 0


def test_trusted_still_blocked_without_plan_gates(
    service: tuple[TrafficDiscoveryService, ApplySpy, str],
) -> None:
    svc, spy, rid = service
    obs = svc.record_observation(
        router_id=rid,
        evidence={"x": 2},
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    prop = svc.create_proposal(
        observation=obs,
        route_intent={"prefix": "192.168.0.0/16"},
        confidence=0.99,
        trusted_policy=True,
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    with pytest.raises(AutoApplyBlocked):
        svc.try_auto_apply(prop)
    assert spy.calls == 0
