"""Sealed apply mid-flight trail: crash durability, secrets, migration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from router_control.application.recovery import (
    SealedApplyTrailParams,
    build_sealed_apply_op_evidence,
    reconstruct_sealed_apply_incident,
    redact_sealed_apply_op_evidence,
    serialize_pre_apply_baseline_for_trail,
)
from router_control.application.wifi_apply_planner import WifiApplyPreState
from router_control.application.wifi_apply_service import apply_wifi_intent, teardown_wifi_ap
from router_control.application.wifi_observation_helpers import sanitize_show_rc_interface_raw
from router_control.persistence.connection import connect, open_database
from router_control.persistence.errors import SealedApplyTrailBeginError
from router_control.persistence.migrations import (
    _MIGRATIONS,
    CURRENT_USER_VERSION,
    _execute_sql_statements,
)
from router_control.persistence.store import PersistenceStore

from tests.test_wifi_apply_service import (
    FakeWifiApplyTransport,
    _on_air_verified_readback,
    _applied_readback,
    _baseline_readback,
    _teardown_on_air_verified_readback,
    _wpa2_intent,
)
from tests.test_wifi_station_show_rc_scrub import _LEAK_TOKEN as _DEVICE_PSK_LEAK_MARKER

_TEST_AP = "WifiMaster0/AccessPoint3"
_FAKE_PSK_MARKER = "SUPER-SECRET-PSK-MARKER-xyzzy-12345"
_UNKNOWN_ROUTER_ID = "rtr-not-enrolled-for-sealed-apply-test"
_TEST_LEASE_OWNER = "test-sealed-apply-lease-owner"


def _trail_params(*, verb: str = "apply", router_id: str | None = None) -> SealedApplyTrailParams:
    return SealedApplyTrailParams(
        route="wifi",
        verb=verb,
        intent_redacted={"ap_id": _TEST_AP, "ssid": "Staff-Private"},
        correlation_id="corr-crash-test",
        router_id=router_id,
    )


def _all_sealed_apply_row_text(store: PersistenceStore) -> str:
    rows = store.conn.execute("SELECT * FROM sealed_apply_runs").fetchall()
    return json.dumps([dict(row) for row in rows])


def _simulate_abrupt_exit_mid_trail(
    store: PersistenceStore,
    *,
    route: str,
    verb: str,
    ops_planned: tuple[str, ...],
    ops_dispatched: tuple[str, ...],
    intent: dict[str, Any] | None = None,
) -> None:
    """Simulate process death after partial dispatch (no terminal finish)."""
    run_id = store.begin_sealed_apply_run(
        route=route,
        verb=verb,
        intent_summary_redacted=intent or {"ap_id": _TEST_AP},
        ops_planned_redacted=ops_planned,
        lease_owner=_TEST_LEASE_OWNER,
    )
    for op in ops_dispatched:
        store.record_sealed_apply_op_intent(run_id, op, lease_owner=_TEST_LEASE_OWNER)
        store.record_sealed_apply_op_progress(run_id, op, lease_owner=_TEST_LEASE_OWNER)


def test_crash_mid_apply_leaves_unfinished_with_dispatched_ops(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "crash.sqlite3")
    store = PersistenceStore(conn)
    _simulate_abrupt_exit_mid_trail(
        store,
        route="wifi",
        verb="apply",
        ops_planned=("set_ssid", "set_wpa_psk", "up"),
        ops_dispatched=("set_ssid", "set_wpa_psk"),
    )
    conn.close()
    reopened = PersistenceStore(open_database(tmp_path / "crash.sqlite3"))
    assert reopened.interrupt_stale_sealed_apply_runs(now_epoch=9_999_999_999) == 1
    unfinished = reopened.list_unfinished_sealed_applies()
    assert len(unfinished) == 1
    row = unfinished[0]
    assert row["status"] == "Interrupted"
    dispatched = json.loads(str(row["ops_dispatched_redacted"]))
    assert len(dispatched) == 2
    assert all(isinstance(op, str) for op in dispatched)


def test_crash_mid_station_apply_leaves_unfinished(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "station-crash.sqlite3")
    store = PersistenceStore(conn)
    _simulate_abrupt_exit_mid_trail(
        store,
        route="wifi.station",
        verb="apply",
        ops_planned=("down", "set_ssid", "set_wpa_psk"),
        ops_dispatched=("down", "set_ssid"),
        intent={"station_id": "WifiMaster0/WifiStation0", "ssid": "Venue-Guest"},
    )
    conn.close()
    reopened = PersistenceStore(open_database(tmp_path / "station-crash.sqlite3"))
    assert reopened.interrupt_stale_sealed_apply_runs(now_epoch=9_999_999_999) == 1
    rows = reopened.list_unfinished_sealed_applies()
    assert len(rows) == 1
    assert rows[0]["route"] == "wifi.station"
    assert json.loads(str(rows[0]["ops_dispatched_redacted"])) == ["down", "set_ssid"]


def test_crash_mid_wireguard_teardown_leaves_unfinished(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "wg-teardown-crash.sqlite3")
    store = PersistenceStore(conn)
    _simulate_abrupt_exit_mid_trail(
        store,
        route="wireguard",
        verb="teardown",
        ops_planned=("down", "no_peer"),
        ops_dispatched=("down",),
        intent={"wg_id": "Wireguard5"},
    )
    conn.close()
    reopened = PersistenceStore(open_database(tmp_path / "wg-teardown-crash.sqlite3"))
    assert reopened.interrupt_stale_sealed_apply_runs(now_epoch=9_999_999_999) == 1
    rows = reopened.list_unfinished_sealed_applies()
    assert len(rows) == 1
    assert rows[0]["verb"] == "teardown"
    assert json.loads(str(rows[0]["ops_dispatched_redacted"])) == ["down"]


def test_successful_apply_finishes_trail_not_unfinished(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "success.sqlite3")
    store = PersistenceStore(conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
        store=store,
        sealed_apply_params=_trail_params(),
    )
    assert result.overall == "applied"
    assert store.list_unfinished_sealed_applies() == []
    row = store.conn.execute(
        "SELECT status, overall FROM sealed_apply_runs LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["status"] == "Succeeded"
    assert row["overall"] == "applied"


def test_apply_unknown_router_id_completes_with_null_trail_router(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "unknown-router.sqlite3")
    store = PersistenceStore(conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
        store=store,
        sealed_apply_params=_trail_params(router_id=_UNKNOWN_ROUTER_ID),
    )
    assert result.overall == "applied"
    row = store.conn.execute(
        "SELECT router_id, status, overall FROM sealed_apply_runs LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["router_id"] is None
    assert row["status"] == "Succeeded"
    assert row["overall"] == "applied"


def test_handler_exception_finishes_trail_not_orphan_running(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "exception-finish.sqlite3")
    base_store = PersistenceStore(conn)

    class FaultAfterFirstOpStore(PersistenceStore):
        def __init__(self, inner: PersistenceStore) -> None:
            super().__init__(inner.conn)
            self._op_count = 0

        def record_sealed_apply_op_progress(
            self,
            run_id: str,
            op_name_redacted: str,
            *,
            lease_owner: str,
            op_evidence_redacted: dict[str, Any] | None = None,
            now: Any = None,
            now_epoch: int | None = None,
        ) -> None:
            super().record_sealed_apply_op_progress(
                run_id,
                op_name_redacted,
                lease_owner=lease_owner,
                op_evidence_redacted=op_evidence_redacted,
                now=now,
                now_epoch=now_epoch,
            )
            self._op_count += 1
            if self._op_count >= 1:
                raise RuntimeError("simulated unexpected handler fault")

    store = FaultAfterFirstOpStore(base_store)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])

    with pytest.raises(RuntimeError, match="simulated unexpected handler fault"):
        apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
            store=store,
            sealed_apply_params=_trail_params(),
        )

    row = store.conn.execute("SELECT status, overall FROM sealed_apply_runs LIMIT 1").fetchone()
    assert row is not None
    assert row["status"] == "Failed"
    assert row["overall"] == "failed"
    assert store.list_unfinished_sealed_applies() == []


def test_failure_with_rollback_records_rolled_back_status(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "rollback.sqlite3")
    store = PersistenceStore(conn)

    def _failing_psk_resolver(_ref: str) -> str:
        raise RuntimeError("credential decode failed")

    transport = FakeWifiApplyTransport()
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=_failing_psk_resolver,
        store=store,
        sealed_apply_params=_trail_params(),
        compensate_on_failure=True,
    )
    assert result.overall == "rolled_back"
    assert store.list_unfinished_sealed_applies() == []
    row = store.conn.execute(
        "SELECT status, overall FROM sealed_apply_runs LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["status"] == "RolledBack"
    assert row["overall"] == "rolled_back"


def test_secret_marker_never_in_sealed_apply_runs_columns(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "secrets.sqlite3")
    store = PersistenceStore(conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])
    apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
        store=store,
        sealed_apply_params=_trail_params(),
    )
    blob = _all_sealed_apply_row_text(store)
    assert _FAKE_PSK_MARKER not in blob


def test_wifi_teardown_trail_finishes_on_success(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "wifi-teardown.sqlite3")
    store = PersistenceStore(conn)
    transport = FakeWifiApplyTransport(
        show_interface_readback_sequence=[_teardown_on_air_verified_readback()],
    )
    result = teardown_wifi_ap(
        ap_id=_TEST_AP,
        transport=transport,
        store=store,
        sealed_apply_params=_trail_params(verb="teardown"),
    )
    assert result.overall == "applied"
    row = store.conn.execute("SELECT status, verb FROM sealed_apply_runs LIMIT 1").fetchone()
    assert row is not None
    assert row["status"] == "Succeeded"
    assert row["verb"] == "teardown"


def _build_legacy_v8_db(path: Path) -> None:
    conn = connect(path, wal=False)
    try:
        for version in range(1, 9):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_migration_v8_to_v9_sealed_apply_runs(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v8.sqlite3"
    _build_legacy_v8_db(path)
    conn = connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 8
        assert (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sealed_apply_runs'"
            ).fetchone()
            is None
        )
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        assert (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sealed_apply_runs'"
            ).fetchone()
            is not None
        )
        store = PersistenceStore(conn)
        assert store.list_unfinished_sealed_applies() == []
    finally:
        conn.close()


def test_fresh_v9_db_no_false_unfinished(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "fresh-v9.sqlite3")
    store = PersistenceStore(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    assert store.list_unfinished_sealed_applies() == []


def test_trail_begin_failure_blocks_device_writes(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "trail-begin-fail.sqlite3")
    base_store = PersistenceStore(conn)

    class FaultBeginStore(PersistenceStore):
        def begin_sealed_apply_run(self, **kwargs: Any) -> str:
            raise RuntimeError("BEGIN_RAISE")

    store = FaultBeginStore(base_store.conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])

    with pytest.raises(SealedApplyTrailBeginError):
        apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
            store=store,
            sealed_apply_params=_trail_params(),
        )

    assert transport.write_commands == []
    assert store.conn.execute("SELECT COUNT(*) FROM sealed_apply_runs").fetchone()[0] == 0


def test_parallel_runtime_does_not_interrupt_active_sealed_apply(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "parallel-runtime.sqlite3")
    store_a = PersistenceStore(conn)
    run_id = store_a.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": _TEST_AP},
        ops_planned_redacted=("set_ssid",),
        lease_owner="runtime-a",
        now_epoch=1000,
        lease_seconds=300,
    )
    lease_row = store_a.conn.execute(
        "SELECT lease_until_epoch FROM sealed_apply_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert lease_row is not None
    valid_until = int(lease_row["lease_until_epoch"])

    store_b = PersistenceStore(open_database(tmp_path / "parallel-runtime.sqlite3"))
    assert store_b.interrupt_stale_sealed_apply_runs(now_epoch=valid_until - 1) == 0
    row = store_b.conn.execute(
        "SELECT status FROM sealed_apply_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    assert row is not None
    assert row["status"] == "Running"

    assert store_b.interrupt_stale_sealed_apply_runs(now_epoch=valid_until + 1) == 1
    expired = store_b.conn.execute(
        "SELECT status FROM sealed_apply_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    assert expired is not None
    assert expired["status"] == "Interrupted"


def test_migration_v10_to_v11_sealed_apply_recovery_columns(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v10.sqlite3"
    _build_legacy_v8_db(path)
    conn = open_database(path)
    conn.close()
    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        cols = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(sealed_apply_runs)").fetchall()
        }
        assert "pre_apply_baseline_redacted" in cols
        assert "ops_evidence_redacted" in cols
        assert "outcome_snapshot_redacted" in cols
    finally:
        conn.close()


def test_redact_sealed_apply_op_evidence_scrubs_device_plaintext_psk() -> None:
    raw_ack = sanitize_show_rc_interface_raw(
        {
            "parse": {
                "interface": {
                    "authentication": f"wpa-psk {_DEVICE_PSK_LEAK_MARKER}",
                    "psk": _DEVICE_PSK_LEAK_MARKER,
                }
            }
        }
    )
    evidence = redact_sealed_apply_op_evidence(
        build_sealed_apply_op_evidence(
            {"op": "set_wpa_psk", "ok": True},
            device_ack=raw_ack,
        )
    )
    blob = json.dumps(evidence)
    assert _DEVICE_PSK_LEAK_MARKER not in blob
    assert _FAKE_PSK_MARKER not in blob


def test_crash_mid_apply_trail_has_pre_apply_and_device_evidence(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "evidence-crash.sqlite3")
    store = PersistenceStore(conn)
    baseline = serialize_pre_apply_baseline_for_trail(
        WifiApplyPreState(known=True, had_ssid=False, had_psk=False, was_admin_up=False),
        observed={"ssid": "", "encryption": {}, "state": "down"},
    )
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": _TEST_AP, "ssid": "Staff-Private"},
        ops_planned_redacted=("set_ssid", "set_wpa_psk", "up"),
        lease_owner=_TEST_LEASE_OWNER,
    )
    store.record_sealed_apply_pre_apply_baseline(
        run_id, baseline, lease_owner=_TEST_LEASE_OWNER
    )
    store.record_sealed_apply_op_intent(run_id, "set_ssid", lease_owner=_TEST_LEASE_OWNER)
    store.record_sealed_apply_op_progress(
        run_id,
        "set_ssid",
        lease_owner=_TEST_LEASE_OWNER,
        op_evidence_redacted=build_sealed_apply_op_evidence(
            {"op": "set_ssid", "ok": True, "status_ident": "Core::Interface"}
        ),
    )
    conn.close()

    reopened = PersistenceStore(open_database(tmp_path / "evidence-crash.sqlite3"))
    assert reopened.interrupt_stale_sealed_apply_runs(now_epoch=9_999_999_999) == 1
    row = reopened.list_unfinished_sealed_applies()[0]
    chain = reconstruct_sealed_apply_incident(trail_row=row)
    assert chain["pre_apply_baseline"] is not None
    assert chain["pre_apply_baseline"]["pre_state"]["known"] is True
    assert chain["ops_evidence"]["set_ssid"]["ok"] is True
    assert chain["ops_dispatched"] == ["set_ssid"]
    assert chain["ops_pending"] == []
    assert chain["outcome"] is None


def test_failed_apply_with_rollback_persists_outcome_and_evidence(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "rollback-evidence.sqlite3")
    store = PersistenceStore(conn)

    def _failing_psk_resolver(_ref: str) -> str:
        raise RuntimeError("credential decode failed")

    transport = FakeWifiApplyTransport(
        readback_sequence=[_baseline_readback(), _baseline_readback()]
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=_failing_psk_resolver,
        store=store,
        sealed_apply_params=_trail_params(),
        compensate_on_failure=True,
    )
    assert result.overall == "rolled_back"
    row = store.conn.execute("SELECT * FROM sealed_apply_runs LIMIT 1").fetchone()
    assert row is not None
    chain = reconstruct_sealed_apply_incident(trail_row=dict(row))
    assert chain["outcome"] is not None
    assert chain["outcome"]["overall"] == "rolled_back"
    assert chain["outcome"]["rollback"]["attempted"] is True
    assert chain["pre_apply_baseline"] is not None
    assert chain["ops_evidence"] != {}


def test_incident_reconstruction_from_trail_and_audit(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "incident.sqlite3")
    store = PersistenceStore(conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
        store=store,
        sealed_apply_params=_trail_params(),
    )
    assert result.overall == "applied"
    trail_row = dict(store.conn.execute("SELECT * FROM sealed_apply_runs LIMIT 1").fetchone())
    from router_control.application.recovery import outcome_snapshot_from_apply_result
    from router_control.persistence.store import build_sealed_apply_audit_summary

    audit_summary = json.loads(
        build_sealed_apply_audit_summary(
            route="wifi",
            verb="apply",
            intent_redacted={"ap_id": _TEST_AP},
            result_payload=result.to_dict(),
            outcome_snapshot=outcome_snapshot_from_apply_result(result),
            trail_snapshot=store.get_sealed_apply_trail_snapshot_for_audit(
                correlation_id="corr-crash-test",
                route="wifi",
                verb="apply",
            ),
        )
    )
    chain = reconstruct_sealed_apply_incident(
        trail_row=trail_row,
        audit_summary=audit_summary,
    )
    assert chain["intent"]["ap_id"] == _TEST_AP
    assert chain["ops_planned"]
    assert chain["ops_dispatched"]
    assert all(op in chain["ops_evidence"] for op in chain["ops_dispatched"])
    assert chain["pre_apply_baseline"] is not None
    assert chain["outcome"]["overall"] == "applied"
    assert chain["outcome"]["verdict_explanation"] is not None
    assert chain["audit_result_overall"] == "applied"


def test_secret_marker_never_in_trail_evidence_or_audit(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "secrets-evidence.sqlite3")
    store = PersistenceStore(conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])
    apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
        store=store,
        sealed_apply_params=_trail_params(),
    )
    blob = _all_sealed_apply_row_text(store)
    assert _FAKE_PSK_MARKER not in blob
    events = store.list_audit_events(action_prefix="sealed_apply.")
    if events:
        assert _FAKE_PSK_MARKER not in json.dumps(events)


def test_crash_after_device_ack_leaves_unconfirmed_op_in_trail(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "unconfirmed-op.sqlite3")
    base_store = PersistenceStore(conn)

    class FaultConfirmStore(PersistenceStore):
        def record_sealed_apply_op_progress(
            self,
            run_id: str,
            op_name_redacted: str,
            *,
            lease_owner: str,
            op_evidence_redacted: dict[str, Any] | None = None,
            now: Any = None,
            now_epoch: int | None = None,
        ) -> None:
            raise SystemExit("crash after device ack before trail confirm")

    store = FaultConfirmStore(base_store.conn)
    transport = FakeWifiApplyTransport(readback_sequence=[_on_air_verified_readback()])

    with pytest.raises(SystemExit):
        apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _FAKE_PSK_MARKER,
            store=store,
            sealed_apply_params=_trail_params(),
        )

    row = store.conn.execute(
        "SELECT ops_pending_redacted, ops_dispatched_redacted, status, overall "
        "FROM sealed_apply_runs LIMIT 1"
    ).fetchone()
    assert row is not None
    assert json.loads(str(row["ops_pending_redacted"])) != []
    assert json.loads(str(row["ops_dispatched_redacted"])) == []
    assert row["status"] == "Failed"
    assert row["overall"] == "failed"
    assert transport.write_commands != []


def test_migration_v9_to_v10_sealed_apply_lease_columns(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v9.sqlite3"
    _build_legacy_v8_db(path)
    conn = open_database(path)
    conn.close()
    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        cols = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(sealed_apply_runs)").fetchall()
        }
        assert "lease_owner" in cols
        assert "lease_until_epoch" in cols
        assert "ops_pending_redacted" in cols
        indexes = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='sealed_apply_runs'"
            ).fetchall()
        }
        assert "idx_sealed_apply_runs_lease_until" in indexes
    finally:
        conn.close()
