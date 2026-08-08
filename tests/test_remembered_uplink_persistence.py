"""Persistence tests for remembered uplink (migration 15)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest
from router_control.persistence.connection import open_database
from router_control.persistence.errors import NotFoundError
from router_control.persistence.migrations import (
    _MIGRATIONS,
    CURRENT_USER_VERSION,
    _execute_sql_statements,
    migrate,
)
from router_control.persistence.store import _UNSET, PersistenceStore


@pytest.fixture
def store(tmp_path) -> PersistenceStore:
    conn = open_database(tmp_path / "remembered-uplink.sqlite3")
    return PersistenceStore(conn)


def _seed_site(store: PersistenceStore) -> str:
    return store.create_site(display_name="Uplink Lab", now=datetime(2026, 8, 5, tzinfo=UTC))


def _seed_router(store: PersistenceStore, site_id: str) -> str:
    return store.enroll_router(
        site_id=site_id,
        display_name="Uplink Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-remembered-uplink",
        host="127.0.0.1",
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )


def test_migration_15_fresh_db_reaches_current_version(tmp_path) -> None:
    conn = open_database(tmp_path / "fresh.sqlite3")
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "remembered_uplink" in tables
    row = conn.execute(
        "SELECT mode, desired_active FROM remembered_uplink WHERE preferences_id = 'default'"
    ).fetchone()
    assert row is not None
    assert row[0] == "wifi"
    assert row[1] == 0


def _build_v14_db(path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 15):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_migration_15_from_v14_is_idempotent(tmp_path) -> None:
    path = tmp_path / "v14.sqlite3"
    _build_v14_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 14
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        migrate(conn, db_path=path)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    finally:
        conn.close()


def test_remembered_uplink_singleton_seed(store: PersistenceStore) -> None:
    row = store.get_remembered_uplink()
    assert row["preferences_id"] == "default"
    assert row["mode"] == "wifi"
    assert row["desired_active"] is False
    assert row["credential_ref_id"] is None


def test_remembered_uplink_no_secret_column(store: PersistenceStore) -> None:
    cols = {
        row[1]
        for row in store.conn.execute('PRAGMA table_info("remembered_uplink")')
    }
    forbidden = {"password", "secret", "psk", "passphrase", "wpa_psk", "wifi_password"}
    assert forbidden.isdisjoint(cols)


def test_upsert_remembered_uplink_partial_update(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    updated = store.upsert_remembered_uplink(
        router_id=router_id,
        ssid="CafeNet",
        band="BAND_5GHZ",
        station_id="WifiMaster1/WifiStation0",
        desired_active=True,
        now=now,
    )
    assert updated["router_id"] == router_id
    assert updated["ssid"] == "CafeNet"
    assert updated["band"] == "BAND_5GHZ"
    assert updated["desired_active"] is True


def test_reset_remembered_uplink(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="uplink-loc",
        now=now,
    )
    store.upsert_remembered_uplink(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=cred_id,
        desired_active=True,
        now=now,
    )
    cleared = store.reset_remembered_uplink(now=now)
    assert cleared["desired_active"] is False
    assert cleared["ssid"] == ""
    assert cleared["credential_ref_id"] is None


def test_get_remembered_uplink_missing_row_raises(tmp_path) -> None:
    conn = open_database(tmp_path / "empty-remembered.sqlite3")
    conn.execute("DELETE FROM remembered_uplink")
    conn.commit()
    store = PersistenceStore(conn)
    with pytest.raises(NotFoundError):
        store.get_remembered_uplink()


def test_unset_sentinel_leaves_credential_ref_unchanged(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="uplink-loc-2",
        now=now,
    )
    store.upsert_remembered_uplink(
        credential_ref_id=cred_id,
        ssid="Keep",
        now=now,
    )
    updated = store.upsert_remembered_uplink(
        ssid="KeepRenamed",
        credential_ref_id=_UNSET,
        now=now,
    )
    assert updated["credential_ref_id"] == cred_id


def test_update_remembered_rejects_desired_active_without_credential(tmp_path) -> None:
    from router_control.application.remembered_uplink import (
        RememberedUplinkService,
        RememberedUplinkValidationError,
    )
    from router_control.composition import FixedClock, create_offline_runtime

    moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "update-active-no-cred.sqlite3",
        clock=FixedClock(moment),
    )
    store = runtime.store
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    svc = RememberedUplinkService(store=store, clock=FixedClock(moment))
    with pytest.raises(RememberedUplinkValidationError) as exc_info:
        svc.update_remembered(
            router_id=router_id,
            ssid="Net",
            desired_active=True,
        )
    assert exc_info.value.code == "remembered_uplink.validation_failed"
    assert exc_info.value.field == "credential_ref_id"


def test_update_remembered_accepts_desired_active_with_credential(tmp_path) -> None:
    from router_control.application.remembered_uplink import RememberedUplinkService
    from router_control.composition import FixedClock, create_offline_runtime

    moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "update-active-with-cred.sqlite3",
        clock=FixedClock(moment),
    )
    store = runtime.store
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="update-active-cred",
        now=moment,
    )
    svc = RememberedUplinkService(store=store, clock=FixedClock(moment))
    payload = svc.update_remembered(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=cred_id,
        desired_active=True,
    )
    assert payload["desired_active"] is True
    assert payload["credential_configured"] is True
    assert payload["credential_ref_id"] == cred_id


def test_update_remembered_rejects_clearing_credential_while_active(tmp_path) -> None:
    from router_control.application.remembered_uplink import (
        RememberedUplinkService,
        RememberedUplinkValidationError,
    )
    from router_control.composition import FixedClock, create_offline_runtime

    moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "update-clear-cred-active.sqlite3",
        clock=FixedClock(moment),
    )
    store = runtime.store
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="clear-cred-active",
        now=moment,
    )
    svc = RememberedUplinkService(store=store, clock=FixedClock(moment))
    svc.update_remembered(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=cred_id,
        desired_active=True,
    )
    with pytest.raises(RememberedUplinkValidationError) as exc_info:
        svc.update_remembered(credential_ref_id=None)
    assert exc_info.value.code == "remembered_uplink.validation_failed"
    assert exc_info.value.field == "credential_ref_id"


def test_clear_remembered_uplink_credential_if_matches_clears_revoked_ref(
    store: PersistenceStore,
) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    revoked_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-revoked-cas",
        now=now,
    )
    store.mark_credential_revoked(revoked_id, now=now)
    store.upsert_remembered_uplink(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=revoked_id,
        desired_active=True,
        now=now,
    )
    assert store.clear_remembered_uplink_credential_if_matches(revoked_id, now=now) is True
    row = store.get_remembered_uplink()
    assert row["credential_ref_id"] is None
    assert row["desired_active"] is False


def test_clear_remembered_uplink_credential_if_matches_noop_after_replacement(
    store: PersistenceStore,
) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    revoked_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-revoked-race",
        now=now,
    )
    store.mark_credential_revoked(revoked_id, now=now)
    store.upsert_remembered_uplink(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=revoked_id,
        desired_active=True,
        now=now,
    )
    new_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-new-usable",
        now=now,
    )
    store.upsert_remembered_uplink(
        credential_ref_id=new_id,
        desired_active=True,
        now=now,
    )
    assert store.clear_remembered_uplink_credential_if_matches(revoked_id, now=now) is False
    row = store.get_remembered_uplink()
    assert row["credential_ref_id"] == new_id
    assert row["desired_active"] is True


def test_get_remembered_heal_rereads_after_cas_noop_mid_flight_put(
    store: PersistenceStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Heal CAS no-op: concurrent PUT during clear must re-read usable ref."""
    from router_control.application.remembered_uplink import RememberedUplinkService
    from router_control.ports.clock import SystemClock

    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    revoked_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-race-revoked",
        now=now,
    )
    store.mark_credential_revoked(revoked_id, now=now)
    store.upsert_remembered_uplink(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=revoked_id,
        desired_active=True,
        now=now,
    )
    new_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-race-new",
        now=now,
    )
    service = RememberedUplinkService(store=store, clock=SystemClock())
    real_resolve = RememberedUplinkService._resolve_credential_ref
    resolve_calls = {"n": 0}

    def patched_resolve(self, ref_id: str | None):
        resolve_calls["n"] += 1
        if resolve_calls["n"] == 1:
            return False, None
        return real_resolve(self, ref_id)

    original_clear = store.clear_remembered_uplink_credential_if_matches

    def clear_during_cas(expected_ref_id: str, *, now=None):
        store.upsert_remembered_uplink(
            credential_ref_id=new_id,
            desired_active=True,
            now=now,
        )
        return original_clear(expected_ref_id, now=now)

    monkeypatch.setattr(
        RememberedUplinkService,
        "_resolve_credential_ref",
        patched_resolve,
    )
    monkeypatch.setattr(
        store,
        "clear_remembered_uplink_credential_if_matches",
        clear_during_cas,
    )

    payload = service.get_remembered()
    assert payload["credential_configured"] is True
    assert payload["credential_ref_id"] == new_id
    assert payload["desired_active"] is True
    row = store.get_remembered_uplink()
    assert row["credential_ref_id"] == new_id
    assert resolve_calls["n"] >= 2


def test_update_remembered_preserves_desired_active_when_replacing_revoked_credential(
    tmp_path,
) -> None:
    from router_control.application.remembered_uplink import RememberedUplinkService
    from router_control.composition import FixedClock, create_offline_runtime

    moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "update-replace-revoked-cred.sqlite3",
        clock=FixedClock(moment),
    )
    store = runtime.store
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    old_cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="old-revoked-cred",
        now=moment,
    )
    new_cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="new-valid-cred",
        now=moment,
    )
    svc = RememberedUplinkService(store=store, clock=FixedClock(moment))
    svc.update_remembered(
        router_id=router_id,
        ssid="Net",
        credential_ref_id=old_cred_id,
        desired_active=True,
    )
    store.mark_credential_revoked(old_cred_id, now=moment)
    payload = svc.update_remembered(credential_ref_id=new_cred_id)
    assert payload["desired_active"] is True
    assert payload["credential_configured"] is True
    assert payload["credential_ref_id"] == new_cred_id


def test_get_remembered_self_heal_desired_active_without_credential(tmp_path) -> None:
    from router_control.application.remembered_uplink import RememberedUplinkService
    from router_control.composition import FixedClock, create_offline_runtime

    moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "self-heal-desired-no-cred.sqlite3",
        clock=FixedClock(moment),
    )
    store = runtime.store
    store.upsert_remembered_uplink(
        credential_ref_id=None,
        ssid="OrphanNet",
        desired_active=True,
        now=moment,
    )
    svc = RememberedUplinkService(store=store, clock=FixedClock(moment))
    payload = svc.get_remembered()
    assert payload["credential_ref_id"] is None
    assert payload["credential_configured"] is False
    assert payload["desired_active"] is False


def test_get_remembered_self_heal_after_credential_fk_set_null(tmp_path) -> None:
    from router_control.application.remembered_uplink import RememberedUplinkService
    from router_control.composition import FixedClock, create_offline_runtime

    moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "self-heal-fk-set-null.sqlite3",
        clock=FixedClock(moment),
    )
    store = runtime.store
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="fk-set-null-loc",
        now=moment,
    )
    store.upsert_remembered_uplink(
        credential_ref_id=cred_id,
        ssid="Net",
        desired_active=True,
        now=moment,
    )
    store.conn.execute(
        "DELETE FROM credential_refs WHERE credential_ref_id = ?", (cred_id,)
    )
    store.conn.commit()
    row = store.get_remembered_uplink()
    assert row["credential_ref_id"] is None
    assert row["desired_active"] is True

    svc = RememberedUplinkService(store=store, clock=FixedClock(moment))
    payload = svc.get_remembered()
    assert payload["credential_ref_id"] is None
    assert payload["credential_configured"] is False
    assert payload["desired_active"] is False


def test_get_remembered_self_heal_returns_fresh_updated_at(tmp_path) -> None:
    from router_control.application.remembered_uplink import RememberedUplinkService
    from router_control.composition import FixedClock, create_offline_runtime

    old_moment = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    new_moment = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "self-heal-updated-at.sqlite3",
        clock=FixedClock(old_moment),
    )
    store = runtime.store
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="self-heal-loc",
        now=old_moment,
    )
    store.upsert_remembered_uplink(
        credential_ref_id=cred_id,
        ssid="Net",
        desired_active=True,
        now=old_moment,
    )
    store.mark_credential_revoked(cred_id, now=old_moment)
    svc = RememberedUplinkService(store=store, clock=FixedClock(new_moment))
    payload = svc.get_remembered()
    assert payload["credential_ref_id"] is None
    assert payload["credential_configured"] is False
    assert payload["desired_active"] is False
    assert payload["updated_at"] == new_moment.isoformat().replace("+00:00", "Z")


def test_remembered_credential_ref_fk_set_null_on_router_delete(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="uplink-fk",
        now=now,
    )
    store.upsert_remembered_uplink(
        credential_ref_id=cred_id,
        now=now,
    )
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("DELETE FROM routers WHERE router_id = ?", (router_id,))
