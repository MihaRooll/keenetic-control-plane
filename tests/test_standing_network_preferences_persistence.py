"""Persistence tests for standing network preferences (migration 14)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime

import pytest
from router_control.application.standing_network_preferences import (
    StandingNetworkPreferencesService,
    StandingNetworkPreferencesValidationError,
    _validate_ap_id,
)
from router_control.persistence.connection import open_database
from router_control.persistence.errors import NotFoundError, PreconditionFailed
from router_control.persistence.migrations import (
    _MIGRATIONS,
    CURRENT_USER_VERSION,
    _execute_sql_statements,
    migrate,
)
from router_control.persistence.store import _UNSET, PersistenceStore
from router_control.ports.clock import SystemClock


@pytest.fixture
def store(tmp_path) -> PersistenceStore:
    conn = open_database(tmp_path / "standing-prefs.sqlite3")
    return PersistenceStore(conn)


def _seed_site(store: PersistenceStore) -> str:
    return store.create_site(display_name="Standing Lab", now=datetime(2026, 8, 5, tzinfo=UTC))


def _seed_router(store: PersistenceStore, site_id: str) -> str:
    return store.enroll_router(
        site_id=site_id,
        display_name="Lab Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-standing-prefs",
        host="127.0.0.1",
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )


def test_migration_14_fresh_db_reaches_current_version(tmp_path) -> None:
    conn = open_database(tmp_path / "fresh.sqlite3")
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "standing_network_preferences" in tables
    row = conn.execute(
        "SELECT staff_ssid, guest_default_ssid, guest_default_enabled "
        "FROM standing_network_preferences WHERE preferences_id = 'default'"
    ).fetchone()
    assert row is not None
    assert row[0] == "Рабочая сеть"
    assert row[1] == "Гостевая сеть"
    assert row[2] == 0


def _build_v13_db(path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 14):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_migration_14_from_v13_is_idempotent(tmp_path) -> None:
    path = tmp_path / "v13.sqlite3"
    _build_v13_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 13
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        migrate(conn, db_path=path)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    finally:
        conn.close()


def test_standing_preferences_singleton_seed(store: PersistenceStore) -> None:
    row = store.get_standing_network_preferences()
    assert row["preferences_id"] == "default"
    assert row["staff_ssid"] == "Рабочая сеть"
    assert row["guest_default_ssid"] == "Гостевая сеть"
    assert row["staff_password_credential_ref_id"] is None
    assert row["guest_default_enabled"] is False


def test_standing_preferences_no_secret_column(store: PersistenceStore) -> None:
    cols = {
        row[1]
        for row in store.conn.execute('PRAGMA table_info("standing_network_preferences")')
    }
    forbidden = {"password", "secret", "psk", "passphrase", "wpa_psk", "wifi_password"}
    assert forbidden.isdisjoint(cols)


def test_upsert_standing_preferences_partial_update(store: PersistenceStore) -> None:
    now = datetime(2026, 8, 5, tzinfo=UTC)
    updated = store.upsert_standing_network_preferences(
        staff_ssid="Corp WiFi",
        now=now,
    )
    assert updated["staff_ssid"] == "Corp WiFi"
    assert updated["guest_default_ssid"] == "Гостевая сеть"


def test_clear_standing_staff_password_ref_if_matches_clears_revoked_ref(
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
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=revoked_id,
        now=now,
    )
    assert store.clear_standing_staff_password_ref_if_matches(revoked_id, now=now) is True
    row = store.get_standing_network_preferences()
    assert row["staff_password_credential_ref_id"] is None


def test_clear_standing_staff_password_ref_if_matches_noop_after_replacement(
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
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=revoked_id,
        now=now,
    )
    new_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-new-usable",
        now=now,
    )
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=new_id,
        now=now,
    )
    assert store.clear_standing_staff_password_ref_if_matches(revoked_id, now=now) is False
    row = store.get_standing_network_preferences()
    assert row["staff_password_credential_ref_id"] == new_id


def test_service_get_heals_revoked_ref_honestly(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    revoked_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-heal-revoked",
        now=now,
    )
    store.mark_credential_revoked(revoked_id, now=now)
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=revoked_id,
        now=now,
    )
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    prefs = service.get_preferences()
    assert prefs["staff_password_configured"] is False
    assert prefs["staff_password_credential_ref_id"] is None
    row = store.get_standing_network_preferences()
    assert row["staff_password_credential_ref_id"] is None


def test_service_get_heal_rereads_after_cas_noop_mid_flight_put(
    store: PersistenceStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Heal CAS no-op: concurrent PUT during clear must re-read usable ref."""
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
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=revoked_id,
        now=now,
    )
    new_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-race-new",
        now=now,
    )
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    real_resolve = StandingNetworkPreferencesService._resolve_staff_password_ref
    resolve_calls = {"n": 0}

    def patched_resolve(self, ref_id: str | None):
        resolve_calls["n"] += 1
        if resolve_calls["n"] == 1:
            return False, None
        return real_resolve(self, ref_id)

    original_clear = store.clear_standing_staff_password_ref_if_matches

    def clear_during_cas(expected_ref_id: str, *, now=None):
        store.upsert_standing_network_preferences(
            staff_password_credential_ref_id=new_id,
            now=now,
        )
        return original_clear(expected_ref_id, now=now)

    monkeypatch.setattr(
        StandingNetworkPreferencesService,
        "_resolve_staff_password_ref",
        patched_resolve,
    )
    monkeypatch.setattr(
        store,
        "clear_standing_staff_password_ref_if_matches",
        clear_during_cas,
    )

    prefs = service.get_preferences()
    assert prefs["staff_password_configured"] is True
    assert prefs["staff_password_credential_ref_id"] == new_id
    row = store.get_standing_network_preferences()
    assert row["staff_password_credential_ref_id"] == new_id
    assert resolve_calls["n"] >= 2


def test_standing_credential_ref_fk_set_null_on_router_delete(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-1",
        now=now,
    )
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=cred_id,
        now=now,
    )
    row = store.get_standing_network_preferences()
    assert row["staff_password_credential_ref_id"] == cred_id

    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("DELETE FROM routers WHERE router_id = ?", (router_id,))


def test_clear_standing_credential_ref(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-2",
        now=now,
    )
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=cred_id,
        now=now,
    )
    cleared = store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=None,
        now=now,
    )
    assert cleared["staff_password_credential_ref_id"] is None


def test_get_standing_preferences_missing_row_raises(tmp_path) -> None:
    conn = open_database(tmp_path / "empty-standing.sqlite3")
    conn.execute("DELETE FROM standing_network_preferences")
    conn.commit()
    store = PersistenceStore(conn)
    with pytest.raises(NotFoundError):
        store.get_standing_network_preferences()


def test_seed_standing_network_preferences_defaults_reseeds_after_delete(
    store: PersistenceStore,
) -> None:
    store.conn.execute("DELETE FROM standing_network_preferences")
    store.conn.commit()
    store.seed_standing_network_preferences_defaults()
    row = store.get_standing_network_preferences()
    assert row["staff_ssid"] == "Рабочая сеть"
    assert row["guest_default_ssid"] == "Гостевая сеть"
    assert row["staff_password_credential_ref_id"] is None
    assert row["guest_default_enabled"] is False


def test_seed_standing_network_preferences_defaults_is_noop_when_row_exists(
    store: PersistenceStore,
) -> None:
    now = datetime(2026, 8, 5, tzinfo=UTC)
    store.upsert_standing_network_preferences(
        staff_ssid="Custom Staff",
        guest_default_ssid="Custom Guest",
        now=now,
    )
    store.seed_standing_network_preferences_defaults()
    row = store.get_standing_network_preferences()
    assert row["staff_ssid"] == "Custom Staff"
    assert row["guest_default_ssid"] == "Custom Guest"


def test_unset_sentinel_leaves_credential_ref_unchanged(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    router_id = _seed_router(store, site_id)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="loc-3",
        now=now,
    )
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=cred_id,
        now=now,
    )
    updated = store.upsert_standing_network_preferences(
        staff_ssid="Only SSID",
        staff_password_credential_ref_id=_UNSET,
        now=now,
    )
    assert updated["staff_ssid"] == "Only SSID"
    assert updated["staff_password_credential_ref_id"] == cred_id


def _build_v15_db(path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 16):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_migration_16_upgrade_from_v15_adds_columns_as_null(tmp_path) -> None:
    path = tmp_path / "v15-standing.sqlite3"
    _build_v15_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 15
        conn.execute(
            "UPDATE standing_network_preferences SET "
            "staff_ssid = ?, guest_default_ssid = ?, updated_at = ? "
            "WHERE preferences_id = 'default'",
            (
                "Populated Staff",
                "Populated Guest",
                "2026-08-05T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 16
        row = conn.execute(
            "SELECT staff_ssid, guest_default_ssid, staff_ap_id, guest_ap_id "
            "FROM standing_network_preferences WHERE preferences_id = 'default'"
        ).fetchone()
        assert row is not None
        assert row[0] == "Populated Staff"
        assert row[1] == "Populated Guest"
        assert row[2] is None
        assert row[3] is None
    finally:
        conn.close()


def test_migration_16_fresh_db_reaches_current_version(tmp_path) -> None:
    conn = open_database(tmp_path / "fresh-v16.sqlite3")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    assert CURRENT_USER_VERSION == 16
    row = conn.execute(
        "SELECT staff_ap_id, guest_ap_id "
        "FROM standing_network_preferences WHERE preferences_id = 'default'"
    ).fetchone()
    assert row is not None
    assert row[0] is None
    assert row[1] is None


def test_migration_16_self_heals_after_row_deleted_with_new_columns(
    store: PersistenceStore,
) -> None:
    store.conn.execute("DELETE FROM standing_network_preferences")
    store.conn.commit()
    store.seed_standing_network_preferences_defaults()
    row = store.get_standing_network_preferences()
    assert row["staff_ap_id"] is None
    assert row["guest_ap_id"] is None


def test_migration_16_reopen_after_upgrade_validates_fingerprint(tmp_path) -> None:
    path = tmp_path / "reopen-v16.sqlite3"
    conn = open_database(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 16
    conn.close()

    conn2 = open_database(path)
    try:
        assert conn2.execute("PRAGMA user_version").fetchone()[0] == 16
    finally:
        conn2.close()


def test_migrate_fails_closed_on_out_of_band_version_drift(tmp_path) -> None:
    path = tmp_path / "drift.sqlite3"
    conn = open_database(path)
    conn.execute("PRAGMA user_version = 999")
    conn.commit()
    version_before = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version_before == 999

    with pytest.raises(RuntimeError, match="newer than supported"):
        migrate(conn, db_path=path)

    version_after = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version_after == 999


def test_upsert_standing_ap_ids_roundtrip(store: PersistenceStore) -> None:
    now = datetime(2026, 8, 5, tzinfo=UTC)
    updated = store.upsert_standing_network_preferences(
        staff_ap_id="WifiMaster0/AccessPoint1",
        guest_ap_id="WifiMaster1/AccessPoint2",
        now=now,
    )
    assert updated["staff_ap_id"] == "WifiMaster0/AccessPoint1"
    assert updated["guest_ap_id"] == "WifiMaster1/AccessPoint2"

    cleared = store.upsert_standing_network_preferences(
        staff_ap_id=None,
        guest_ap_id=None,
        now=now,
    )
    assert cleared["staff_ap_id"] is None
    assert cleared["guest_ap_id"] is None


def test_unset_sentinel_leaves_ap_ids_unchanged(store: PersistenceStore) -> None:
    now = datetime(2026, 8, 5, tzinfo=UTC)
    store.upsert_standing_network_preferences(
        staff_ap_id="WifiMaster0/AccessPoint0",
        guest_ap_id="WifiMaster0/AccessPoint3",
        now=now,
    )
    updated = store.upsert_standing_network_preferences(
        staff_ssid="SSID only",
        staff_ap_id=_UNSET,
        guest_ap_id=_UNSET,
        now=now,
    )
    assert updated["staff_ssid"] == "SSID only"
    assert updated["staff_ap_id"] == "WifiMaster0/AccessPoint0"
    assert updated["guest_ap_id"] == "WifiMaster0/AccessPoint3"


def test_seed_defaults_leaves_ap_ids_null(store: PersistenceStore) -> None:
    store.conn.execute("DELETE FROM standing_network_preferences")
    store.conn.commit()
    store.seed_standing_network_preferences_defaults()
    row = store.get_standing_network_preferences()
    assert row["staff_ap_id"] is None
    assert row["guest_ap_id"] is None


@pytest.mark.parametrize(
    ("value", "field"),
    [
        ("WifiMaster0/AccessPoint0", "staff_ap_id"),
        ("WifiMaster1/AccessPoint6", "guest_ap_id"),
    ],
)
def test_validate_ap_id_accepts_canonical_shape(value: str, field: str) -> None:
    assert _validate_ap_id(value, field=field) == value


@pytest.mark.parametrize(
    ("value", "field"),
    [
        ("AccessPoint7", "staff_ap_id"),
        ("WifiMaster0/AccessPoint7", "staff_ap_id"),
        ("wifimaster0/AccessPoint0", "staff_ap_id"),
        (" WifiMaster0/AccessPoint0", "staff_ap_id"),
    ],
)
def test_validate_ap_id_rejects_invalid_shape(value: str, field: str) -> None:
    with pytest.raises(StandingNetworkPreferencesValidationError) as exc_info:
        _validate_ap_id(value, field=field)
    assert exc_info.value.code == "standing.validation_failed"
    assert exc_info.value.field == field


def test_service_update_preferences_validates_ap_id(store: PersistenceStore) -> None:
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    with pytest.raises(StandingNetworkPreferencesValidationError):
        service.update_preferences(staff_ap_id="WifiMaster0/AccessPoint9")
    prefs = service.update_preferences(staff_ap_id="WifiMaster0/AccessPoint2")
    assert prefs["staff_ap_id"] == "WifiMaster0/AccessPoint2"


def test_service_update_preferences_rejects_overlapping_ap_roles(
    store: PersistenceStore,
) -> None:
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    ap_id = "WifiMaster0/AccessPoint0"
    service.update_preferences(staff_ap_id=ap_id)
    with pytest.raises(StandingNetworkPreferencesValidationError) as exc_info:
        service.update_preferences(guest_ap_id=ap_id)
    assert exc_info.value.code == "standing.ap_role_overlap"
    assert exc_info.value.field is None


def test_service_update_preferences_rejects_simultaneous_same_ap_roles(
    store: PersistenceStore,
) -> None:
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    ap_id = "WifiMaster0/AccessPoint1"
    with pytest.raises(StandingNetworkPreferencesValidationError) as exc_info:
        service.update_preferences(staff_ap_id=ap_id, guest_ap_id=ap_id)
    assert exc_info.value.code == "standing.ap_role_overlap"


def test_service_update_preferences_allows_clearing_overlap(store: PersistenceStore) -> None:
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    ap_id = "WifiMaster0/AccessPoint2"
    # Escape hatch: plant legacy overlap via raw SQL (store now rejects overlap).
    store.conn.execute(
        "UPDATE standing_network_preferences SET staff_ap_id = ?, guest_ap_id = ? "
        "WHERE preferences_id = ?",
        (ap_id, ap_id, store._STANDING_PREFS_ID),
    )
    cleared = service.update_preferences(guest_ap_id=None)
    assert cleared["staff_ap_id"] == ap_id
    assert cleared["guest_ap_id"] is None


def test_upsert_standing_ap_ids_rejects_overlap(store: PersistenceStore) -> None:
    ap_id = "WifiMaster0/AccessPoint5"
    with pytest.raises(PreconditionFailed, match="AP role overlap"):
        store.upsert_standing_network_preferences(
            staff_ap_id=ap_id,
            guest_ap_id=ap_id,
            now=datetime(2026, 8, 5, tzinfo=UTC),
        )


def test_service_update_preferences_concurrent_same_ap_roles_fail_closed(
    store: PersistenceStore,
) -> None:
    """Concurrent partial PUTs for the same AP must not leave staff/guest overlap."""
    service = StandingNetworkPreferencesService(store=store, clock=SystemClock())
    ap_id = "WifiMaster0/AccessPoint4"
    barrier = threading.Barrier(2, timeout=5)
    overlap_errors: list[StandingNetworkPreferencesValidationError] = []
    successes: list[dict] = []
    unexpected_errors: list[BaseException] = []

    def set_staff() -> None:
        try:
            barrier.wait()
            successes.append(service.update_preferences(staff_ap_id=ap_id))
        except StandingNetworkPreferencesValidationError as exc:
            if exc.code == "standing.ap_role_overlap":
                overlap_errors.append(exc)
            else:
                unexpected_errors.append(exc)
        except BaseException as exc:
            unexpected_errors.append(exc)

    def set_guest() -> None:
        try:
            barrier.wait()
            successes.append(service.update_preferences(guest_ap_id=ap_id))
        except StandingNetworkPreferencesValidationError as exc:
            if exc.code == "standing.ap_role_overlap":
                overlap_errors.append(exc)
            else:
                unexpected_errors.append(exc)
        except BaseException as exc:
            unexpected_errors.append(exc)

    t_staff = threading.Thread(target=set_staff, name="staff-ap")
    t_guest = threading.Thread(target=set_guest, name="guest-ap")
    t_staff.start()
    t_guest.start()
    t_staff.join(timeout=10)
    t_guest.join(timeout=10)
    assert not t_staff.is_alive()
    assert not t_guest.is_alive()
    assert not unexpected_errors, unexpected_errors

    final = service.get_preferences()
    staff_ap = final["staff_ap_id"]
    guest_ap = final["guest_ap_id"]
    assert not (
        staff_ap is not None and guest_ap is not None and staff_ap == guest_ap
    )
    assert overlap_errors, "expected at least one standing.ap_role_overlap failure"
    assert len(successes) == 1
