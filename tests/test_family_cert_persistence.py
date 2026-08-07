"""Durable router family certifications."""

from __future__ import annotations

from pathlib import Path

from router_control.composition import create_offline_runtime


def test_family_cert_insert_and_list(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "family-cert.sqlite3")
    store = runtime.store
    site = store.create_site(display_name="Lab", now=runtime.clock.now())
    router_id = store.enroll_router(
        site_id=site,
        display_name="Cert Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:cert",
        host="127.0.0.1",
        now=runtime.clock.now(),
    )
    now = runtime.clock.now()
    cert_id = store.upsert_family_certification(
        router_id=router_id,
        family="fail_safe",
        identity_tuple_digest="sha256:tuple",
        shape_digest="sha256:shape",
        codec_digest="sha256:codec",
        executor_digest="sha256:executor",
        evidence_digest="sha256:evidence",
        certification_level="LabProven",
        valid_from=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        valid_until=(now.replace(year=now.year + 1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        now=now,
    )
    rows = store.list_active_family_certifications(router_id)
    assert any(r["certification_id"] == cert_id for r in rows)
    store.revoke_family_certification(cert_id, now=now)
    active = store.list_active_family_certifications(router_id)
    assert all(r["certification_id"] != cert_id for r in active)
