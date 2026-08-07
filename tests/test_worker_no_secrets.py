"""Worker payload/result/audit must not contain secrets."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore

FORBIDDEN = (
    "super-secret-password",
    "BEGIN RSA PRIVATE KEY",
    "provider_locator:dpapi:",
    "startup-config",
)


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    conn = open_database(tmp_path / "worker-secrets.sqlite3")
    return PersistenceStore(conn)


def test_dispatch_payload_and_audit_no_secrets(store: PersistenceStore) -> None:
    site = store.create_site(display_name="S", now=datetime(2026, 7, 22, tzinfo=UTC))
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="commissioning_assess_readonly",
        idempotency_key="sec-k",
        request_digest="sha256:sec",
        correlation_id="crun_sec",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload={"run_id": "crun_sec", "idempotency_key": "sec-k", "request_digest": "sha256:sec"},
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    dump = store.dump_text_for_secret_scan()
    for token in FORBIDDEN:
        assert token not in dump
