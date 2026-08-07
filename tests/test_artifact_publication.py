"""P1-A artifact staging metadata pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.domain.enums import ArtifactStagingStatus
from router_control.persistence.artifacts import (
    ArtifactStagingPublisher,
    BackupArtifactPublisher,
    FakeBlobStore,
    compute_content_digest,
)
from router_control.persistence.connection import open_database
from router_control.persistence.errors import ArtifactNotRestorableError
from router_control.persistence.store import PersistenceStore


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "art.sqlite3"))


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


def test_staging_pipeline_metadata(tmp_path: Path, store: PersistenceStore) -> None:
    staging_root = tmp_path / "staging"
    publisher = ArtifactStagingPublisher(store=store, staging_root=staging_root)
    staging_id, digest = publisher.stage_bytes(
        content_bytes=b"artifact-bytes",
        router_id=_seed(store),
        restorable=False,
        restorable_reason="fake-non-live",
    )
    row = store.get_artifact_staging(staging_id)
    assert row is not None
    assert row["staging_status"] == ArtifactStagingStatus.RENAMED.value
    assert row["content_digest"] == digest
    assert int(row["restorable"]) == 0


def test_fake_backup_not_live_restorable(store: PersistenceStore) -> None:
    rid = _seed(store)
    blob = FakeBlobStore()
    backup_pub = BackupArtifactPublisher(blob_store=blob, store=store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="bk",
        request_digest="sha256:bk",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    aid = backup_pub.publish(
        artifact_id=None,
        router_id=rid,
        operation_id=out.operation_id,
        content_bytes=b"backup",
        content_digest="sha256:" + __import__("hashlib").sha256(b"backup").hexdigest(),
        identity_fingerprint="digest:fp:1",
    )
    store.mark_backup_metadata_restorable(
        artifact_id=aid,
        restorable=False,
        restorable_reason="fake-legacy-bytes",
    )
    with pytest.raises(ArtifactNotRestorableError):
        store.assert_backup_restorable(aid)


def test_non_restorable_staging_publish_blocked(tmp_path: Path, store: PersistenceStore) -> None:
    publisher = ArtifactStagingPublisher(
        store=store, staging_root=tmp_path / "stg2"
    )
    staging_id, _ = publisher.stage_bytes(
        content_bytes=b"x",
        restorable=False,
    )
    with pytest.raises(ArtifactNotRestorableError):
        publisher.publish_staged(staging_id=staging_id, artifact_id="art-1")


def test_staging_metadata_never_precedes_bytes(tmp_path: Path, store: PersistenceStore) -> None:
    staging_root = tmp_path / "order-check"
    publisher = ArtifactStagingPublisher(store=store, staging_root=staging_root)
    staging_id, digest = publisher.stage_bytes(content_bytes=b"ordered", restorable=True)
    row = store.get_artifact_staging(staging_id)
    assert row is not None
    final_path = Path(str(row["final_path"]))
    assert final_path.is_file()
    assert row["staging_status"] == ArtifactStagingStatus.RENAMED.value
    assert compute_content_digest(final_path.read_bytes()) == digest


def test_orphan_temp_reconciled_to_renamed(tmp_path: Path, store: PersistenceStore) -> None:
    staging_root = tmp_path / "orphan"
    publisher = ArtifactStagingPublisher(store=store, staging_root=staging_root)
    staging_id, _ = publisher.stage_bytes(content_bytes=b"orphan-bytes", restorable=True)
    row = store.get_artifact_staging(staging_id)
    assert row is not None
    store.advance_artifact_staging(
        staging_id,
        staging_status=ArtifactStagingStatus.WRITTEN.value,
    )
    status = publisher.reconcile_orphan_staging(staging_id=staging_id)
    assert status == ArtifactStagingStatus.RECONCILED.value
    row = store.get_artifact_staging(staging_id)
    assert row is not None
    assert row["final_path"]
    assert Path(str(row["final_path"])).is_file()


def test_orphan_without_bytes_abandoned(tmp_path: Path, store: PersistenceStore) -> None:
    staging_root = tmp_path / "missing"
    publisher = ArtifactStagingPublisher(store=store, staging_root=staging_root)
    temp_path = staging_root / ".missing.part"
    staging_id = store.create_artifact_staging(
        temp_path=str(temp_path),
        content_digest="sha256:" + __import__("hashlib").sha256(b"missing").hexdigest(),
        size_bytes=7,
        restorable=False,
    )
    status = publisher.reconcile_orphan_staging(staging_id=staging_id)
    assert status == ArtifactStagingStatus.ABANDONED.value
