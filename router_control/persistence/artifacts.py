"""Fake-safe backup artifact publication — validate bytes/digest before SQLite metadata."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from router_control.domain.enums import ArtifactStagingStatus
from router_control.persistence.errors import ArtifactNotRestorableError
from router_control.persistence.ids import new_id
from router_control.persistence.store import PersistenceStore


def compute_content_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class FakeBlobStore:
    """Process-local in-memory backup bytes keyed by artifact_id (M4 fake-only)."""

    _blobs: dict[str, bytes] = field(default_factory=dict)

    def put(self, artifact_id: str, data: bytes, *, expected_digest: str | None = None) -> str:
        digest = compute_content_digest(data)
        if expected_digest is not None and digest != expected_digest:
            raise ValueError("backup digest mismatch")
        self._blobs[artifact_id] = data
        return digest

    def get(self, artifact_id: str) -> bytes | None:
        return self._blobs.get(artifact_id)


def redacted_backup_dto(row: Any) -> dict[str, Any]:
    """API-safe backup metadata — no storage locator or raw content."""
    return {
        "artifact_id": row["artifact_id"],
        "router_id": row["router_id"],
        "operation_id": row["operation_id"],
        "content_digest": row["content_digest"],
        "size_bytes": int(row["size_bytes"]),
        "verification_status": row["verification_status"],
        "identity_fingerprint_digest": row["identity_fingerprint"],
        "created_at": row["created_at"],
    }


def _utc_now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fsync_file(path: Path) -> None:
    fd = os.open(str(path), os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = path.parent
    if parent != Path(path.anchor) and parent.exists():
        try:
            dir_fd = os.open(str(parent), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _verify_file_digest(path: Path, expected_digest: str) -> None:
    actual = compute_content_digest(path.read_bytes())
    if actual != expected_digest:
        raise ValueError("content digest validation failed")


@dataclass
class BackupArtifactPublisher:
    blob_store: FakeBlobStore
    store: PersistenceStore

    def publish(
        self,
        *,
        artifact_id: str | None,
        router_id: str,
        operation_id: str,
        content_bytes: bytes,
        content_digest: str,
        identity_fingerprint: str,
        now: datetime | None = None,
    ) -> str:
        """Validate digest against bytes, store blob, then persist SQLite metadata."""
        actual = compute_content_digest(content_bytes)
        if actual != content_digest:
            raise ValueError("content digest validation failed")
        aid = artifact_id or new_id("bkp")
        self.blob_store.put(aid, content_bytes, expected_digest=content_digest)
        self.store.insert_backup_artifact_metadata(
            artifact_id=aid,
            router_id=router_id,
            operation_id=operation_id,
            content_digest=content_digest,
            size_bytes=len(content_bytes),
            identity_fingerprint=identity_fingerprint,
            now=now,
        )
        return aid


@dataclass
class ArtifactStagingPublisher:
    """Staging pipeline: reserve → bytes → fsync → hash → rename → dir fsync → metadata."""

    store: PersistenceStore
    staging_root: Path = field(default_factory=lambda: Path("data/artifact-staging"))

    def stage_bytes(
        self,
        *,
        content_bytes: bytes,
        content_digest: str | None = None,
        router_id: str | None = None,
        operation_id: str | None = None,
        job_id: str | None = None,
        restorable: bool = False,
        restorable_reason: str = "fake-non-live",
        now: datetime | None = None,
    ) -> tuple[str, str]:
        actual = compute_content_digest(content_bytes)
        if content_digest is not None and actual != content_digest:
            raise ValueError("content digest validation failed")
        self.staging_root.mkdir(parents=True, exist_ok=True)
        temp_name = f".{new_id('tmp')}.part"
        temp_path = self.staging_root / temp_name
        staging_id = self.store.create_artifact_staging(
            temp_path=str(temp_path),
            content_digest=actual,
            size_bytes=len(content_bytes),
            router_id=router_id,
            operation_id=operation_id,
            job_id=job_id,
            restorable=restorable,
            restorable_reason=restorable_reason,
            now=now,
        )
        temp_path.write_bytes(content_bytes)
        self.store.advance_artifact_staging(
            staging_id,
            staging_status=ArtifactStagingStatus.WRITTEN.value,
            now=now,
        )
        _fsync_file(temp_path)
        self.store.advance_artifact_staging(
            staging_id,
            staging_status=ArtifactStagingStatus.FSYNCED.value,
            now=now,
        )
        _verify_file_digest(temp_path, actual)
        final_path = temp_path.with_suffix(".bin")
        os.replace(temp_path, final_path)
        _fsync_file(final_path)
        self.store.advance_artifact_staging(
            staging_id,
            staging_status=ArtifactStagingStatus.RENAMED.value,
            final_path=str(final_path),
            now=now,
        )
        return staging_id, actual

    def publish_staged(
        self,
        *,
        staging_id: str,
        artifact_id: str,
        now: datetime | None = None,
    ) -> None:
        row = self.store.get_artifact_staging(staging_id)
        if row is None:
            raise ValueError("staging record not found")
        if int(row["restorable"]) != 1:
            raise ArtifactNotRestorableError(
                f"artifact explicitly non-live-restorable: {row['restorable_reason']}"
            )
        final_path = row["final_path"]
        if not final_path:
            raise ValueError("staging bytes not durable")
        path = Path(str(final_path))
        if not path.is_file():
            raise ValueError("staging bytes missing on disk")
        _verify_file_digest(path, str(row["content_digest"]))
        self.store.advance_artifact_staging(
            staging_id,
            staging_status=ArtifactStagingStatus.PUBLISHED.value,
            artifact_id=artifact_id,
            now=now,
        )
        self.store.link_artifact_publication(
            staging_id=staging_id,
            artifact_id=artifact_id,
            now=now,
        )

    def reconcile_orphan_staging(
        self,
        *,
        staging_id: str,
        now: datetime | None = None,
    ) -> str:
        """Crash/orphan reconcile: bytes win; metadata never precedes durable bytes."""
        row = self.store.get_artifact_staging(staging_id)
        if row is None:
            raise ValueError("staging record not found")
        status = str(row["staging_status"])
        temp_path = Path(str(row["temp_path"]))
        final_path = Path(str(row["final_path"])) if row["final_path"] else None
        digest = str(row["content_digest"])

        if status == ArtifactStagingStatus.PUBLISHED.value:
            if final_path is None or not final_path.is_file():
                raise ValueError("published staging missing durable bytes")
            _verify_file_digest(final_path, digest)
            return status

        if final_path is not None and final_path.is_file():
            _verify_file_digest(final_path, digest)
            self.store.advance_artifact_staging(
                staging_id,
                staging_status=ArtifactStagingStatus.RENAMED.value,
                final_path=str(final_path),
                now=now,
            )
            status = ArtifactStagingStatus.RENAMED.value
        elif temp_path.is_file():
            _verify_file_digest(temp_path, digest)
            _fsync_file(temp_path)
            target = temp_path.with_suffix(".bin")
            os.replace(temp_path, target)
            _fsync_file(target)
            self.store.advance_artifact_staging(
                staging_id,
                staging_status=ArtifactStagingStatus.RENAMED.value,
                final_path=str(target),
                now=now,
            )
            status = ArtifactStagingStatus.RENAMED.value
        else:
            self.store.advance_artifact_staging(
                staging_id,
                staging_status=ArtifactStagingStatus.ABANDONED.value,
                now=now,
            )
            return ArtifactStagingStatus.ABANDONED.value

        self.store.advance_artifact_staging(
            staging_id,
            staging_status=ArtifactStagingStatus.RECONCILED.value,
            now=now,
        )
        return ArtifactStagingStatus.RECONCILED.value


def reconcile_orphan_staging_records(
    publisher: ArtifactStagingPublisher,
    store: PersistenceStore,
    *,
    limit: int = 100,
    now: datetime | None = None,
) -> list[str]:
    """Startup orphan reconcile — bytes win; metadata never precedes durable bytes."""
    outcomes: list[str] = []
    for row in store.list_pending_artifact_staging(limit=limit):
        staging_id = str(row["staging_id"])
        try:
            status = publisher.reconcile_orphan_staging(staging_id=staging_id, now=now)
            outcomes.append(status)
        except (ValueError, OSError):
            outcomes.append(ArtifactStagingStatus.ABANDONED.value)
    return outcomes


@dataclass
class DpapiDurableArtifactStore:
    """Windows DPAPI CurrentUser encrypted durable backup bytes (offline tests only)."""

    store: PersistenceStore
    staging_root: Path
    encrypted_root: Path = field(default_factory=lambda: Path("data/artifact-encrypted"))

    def __post_init__(self) -> None:
        self.encrypted_root.mkdir(parents=True, exist_ok=True)

    def publish_encrypted(
        self,
        *,
        artifact_id: str,
        router_id: str,
        operation_id: str,
        content_bytes: bytes,
        content_digest: str,
        identity_fingerprint: str,
        now: datetime | None = None,
    ) -> str:
        from router_control.adapters.secrets.dpapi import protect_bytes

        publisher = ArtifactStagingPublisher(store=self.store, staging_root=self.staging_root)
        staging_id, actual = publisher.stage_bytes(
            content_bytes=content_bytes,
            content_digest=content_digest,
            router_id=router_id,
            operation_id=operation_id,
            restorable=True,
            restorable_reason="dpapi-durable-offline",
            now=now,
        )
        row = self.store.get_artifact_staging(staging_id)
        if row is None or not row["final_path"]:
            raise ValueError("staging bytes not durable")
        plain_path = Path(str(row["final_path"]))
        encrypted_path = self.encrypted_root / f"{artifact_id}.dpapi.bin"
        encrypted_path.write_bytes(protect_bytes(plain_path.read_bytes()))
        _fsync_file(encrypted_path)
        self.store.insert_backup_artifact_metadata(
            artifact_id=artifact_id,
            router_id=router_id,
            operation_id=operation_id,
            content_digest=actual,
            size_bytes=len(content_bytes),
            identity_fingerprint=identity_fingerprint,
            now=now,
        )
        self.store.advance_artifact_staging(
            staging_id,
            staging_status=ArtifactStagingStatus.PUBLISHED.value,
            artifact_id=artifact_id,
            now=now,
        )
        self.store.mark_backup_metadata_restorable(
            artifact_id=artifact_id,
            restorable=True,
            restorable_reason="dpapi-durable-offline",
            now=now,
        )
        return artifact_id

    def restore(self, artifact_id: str) -> bytes:
        from router_control.adapters.secrets.dpapi import unprotect_bytes

        self.store.assert_backup_restorable(artifact_id)
        row = self.store.get_backup_artifact(artifact_id)
        if row is None:
            raise ArtifactNotRestorableError("backup artifact metadata missing")
        encrypted_path = self.encrypted_root / f"{artifact_id}.dpapi.bin"
        if not encrypted_path.is_file():
            raise ArtifactNotRestorableError("encrypted backup bytes missing")
        plain = unprotect_bytes(encrypted_path.read_bytes())
        expected = str(row["content_digest"])
        actual = compute_content_digest(plain)
        if actual != expected:
            raise ValueError("restored backup digest mismatch")
        return plain


@dataclass
class DurableBackupArtifactPublisher:
    """Publish backup bytes via DPAPI durable store (offline/restorable tests)."""

    durable_store: DpapiDurableArtifactStore

    def publish(
        self,
        *,
        artifact_id: str | None,
        router_id: str,
        operation_id: str,
        content_bytes: bytes,
        content_digest: str,
        identity_fingerprint: str,
        now: datetime | None = None,
    ) -> str:
        aid = artifact_id or new_id("bkp")
        return self.durable_store.publish_encrypted(
            artifact_id=aid,
            router_id=router_id,
            operation_id=operation_id,
            content_bytes=content_bytes,
            content_digest=content_digest,
            identity_fingerprint=identity_fingerprint,
            now=now,
        )
