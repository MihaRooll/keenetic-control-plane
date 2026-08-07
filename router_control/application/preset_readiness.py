"""Event preset readiness — deterministic, no router I/O."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from router_control.application.commissioning import CommissioningService
from router_control.application.preset_planner import PresetPlannerService
from router_control.domain.errors import (
    EventPresetConflict,
    EventPresetIdempotencyConflict,
    EventPresetNotFound,
    EventPresetPreconditionFailed,
    EventPresetValidationFailed,
)
from router_control.domain.event_preset import (
    ValidationStatus,
    build_safe_default_document,
    derive_readiness_status,
    document_to_revision_fields,
    validate_document,
)
from router_control.domain.network_intents import (
    BlockingFor,
    EventPresetDocument,
    FindingSeverity,
    IntentValidationError,
    ReadinessFinding,
    parse_event_preset_document,
)
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PreconditionFailed,
)
from router_control.persistence.store import PersistenceStore
from router_control.ports.clock import ClockPort


def _map_store_error(exc: Exception) -> Exception:
    if isinstance(exc, NotFoundError):
        return EventPresetNotFound(str(exc))
    if isinstance(exc, PreconditionFailed):
        return EventPresetPreconditionFailed(str(exc))
    if isinstance(exc, IdempotencyConflict):
        return EventPresetIdempotencyConflict(str(exc))
    if isinstance(exc, ConflictError):
        return EventPresetConflict(str(exc))
    return exc


@dataclass
class EventPresetCatalogService:
    store: PersistenceStore
    clock: ClockPort
    planner: PresetPlannerService = field(default_factory=PresetPlannerService)
    readiness: PresetReadinessService | None = None

    def list_presets_for_site(self, site_id: str) -> list[dict[str, Any]]:
        if self.store.get_site(site_id) is None:
            raise EventPresetNotFound("site not found")
        return [
            self._public_preset(row)
            for row in self.store.list_event_presets_for_site(site_id)
        ]

    def get_preset(self, preset_id: str) -> dict[str, Any]:
        row = self.store.get_event_preset(preset_id)
        if row is None:
            raise EventPresetNotFound("event preset not found")
        return self._public_preset(row)

    def get_revision(self, preset_id: str, revision_id: str) -> dict[str, Any]:
        revision = self.store.get_event_preset_revision(revision_id)
        if revision is None or str(revision["preset_id"]) != preset_id:
            raise EventPresetNotFound("revision not found")
        body = self.store._row_to_event_preset_revision(revision)
        body["canonical_document"] = self.store.revision_canonical_json(revision)
        return body

    def create_preset(
        self,
        *,
        site_id: str,
        name: str,
        document: dict[str, Any] | None,
        idempotency_key: str,
        request_digest: str,
        correlation_id: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        try:
            doc = (
                build_safe_default_document(name=name)
                if document is None
                else parse_event_preset_document(document)
            )
        except IntentValidationError as exc:
            raise EventPresetValidationFailed(
                message=str(exc),
                reason_code=exc.code,
                field=exc.field,
            ) from exc
        status, findings = validate_document(doc)
        canonical, digest = document_to_revision_fields(doc)
        summary = None if not findings else findings[0].summary_redacted
        try:
            preset, revision, created = self.store.create_event_preset(
                site_id=site_id,
                name=doc.name,
                canonical_json=json.dumps(canonical, sort_keys=True, separators=(",", ":")),
                canonical_digest=digest,
                validation_status=status.value,
                summary_redacted=summary,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                correlation_id=correlation_id,
                now=self.clock.now(),
            )
        except Exception as exc:
            raise _map_store_error(exc) from exc
        return self._public_preset_dict(preset), self._public_revision_dict(revision), created

    def create_revision(
        self,
        *,
        preset_id: str,
        document: dict[str, Any],
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None = None,
        correlation_id: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        try:
            doc = parse_event_preset_document(document)
        except IntentValidationError as exc:
            raise EventPresetValidationFailed(
                message=str(exc),
                reason_code=exc.code,
                field=exc.field,
            ) from exc
        status, findings = validate_document(doc)
        canonical, digest = document_to_revision_fields(doc)
        summary = None if not findings else findings[0].summary_redacted
        try:
            preset, revision, created = self.store.create_event_preset_revision_idempotent(
                preset_id=preset_id,
                canonical_json=json.dumps(canonical, sort_keys=True, separators=(",", ":")),
                canonical_digest=digest,
                validation_status=status.value,
                summary_redacted=summary,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expected_version=expected_version,
                correlation_id=correlation_id,
                now=self.clock.now(),
            )
        except Exception as exc:
            raise _map_store_error(exc) from exc
        return self._public_preset_dict(preset), self._public_revision_dict(revision), created

    def publish_revision(
        self,
        *,
        preset_id: str,
        revision_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None = None,
        correlation_id: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        try:
            preset, created = self.store.publish_event_preset_revision_idempotent(
                preset_id=preset_id,
                revision_id=revision_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expected_version=expected_version,
                correlation_id=correlation_id,
                now=self.clock.now(),
            )
        except Exception as exc:
            raise _map_store_error(exc) from exc
        return self._public_preset_dict(preset), created

    def validate_preset(self, preset_id: str) -> dict[str, Any]:
        svc = self.readiness or PresetReadinessService(store=self.store, planner=self.planner)
        return svc.validate_preset(preset_id=preset_id)

    def plan_preview(self, preset_id: str) -> dict[str, Any]:
        row = self.store.get_event_preset(preset_id)
        if row is None:
            raise EventPresetNotFound("event preset not found")
        revision_id = row["published_revision_id"] or row["current_revision_id"]
        revision = self.store.get_event_preset_revision(str(revision_id))
        if revision is None:
            raise EventPresetNotFound("revision not found")
        doc = parse_event_preset_document(self.store.revision_canonical_json(revision))
        status = ValidationStatus(str(revision["validation_status"]))
        return self.planner.build_plan_preview(document=doc, validation_status=status)

    def readiness_report(self, preset_id: str) -> dict[str, Any]:
        svc = self.readiness or PresetReadinessService(store=self.store, planner=self.planner)
        return svc.build_readiness_report(preset_id=preset_id)

    def enqueue_validate_async(
        self,
        *,
        preset_id: str,
        idempotency_key: str,
        request_digest: str,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        preset = self.store.get_event_preset(preset_id)
        if preset is None:
            raise EventPresetNotFound("event preset not found")
        router_id = self._sentinel_router_id(str(preset["site_id"]))
        existing = self.store.peek_idempotency(
            router_id=router_id,
            operation_kind="preset_validate",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        if existing is not None:
            return self._async_preset_envelope(existing, router_id)
        outcome = self.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="preset_validate",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            actor_id=actor_id,
            correlation_id=correlation_id or preset_id,
            initial_job_status="Queued",
            dispatch_payload={"preset_id": preset_id},
            now=self.clock.now(),
        )
        body = self._async_preset_body(outcome, router_id)
        self.store.update_idempotency_response(
            outcome.idempotency_record_id,
            http_status=202,
            body=body,
        )
        return body

    def enqueue_plan_readiness_async(
        self,
        *,
        preset_id: str,
        idempotency_key: str,
        request_digest: str,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        preset = self.store.get_event_preset(preset_id)
        if preset is None:
            raise EventPresetNotFound("event preset not found")
        router_id = self._sentinel_router_id(str(preset["site_id"]))
        existing = self.store.peek_idempotency(
            router_id=router_id,
            operation_kind="preset_plan_readiness",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        if existing is not None:
            return self._async_preset_envelope(existing, router_id)
        outcome = self.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="preset_plan_readiness",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            actor_id=actor_id,
            correlation_id=correlation_id or preset_id,
            initial_job_status="Queued",
            dispatch_payload={"preset_id": preset_id},
            now=self.clock.now(),
        )
        body = self._async_preset_body(outcome, router_id)
        self.store.update_idempotency_response(
            outcome.idempotency_record_id,
            http_status=202,
            body=body,
        )
        return body

    def _sentinel_router_id(self, site_id: str) -> str:
        for row in self.store.list_routers(limit=200):
            if row["display_name"] == "__catalog__":
                return str(row["router_id"])
        return self.store.enroll_router(
            site_id=site_id,
            display_name="__catalog__",
            vendor="Catalog",
            model="None",
            identity_fingerprint="digest:catalog",
            host="127.0.0.1",
            now=self.clock.now(),
        )

    @staticmethod
    def _async_preset_body(outcome: Any, router_id: str) -> dict[str, Any]:
        return {
            "operation_id": outcome.operation_id,
            "job_id": outcome.job_id,
            "status": "Queued",
            "router_id": router_id,
            "links": {
                "operation": f"/api/router-control/v1/operations/{outcome.operation_id}",
                "job": f"/api/router-control/v1/jobs/{outcome.job_id}",
            },
        }

    def _async_preset_envelope(self, existing: Any, router_id: str) -> dict[str, Any]:
        import json

        if existing.response_ref:
            stored = json.loads(existing.response_ref)
            if isinstance(stored, dict):
                body = stored.get("body")
                if isinstance(body, dict):
                    typed_body: dict[str, Any] = body
                    return typed_body
        return self._async_preset_body(existing, router_id)

    def _public_preset(self, row: Any) -> dict[str, Any]:
        return self._public_preset_dict(self.store._row_to_event_preset(row))

    def _public_preset_dict(self, preset: dict[str, Any]) -> dict[str, Any]:
        return {
            "preset_id": preset["preset_id"],
            "site_id": preset["site_id"],
            "name": preset["name"],
            "version": preset["version"],
            "current_revision_id": preset["current_revision_id"],
            "published_revision_id": preset["published_revision_id"],
            "created_at": preset["created_at"],
            "updated_at": preset["updated_at"],
            "write_ready": False,
            "etag": preset["etag"],
        }

    def _public_revision_dict(self, revision: dict[str, Any]) -> dict[str, Any]:
        return {
            "revision_id": revision["revision_id"],
            "preset_id": revision["preset_id"],
            "revision_number": revision["revision_number"],
            "canonical_digest": revision["canonical_digest"],
            "validation_status": revision["validation_status"],
            "summary_redacted": revision["summary_redacted"],
            "created_at": revision["created_at"],
            "write_ready": False,
            "etag": revision["etag"],
        }


@dataclass
class PresetReadinessService:
    store: PersistenceStore
    planner: PresetPlannerService = field(default_factory=PresetPlannerService)
    commissioning_lookup: Callable[[str], dict[str, Any] | None] | None = None

    def validate_preset(self, *, preset_id: str) -> dict[str, Any]:
        revision = self._current_revision_row(preset_id)
        document = self._document_from_revision(revision)
        status, findings = validate_document(document)
        return self._validation_payload(
            preset_id=preset_id,
            revision_id=str(revision["revision_id"]),
            status=status,
            findings=findings,
        )

    def build_readiness_report(
        self,
        *,
        preset_id: str,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        preset_row = self.store.get_event_preset(preset_id)
        if preset_row is None:
            raise EventPresetNotFound("event preset not found")
        revision = self._current_revision_row(preset_id)
        document = self._document_from_revision(revision)
        status, findings = validate_document(document)
        findings = list(findings)
        findings.extend(self.planner.plan_blocker_findings())
        findings.extend(self._topology_findings(document))
        readiness_status = derive_readiness_status(status, findings)
        commissioning_summary = self._commissioning_summary(
            site_id or str(preset_row["site_id"])
        )
        write_blockers = [
            f.to_public()
            for f in findings
            if f.blocking_for == BlockingFor.WRITE
            and f.severity == FindingSeverity.ERROR
        ]
        validation_blockers = [
            f.to_public()
            for f in findings
            if f.blocking_for == BlockingFor.VALIDATION
            and f.severity == FindingSeverity.ERROR
        ]
        apply_blockers = [
            f.to_public()
            for f in findings
            if f.blocking_for == BlockingFor.APPLY_FRAGMENT
        ]
        return {
            "preset_id": preset_id,
            "site_id": str(preset_row["site_id"]),
            "revision_id": str(revision["revision_id"]),
            "validation_status": status.value,
            "readiness_status": readiness_status.value,
            "valid_offline": status == ValidationStatus.VALID_OFFLINE,
            "ready_for_read_only_assessment": (
                readiness_status == ValidationStatus.READY_FOR_READ_ONLY_ASSESSMENT
            ),
            "write_ready": False,
            "findings": [f.to_public() for f in findings],
            "validation_blockers": validation_blockers,
            "apply_fragment_blockers": apply_blockers,
            "write_blockers": write_blockers,
            "commissioning_summary": commissioning_summary,
        }

    def _commissioning_summary(self, site_id: str) -> dict[str, Any] | None:
        if self.commissioning_lookup is not None:
            return self.commissioning_lookup(site_id)
        runs = self.store.list_commissioning_runs_for_site(site_id, limit=1)
        if not runs:
            return None
        run = self.store._row_to_commissioning_run(runs[0])
        return {
            "run_id": run["run_id"],
            "state": run["state"],
            "read_only_ready": run["state"] == "ReadyReadOnly",
            "write_ready": False,
        }

    def _topology_findings(self, document: EventPresetDocument) -> list[ReadinessFinding]:
        findings: list[ReadinessFinding] = []
        if not document.local_order_url.startswith("https://"):
            findings.append(
                ReadinessFinding(
                    code="local_order_url_not_https",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted="local_order_url must use HTTPS",
                )
            )
        guest = next((z for z in document.zones if z.zone_id.value == "Guest"), None)
        if guest and guest.wifi and guest.wifi.captive_portal.value != "Disabled":
            findings.append(
                ReadinessFinding(
                    code="captive_portal_disabled_required",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted="captive portal must be Disabled for safe default posture",
                )
            )
        return findings

    def _current_revision_row(self, preset_id: str) -> Any:
        preset = self.store.get_event_preset(preset_id)
        if preset is None:
            raise EventPresetNotFound("event preset not found")
        revision_id = preset["published_revision_id"] or preset["current_revision_id"]
        if not revision_id:
            raise EventPresetNotFound("preset has no revision")
        revision = self.store.get_event_preset_revision(str(revision_id))
        if revision is None:
            raise EventPresetNotFound("revision not found")
        return revision

    def _document_from_revision(self, revision: Any) -> EventPresetDocument:
        from router_control.domain.network_intents import parse_event_preset_document

        payload = self.store.revision_canonical_json(revision)
        return parse_event_preset_document(payload)

    def _validation_payload(
        self,
        *,
        preset_id: str,
        revision_id: str,
        status: ValidationStatus,
        findings: list[ReadinessFinding],
    ) -> dict[str, Any]:
        return {
            "preset_id": preset_id,
            "revision_id": revision_id,
            "validation_status": status.value,
            "write_ready": False,
            "findings": [f.to_public() for f in findings],
        }


def wire_commissioning_lookup(
    service: CommissioningService,
) -> Callable[[str], dict[str, Any] | None]:
    def lookup(site_id: str) -> dict[str, Any] | None:
        runs = service.list_runs_for_site(site_id)
        if not runs:
            return None
        latest = runs[0]
        return {
            "run_id": latest["run_id"],
            "state": latest["state"],
            "read_only_ready": latest.get("read_only_ready", False),
            "write_ready": False,
        }

    return lookup
