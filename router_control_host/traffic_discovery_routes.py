"""TrafficDiscovery API routes — proposals-only; auto-apply always blocked."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.domain.traffic import RouteProposal, TrafficObservation

from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["traffic-discovery"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RecordObservationBody(_StrictModel):
    router_id: str = Field(min_length=1)
    evidence: dict[str, Any]
    source: str = "offline"


class CreateProposalBody(_StrictModel):
    traffic_observation_id: str = Field(min_length=1)
    route_intent: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400)
    trusted_policy: bool = False


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _parse_ts(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialize_observation(obs: TrafficObservation) -> dict[str, Any]:
    return {
        "traffic_observation_id": obs.traffic_observation_id,
        "router_id": obs.router_id,
        "evidence_digest": obs.evidence_digest,
        "observed_at": _iso_utc(obs.observed_at),
        "source": obs.source,
    }


def _serialize_proposal(prop: RouteProposal) -> dict[str, Any]:
    return {
        "proposal_id": prop.proposal_id,
        "router_id": prop.router_id,
        "traffic_observation_id": prop.traffic_observation_id,
        "proposal_digest": prop.proposal_digest,
        "confidence": prop.confidence,
        "expires_at": _iso_utc(prop.expires_at),
        "trusted_policy": prop.trusted_policy,
        "auto_apply_blocked": prop.auto_apply_blocked,
        "status": prop.status,
    }


def _proposal_from_row(row: Any) -> RouteProposal:
    return RouteProposal(
        proposal_id=str(row["proposal_id"]),
        router_id=str(row["router_id"]),
        traffic_observation_id=str(row["traffic_observation_id"]),
        proposal_digest=str(row["proposal_digest"]),
        confidence=float(row["confidence"]),
        expires_at=_parse_ts(str(row["expires_at"])),
        trusted_policy=bool(int(row["trusted_policy"])),
        auto_apply_blocked=bool(int(row["auto_apply_blocked"])),
        status=str(row["status"]),
    )


def _observation_from_row(row: Any) -> TrafficObservation:
    return TrafficObservation(
        traffic_observation_id=str(row["traffic_observation_id"]),
        router_id=str(row["router_id"]),
        evidence_digest=str(row["evidence_digest"]),
        observed_at=_parse_ts(str(row["observed_at"])),
        source=str(row["source"]),
    )


@router.post("/traffic/observations", status_code=201)
def record_traffic_observation(request: Request, body: RecordObservationBody) -> JSONResponse:
    host = _state(request)
    service = host.traffic_service()
    try:
        obs = service.record_observation(
            router_id=body.router_id.strip(),
            evidence=body.evidence,
            source=body.source,
        )
    except Exception as exc:
        return error_response(
            request,
            status_code=422,
            code="traffic.observation_failed",
            message=str(exc),
        )
    row = service.store.get_traffic_observation(obs.traffic_observation_id)
    if row is not None and row["evidence_json"] is not None:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="evidence_json must remain unset",
        )
    payload = _serialize_observation(obs)
    if "evidence" in payload:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="raw evidence must not be echoed",
        )
    return JSONResponse(payload, status_code=201, headers=_ok_headers(request))


@router.post("/traffic/proposals", status_code=201)
def create_traffic_proposal(request: Request, body: CreateProposalBody) -> JSONResponse:
    host = _state(request)
    service = host.traffic_service()
    row = service.store.get_traffic_observation(body.traffic_observation_id.strip())
    if row is None:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="traffic observation not found",
        )
    observation = _observation_from_row(row)
    try:
        prop = service.create_proposal(
            observation=observation,
            route_intent=body.route_intent,
            confidence=body.confidence,
            ttl_seconds=body.ttl_seconds,
            trusted_policy=body.trusted_policy,
        )
    except ValueError as exc:
        return error_response(
            request,
            status_code=422,
            code="traffic.proposal_failed",
            message=str(exc),
        )
    stored = service.store.get_route_proposal(prop.proposal_id)
    if stored is not None and stored["proposal_json"] is not None:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="proposal_json must remain unset",
        )
    payload = _serialize_proposal(prop)
    return JSONResponse(
        payload,
        status_code=201,
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/traffic/proposals/{prop.proposal_id}"},
        ),
    )


@router.get("/traffic/proposals/{proposal_id}")
def get_traffic_proposal(request: Request, proposal_id: str) -> JSONResponse:
    host = _state(request)
    row = host.runtime.store.get_route_proposal(proposal_id)
    if row is None:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="proposal not found",
        )
    prop = _proposal_from_row(row)
    return JSONResponse(_serialize_proposal(prop), headers=_ok_headers(request))
