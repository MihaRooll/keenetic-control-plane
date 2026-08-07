"""Explicit learn/confirm/pin SSH host-key workflow for Add-router wizard."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from router_control.adapters.netcraze.errors import SshHostKeyMismatch, SshHostKeyMissing
from router_control.adapters.netcraze.ssh_tunnel import (
    learn_ssh_host_key,
    normalize_sha256_fingerprint,
)
from router_control.persistence.errors import ConflictError, NotFoundError, PreconditionFailed
from router_control.persistence.store import EndpointSshHostKeyPin, PersistenceStore

if TYPE_CHECKING:
    from collections.abc import Callable


class SshHostKeyPinError(Exception):
    """Base error for SSH host-key pin application workflow."""


class SshHostKeyPinConflict(SshHostKeyPinError):
    """Existing stored pin differs from candidate confirmation."""

    def __init__(
        self,
        message: str,
        *,
        existing: EndpointSshHostKeyPin,
        candidate_fingerprint_sha256: str,
        candidate_algorithm: str,
    ) -> None:
        super().__init__(message)
        self.existing = existing
        self.candidate_fingerprint_sha256 = candidate_fingerprint_sha256
        self.candidate_algorithm = candidate_algorithm


class PendingLearnMissing(SshHostKeyPinError):
    """No pending learn candidate exists for confirm."""


class PendingLearnMismatch(SshHostKeyPinError):
    """Confirm echo does not match the pending learn candidate."""


@dataclass(frozen=True, slots=True)
class PendingLearnCandidate:
    fingerprint_sha256: str
    algorithm: str


class PendingLearnRegistry:
    """In-process short-lived pending learn candidates keyed by router_id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, PendingLearnCandidate] = {}

    def put(
        self,
        router_id: str,
        *,
        fingerprint_sha256: str,
        algorithm: str,
    ) -> None:
        normalized = normalize_sha256_fingerprint(fingerprint_sha256)
        algorithm_value = algorithm.strip()
        if not algorithm_value:
            raise PreconditionFailed("ssh host key algorithm is required")
        with self._lock:
            self._pending[router_id] = PendingLearnCandidate(
                fingerprint_sha256=normalized,
                algorithm=algorithm_value,
            )

    def get(self, router_id: str) -> PendingLearnCandidate | None:
        with self._lock:
            return self._pending.get(router_id)

    def clear(self, router_id: str) -> None:
        with self._lock:
            self._pending.pop(router_id, None)

    def require_match(
        self,
        router_id: str,
        *,
        fingerprint_sha256: str,
        algorithm: str,
    ) -> PendingLearnCandidate:
        pending = self.get(router_id)
        if pending is None:
            raise PendingLearnMissing(
                "no pending ssh host key learn for router; call learn before confirm"
            )
        try:
            normalized = normalize_sha256_fingerprint(fingerprint_sha256)
        except SshHostKeyMissing as exc:
            raise PendingLearnMismatch(str(exc)) from exc
        algorithm_value = algorithm.strip()
        if not algorithm_value:
            raise PendingLearnMismatch("ssh host key algorithm is required")
        if (
            pending.fingerprint_sha256 != normalized
            or pending.algorithm != algorithm_value
        ):
            raise PendingLearnMismatch(
                "fingerprint echo does not match pending learn candidate"
            )
        return pending


_LEARN_WARNING = (
    "Verify this fingerprint out-of-band before confirming. "
    "The learn step does not authenticate to the router."
)


@dataclass(frozen=True, slots=True)
class LearnCandidateResult:
    fingerprint_sha256: str
    algorithm: str
    warning: str


def learn_candidate(
    host: str,
    *,
    port: int = 22,
    connect_timeout: float = 10.0,
    source_address: str | None = None,
    allow_loopback_test_seam: bool = False,
    transport_factory: Callable[..., Any] | None = None,
) -> LearnCandidateResult:
    learned = learn_ssh_host_key(
        host,
        port=port,
        connect_timeout=connect_timeout,
        source_address=source_address,
        allow_loopback_test_seam=allow_loopback_test_seam,
        transport_factory=transport_factory,
    )
    return LearnCandidateResult(
        fingerprint_sha256=learned.fingerprint_sha256,
        algorithm=learned.algorithm,
        warning=_LEARN_WARNING,
    )


def record_pending_learn(
    pending_registry: PendingLearnRegistry,
    router_id: str,
    result: LearnCandidateResult,
) -> None:
    pending_registry.put(
        router_id,
        fingerprint_sha256=result.fingerprint_sha256,
        algorithm=result.algorithm,
    )


def confirm_pin(
    store: PersistenceStore,
    router_id: str,
    fingerprint_echo: str,
    algorithm: str,
    *,
    pending_registry: PendingLearnRegistry,
    allow_overwrite: bool = False,
) -> EndpointSshHostKeyPin:
    if store.get_router(router_id) is None:
        raise NotFoundError("router not found")
    try:
        pending_registry.require_match(
            router_id,
            fingerprint_sha256=fingerprint_echo,
            algorithm=algorithm,
        )
    except PendingLearnMissing as exc:
        raise PreconditionFailed(str(exc)) from exc
    except PendingLearnMismatch as exc:
        raise PreconditionFailed(str(exc)) from exc
    try:
        normalized_echo = normalize_sha256_fingerprint(fingerprint_echo)
    except SshHostKeyMissing as exc:
        raise PreconditionFailed(str(exc)) from exc
    algorithm_value = algorithm.strip()
    if not algorithm_value:
        raise PreconditionFailed("ssh host key algorithm is required")
    existing = store.get_endpoint_ssh_host_key(router_id)
    if (
        existing is not None
        and existing.fingerprint_sha256 != normalized_echo
        and not allow_overwrite
    ):
        raise SshHostKeyPinConflict(
            "stored ssh host key pin differs from candidate fingerprint",
            existing=existing,
            candidate_fingerprint_sha256=normalized_echo,
            candidate_algorithm=algorithm_value,
        )
    try:
        store.set_endpoint_ssh_host_key(
            router_id,
            normalized_echo,
            algorithm_value,
            "learned_confirmed",
            allow_overwrite=allow_overwrite,
        )
    except ConflictError as exc:
        existing = store.get_endpoint_ssh_host_key(router_id)
        if existing is None:
            raise
        raise SshHostKeyPinConflict(
            str(exc),
            existing=existing,
            candidate_fingerprint_sha256=normalized_echo,
            candidate_algorithm=algorithm_value,
        ) from exc
    pending_registry.clear(router_id)
    pinned = store.get_endpoint_ssh_host_key(router_id)
    if pinned is None:
        raise SshHostKeyPinError("ssh host key pin was not persisted")
    return pinned


_STORED_PIN_REQUIRED_MESSAGE = (
    "stored confirmed SSH host key pin is required for live connection"
)


def _normalize_management_host(host: str) -> str:
    candidate = host.strip()
    if candidate.lower().startswith("http://"):
        candidate = candidate[7:]
    elif candidate.lower().startswith("https://"):
        candidate = candidate[8:]
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    if candidate.count(":") == 1 and not candidate.startswith("["):
        candidate = candidate.split(":", 1)[0]
    return candidate.strip()


def resolve_identity_router_id_for_host(
    store: PersistenceStore,
    host: str,
) -> str | None:
    """Resolve store-backed router identity from management host when router_id is omitted."""
    from router_control.application.router_discovery import (
        ENROLLMENT_DRAFT_LIFECYCLE,
        ENROLLMENT_DRAFT_MODEL,
    )

    normalized = _normalize_management_host(host)
    if not normalized:
        return None

    matches: list[tuple[tuple[int, int, str, str], str]] = []
    for router_row in store.list_routers(limit=200):
        rid = str(router_row["router_id"])
        endpoint = store.get_primary_endpoint(rid)
        if endpoint is None:
            continue
        ep_host = _normalize_management_host(str(endpoint["host"] or ""))
        if ep_host != normalized:
            continue

        lifecycle = str(router_row["lifecycle_status"])
        model = str(router_row["model"] or "").strip()
        is_genuine = (
            lifecycle == "Enrolled"
            and model != ""
            and model != ENROLLMENT_DRAFT_MODEL
        )
        is_draft = lifecycle == ENROLLMENT_DRAFT_LIFECYCLE and (
            model == "" or model == ENROLLMENT_DRAFT_MODEL
        )
        has_pin = store.get_endpoint_ssh_host_key(rid) is not None
        created_at = str(router_row["created_at"])

        if is_genuine:
            tier = 0
        elif is_draft:
            tier = 2
        else:
            tier = 1

        pin_rank = 0 if has_pin else 1
        sort_key = (tier, pin_rank if tier >= 1 else 0, created_at, rid)
        matches.append((sort_key, rid))

    if not matches:
        return None
    matches.sort(key=lambda item: item[0])
    return matches[0][1]


def resolve_ssh_host_key_sha256(
    *,
    explicit: str | None,
    router_id: str | None,
    store: PersistenceStore,
    host: str | None = None,
) -> str:
    """Resolve SSH host-key pin for live transport.

    Live path trusts only a stored confirmed pin when the store knows the router
    (via router_id or resolvable host). A client-supplied fingerprint may match
    the stored pin (mismatch is refused) but never substitute for its absence.
    When the host is genuinely unknown to the store, explicit fingerprint may be
    used for first-contact bootstrap. Learn/confirm uses learn_candidate /
    confirm_pin directly.
    """
    effective_router_id = router_id
    if not effective_router_id and host and str(host).strip():
        effective_router_id = resolve_identity_router_id_for_host(
            store,
            str(host).strip(),
        )

    if effective_router_id:
        stored_pin = store.get_endpoint_ssh_host_key(effective_router_id)
        if stored_pin is not None:
            stored_fingerprint = stored_pin.fingerprint_sha256
            if explicit is not None and str(explicit).strip():
                normalized_explicit = normalize_sha256_fingerprint(str(explicit))
                if normalized_explicit != stored_fingerprint:
                    raise SshHostKeyMismatch(
                        "SSH host key fingerprint does not match stored confirmed pin"
                    )
            return stored_fingerprint
        if explicit is not None and str(explicit).strip():
            raise SshHostKeyMissing(_STORED_PIN_REQUIRED_MESSAGE)
        raise SshHostKeyMissing(
            "SSH host key SHA256 fingerprint is required (explicit param or stored pin)"
        )

    if explicit is not None and str(explicit).strip():
        return normalize_sha256_fingerprint(str(explicit))
    raise SshHostKeyMissing(
        "SSH host key SHA256 fingerprint is required (explicit param or stored pin)"
    )


__all__ = [
    "LearnCandidateResult",
    "PendingLearnCandidate",
    "PendingLearnMismatch",
    "PendingLearnMissing",
    "PendingLearnRegistry",
    "SshHostKeyPinConflict",
    "SshHostKeyPinError",
    "confirm_pin",
    "learn_candidate",
    "record_pending_learn",
    "resolve_identity_router_id_for_host",
    "resolve_ssh_host_key_sha256",
]
