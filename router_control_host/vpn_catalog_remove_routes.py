"""VPN catalog remove routes — soft-retire profiles with secret-ref release."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.secrets.memory import VaultError
from router_control.application.router_apply_lock import run_with_router_apply_lock
from router_control.persistence.errors import NotFoundError
from router_control.persistence.store import (
    ActivateInProgressError,
    ActiveProfileError,
    AlreadyRetiredError,
    PersistenceStore,
)

from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["vpn-catalog-remove"])

_ACTIVE_REFUSE_MESSAGE = (
    "Этот VPN сейчас подключён. Сначала нажмите «Отключить», "
    "потом уберите профиль из списка."
)
_ACTIVATE_IN_PROGRESS_MESSAGE = (
    "Сейчас идёт подключение этого VPN — подождите и повторите."
)

_T = TypeVar("_T")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VpnCatalogRemoveBody(_StrictModel):
    confirm_catalog_remove: bool = Field(...)


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _sorted_apply_lock_keys(store: PersistenceStore) -> list[str]:
    keys = {str(row["router_id"]) for row in store.list_routers()}
    keys.add("__default__")
    return sorted(keys)


def _run_with_sorted_apply_locks(store: PersistenceStore, fn: Callable[[], _T]) -> _T:
    keys = _sorted_apply_lock_keys(store)

    def acquire(index: int) -> _T:
        if index >= len(keys):
            return fn()
        return run_with_router_apply_lock(keys[index], lambda: acquire(index + 1))

    return acquire(0)


@router.post("/vpn-profiles/{profile_id}/remove")
def remove_vpn_profile_from_catalog(
    profile_id: str,
    request: Request,
    body: VpnCatalogRemoveBody,
) -> JSONResponse:
    if not body.confirm_catalog_remove:
        return error_response(
            request,
            status_code=400,
            code="vpn_catalog.confirm_required",
            message="confirm_catalog_remove must be true to remove profile from catalog",
        )
    host = _state(request)
    store = host.runtime.store
    now = host.runtime.clock.now()

    def _remove_under_lock() -> int:
        ref_ids = store.prepare_vpn_profile_catalog_remove(profile_id, now=now)
        secrets_released = 0
        for ref_id in ref_ids:
            if store.count_credential_ref_profile_links(ref_id) != 1:
                continue
            if store.credential_ref_has_non_vpn_live_links(ref_id):
                continue
            host.runtime.vault.revoke(ref_id)
            store.mark_credential_revoked(ref_id, now=now)
            secrets_released += 1
        store.commit_vpn_profile_catalog_remove(profile_id, now=now)
        return secrets_released

    try:
        secrets_released = _run_with_sorted_apply_locks(store, _remove_under_lock)
    except NotFoundError:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="profile not found",
        )
    except AlreadyRetiredError:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="profile not found",
        )
    except ActivateInProgressError:
        return error_response(
            request,
            status_code=409,
            code="vpn_catalog.activate_in_progress",
            message=_ACTIVATE_IN_PROGRESS_MESSAGE,
        )
    except ActiveProfileError:
        return error_response(
            request,
            status_code=409,
            code="vpn_catalog.active_profile",
            message=_ACTIVE_REFUSE_MESSAGE,
        )
    except VaultError as exc:
        return error_response(
            request,
            status_code=502,
            code="vpn_catalog.secret_revoke_failed",
            message=str(exc),
        )

    return JSONResponse(
        {
            "profile_id": profile_id,
            "removed_from_catalog": True,
            "secrets_released": secrets_released,
        },
        status_code=200,
        headers=_ok_headers(request),
    )
