"""NC-1812 nested-RCI WireGuard peer web-E2E probe — plan-only by default; live gated."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CONTRACT_ID = "nc1812-awg-peer-nested-rci-web-e2e-probe-20260724"

GATE_A_MODEL = "NC-1812"
GATE_A_FIRMWARE = "5.01.C.1.0-0"
GATE_A_TRANSPORT = "ssh_tunnel"
GATE_A_SSH_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"

LAB_HOST = "192.168.2.1"
LAB_SOURCE_ADDRESS = "192.168.2.10"
LAB_USERNAME = "admin"
LAB_CREDENTIAL_REF_ID = "cred_db65665dd59f600bdd23544d85564c83"
DEFAULT_BASE_URL = "http://127.0.0.1:8787"
DEFAULT_SECRETS_ROOT = "data/secrets"
DEFAULT_PEER_PUBLIC_KEY = "Oq6wuNSfv44nSkw3d3zfIqzda3ZZQlogDvY3nCLq/vM="
DEFAULT_PEER_ENDPOINT = "203.0.113.1:51820"
DEFAULT_PEER_ALLOW_IPS = "10.99.99.0 255.255.255.0"
DEFAULT_PEER_KEEPALIVE = 25

BOUNDED_WG_ID_RE = re.compile(r"^Wireguard[5-9]$")

LIVE_STEPS: tuple[str, ...] = (
    "enroll_throwaway_awg_private_key",
    "enroll_throwaway_awg_preshared_key_if_with_psk",
    "mint_hub_admin_cookie",
    "post_wireguard_preview",
    "post_wireguard_apply",
    "post_wireguard_teardown",
    "delete_throwaway_credentials",
)

@dataclass(frozen=True, slots=True)
class ProbeConfig:
    host: str
    source_address: str
    username: str
    router_credential_ref_id: str
    ssh_host_key_sha256: str
    wg_id: str
    base_url: str
    secrets_root: str
    peer_public_key: str
    peer_endpoint: str
    peer_allow_ips: str
    peer_keepalive: int
    with_psk: bool
    artifact_out: str
    confirm_live: bool


def validate_wg_id(wg_id: str) -> str:
    """Validate bounded test interface id; raise ValueError when out of range."""
    candidate = wg_id.strip()
    if not BOUNDED_WG_ID_RE.fullmatch(candidate):
        raise ValueError(
            f"wg_id must match ^Wireguard[5-9]$ (refusing {candidate!r})"
        )
    return candidate


def gate_a_tuple_binding(*, ssh_pin: str = GATE_A_SSH_PIN) -> dict[str, str]:
    return {
        "model": GATE_A_MODEL,
        "firmware_version": GATE_A_FIRMWARE,
        "transport": GATE_A_TRANSPORT,
        "ssh_host_key_fingerprint_sha256": ssh_pin,
    }


def build_intent_payload(config: ProbeConfig, *, credential_placeholders: bool) -> dict[str, Any]:
    """Build wireguard intent fields for preview/apply/teardown bodies."""
    payload: dict[str, Any] = {
        "wg_id": config.wg_id,
        "enabled": True,
        "peer_rci_shape": "nested_rci",
        "peer_public_key": config.peer_public_key,
        "peer_endpoint": config.peer_endpoint,
        "peer_allow_ips": config.peer_allow_ips,
        "peer_keepalive_interval": config.peer_keepalive,
    }
    if credential_placeholders:
        payload["private_key_credential_ref_id"] = "<throwaway-enrolled-at-live>"
        if config.with_psk:
            payload["preshared_key_credential_ref_id"] = "<throwaway-enrolled-at-live>"
    return payload


def build_apply_body(config: ProbeConfig, *, credential_placeholders: bool) -> dict[str, Any]:
    body = build_intent_payload(config, credential_placeholders=credential_placeholders)
    body["confirm_live_apply"] = True
    body["host"] = config.host
    body["username"] = config.username
    body["router_credential_ref_id"] = config.router_credential_ref_id
    body["ssh_host_key_sha256"] = config.ssh_host_key_sha256
    body["source_address"] = config.source_address
    return body


def build_teardown_body(config: ProbeConfig, *, credential_placeholders: bool) -> dict[str, Any]:
    body = build_intent_payload(config, credential_placeholders=credential_placeholders)
    body["confirm_live_teardown"] = True
    body["host"] = config.host
    body["username"] = config.username
    body["router_credential_ref_id"] = config.router_credential_ref_id
    body["ssh_host_key_sha256"] = config.ssh_host_key_sha256
    body["source_address"] = config.source_address
    return body


def build_plan(config: ProbeConfig) -> dict[str, Any]:
    """Pure plan payload for plan-only mode (no vault, no network)."""
    return {
        "contract_id": CONTRACT_ID,
        "campaign": "awg-peer-nested-rci-web-e2e-live-verify",
        "mode": "plan-only",
        "confirm_live": False,
        "mutation_allowed": False,
        "write_shapes_registered": False,
        "system_configuration_saved": False,
        "identity_tuple": gate_a_tuple_binding(ssh_pin=config.ssh_host_key_sha256),
        "connection": {
            "host": config.host,
            "username": config.username,
            "router_credential_ref_id": config.router_credential_ref_id,
            "source_address": config.source_address,
        },
        "bounded_test_interface": config.wg_id,
        "peer_rci_shape": "nested_rci",
        "peer_public_key": config.peer_public_key,
        "peer_endpoint": config.peer_endpoint,
        "peer_allow_ips": config.peer_allow_ips,
        "peer_keepalive_interval": config.peer_keepalive,
        "with_psk": config.with_psk,
        "base_url": config.base_url,
        "artifact_out": config.artifact_out,
        "steps_would_run": list(LIVE_STEPS),
        "preview_intent": build_intent_payload(config, credential_placeholders=True),
        "apply_body_shape": build_apply_body(config, credential_placeholders=True),
        "teardown_body_shape": build_teardown_body(config, credential_placeholders=True),
        "bounds": {
            "wg_id_pattern": "^Wireguard[5-9]$",
            "requires_confirm_live_flag": True,
            "no_system_configuration_save": True,
            "secrets_in_memory_only": True,
        },
    }


def default_artifact_out(host: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return f"data/artifacts/awg-peer-nested-rci-live-verify-{host}-{stamp}.json"


def _generate_throwaway_wg_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def _host_header_from_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"base_url must include scheme and host: {base_url!r}")
    return parsed.netloc


def _http_headers(base_url: str) -> dict[str, str]:
    return {
        "Host": _host_header_from_base_url(base_url),
        "Origin": base_url.rstrip("/"),
        "Referer": f"{base_url.rstrip('/')}/",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _post_json(
    *,
    base_url: str,
    path: str,
    body: dict[str, Any],
    cookie: str,
) -> tuple[int, dict[str, Any] | list[Any] | str]:
    import httpx

    url = f"{base_url.rstrip('/')}{path}"
    with httpx.Client(timeout=120.0) as client:
        response = client.post(
            url,
            json=body,
            cookies={"hub_admin": cookie},
            headers=_http_headers(base_url),
        )
    try:
        payload: dict[str, Any] | list[Any] | str = response.json()
    except json.JSONDecodeError:
        payload = response.text
    return response.status_code, payload


def _assert_evidence_has_no_in_memory_secrets(
    evidence: dict[str, Any],
    *,
    forbidden_substrings: frozenset[str],
) -> None:
    """Reject evidence if serialized form contains in-memory throwaway secret values."""
    serialized = json.dumps(evidence, sort_keys=True)
    for fragment in forbidden_substrings:
        if fragment and fragment in serialized:
            raise RuntimeError("evidence would leak in-memory throwaway secret material")


def _safe_error_message(exc: BaseException) -> str:
    return f"{exc.__class__.__name__}: operation failed"


def _delete_credential(vault: Any, ref_id: str | None) -> bool:
    if not ref_id:
        return True
    try:
        vault.delete(ref_id)
    except Exception:
        return False
    return True


def run_live_sequence(config: ProbeConfig) -> int:
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault
    from router_control_host.auth import mint_hub_admin_cookie

    pk_plain: str | None = None
    psk_plain: str | None = None
    pk_ref: str | None = None
    psk_ref: str | None = None
    vault: WindowsDpapiVault | None = None

    preview_status: int | None = None
    apply_status: int | None = None
    teardown_status: int | None = None
    preview_body: dict[str, Any] | list[Any] | str | None = None
    apply_body: dict[str, Any] | list[Any] | str | None = None
    teardown_body: dict[str, Any] | list[Any] | str | None = None
    pk_deleted = False
    psk_deleted = False
    findings: list[str] = []
    exit_code = 0

    try:
        pk_plain = _generate_throwaway_wg_key()
        if config.with_psk:
            psk_plain = _generate_throwaway_wg_key()

        vault = WindowsDpapiVault(root=Path(config.secrets_root))
        pk_ref = vault.create(kind="awg_private_key", secret=pk_plain).credential_ref_id
        if config.with_psk:
            assert psk_plain is not None
            psk_ref = vault.create(kind="awg_preshared_key", secret=psk_plain).credential_ref_id

        cookie = mint_hub_admin_cookie()

        intent = build_intent_payload(config, credential_placeholders=False)
        intent["private_key_credential_ref_id"] = pk_ref
        if config.with_psk and psk_ref is not None:
            intent["preshared_key_credential_ref_id"] = psk_ref

        preview_status, preview_body = _post_json(
            base_url=config.base_url,
            path="/api/router-control/v1/wireguard/preview",
            body=intent,
            cookie=cookie,
        )

        apply_payload = dict(intent)
        apply_payload.update(
            {
                "confirm_live_apply": True,
                "host": config.host,
                "username": config.username,
                "router_credential_ref_id": config.router_credential_ref_id,
                "ssh_host_key_sha256": config.ssh_host_key_sha256,
                "source_address": config.source_address,
            }
        )
        apply_status, apply_body = _post_json(
            base_url=config.base_url,
            path="/api/router-control/v1/wireguard/apply",
            body=apply_payload,
            cookie=cookie,
        )

        teardown_payload = dict(intent)
        teardown_payload.update(
            {
                "confirm_live_teardown": True,
                "host": config.host,
                "username": config.username,
                "router_credential_ref_id": config.router_credential_ref_id,
                "ssh_host_key_sha256": config.ssh_host_key_sha256,
                "source_address": config.source_address,
            }
        )
        teardown_status, teardown_body = _post_json(
            base_url=config.base_url,
            path="/api/router-control/v1/wireguard/teardown",
            body=teardown_payload,
            cookie=cookie,
        )

        if preview_status != 200:
            findings.append(f"preview_http_status={preview_status}")
            exit_code = 1
        if apply_status != 200:
            findings.append(f"apply_http_status={apply_status}")
            exit_code = 1
        if teardown_status != 200:
            findings.append(f"teardown_http_status={teardown_status}")
            exit_code = 1

        if isinstance(apply_body, dict):
            overall = apply_body.get("overall")
            if overall != "applied":
                findings.append(f"apply_overall={overall!r}")
                exit_code = 1
        if isinstance(teardown_body, dict):
            overall = teardown_body.get("overall")
            if overall != "applied":
                findings.append(f"teardown_overall={overall!r}")
                exit_code = 1

    except Exception as exc:
        print(_safe_error_message(exc), file=sys.stderr)
        findings.append(_safe_error_message(exc))
        exit_code = 1
    finally:
        if vault is not None:
            pk_deleted = _delete_credential(vault, pk_ref)
            psk_deleted = _delete_credential(vault, psk_ref)

        forbidden = frozenset(
            value
            for value in (pk_plain, psk_plain)
            if isinstance(value, str) and value
        )
        evidence: dict[str, Any] = {
            "contract_id": CONTRACT_ID,
            "campaign": "awg-peer-nested-rci-web-e2e-live-verify",
            "mode": "live",
            "confirm_live": True,
            "identity_tuple": gate_a_tuple_binding(ssh_pin=config.ssh_host_key_sha256),
            "connection": {
                "host": config.host,
                "username": config.username,
                "router_credential_ref_id": config.router_credential_ref_id,
                "source_address": config.source_address,
            },
            "bounded_test_interface": config.wg_id,
            "peer_rci_shape": "nested_rci",
            "peer_public_key": config.peer_public_key,
            "peer_endpoint": config.peer_endpoint,
            "peer_allow_ips": config.peer_allow_ips,
            "peer_keepalive_interval": config.peer_keepalive,
            "with_psk": config.with_psk,
            "preview_http_status": preview_status,
            "apply_http_status": apply_status,
            "teardown_http_status": teardown_status,
            "preview": preview_body,
            "apply": apply_body,
            "teardown": teardown_body,
            "system_configuration_saved": False,
            "throwaway_credentials_deleted": {
                "awg_private_key_ref_deleted": pk_deleted,
                **(
                    {"awg_preshared_key_ref_deleted": psk_deleted}
                    if config.with_psk
                    else {}
                ),
            },
            "findings": findings,
            "summary": (
                "nested_rci peer web-E2E live verify completed"
                if not findings
                else "nested_rci peer web-E2E live verify completed with findings"
            ),
        }
        try:
            _assert_evidence_has_no_in_memory_secrets(evidence, forbidden_substrings=forbidden)
        except RuntimeError as exc:
            print(_safe_error_message(exc), file=sys.stderr)
            exit_code = 1
        else:
            artifact_path = Path(config.artifact_out)
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            artifact_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

        pk_plain = None
        psk_plain = None

    return exit_code


def config_from_args(args: argparse.Namespace) -> ProbeConfig:
    artifact_out = args.artifact_out.strip() or default_artifact_out(args.host)
    return ProbeConfig(
        host=args.host.strip(),
        source_address=args.source_address.strip(),
        username=args.username.strip(),
        router_credential_ref_id=args.router_credential_ref.strip(),
        ssh_host_key_sha256=args.ssh_host_key_sha256.strip(),
        wg_id=validate_wg_id(args.wg_id),
        base_url=args.base_url.strip(),
        secrets_root=args.secrets_root.strip(),
        peer_public_key=args.peer_public_key.strip(),
        peer_endpoint=args.peer_endpoint.strip(),
        peer_allow_ips=args.peer_allow_ips.strip(),
        peer_keepalive=int(args.peer_keepalive),
        with_psk=bool(args.with_psk),
        artifact_out=artifact_out,
        confirm_live=bool(args.confirm_live),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bounded web-E2E probe for nested_rci WireGuard peer transport "
            "(plan-only by default; --confirm-live required for vault/network)."
        )
    )
    parser.add_argument("--host", default=LAB_HOST, help="Router management SSH host")
    parser.add_argument(
        "--source-address",
        default=LAB_SOURCE_ADDRESS,
        help="Literal private local IPv4/IPv6 bind for live SSH",
    )
    parser.add_argument("--username", default=LAB_USERNAME, help="RCI auth username")
    parser.add_argument(
        "--router-credential-ref",
        default=LAB_CREDENTIAL_REF_ID,
        help="DPAPI router credential ref id (not password)",
    )
    parser.add_argument(
        "--ssh-host-key-sha256",
        default=GATE_A_SSH_PIN,
        help="Pinned SSH host key SHA256 fingerprint",
    )
    parser.add_argument(
        "--wg-id",
        default="Wireguard5",
        help="Bounded throwaway interface id (Wireguard5–9 only)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="router_control_host base URL",
    )
    parser.add_argument(
        "--secrets-root",
        default=DEFAULT_SECRETS_ROOT,
        help="DPAPI vault root (live only)",
    )
    parser.add_argument(
        "--peer-public-key",
        default=DEFAULT_PEER_PUBLIC_KEY,
        help="Non-secret test peer public key",
    )
    parser.add_argument(
        "--peer-endpoint",
        default=DEFAULT_PEER_ENDPOINT,
        help="Non-secret peer endpoint host:port",
    )
    parser.add_argument(
        "--peer-allow-ips",
        default=DEFAULT_PEER_ALLOW_IPS,
        help="Non-secret peer allow-ips (address mask)",
    )
    parser.add_argument(
        "--peer-keepalive",
        type=int,
        default=DEFAULT_PEER_KEEPALIVE,
        help="Peer keepalive interval seconds (3..3600)",
    )
    parser.add_argument(
        "--with-psk",
        action="store_true",
        help="Also enroll throwaway preshared-key credential ref",
    )
    parser.add_argument(
        "--artifact-out",
        default="",
        help="Sanitized live evidence JSON path",
    )
    parser.add_argument(
        "--confirm-live",
        action="store_true",
        help="Perform vault enroll + web preview/apply/teardown (requires T4 gate)",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        config = config_from_args(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not config.confirm_live:
        plan = build_plan(config)
        print(json.dumps(plan, indent=2))
        return 0

    return run_live_sequence(config)


if __name__ == "__main__":
    raise SystemExit(main())
