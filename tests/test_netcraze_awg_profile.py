"""AmneziaWG profile parser tests — local only, mock vault."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.awg_profile import (
    AWG2X_ASC_COMPILE_MESSAGE,
    DUALSTACK_IPV6_OPERATOR_NOTE,
    AwgProfileError,
    awg2x_asc_compile_error,
    parse_awg_profile_path,
    parse_awg_profile_text,
    require_asc9_args_for_compile,
)
from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.wireguard_apply_planner import compile_wireguard_intent_to_ops
from router_control.domain.network_intents import WireguardIntent

REAL_ASC9_VALUES = (4, 10, 50, 130, 69, 149835824, 1778159739, 1704282148, 748462068)
REAL_ASC9_STRING = " ".join(str(value) for value in REAL_ASC9_VALUES)

SAMPLE_PROFILE = """
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 10
Jmax = 50
S1 = 130
S2 = 69
H1 = 149835824
H2 = 1778159739
H3 = 1704282148
H4 = 748462068

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
PresharedKey = EXAMPLE_PSK_PLACEHOLDER_CCCCCCCCCCCCCCCCCCCCCCCCCCCC
Endpoint = EXAMPLE_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

SECRET_SENTINELS = (
    "EXAMPLE_PRIVATE_KEY_PLACEHOLDER",
    "EXAMPLE_PUBLIC_KEY_PLACEHOLDER",
    "EXAMPLE_PSK_PLACEHOLDER",
    "EXAMPLE_ENDPOINT",
)


@pytest.fixture
def vault() -> MemoryVault:
    return MemoryVault()


def test_parse_accepts_enumerated_fields(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    assert "PrivateKey" in parsed.interface_field_names
    assert parsed.interface_address_present is True
    assert "Jc" in parsed.awg_param_names
    assert parsed.endpoint_configured is True
    assert len(parsed.credential_refs) == 2
    roles = {ref.role for ref in parsed.credential_refs}
    assert roles == {"PrivateKey", "PresharedKey"}
    assert parsed.asc9_args == REAL_ASC9_VALUES
    assert parsed.peer_keepalive_interval == 25


def test_asc9_args_in_sanitized_dict_without_secrets(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    sanitized = parsed.sanitized_dict()
    assert sanitized["asc9_args"] == list(REAL_ASC9_VALUES)
    assert "peer_public_key" not in sanitized
    assert "peer_endpoint" not in sanitized
    assert "peer_allow_ips" not in sanitized
    artifact = json.dumps(sanitized)
    for sentinel in ("EXAMPLE_PRIVATE_KEY_PLACEHOLDER", "EXAMPLE_PSK_PLACEHOLDER"):
        assert sentinel not in artifact
    assert "EXAMPLE_ENDPOINT" not in artifact


def test_sanitized_dict_for_apply_includes_peer_routing_fields(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    apply_payload = parsed.sanitized_dict_for_apply()
    assert (
        apply_payload["peer_public_key"]
        == "EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    assert apply_payload["peer_endpoint"] == "EXAMPLE_ENDPOINT:51820"
    assert apply_payload["peer_allow_ips"] == "0.0.0.0/0"
    assert apply_payload["peer_keepalive_interval"] == 25
    evidence_payload = parsed.sanitized_dict()
    assert "peer_endpoint" not in evidence_payload


AWG_15_INTERFACE_FIELDS = ("S3", "S4", "I1", "I2", "I3", "I4", "I5")

AWG_15_PROFILE = """
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
S3 = 90
S4 = 90
I1 = 1111111111
I2 = 2222222222
I3 = 3333333333
I4 = 4444444444
I5 = 5555555555
H1 = 1234567890
H2 = 1234567890
H3 = 1234567890
H4 = 1234567890

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
PresharedKey = EXAMPLE_PSK_PLACEHOLDER_CCCCCCCCCCCCCCCCCCCCCCCCCCCC
Endpoint = EXAMPLE_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0
"""


def test_parse_accepts_awg_15_interface_fields(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(AWG_15_PROFILE, vault=vault)
    for name in AWG_15_INTERFACE_FIELDS:
        assert name in parsed.interface_field_names
        assert name in parsed.awg_param_names
    assert parsed.asc9_args is None
    sanitized = parsed.sanitized_dict()
    assert "asc9_args" not in sanitized
    artifact = json.dumps(sanitized)
    for name in AWG_15_INTERFACE_FIELDS:
        assert f'"{name}"' in artifact
    value_scan = json.dumps(
        {
            **sanitized,
            "credential_refs": [
                {**ref, "credential_ref_id": ""}
                for ref in sanitized["credential_refs"]
            ],
        }
    )
    for sentinel in ("90", "1111111111", "2222222222", "3333333333", "4444444444", "5555555555"):
        assert sentinel not in value_scan
    for sentinel in ("EXAMPLE_PRIVATE_KEY_PLACEHOLDER", "EXAMPLE_PSK_PLACEHOLDER"):
        assert sentinel not in artifact
    assert "peer_public_key" not in sanitized
    assert "peer_endpoint" not in sanitized
    apply_payload = parsed.sanitized_dict_for_apply()
    assert (
        apply_payload["peer_public_key"]
        == "EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    assert apply_payload["peer_endpoint"] == "EXAMPLE_ENDPOINT:51820"


def test_awg2x_compile_rejected_with_clear_message(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(AWG_15_PROFILE, vault=vault)
    assert awg2x_asc_compile_error() == AWG2X_ASC_COMPILE_MESSAGE
    with pytest.raises(AwgProfileError, match="AmneziaWG 2.x"):
        require_asc9_args_for_compile(parsed)


def test_profile_asc9_e2e_planner_sealed_ops(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    asc9 = require_asc9_args_for_compile(parsed)
    private_ref = next(
        ref.credential_ref_id for ref in parsed.credential_refs if ref.role == "PrivateKey"
    )
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=asc9,
        private_key_credential_ref_id=private_ref,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    asc_op = next(
        op for op in plan.apply_ops if op.operation == WireguardRciOperation.SET_ASC.value
    )
    assert asc_op.asc_args == REAL_ASC9_STRING
    serialized = json.dumps(
        {
            "apply_ops": [
                {
                    "operation": op.operation,
                    "asc_args": op.asc_args,
                    "credential_ref_id": op.credential_ref_id,
                }
                for op in plan.apply_ops
            ]
        }
    )
    assert "EXAMPLE_PRIVATE_KEY" not in serialized
    assert "EXAMPLE_PSK" not in serialized


def test_rejects_unknown_field(vault: MemoryVault) -> None:
    bad = SAMPLE_PROFILE.replace(
        "Jc = 4",
        "Jc = 4\nUnknownField = value",
    )
    with pytest.raises(AwgProfileError, match="unknown"):
        parse_awg_profile_text(bad, vault=vault)


def test_rejects_multiple_peers(vault: MemoryVault) -> None:
    extra_peer = (
        "\n[Peer]\n"
        "PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
        "Endpoint = EXAMPLE_ENDPOINT:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )
    bad = SAMPLE_PROFILE + extra_peer
    with pytest.raises(AwgProfileError, match="exactly one"):
        parse_awg_profile_text(bad, vault=vault)


def test_rejects_missing_required_peer_endpoint(vault: MemoryVault) -> None:
    text = """
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
AllowedIPs = 0.0.0.0/0
"""
    with pytest.raises(AwgProfileError, match="Endpoint"):
        parse_awg_profile_text(text, vault=vault)


def test_sanitized_artifact_has_no_secrets(vault: MemoryVault, tmp_path: Path) -> None:
    profile_path = tmp_path / "sample.conf"
    profile_path.write_text(SAMPLE_PROFILE, encoding="utf-8")
    parsed = parse_awg_profile_path(profile_path, vault=vault)
    sanitized = parsed.sanitized_dict()
    artifact = json.dumps(sanitized)
    for sentinel in ("EXAMPLE_PRIVATE_KEY_PLACEHOLDER", "EXAMPLE_PSK_PLACEHOLDER"):
        assert sentinel not in artifact
    assert "EXAMPLE_ENDPOINT" not in artifact
    assert "peer_public_key" not in sanitized
    assert "peer_endpoint" not in sanitized
    assert "peer_allow_ips" not in sanitized


def test_dpapi_refs_only_roles(vault: MemoryVault) -> None:
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    sanitized = parsed.sanitized_dict()
    for ref in sanitized["credential_refs"]:
        assert "role" in ref
        assert ref["role"] in {"PrivateKey", "PresharedKey"}
        assert ref["credential_ref_id"].startswith("cred_")


def _minimal_profile(
    *,
    address: str = "10.0.0.2/32",
    endpoint: str = "EXAMPLE_ENDPOINT:51820",
) -> str:
    return f"""
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = {address}
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
PresharedKey = EXAMPLE_PSK_PLACEHOLDER_CCCCCCCCCCCCCCCCCCCCCCCCCCCC
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0
"""


def test_distinct_profile_contents_produce_distinct_digests(vault: MemoryVault) -> None:
    profiles = [
        _minimal_profile(address="10.0.0.2/32"),
        _minimal_profile(address="10.0.0.3/32"),
        _minimal_profile(address="10.0.0.4/32", endpoint="EXAMPLE_ENDPOINT:51821"),
    ]
    parsed = [parse_awg_profile_text(text, vault=vault) for text in profiles]
    digests = {item.profile_digest for item in parsed}
    assert len(digests) == 3
    for text, item in zip(profiles, parsed, strict=True):
        expected = f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"
        assert item.profile_digest == expected


def test_rejects_duplicate_interface_field(vault: MemoryVault) -> None:
    text = _minimal_profile().replace(
        "Address = 10.0.0.2/32",
        "Address = 10.0.0.2/32\nAddress = 10.0.0.3/32",
    )
    with pytest.raises(AwgProfileError, match="duplicate interface field"):
        parse_awg_profile_text(text, vault=vault)


def test_rejects_duplicate_interface_section(vault: MemoryVault) -> None:
    text = _minimal_profile() + "\n[Interface]\nDNS = 1.1.1.1\n"
    with pytest.raises(AwgProfileError, match="duplicate \\[Interface\\] section"):
        parse_awg_profile_text(text, vault=vault)


class FailingPskVault(MemoryVault):
    def create(self, *, kind: str, secret: str):
        if kind == "awg_preshared_key":
            raise RuntimeError("simulated PSK vault failure")
        return super().create(kind=kind, secret=secret)


def test_psk_create_failure_cleans_private_key_orphan() -> None:
    vault = FailingPskVault()
    with pytest.raises(RuntimeError, match="PSK"):
        parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    assert not vault._secrets
    assert not vault._kinds


def test_profile_dual_stack_allowed_ips_success(vault: MemoryVault) -> None:
    profile = SAMPLE_PROFILE.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0")
    parsed = parse_awg_profile_text(profile, vault=vault)
    assert parsed.peer_allow_ips == "0.0.0.0/0"
    assert parsed.unsupported_fields == ("AllowedIPs",)
    assert parsed.operator_notes == (DUALSTACK_IPV6_OPERATOR_NOTE,)
    apply_payload = parsed.sanitized_dict_for_apply()
    assert apply_payload["peer_allow_ips"] == "0.0.0.0/0"
    assert "unsupported_fields" in apply_payload
    assert "operator_notes" in apply_payload
    assert "::/0" not in json.dumps(apply_payload)


def test_profile_ipv6_only_allowed_ips_refused(vault: MemoryVault) -> None:
    profile = SAMPLE_PROFILE.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0")
    with pytest.raises(AwgProfileError, match="no usable IPv4"):
        parse_awg_profile_text(profile, vault=vault)


def test_profile_multi_ipv4_allowed_ips_order_preserved(vault: MemoryVault) -> None:
    profile = SAMPLE_PROFILE.replace(
        "AllowedIPs = 0.0.0.0/0",
        "AllowedIPs = 10.0.0.0/8, 192.168.1.0/24, ::/0",
    )
    parsed = parse_awg_profile_text(profile, vault=vault)
    assert parsed.peer_allow_ips == "10.0.0.0/8, 192.168.1.0/24"
    assert parsed.unsupported_fields == ("AllowedIPs",)
    assert "::/0" not in parsed.sanitized_dict_for_apply()["peer_allow_ips"]


@pytest.mark.parametrize(
    ("keepalive_value",),
    [
        ("0",),
        ("2",),
        ("3601",),
        ("abc",),
    ],
)
def test_rejects_invalid_persistent_keepalive(
    vault: MemoryVault, keepalive_value: str
) -> None:
    profile = SAMPLE_PROFILE.replace(
        "PersistentKeepalive = 25",
        f"PersistentKeepalive = {keepalive_value}",
    )
    with pytest.raises(AwgProfileError, match="PersistentKeepalive"):
        parse_awg_profile_text(profile, vault=vault)


def test_omits_peer_keepalive_when_key_absent(vault: MemoryVault) -> None:
    profile = SAMPLE_PROFILE.replace("PersistentKeepalive = 25\n", "")
    parsed = parse_awg_profile_text(profile, vault=vault)
    assert parsed.peer_keepalive_interval is None
    assert "peer_keepalive_interval" not in parsed.sanitized_dict_for_apply()
