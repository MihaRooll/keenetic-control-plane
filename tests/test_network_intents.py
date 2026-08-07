"""Network intent validation and canonical digest tests."""

from __future__ import annotations

import copy

import pytest
from router_control.domain.event_preset import build_safe_default_document, validate_document
from router_control.domain.network_intents import (
    CaptivePortalMode,
    IntentValidationError,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
    canonical_digest,
    parse_event_preset_document,
    validate_zone_invariants,
    validation_blocking,
)


def test_safe_default_valid_offline() -> None:
    doc = build_safe_default_document()
    status, findings = validate_document(doc)
    assert status.value == "ValidOffline"
    assert not validation_blocking(findings)


def test_canonical_digest_stable_excludes_timestamps() -> None:
    doc = build_safe_default_document()
    d1 = doc.to_canonical()
    d2 = copy.deepcopy(d1)
    assert canonical_digest(d1) == canonical_digest(d2)
    assert doc.canonical_digest.startswith("sha256:")


def test_unknown_top_level_field_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["mystery_field"] = True
    with pytest.raises(IntentValidationError, match="unrecognized field"):
        parse_event_preset_document(doc)


def test_duplicate_zone_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["zones"] = [doc["zones"][0], doc["zones"][0], doc["zones"][2], doc["zones"][3]]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert validation_blocking(findings)


def test_subnet_overlap_detected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["zones"][0]["ipv4_cidr"] = "10.10.20.0/24"
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "subnet_overlap" for f in findings)


def test_vlan_overlap_detected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["zones"][1]["vlan_id"] = doc["zones"][0]["vlan_id"]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "vlan_overlap" for f in findings)


def test_management_outside_admin_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["zones"][1]["management_allowed"] = True
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "management_outside_admin" for f in findings)


def test_guest_wifi_requires_order_page() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["wifi"]["enabled"] = True
    guest["wifi"]["credential_ref_id"] = "credref:guest"
    guest["firewall"]["rules"] = [
        {"action": "Deny", "destination_family": "OrderPage", "ordinal": 0},
    ]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "guest_wifi_without_order_page" for f in findings)


def test_guest_internet_allow_rejected_even_with_order_page() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["firewall"]["rules"] = [
        {"action": "Allow", "destination_family": "OrderPage", "ordinal": 0},
        {"action": "Allow", "destination_family": "Internet", "ordinal": 1},
    ]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "guest_not_order_page_only" for f in findings)


def test_dhcp_pool_special_address_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["dhcp"]["pool_start"] = "10.10.10.1"
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "dhcp_pool_special_address" for f in findings)


def test_reservation_outside_subnet_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["dhcp"]["reservations"] = [
        {"mac_address": "aa:bb:cc:dd:ee:01", "ipv4_address": "10.10.99.50"},
    ]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "reservation_outside_subnet" for f in findings)


def test_reservation_outside_pool_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["dhcp"]["reservations"] = [
        {"mac_address": "aa:bb:cc:dd:ee:01", "ipv4_address": "10.10.10.10"},
    ]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "reservation_outside_pool" for f in findings)


def test_duplicate_reservation_ip_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["dhcp"]["reservations"] = [
        {"mac_address": "aa:bb:cc:dd:ee:01", "ipv4_address": "10.10.10.60"},
        {"mac_address": "aa:bb:cc:dd:ee:02", "ipv4_address": "10.10.10.60"},
    ]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "reservation_duplicate_ip" for f in findings)


def test_duplicate_reservation_mac_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["dhcp"]["reservations"] = [
        {"mac_address": "aa:bb:cc:dd:ee:01", "ipv4_address": "10.10.10.60"},
        {"mac_address": "aa:bb:cc:dd:ee:01", "ipv4_address": "10.10.10.61"},
    ]
    parsed = parse_event_preset_document(doc)
    findings = validate_zone_invariants(parsed)
    assert any(f.code == "reservation_duplicate_mac" for f in findings)


def test_plaintext_passphrase_key_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    staff = next(z for z in doc["zones"] if z["zone_id"] == "Staff")
    staff["wifi"]["passphrase"] = "secret"
    with pytest.raises(IntentValidationError, match="secret-shaped"):
        parse_event_preset_document(doc)


def test_credential_ref_only_wifi() -> None:
    doc = build_safe_default_document().to_canonical()
    promo = next(z for z in doc["zones"] if z["zone_id"] == "Promo")
    assert promo["wifi"]["credential_ref_id"].startswith("credref:")
    assert "passphrase" not in promo["wifi"]


def test_ipv6_posture_required() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["zones"][0].pop("ipv6_posture")
    with pytest.raises(IntentValidationError):
        parse_event_preset_document(doc)


def test_parse_keyerror_maps_to_missing_field() -> None:
    doc = build_safe_default_document().to_canonical()
    doc.pop("name")
    with pytest.raises(IntentValidationError) as exc_info:
        parse_event_preset_document(doc)
    assert exc_info.value.code == "missing_field"


def test_parse_valueerror_maps_to_invalid_value() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"]["mode"] = "NotARealMode"
    with pytest.raises(IntentValidationError) as exc_info:
        parse_event_preset_document(doc)
    assert exc_info.value.code == "invalid_value"


def test_dns_fqdn_normalized() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["zones"][0]["dns"]["local_fqdn"] = "Guest.Booth.Local."
    parsed = parse_event_preset_document(doc)
    guest = next(z for z in parsed.zones if z.zone_id.value == "Guest")
    assert guest.dns.local_fqdn == "guest.booth.local"


def test_wifi_intent_defaults_back_compat() -> None:
    intent = WifiIntent(
        ssid="Guest",
        enabled=False,
        credential_ref_id=None,
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=True,
    )
    assert intent.wpa_mode == WifiWpaMode.WPA2
    assert intent.band == WifiBand.BAND_2_4GHZ
    canonical = intent.to_canonical()
    assert canonical["wpa_mode"] == "WPA2"
    assert canonical["band"] == "BAND_2_4GHZ"


def test_parse_wifi_rejects_omitted_wpa_mode_band_or_guest_isolation() -> None:
    doc = build_safe_default_document().to_canonical()
    for field in ("wpa_mode", "band", "guest_isolation"):
        broken = copy.deepcopy(doc)
        zone = next(z for z in broken["zones"] if z["zone_id"] == "Staff")
        zone["wifi"].pop(field)
        with pytest.raises(IntentValidationError, match=f"{field}"):
            parse_event_preset_document(broken)


def test_parse_wifi_wpa_mode_and_band() -> None:
    doc = build_safe_default_document().to_canonical()
    staff = next(z for z in doc["zones"] if z["zone_id"] == "Staff")
    staff["wifi"]["wpa_mode"] = "WPA2"
    staff["wifi"]["band"] = "BAND_5GHZ"
    parsed = parse_event_preset_document(doc)
    staff_zone = next(z for z in parsed.zones if z.zone_id.value == "Staff")
    assert staff_zone.wifi is not None
    assert staff_zone.wifi.wpa_mode.value == "WPA2"
    assert staff_zone.wifi.band.value == "BAND_5GHZ"


def test_parse_wifi_invalid_wpa_mode_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    staff = next(z for z in doc["zones"] if z["zone_id"] == "Staff")
    staff["wifi"]["wpa_mode"] = "WPA4"
    with pytest.raises(IntentValidationError, match="invalid wpa_mode"):
        parse_event_preset_document(doc)


def test_parse_wifi_invalid_band_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    promo = next(z for z in doc["zones"] if z["zone_id"] == "Promo")
    promo["wifi"]["band"] = "BAND_6GHZ"
    with pytest.raises(IntentValidationError, match="invalid band"):
        parse_event_preset_document(doc)


def test_parse_wifi_unknown_field_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    promo = next(z for z in doc["zones"] if z["zone_id"] == "Promo")
    promo["wifi"]["encryption"] = "wpa2"
    with pytest.raises(IntentValidationError, match="unrecognized field"):
        parse_event_preset_document(doc)


def test_parse_wifi_plaintext_psk_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    staff = next(z for z in doc["zones"] if z["zone_id"] == "Staff")
    staff["wifi"]["psk"] = "secret12345"
    with pytest.raises(IntentValidationError, match="secret-shaped"):
        parse_event_preset_document(doc)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("zones", ["Guest"]),
        ("uplink", "Ethernet"),
        ("rack_assets", [1]),
    ],
)
def test_parse_event_preset_rejects_malformed_nested_shapes(
    field: str, value: object
) -> None:
    doc = build_safe_default_document().to_canonical()
    doc[field] = value
    with pytest.raises(IntentValidationError) as exc_info:
        parse_event_preset_document(doc)
    assert exc_info.value.code == "invalid_shape"


_ASC_9 = [5, 42, 54, 0, 0, 1, 2, 3, 4]
_ASC_16 = [5, 42, 54, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0]


def test_parse_wireguard_enabled_required() -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="enabled"):
        parse_network_intent("wireguard", {"wg_id": "Wireguard5", "asc_args": _ASC_9})


def test_parse_wireguard_intent_ok() -> None:
    from router_control.domain.network_intents import WireguardIntent, parse_network_intent

    intent = parse_network_intent(
        "wireguard",
        {"wg_id": "Wireguard5", "enabled": True, "asc_args": _ASC_9},
    )
    assert isinstance(intent, WireguardIntent)
    assert intent.wg_id == "Wireguard5"
    assert intent.asc_args == tuple(_ASC_9)


def test_parse_wireguard_awg_kind_alias() -> None:
    from router_control.domain.network_intents import parse_network_intent

    intent = parse_network_intent("awg", {"wg_id": "Wireguard9", "enabled": False})
    assert intent.wg_id == "Wireguard9"
    assert intent.enabled is False


@pytest.mark.parametrize("wg_id", ["Wireguard0", "Wireguard4", "Wireguard10"])
def test_parse_wireguard_rejects_non_test_interfaces(wg_id: str) -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="Wireguard5"):
        parse_network_intent("wireguard", {"wg_id": wg_id, "enabled": True})


@pytest.mark.parametrize(
    "secret_key",
    [
        "private-key",
        "private_key",
        "preshared-key",
        "preshared_key",
        "psk",
    ],
)
def test_parse_wireguard_rejects_raw_secret_shaped_keys(secret_key: str) -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="secret-shaped"):
        parse_network_intent(
            "wireguard",
            {"wg_id": "Wireguard5", "enabled": True, secret_key: "x"},
        )


def test_parse_wireguard_accepts_credential_refs_and_peer_fields() -> None:
    from router_control.domain.network_intents import WireguardIntent, parse_network_intent

    intent = parse_network_intent(
        "wireguard",
        {
            "wg_id": "Wireguard5",
            "enabled": True,
            "private_key_credential_ref_id": "credref:awg-private",
            "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "peer_endpoint": "vpn.example.com:51820",
            "peer_allow_ips": "10.0.0.0/24",
            "peer_keepalive_interval": 25,
        },
    )
    assert isinstance(intent, WireguardIntent)
    assert intent.private_key_credential_ref_id == "credref:awg-private"
    assert intent.peer_public_key is not None
    assert intent.peer_endpoint == "vpn.example.com:51820"


def test_parse_wireguard_peer_fields_require_private_key_ref() -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="private_key_credential_ref_id"):
        parse_network_intent(
            "wireguard",
            {
                "wg_id": "Wireguard5",
                "enabled": True,
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            },
        )


def test_parse_wireguard_peer_rci_shape_defaults_nested_rci() -> None:
    from router_control.domain.network_intents import WireguardPeerRciShape, parse_network_intent

    intent = parse_network_intent(
        "wireguard",
        {
            "wg_id": "Wireguard5",
            "enabled": True,
            "private_key_credential_ref_id": "credref:awg-private",
            "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        },
    )
    assert intent.peer_rci_shape is WireguardPeerRciShape.NESTED_RCI


def test_parse_wireguard_accepts_nested_rci_shape() -> None:
    from router_control.domain.network_intents import WireguardPeerRciShape, parse_network_intent

    intent = parse_network_intent(
        "wireguard",
        {
            "wg_id": "Wireguard5",
            "enabled": True,
            "private_key_credential_ref_id": "credref:awg-private",
            "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "peer_rci_shape": "nested_rci",
        },
    )
    assert intent.peer_rci_shape is WireguardPeerRciShape.NESTED_RCI


def test_wireguard_to_canonical_omits_default_peer_rci_shape() -> None:
    from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape

    nested = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        private_key_credential_ref_id="credref:awg-private",
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )
    assert "peer_rci_shape" not in nested.to_canonical()

    path_style = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        private_key_credential_ref_id="credref:awg-private",
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        peer_rci_shape=WireguardPeerRciShape.PATH_STYLE,
    )
    assert path_style.to_canonical()["peer_rci_shape"] == "path_style"


def test_parse_wireguard_rejects_path_style() -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="path_style"):
        parse_network_intent(
            "wireguard",
            {
                "wg_id": "Wireguard5",
                "enabled": True,
                "private_key_credential_ref_id": "credref:awg-private",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_rci_shape": "path_style",
            },
        )


def test_parse_wireguard_rejects_unknown_peer_rci_shape() -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="peer_rci_shape"):
        parse_network_intent(
            "wireguard",
            {
                "wg_id": "Wireguard5",
                "enabled": True,
                "private_key_credential_ref_id": "credref:awg-private",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_rci_shape": "raw_rci",
            },
        )


def test_parse_wireguard_16_arg_allowed_for_planner_unsupported() -> None:
    from router_control.application.wireguard_apply_planner import compile_wireguard_intent_to_ops
    from router_control.domain.network_intents import parse_network_intent

    intent = parse_network_intent(
        "wireguard",
        {"wg_id": "Wireguard5", "enabled": True, "asc_args": _ASC_16},
    )
    plan = compile_wireguard_intent_to_ops(intent)
    assert plan.verification_status == "unsupported_pending_verification"
    assert plan.apply_ops == ()


def test_parse_wireguard_invalid_asc_length_rejected() -> None:
    from router_control.domain.network_intents import parse_network_intent

    with pytest.raises(IntentValidationError, match="exactly 9 or 16"):
        parse_network_intent(
            "wireguard",
            {"wg_id": "Wireguard5", "enabled": True, "asc_args": [1, 2, 3]},
        )


def test_parse_wireguard_negative_asc_rejected() -> None:
    from router_control.domain.network_intents import parse_network_intent

    negative = list(_ASC_9)
    negative[0] = -1
    with pytest.raises(IntentValidationError, match="non-negative"):
        parse_network_intent(
            "wireguard",
            {"wg_id": "Wireguard5", "enabled": True, "asc_args": negative},
        )


def test_parse_wireguard_asc_jc_over_max_rejected() -> None:
    from router_control.domain.network_intents import parse_network_intent

    over = list(_ASC_9)
    over[0] = 100_000
    with pytest.raises(IntentValidationError, match="asc args must be exactly"):
        parse_network_intent(
            "wireguard",
            {"wg_id": "Wireguard5", "enabled": True, "asc_args": over},
        )


def test_parse_wireguard_real_uint32_h_values_accepted() -> None:
    from router_control.domain.network_intents import parse_network_intent

    intent = parse_network_intent(
        "wireguard",
        {
            "wg_id": "Wireguard5",
            "enabled": True,
            "asc_args": [4, 10, 50, 130, 69, 149835824, 1778159739, 1704282148, 748462068],
        },
    )
    assert intent.asc_args is not None
    assert intent.asc_args[5] == 149835824
