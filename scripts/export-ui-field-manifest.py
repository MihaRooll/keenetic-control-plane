"""Generate ui-field-manifest.json from live Pydantic request body models.

Source of truth is direct pydantic reflection on route body classes (not openapi-v0.json):
OpenAPI lags route modules and omits curated disclosure/tooltips; importing models keeps
the manifest aligned with the actual accepted request shapes.

Residual reflection holes (honestly pinned; see MANUAL_BODY_GUARD_DECISION_TABLE in
tests/test_ui_field_manifest.py):
- manual-dict bodies: KeyTrackingDict behavioral tests (not regex); residual dynamic
  getattr and whole-body JSON dump
- API handlers without extra=forbid still accept unknown body keys (UI gap, separate track)
- untested handler branches may omit key-access coverage until probed
"""

from __future__ import annotations

import json
import sys
import tempfile
import types
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal, NotRequired, TypedDict, Union, get_args, get_origin

from pydantic import BaseModel
from pydantic.aliases import AliasChoices
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "router_control_host" / "web" / "ui-field-manifest.json"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

API_PREFIX = "/api/router-control/v1"

# Route body models — direct import (not openapi-v0.json); see module docstring.
from router_control_host.bootstrap_discovery_routes import BootstrapDiscoveryBody  # noqa: E402
from router_control_host.connection_health_routes import ConnectionHealthBody  # noqa: E402
from router_control_host.internet_status_routes import InternetStatusObserveBody  # noqa: E402
from router_control_host.keendns_routes import (  # noqa: E402
    KeenDnsPreviewBody,
    KeenDnsStatusBody,
)
from router_control_host.network_family_preview_routes import (  # noqa: E402
    DhcpPreviewBody,
    DnsPreviewBody,
    FirewallPreviewBody,
    VlanPreviewBody,
)
from router_control_host.remembered_uplink_routes import PutRememberedUplinkBody  # noqa: E402
from router_control_host.router_discovery_routes import RouterDiscoveryBody  # noqa: E402
from router_control_host.routes import API_PREFIX as _HOST_API_PREFIX  # noqa: E402
from router_control_host.routes import (  # noqa: E402
    ConfirmPlanBody,
    CreateDeploymentRevisionBody,
    CreateDesiredRevisionBody,
    CreatePlanBody,
    EnrollRouterBody,
    PutCredentialBody,
    RotateCredentialBody,
    VpnProfileActivateBody,
    VpnProfileDeactivateBody,
    VpnProfileImportBody,
    VpnProfileParsePreviewBody,
)
from router_control_host.ssh_host_key_routes import (  # noqa: E402
    ManagementUsernameBody,
    SshHostKeyConfirmBody,
    SshHostKeyLearnBody,
)
from router_control_host.standing_network_preferences_routes import (  # noqa: E402
    PutStandingNetworkPreferencesBody,
)
from router_control_host.traffic_discovery_routes import (  # noqa: E402
    CreateProposalBody,
    RecordObservationBody,
)
from router_control_host.vpn_catalog_remove_routes import VpnCatalogRemoveBody  # noqa: E402
from router_control_host.vpn_catalog_status_routes import VpnCatalogStatusBody  # noqa: E402
from router_control_host.vpn_policy_preview_routes import VpnPolicyPreviewBody  # noqa: E402
from router_control_host.wifi_apply_routes import (  # noqa: E402
    WifiApplyBody,
    WifiPreviewBody,
    WifiTeardownBody,
)
from router_control_host.wifi_observed_routes import WifiObservedStateBody  # noqa: E402
from router_control_host.wifi_site_survey_routes import WifiSiteSurveyBody  # noqa: E402
from router_control_host.wifi_station_apply_routes import (  # noqa: E402
    WifiStationApplyBody,
    WifiStationTeardownBody,
)
from router_control_host.wifi_station_preview_routes import WifiStationPreviewBody  # noqa: E402
from router_control_host.wireguard_apply_routes import (  # noqa: E402
    WireguardApplyBody,
    WireguardObserveBody,
    WireguardPreviewBody,
    WireguardTeardownBody,
)
from router_control_host.wizard_draft_routes import WizardDraftRouterBody  # noqa: E402

assert _HOST_API_PREFIX == API_PREFIX


class CuratedFieldMeta(TypedDict):
    disclosure: Literal["simple", "advanced"]
    tooltip: str
    verification_note: str
    reject_http_code: NotRequired[str]


CuratedKey = tuple[str, str]

CURATED_META: dict[CuratedKey, CuratedFieldMeta] = {
    # --- wifi_ap ---
    ("wifi_ap", "ap_id"): {
        "disclosure": "advanced",
        "tooltip": "Идентификатор точки доступа из allowlist (например AccessPoint3).",
        "verification_note": "device_verified_wpa2: ap_id валидируется allowlist перед apply.",
    },
    ("wifi_ap", "band"): {
        "disclosure": "simple",
        "tooltip": "Диапазон Wi‑Fi: 2,4 ГГц или 5 ГГц.",
        "verification_note": "device_verified_wpa2: band мапится на WifiMaster0/1 в planner.",
    },
    ("wifi_ap", "captive_portal"): {
        "disclosure": "advanced",
        "tooltip": "Captive portal: Enabled отклоняется API (422); Disabled — noop.",
        "verification_note": "Enabled → 422 wifi.captive_portal_unsupported; Disabled noop.",
        "reject_http_code": "wifi.captive_portal_unsupported",
    },
    ("wifi_ap", "compensate_on_failure"): {
        "disclosure": "advanced",
        "tooltip": "Откат изменений при ошибке live apply.",
        "verification_note": "device_verified_wpa2: флаг сервиса компенсации на live path.",
    },
    ("wifi_ap", "confirm_live_apply"): {
        "disclosure": "advanced",
        "tooltip": "Явное подтверждение отправки live apply на роутер.",
        "verification_note": "device_verified_wpa2: без true apply не dispatchится.",
    },
    ("wifi_ap", "confirm_live_teardown"): {
        "disclosure": "advanced",
        "tooltip": "Явное подтверждение live teardown точки доступа.",
        "verification_note": "device_verified_wpa2: альтернатива confirm_live_apply для teardown.",
    },
    ("wifi_ap", "credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Ссылка на sealed credential с паролем WPA (не plaintext).",
        "verification_note": "device_verified_wpa2: PSK резолвится через vault на apply.",
    },
    ("wifi_ap", "enabled"): {
        "disclosure": "advanced",
        "tooltip": "Включить или выключить точку доступа после apply.",
        "verification_note": "device_verified_wpa2: enabled участвует в planner CLI.",
    },
    ("wifi_ap", "guest_isolation"): {
        "disclosure": "advanced",
        "tooltip": "Guest isolation: true отклоняется API (422); false — noop.",
        "verification_note": "true → 422 wifi.guest_isolation_unsupported; false noop.",
        "reject_http_code": "wifi.guest_isolation_unsupported",
    },
    ("wifi_ap", "host"): {
        "disclosure": "advanced",
        "tooltip": "IP или hostname роутера для live SSH/RCI сессии.",
        "verification_note": "device_verified_wpa2: live connection tuple на expendable lab.",
    },
    ("wifi_ap", "idempotent"): {
        "disclosure": "advanced",
        "tooltip": "Повторный apply без лишних записей при неизменном intent.",
        "verification_note": "device_verified_wpa2: idempotent path в apply service.",
    },
    ("wifi_ap", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed credential для SSH-логина на роутер.",
        "verification_note": "device_verified_wpa2: live path credential ref, не plaintext.",
    },
    ("wifi_ap", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "ID зарегистрированного роутера; подставляет host/key из store.",
        "verification_note": "device_verified_wpa2: опциональная indirection для live tuple.",
    },
    ("wifi_ap", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный source IP для SSH к роутеру.",
        "verification_note": "device_verified_wpa2: опциональный bind address live path.",
    },
    ("wifi_ap", "ssid"): {
        "disclosure": "simple",
        "tooltip": "Имя беспроводной сети (SSID), 1–32 символа.",
        "verification_note": "device_verified_wpa2: SSID применяется planner на lab device.",
    },
    ("wifi_ap", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 pin host key роутера для fail-closed SSH.",
        "verification_note": "device_verified_wpa2: Gate A host-key preflight.",
    },
    ("wifi_ap", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username для live сессии на роутер.",
        "verification_note": "device_verified_wpa2: часть live connection tuple.",
    },
    ("wifi_ap", "wpa_mode"): {
        "disclosure": "advanced",
        "tooltip": "Режим WPA: WPA2, WPA3 или mixed.",
        "verification_note": "device_verified_wpa2: wpa_mode в planner/teardown grammar.",
    },
    # --- wifi_station ---
    ("wifi_station", "auth_mode"): {
        "disclosure": "advanced",
        "tooltip": "Режим аутентификации станции (wpa2_psk; open не поддерживается).",
        "verification_note": "device_accepted_grammar: OPEN отклоняется API до dispatch.",
    },
    ("wifi_station", "band"): {
        "disclosure": "simple",
        "tooltip": "Диапазон для клиентского Wi‑Fi (WISP): 2,4 или 5 ГГц.",
        "verification_note": "device_accepted_grammar: band → station_id mapping проверен.",
    },
    ("wifi_station", "bssid"): {
        "disclosure": "advanced",
        "tooltip": "Опциональный BSSID для привязки к конкретной AP.",
        "verification_note": "device_accepted_grammar: опционально в uplink intent.",
    },
    ("wifi_station", "compensate_on_failure"): {
        "disclosure": "advanced",
        "tooltip": "Компенсация при ошибке live station apply.",
        "verification_note": "device_accepted_grammar: флаг apply service.",
    },
    ("wifi_station", "confirm_live_apply"): {
        "disclosure": "advanced",
        "tooltip": "Подтверждение live dispatch station apply.",
        "verification_note": "device_accepted_grammar: обязателен true для apply route.",
    },
    ("wifi_station", "confirm_live_teardown"): {
        "disclosure": "advanced",
        "tooltip": "Подтверждение live station teardown.",
        "verification_note": "device_accepted_grammar: альтернатива confirm_live_apply.",
    },
    ("wifi_station", "credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Sealed credential PSK для станции (обязателен для WifiWan).",
        "verification_note": "device_accepted_grammar: без ref_id preview/apply fail-closed.",
    },
    ("wifi_station", "host"): {
        "disclosure": "advanced",
        "tooltip": "Адрес роутера для live station apply.",
        "verification_note": "device_accepted_grammar: live connection tuple.",
    },
    ("wifi_station", "idempotent"): {
        "disclosure": "advanced",
        "tooltip": "Идempotent station apply при неизменном intent.",
        "verification_note": "device_accepted_grammar: service flag.",
    },
    ("wifi_station", "mode"): {
        "disclosure": "advanced",
        "tooltip": "Режим uplink; station apply требует WifiWan.",
        "verification_note": "device_accepted_grammar: иные mode отклоняются API.",
    },
    ("wifi_station", "priority"): {
        "disclosure": "advanced",
        "tooltip": "Приоритет uplink (default 100). Нестандартное значение offline/preview → 422.",
        "verification_note": (
            "priority≠100 без include_ip_global → 422 wifi.station_priority_requires_ip_global; "
            "default 100 noop offline; live path применяет ip global."
        ),
        "reject_http_code": "wifi.station_priority_requires_ip_global",
    },
    ("wifi_station", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential роутера для live path.",
        "verification_note": "device_accepted_grammar: credential ref, не plaintext.",
    },
    ("wifi_station", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "Зарегистрированный router_id для live tuple из store.",
        "verification_note": "device_accepted_grammar: optional store indirection.",
    },
    ("wifi_station", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind address для SSH.",
        "verification_note": "device_accepted_grammar: optional live param.",
    },
    ("wifi_station", "ssid"): {
        "disclosure": "simple",
        "tooltip": "SSID upstream сети для WISP станции.",
        "verification_note": "device_accepted_grammar: SSID в station planner CLI.",
    },
    ("wifi_station", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 pin SSH host key роутера.",
        "verification_note": "device_accepted_grammar: Gate A preflight.",
    },
    ("wifi_station", "uplink_settle_seconds"): {
        "disclosure": "advanced",
        "tooltip": "Ожидание uplink settle после apply (сек; clamp на live).",
        "verification_note": "device_accepted_grammar: bounded settle на live path.",
    },
    ("wifi_station", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username для live station apply.",
        "verification_note": "device_accepted_grammar: live tuple field.",
    },
    # --- wireguard ---
    ("wireguard", "asc_args"): {
        "disclosure": "advanced",
        "tooltip": "Опциональные ASC аргументы AmneziaWG (массив int).",
        "verification_note": "offline compile only; live verification varies by profile.",
    },
    ("wireguard", "confirm_live_apply"): {
        "disclosure": "advanced",
        "tooltip": "Подтверждение live WireGuard apply.",
        "verification_note": "confirm gate; multi-profile live status not unified.",
    },
    ("wireguard", "confirm_live_teardown"): {
        "disclosure": "advanced",
        "tooltip": "Подтверждение live WireGuard teardown.",
        "verification_note": "confirm gate; multi-profile live status not unified.",
    },
    ("wireguard", "enabled"): {
        "disclosure": "advanced",
        "tooltip": "Поднять интерфейс WireGuard после конфигурации.",
        "verification_note": "planner field; device verification profile-dependent.",
    },
    ("wireguard", "handshake_settle_seconds"): {
        "disclosure": "advanced",
        "tooltip": "Ожидание handshake перед recheck (0 = без ожидания).",
        "verification_note": "live apply option; clamp 20–30s when >0.",
    },
    ("wireguard", "host"): {
        "disclosure": "advanced",
        "tooltip": "Адрес роутера для live WireGuard apply.",
        "verification_note": "live connection tuple; not single verified profile.",
    },
    ("wireguard", "peer_allow_ips"): {
        "disclosure": "simple",
        "tooltip": "Allowed IPs peer (CIDR/spisok через запятую).",
        "verification_note": "intent grammar compiled; live varies by wg_id/profile.",
    },
    ("wireguard", "peer_endpoint"): {
        "disclosure": "simple",
        "tooltip": "Endpoint peer host:port для туннеля.",
        "verification_note": "intent field; nested vs path_style affects RCI shape.",
    },
    ("wireguard", "peer_keepalive_interval"): {
        "disclosure": "advanced",
        "tooltip": "Persistent keepalive interval (3–3600 сек).",
        "verification_note": "optional peer param; bounds from model.",
    },
    ("wireguard", "peer_public_key"): {
        "disclosure": "simple",
        "tooltip": "Публичный ключ WireGuard peer (base64).",
        "verification_note": "required for peer config; not a secret field.",
    },
    ("wireguard", "peer_rci_shape"): {
        "disclosure": "advanced",
        "tooltip": "Форма RCI peer: path_style или nested_rci.",
        "verification_note": "default nested_rci; shape affects CLI vs nested body.",
    },
    ("wireguard", "preshared_key_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed credential ref для preshared key (не plaintext).",
        "verification_note": "credential ref only; no plaintext PSK in manifest.",
    },
    ("wireguard", "private_key_credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Sealed credential ref для private key интерфейса.",
        "verification_note": "credential ref only; no plaintext private key.",
    },
    ("wireguard", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential для live apply.",
        "verification_note": "live tuple; credential ref pattern.",
    },
    ("wireguard", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "router_id для live tuple из store.",
        "verification_note": "optional store indirection.",
    },
    ("wireguard", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind для SSH live session.",
        "verification_note": "optional live param.",
    },
    ("wireguard", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 SSH host key pin.",
        "verification_note": "Gate A preflight on live path.",
    },
    ("wireguard", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username live session.",
        "verification_note": "live tuple field.",
    },
    ("wireguard", "wg_id"): {
        "disclosure": "simple",
        "tooltip": "Идентификатор интерфейса WireguardN из allowlist.",
        "verification_note": "wg_id validated against allowlist before dispatch.",
    },
    ("wireguard", "interface_address"): {
        "disclosure": "simple",
        "tooltip": "IPv4 адрес или CIDR интерфейса туннеля (interface address).",
        "verification_note": (
            "device_verified: parse/allowlist — только IPv4 (ipaddress.IPv4Network); "
            "IPv6 не принимается; readback через show interface."
        ),
    },
    ("wireguard", "ip_global_priority"): {
        "disclosure": "advanced",
        "tooltip": "Приоритет ip global для маршрутизации через туннель (0–65535).",
        "verification_note": (
            "device_verified: ip global priority применяется; "
            "взаимоисключимо с ip_global_auto."
        ),
    },
    ("wireguard", "ip_global_auto"): {
        "disclosure": "advanced",
        "tooltip": "Автовыбор ip global priority роутером (без явного числа).",
        "verification_note": (
            "device_verified: ip global auto path; "
            "422 если задан одновременно ip_global_priority."
        ),
    },
    ("wireguard", "tcp_mss_pmtu"): {
        "disclosure": "advanced",
        "tooltip": "Включить TCP MSS clamp / PMTU на интерфейсе туннеля.",
        "verification_note": (
            "device_verified: tcp mss pmtu apply/clear на expendable lab; "
            "не captive portal."
        ),
    },
    # --- vlan ---
    ("vlan", "bridge_id"): {
        "disclosure": "simple",
        "tooltip": "Bridge интерфейс для VLAN subinterface.",
        "verification_note": "offline_unverified: preview compile only, no live apply route.",
    },
    ("vlan", "ipv4_cidr"): {
        "disclosure": "simple",
        "tooltip": "IPv4 CIDR VLAN интерфейса.",
        "verification_note": "offline_unverified: planner grammar not device-applied here.",
    },
    ("vlan", "ipv4_gateway"): {
        "disclosure": "simple",
        "tooltip": "IPv4 gateway VLAN зоны.",
        "verification_note": "offline_unverified: preview-only family.",
    },
    ("vlan", "vlan_id"): {
        "disclosure": "simple",
        "tooltip": "802.1Q VLAN ID (1–4094).",
        "verification_note": "offline_unverified: bounds from model, not live-tested.",
    },
    ("vlan", "zone_id"): {
        "disclosure": "simple",
        "tooltip": "ID зоны/интерфейса из allowlist.",
        "verification_note": "offline_unverified: zone_id allowlist check in route.",
    },
    # --- dhcp ---
    ("dhcp", "lease_seconds"): {
        "disclosure": "simple",
        "tooltip": "Время аренды DHCP в секундах (60–604800).",
        "verification_note": "offline_unverified: bounds enforced, no device apply.",
    },
    ("dhcp", "pool_end"): {
        "disclosure": "simple",
        "tooltip": "Конец пула DHCP адресов.",
        "verification_note": "offline_unverified: preview compile only.",
    },
    ("dhcp", "pool_start"): {
        "disclosure": "simple",
        "tooltip": "Начало пула DHCP адресов.",
        "verification_note": "offline_unverified: preview compile only.",
    },
    ("dhcp", "reservations"): {
        "disclosure": "advanced",
        "tooltip": "Статические резервации MAC→IPv4 (массив объектов).",
        "verification_note": "offline_unverified: nested item fields exported as reservations.*.",
    },
    ("dhcp", "reservations.ipv4_address"): {
        "disclosure": "advanced",
        "tooltip": "Зарезервированный IPv4 адрес для MAC в reservations[].",
        "verification_note": "offline_unverified: nested reservation item field.",
    },
    ("dhcp", "reservations.mac_address"): {
        "disclosure": "advanced",
        "tooltip": "MAC адрес клиента для статической DHCP резервации.",
        "verification_note": "offline_unverified: nested reservation item field.",
    },
    ("dhcp", "zone_id"): {
        "disclosure": "simple",
        "tooltip": "Зона DHCP сервера из allowlist.",
        "verification_note": "offline_unverified: allowlist validation only.",
    },
    # --- dns ---
    ("dns", "local_fqdn"): {
        "disclosure": "simple",
        "tooltip": "Локальное FQDN имя для DNS зоны.",
        "verification_note": "offline_unverified: preview-only compile.",
    },
    ("dns", "upstream_resolvers"): {
        "disclosure": "simple",
        "tooltip": "Список upstream DNS резолверов (минимум один).",
        "verification_note": "offline_unverified: min_length=1 on array.",
    },
    ("dns", "zone_id"): {
        "disclosure": "simple",
        "tooltip": "ID DNS зоны из allowlist.",
        "verification_note": "offline_unverified: allowlist check in route.",
    },
    # --- firewall ---
    ("firewall", "rules"): {
        "disclosure": "simple",
        "tooltip": "Правила firewall (массив объектов action/destination/ordinal).",
        "verification_note": "offline_unverified: nested item fields exported as rules.*.",
    },
    ("firewall", "rules.action"): {
        "disclosure": "simple",
        "tooltip": "Действие правила: Allow или Deny.",
        "verification_note": "offline_unverified: nested firewall rule item field.",
    },
    ("firewall", "rules.destination_family"): {
        "disclosure": "simple",
        "tooltip": "Семейство назначения правила (Internet, Dns, LocalZone и т.п.).",
        "verification_note": "offline_unverified: nested firewall rule item field.",
    },
    ("firewall", "rules.ordinal"): {
        "disclosure": "advanced",
        "tooltip": "Порядковый номер правила в списке (≥0).",
        "verification_note": "offline_unverified: nested firewall rule item field.",
    },
    ("firewall", "zone_id"): {
        "disclosure": "simple",
        "tooltip": "Зона firewall политики из allowlist.",
        "verification_note": "offline_unverified: preview-only family.",
    },
    # --- vpn_policy_routing ---
    ("vpn_policy_routing", "address_configured"): {
        "disclosure": "advanced",
        "tooltip": "Флаг: адрес VPN интерфейса уже сконфигурирован.",
        "verification_note": (
            "help_verified_grammar_unapplied: grammar from help/docs, not live apply."
        ),
    },
    ("vpn_policy_routing", "interface_kind"): {
        "disclosure": "advanced",
        "tooltip": "Тип VPN интерфейса (Wireguard и т.п.), если нужен planner.",
        "verification_note": "help_verified_grammar_unapplied: optional hint field.",
    },
    ("vpn_policy_routing", "ip_global"): {
        "disclosure": "simple",
        "tooltip": "Политика ip global: auto, priority или order объект.",
        "verification_note": "help_verified_grammar_unapplied: union object, not device-applied.",
    },
    ("vpn_policy_routing", "ip_global.order"): {
        "disclosure": "simple",
        "tooltip": "Порядок ip global (0–65535) для union-ветки order.",
        "verification_note": (
            "help_verified_grammar_unapplied: union object grammar, not device-applied."
        ),
    },
    ("vpn_policy_routing", "ip_global.priority"): {
        "disclosure": "simple",
        "tooltip": "Приоритет ip global (0–65535) для union-ветки priority.",
        "verification_note": (
            "help_verified_grammar_unapplied: union object grammar, not device-applied."
        ),
    },
    ("vpn_policy_routing", "name_servers"): {
        "disclosure": "advanced",
        "tooltip": "Policy-specific DNS name servers (массив объектов).",
        "verification_note": (
            "help_verified_grammar_unapplied: nested item fields as name_servers.*."
        ),
    },
    ("vpn_policy_routing", "name_servers.address"): {
        "disclosure": "advanced",
        "tooltip": "IP адрес policy-specific DNS сервера.",
        "verification_note": "help_verified_grammar_unapplied: nested name server item field.",
    },
    ("vpn_policy_routing", "name_servers.domain"): {
        "disclosure": "advanced",
        "tooltip": "Опциональный домен для policy-specific DNS сервера.",
        "verification_note": "help_verified_grammar_unapplied: nested name server item field.",
    },
    ("vpn_policy_routing", "name_servers.on_interface"): {
        "disclosure": "advanced",
        "tooltip": "Опциональный интерфейс привязки DNS сервера.",
        "verification_note": "help_verified_grammar_unapplied: nested name server item field.",
    },
    ("vpn_policy_routing", "policy_name"): {
        "disclosure": "simple",
        "tooltip": "Имя policy-based routing правила.",
        "verification_note": "help_verified_grammar_unapplied: preview compile from help grammar.",
    },
    ("vpn_policy_routing", "vpn_interface"): {
        "disclosure": "simple",
        "tooltip": "VPN интерфейс для policy route (WireguardN и т.п.).",
        "verification_note": "help_verified_grammar_unapplied: not live-applied in this phase.",
    },
    # --- wizard_draft ---
    ("wizard_draft", "allow_insecure_http"): {
        "disclosure": "advanced",
        "tooltip": "Разрешить HTTP management endpoint вместо HTTPS.",
        "verification_note": "lab-only draft enroll; Gate A closed; no live probe.",
    },
    ("wizard_draft", "display_name"): {
        "disclosure": "simple",
        "tooltip": "Отображаемое имя роутера в каталоге.",
        "verification_note": "lab-only draft enroll; SQLite + vault, no device writes.",
    },
    ("wizard_draft", "host"): {
        "disclosure": "simple",
        "tooltip": "IP, hostname или URL management endpoint.",
        "verification_note": "lab-only draft enroll; parsed to endpoint tuple.",
    },
    ("wizard_draft", "port"): {
        "disclosure": "advanced",
        "tooltip": "Порт management endpoint (1–65535).",
        "verification_note": "lab-only draft enroll; optional override.",
    },
    ("wizard_draft", "secret"): {
        "disclosure": "simple",
        "tooltip": "Management password для vault intake (write-only).",
        "verification_note": (
            "Значение не сохраняется в manifest и не отображается; "
            "sealed в vault при draft enroll."
        ),
    },
    ("wizard_draft", "username"): {
        "disclosure": "simple",
        "tooltip": "SSH/management username.",
        "verification_note": "lab-only draft enroll; stored on router row.",
    },
    # --- bootstrap_discovery ---
    ("bootstrap_discovery", "allow_insecure_http"): {
        "disclosure": "advanced",
        "tooltip": "Разрешить HTTP для bootstrap discovery.",
        "verification_note": "non-certifying read-only lab observe; certification_eligible=false.",
    },
    ("bootstrap_discovery", "credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Sealed credential ref для management login.",
        "verification_note": "non-certifying read-only lab observe.",
    },
    ("bootstrap_discovery", "host"): {
        "disclosure": "simple",
        "tooltip": "IP или hostname роутера для discovery.",
        "verification_note": "non-certifying read-only lab observe.",
    },
    ("bootstrap_discovery", "username"): {
        "disclosure": "simple",
        "tooltip": "Management username для discovery session.",
        "verification_note": "non-certifying read-only lab observe.",
    },
    # --- router_discovery ---
    ("router_discovery", "include_default_gateway"): {
        "disclosure": "simple",
        "tooltip": "Включить default-gateway кандидата из host route table.",
        "verification_note": (
            "read-only non-certifying: router_discovery.py docstring; "
            "certification_eligible=False; writes_allowed=False; "
            "router_discovery_routes.py L60–66 fail-closed if certifying."
        ),
    },
    ("router_discovery", "include_known_endpoints"): {
        "disclosure": "simple",
        "tooltip": "Включить known-endpoint кандидатов из store.",
        "verification_note": (
            "read-only non-certifying: router_discovery.py docstring; "
            "certification_eligible=False; writes_allowed=False; "
            "router_discovery_routes.py L60–66 fail-closed if certifying."
        ),
    },
    ("router_discovery", "preferred_source_address"): {
        "disclosure": "advanced",
        "tooltip": "Предпочитаемый source bind address для probe кандидатов.",
        "verification_note": (
            "read-only non-certifying: router_discovery.py docstring; "
            "certification_eligible=False; writes_allowed=False; "
            "router_discovery_routes.py L60–66 fail-closed if certifying."
        ),
    },
    ("router_discovery", "probe"): {
        "disclosure": "advanced",
        "tooltip": "Опциональный identity probe кандидатов (default false).",
        "verification_note": (
            "read-only non-certifying: router_discovery.py docstring; "
            "certification_eligible=False; writes_allowed=False; "
            "router_discovery_routes.py L60–66 fail-closed if certifying."
        ),
    },
    # --- connection_health ---
    ("connection_health", "router_id"): {
        "disclosure": "simple",
        "tooltip": "Зарегистрированный router_id для tuple indirection.",
        "verification_note": (
            "read-only non-certifying: connection_health.py docstring; "
            "writes_allowed=False; certification_eligible=False; "
            "connection_health_routes.py L65–71 fail-closed if certifying."
        ),
    },
    ("connection_health", "host"): {
        "disclosure": "simple",
        "tooltip": "IP или hostname роутера для health assess.",
        "verification_note": (
            "read-only non-certifying: connection_health.py docstring; "
            "writes_allowed=False; certification_eligible=False; "
            "connection_health_routes.py L65–71 fail-closed if certifying."
        ),
    },
    ("connection_health", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind address для SSH/management probe.",
        "verification_note": (
            "read-only non-certifying: connection_health.py docstring; "
            "writes_allowed=False; certification_eligible=False; "
            "connection_health_routes.py L65–71 fail-closed if certifying."
        ),
    },
    ("connection_health", "credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Sealed credential ref для management/SSH login.",
        "verification_note": (
            "read-only non-certifying: connection_health.py docstring; "
            "writes_allowed=False; certification_eligible=False; "
            "connection_health_routes.py L65–71 fail-closed if certifying."
        ),
    },
    ("connection_health", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 pin SSH host key для fail-closed probe.",
        "verification_note": (
            "read-only non-certifying: connection_health.py docstring; "
            "writes_allowed=False; certification_eligible=False; "
            "connection_health_routes.py L65–71 fail-closed if certifying."
        ),
    },
    ("connection_health", "probe"): {
        "disclosure": "advanced",
        "tooltip": "Выполнить live reachability probe (default true).",
        "verification_note": (
            "read-only non-certifying: connection_health.py docstring; "
            "writes_allowed=False; certification_eligible=False; "
            "connection_health_routes.py L65–71 fail-closed if certifying."
        ),
    },
    # --- connection_context ---
    ("connection_context", "username"): {
        "disclosure": "simple",
        "tooltip": (
            "SSH/management username для live-сессии; хранится на сервере, "
            "клиенту не возвращается."
        ),
        "verification_note": (
            "POST management-username; value never echoed; "
            "required together with pin and credential for live_ready."
        ),
    },
    # --- ssh_host_key ---
    ("ssh_host_key", "allow_overwrite"): {
        "disclosure": "advanced",
        "tooltip": "Разрешить перезапись существующего pin при confirm.",
        "verification_note": "explicit TOFU confirm; pin stored in SQLite.",
    },
    ("ssh_host_key", "algorithm"): {
        "disclosure": "simple",
        "tooltip": "Алгоритм SSH host key (из learn candidate).",
        "verification_note": "confirm path; must match pending learn.",
    },
    ("ssh_host_key", "fingerprint_sha256"): {
        "disclosure": "simple",
        "tooltip": "SHA256 fingerprint host key для pin.",
        "verification_note": "confirm path; TOFU pin to router row.",
    },
    ("ssh_host_key", "host"): {
        "disclosure": "simple",
        "tooltip": "SSH host для learn candidate.",
        "verification_note": "learn path; live SSH handshake, no RCI writes.",
    },
    ("ssh_host_key", "port"): {
        "disclosure": "advanced",
        "tooltip": "SSH port (default 22).",
        "verification_note": "learn path.",
    },
    ("ssh_host_key", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind address для SSH learn.",
        "verification_note": "learn path; optional.",
    },
    # --- enroll ---
    ("enroll", "credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Sealed credential ref вместо plaintext password.",
        "verification_note": "enroll path; vault ref, not plaintext in store echo.",
    },
    ("enroll", "display_name"): {
        "disclosure": "simple",
        "tooltip": "Отображаемое имя роутера.",
        "verification_note": "enroll path; Gate A gated in live mode.",
    },
    ("enroll", "endpoint"): {
        "disclosure": "advanced",
        "tooltip": "Nested endpoint tuple (host/port/kind/username).",
        "verification_note": "enroll path; optional nested object.",
    },
    ("enroll", "endpoint.host"): {
        "disclosure": "advanced",
        "tooltip": "Management host/IP endpoint.",
        "verification_note": "enroll nested endpoint field.",
    },
    ("enroll", "endpoint.kind"): {
        "disclosure": "advanced",
        "tooltip": "Endpoint kind (management_http/https).",
        "verification_note": "enroll nested endpoint field.",
    },
    ("enroll", "endpoint.port"): {
        "disclosure": "advanced",
        "tooltip": "Management port.",
        "verification_note": "enroll nested endpoint field.",
    },
    ("enroll", "endpoint.source_address"): {
        "disclosure": "advanced",
        "tooltip": "Source bind address для management session.",
        "verification_note": "enroll nested endpoint field.",
    },
    ("enroll", "endpoint.username"): {
        "disclosure": "advanced",
        "tooltip": "Management username.",
        "verification_note": "enroll nested endpoint field.",
    },
    ("enroll", "hardware_revision"): {
        "disclosure": "advanced",
        "tooltip": "Hardware revision string.",
        "verification_note": "enroll path; optional metadata.",
    },
    ("enroll", "management_password"): {
        "disclosure": "simple",
        "tooltip": "Management password intake (write-only).",
        "verification_note": (
            "Значение не сохраняется в manifest и не отображается; "
            "sealed в vault при enroll."
        ),
    },
    ("enroll", "model"): {
        "disclosure": "simple",
        "tooltip": "Модель роутера (vendor-specific).",
        "verification_note": "enroll path; Gate A identity match in live mode.",
    },
    ("enroll", "site_id"): {
        "disclosure": "advanced",
        "tooltip": "Site ID; default site если omitted.",
        "verification_note": "enroll path; optional.",
    },
    ("enroll", "vendor"): {
        "disclosure": "simple",
        "tooltip": "Vendor роутера.",
        "verification_note": "enroll path; Gate A identity match in live mode.",
    },
    # --- change_plan ---
    ("change_plan", "adopt_acknowledged"): {
        "disclosure": "advanced",
        "tooltip": "Подтверждение adopt risk при create/confirm plan.",
        "verification_note": (
            "SQLite plan queue only; apply_plan fail-closed without fake gate "
            "(routes.py apply_plan ~2358–2451)."
        ),
    },
    ("change_plan", "deployment_revision_id"): {
        "disclosure": "advanced",
        "tooltip": "Опциональная deployment revision для plan.",
        "verification_note": "create plan only; SQLite queue, no live router.",
    },
    ("change_plan", "observation_id"): {
        "disclosure": "simple",
        "tooltip": "Observation ID для plan baseline.",
        "verification_note": "create plan; SQLite queue, no live router.",
    },
    ("change_plan", "plan_digest"): {
        "disclosure": "simple",
        "tooltip": "Digest plan для confirm step.",
        "verification_note": "confirm plan; SQLite queue, no live router.",
    },
    ("change_plan", "revision_id"): {
        "disclosure": "simple",
        "tooltip": "Desired revision ID для plan.",
        "verification_note": "create plan; SQLite queue, no live router.",
    },
    ("change_plan", "risk_acknowledged"): {
        "disclosure": "advanced",
        "tooltip": "Опциональное подтверждение risk при confirm.",
        "verification_note": "confirm plan; SQLite queue, no live router.",
    },
    # --- deployment ---
    ("deployment", "execution_target"): {
        "disclosure": "simple",
        "tooltip": "Execution target label (default Lab).",
        "verification_note": "SQLite deployment revision; no live router dispatch.",
    },
    ("deployment", "published_preset_id"): {
        "disclosure": "simple",
        "tooltip": "Published preset ID для deployment revision.",
        "verification_note": "SQLite deployment revision; no live router dispatch.",
    },
    # --- desired_revision ---
    ("desired_revision", "assignments"): {
        "disclosure": "simple",
        "tooltip": "Assignment list для desired document (PUT overlay).",
        "verification_note": "put_desired manual body; SQLite revision store.",
    },
    ("desired_revision", "based_on_observation_id"): {
        "disclosure": "simple",
        "tooltip": "Observation ID baseline (PUT overlay).",
        "verification_note": "put_desired manual body; SQLite revision store.",
    },
    ("desired_revision", "deployment_revision_id"): {
        "disclosure": "simple",
        "tooltip": "Deployment revision ID для create desired.",
        "verification_note": "create desired from deployment; SQLite only.",
    },
    ("desired_revision", "observation_id"): {
        "disclosure": "simple",
        "tooltip": "Observation ID для create desired.",
        "verification_note": "create desired from deployment; SQLite only.",
    },
    ("desired_revision", "reason"): {
        "disclosure": "advanced",
        "tooltip": "Опциональная причина revision (PUT overlay).",
        "verification_note": "put_desired manual body; SQLite revision store.",
    },
    # --- vpn_profile ---
    ("vpn_profile", "display_name"): {
        "disclosure": "simple",
        "tooltip": "Display name imported VPN profile.",
        "verification_note": "import body; catalog + vault, secrets not echoed.",
    },
    ("vpn_profile", "profile_text"): {
        "disclosure": "simple",
        "tooltip": "Raw .conf text для parse-preview или import.",
        "verification_note": "parse-preview/import: sanitized output, secrets sealed in vault.",
    },
    ("vpn_profile", "vpn_kind"): {
        "disclosure": "simple",
        "tooltip": "VPN kind (AmneziaWG only in v1 import).",
        "verification_note": "import body; non-AmneziaWG rejected 422.",
    },
    ("vpn_profile", "wg_id"): {
        "disclosure": "simple",
        "tooltip": "Целевой WireguardN для import/activate (allowlist).",
        "verification_note": "import/activate: wg_id validated against allowlist.",
    },
    ("vpn_profile", "ip_global_auto"): {
        "disclosure": "advanced",
        "tooltip": "Автовыбор ip global priority при import/activate профиля.",
        "verification_note": "import/activate metadata; взаимоисключимо с ip_global_priority.",
    },
    ("vpn_profile", "ip_global_priority"): {
        "disclosure": "advanced",
        "tooltip": "Явный ip global priority для import/activate (0–65535).",
        "verification_note": "import/activate metadata; device_verified on activate path.",
    },
    ("vpn_profile", "tcp_mss_pmtu"): {
        "disclosure": "advanced",
        "tooltip": "TCP MSS clamp / PMTU для import/activate профиля.",
        "verification_note": "import/activate metadata; device_verified on apply.",
    },
    ("vpn_profile", "logical_role"): {
        "disclosure": "advanced",
        "tooltip": "Логическая роль профиля в каталоге (primary и др.).",
        "verification_note": "activate/deactivate: catalog role binding.",
    },
    ("vpn_profile", "confirm_live_apply"): {
        "disclosure": "advanced",
        "tooltip": "Подтверждение live activate/deactivate VPN профиля.",
        "verification_note": "confirm gate на activate/deactivate routes.",
    },
    ("vpn_profile", "handshake_settle_seconds"): {
        "disclosure": "advanced",
        "tooltip": "Ожидание WireGuard handshake после activate (0 = без ожидания).",
        "verification_note": "activate option; clamp 20–30s when >0 on live path.",
    },
    ("vpn_profile", "host"): {
        "disclosure": "advanced",
        "tooltip": "Адрес роутера для live activate/catalog probe.",
        "verification_note": "live connection tuple on activate/status routes.",
    },
    ("vpn_profile", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username для live VPN routes.",
        "verification_note": "live connection tuple field.",
    },
    ("vpn_profile", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential для live VPN routes.",
        "verification_note": "credential ref only; no plaintext secrets.",
    },
    ("vpn_profile", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 pin SSH host key для live VPN routes.",
        "verification_note": "Gate A preflight on live path.",
    },
    ("vpn_profile", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind для SSH live session.",
        "verification_note": "optional live param.",
    },
    ("vpn_profile", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "router_id для live tuple из store.",
        "verification_note": "optional store indirection on activate/status.",
    },
    # --- vpn_catalog ---
    ("vpn_catalog", "confirm_catalog_remove"): {
        "disclosure": "simple",
        "tooltip": "Подтверждение удаления профиля из каталога (must be true).",
        "verification_note": "remove route: 400 если false; retires catalog entry.",
    },
    ("vpn_catalog", "host"): {
        "disclosure": "advanced",
        "tooltip": "Адрес роутера для live catalog-status probe.",
        "verification_note": "catalog-status live tuple field.",
    },
    ("vpn_catalog", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username для live catalog-status probe.",
        "verification_note": "catalog-status live tuple field.",
    },
    ("vpn_catalog", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential для catalog-status probe.",
        "verification_note": "credential ref only.",
    },
    ("vpn_catalog", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 SSH host key pin для catalog-status.",
        "verification_note": "Gate A preflight on live path.",
    },
    ("vpn_catalog", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind для SSH live session.",
        "verification_note": "optional live param.",
    },
    ("vpn_catalog", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "router_id для live tuple из store.",
        "verification_note": "optional store indirection.",
    },
    # --- internet_status ---
    ("internet_status", "host"): {
        "disclosure": "advanced",
        "tooltip": "Адрес роутера для read-only show internet status.",
        "verification_note": "observe route live tuple field.",
    },
    ("internet_status", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username для internet status observe.",
        "verification_note": "observe route live tuple field.",
    },
    ("internet_status", "credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Legacy alias credential ref (prefer router_credential_ref_id).",
        "verification_note": "observe body alias; sealed ref only.",
    },
    ("internet_status", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential для internet status observe.",
        "verification_note": "credential ref only.",
    },
    ("internet_status", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 SSH host key pin для observe.",
        "verification_note": "Gate A preflight on live path.",
    },
    ("internet_status", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Локальный bind для SSH live session.",
        "verification_note": "optional live param.",
    },
    ("internet_status", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "router_id для live tuple из store.",
        "verification_note": "optional store indirection.",
    },
    ("internet_status", "allow_insecure_http"): {
        "disclosure": "advanced",
        "tooltip": "Зарезервировано в схеме observe; handler пока не читает — noop.",
        "verification_note": (
            "declared on InternetStatusObserveBody; observe path never reads it — "
            "accepted for forward-compat only; no HTTP probe behavior."
        ),
    },
    # --- standing_network_preferences ---
    ("standing_network_preferences", "staff_ssid"): {
        "disclosure": "simple",
        "tooltip": "SSID staff Wi‑Fi по умолчанию (host-persisted, без plaintext PSK).",
        "verification_note": "PUT standing prefs; no password field accepted.",
    },
    ("standing_network_preferences", "staff_password_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed credential ref для staff Wi‑Fi PSK.",
        "verification_note": "credential ref only; secret-shaped keys rejected 422.",
    },
    ("standing_network_preferences", "guest_default_ssid"): {
        "disclosure": "simple",
        "tooltip": "SSID guest AP по умолчанию (host-persisted).",
        "verification_note": "PUT standing prefs; guest_default_enabled true rejected.",
    },
    ("standing_network_preferences", "guest_default_enabled"): {
        "disclosure": "advanced",
        "tooltip": "Guest AP enabled default (read-only in API; true → 422).",
        "verification_note": "guest_default_enabled true rejected; hardware apply separate.",
    },
    ("standing_network_preferences", "staff_ap_id"): {
        "disclosure": "simple",
        "tooltip": (
            "Точка доступа, назначенная рабочей сетью "
            "(host-persisted; NULL — не назначено)."
        ),
        "verification_note": (
            "PUT standing prefs; canonical shape WifiMaster[0|1]/AccessPoint[0-6] validated, "
            "no device-eligibility narrowing."
        ),
    },
    ("standing_network_preferences", "guest_ap_id"): {
        "disclosure": "simple",
        "tooltip": (
            "Точка доступа, назначенная гостевой сетью "
            "(host-persisted; NULL — не назначено)."
        ),
        "verification_note": (
            "PUT standing prefs; canonical shape WifiMaster[0|1]/AccessPoint[0-6] validated, "
            "no device-eligibility narrowing."
        ),
    },
    # --- remembered_uplink ---
    ("remembered_uplink", "router_id"): {
        "disclosure": "simple",
        "tooltip": "Router ID для remembered uplink row (optional).",
        "verification_note": "PUT remembered uplink; host SQLite persistence.",
    },
    ("remembered_uplink", "ssid"): {
        "disclosure": "simple",
        "tooltip": "SSID upstream Wi‑Fi для auto-reapply watchdog.",
        "verification_note": "credential_ref only; password keys forbidden.",
    },
    ("remembered_uplink", "band"): {
        "disclosure": "simple",
        "tooltip": "Диапазон Wi‑Fi (BAND_2_4GHZ / BAND_5GHZ).",
        "verification_note": "mapped to WifiMaster station on apply.",
    },
    ("remembered_uplink", "station_id"): {
        "disclosure": "advanced",
        "tooltip": "WifiMasterN/WifiStation0 override (optional).",
        "verification_note": "defaults from band when unset.",
    },
    ("remembered_uplink", "credential_ref_id"): {
        "disclosure": "simple",
        "tooltip": "Sealed credential ref для upstream PSK.",
        "verification_note": "no plaintext password column in remembered_uplink table.",
    },
    ("remembered_uplink", "desired_active"): {
        "disclosure": "simple",
        "tooltip": "Включить uplink watchdog reapply для этой записи.",
        "verification_note": "false → poll_once skips observe/apply.",
    },
    # --- traffic_discovery ---
    ("traffic_discovery", "confidence"): {
        "disclosure": "simple",
        "tooltip": "Proposal confidence 0.0–1.0.",
        "verification_note": "proposals-only; auto_apply_blocked always true.",
    },
    ("traffic_discovery", "evidence"): {
        "disclosure": "advanced",
        "tooltip": "Opaque evidence dict (dynamic keys).",
        "verification_note": (
            "dict[str,Any] opaque; nested keys not enumerated; digest stored only."
        ),
    },
    ("traffic_discovery", "route_intent"): {
        "disclosure": "advanced",
        "tooltip": "Opaque route intent dict (dynamic keys).",
        "verification_note": (
            "dict[str,Any] opaque; nested keys not enumerated; proposal_json unset."
        ),
    },
    ("traffic_discovery", "router_id"): {
        "disclosure": "simple",
        "tooltip": "Router ID для traffic observation.",
        "verification_note": "observation record; evidence not echoed in response.",
    },
    ("traffic_discovery", "source"): {
        "disclosure": "advanced",
        "tooltip": "Evidence source label (default offline).",
        "verification_note": "observation record.",
    },
    ("traffic_discovery", "traffic_observation_id"): {
        "disclosure": "simple",
        "tooltip": "Existing observation ID для proposal.",
        "verification_note": "create proposal; auto_apply_blocked.",
    },
    ("traffic_discovery", "trusted_policy"): {
        "disclosure": "advanced",
        "tooltip": "Trusted policy flag (default false).",
        "verification_note": "create proposal; does not enable auto-apply.",
    },
    ("traffic_discovery", "ttl_seconds"): {
        "disclosure": "advanced",
        "tooltip": "Proposal TTL seconds (1–86400).",
        "verification_note": "create proposal.",
    },
    # --- rci_sealed ---
    ("rci_sealed", "interface_id"): {
        "disclosure": "advanced",
        "tooltip": (
            "Interface ID для interface up/down; обязателен только при "
            "operation interface_up или interface_down."
        ),
        "verification_note": (
            "_FakeRciTransport synthetic ack only (rci_mutation_routes.py ~76–110, ~222); "
            "no live network I/O."
        ),
    },
    ("rci_sealed", "operation"): {
        "disclosure": "simple",
        "tooltip": (
            "UI route selector (не body FailSafe enum): fail_safe_arm, fail_safe_disarm, "
            "interface_up, interface_down, configuration_save, reboot. "
            "Тело запроса — body_operation_by_value; маршрут — route_key_by_value."
        ),
        "verification_note": (
            "_FakeRciTransport synthetic ack only (rci_mutation_routes.py ~76–110, ~222); "
            "no live network I/O."
        ),
    },
    # --- wifi_site_survey ---
    ("wifi_site_survey", "allow_insecure_http"): {
        "disclosure": "advanced",
        "tooltip": "Allow insecure HTTP for live path.",
        "verification_note": (
            "fake mode: SYNTH-SSID-* fixtures (wifi_site_survey_routes.py ~68–95); "
            "live path Gate A gated."
        ),
    },
    ("wifi_site_survey", "credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Legacy alias for router_credential_ref_id.",
        "verification_note": "read-only site survey; fake or live read session.",
    },
    ("wifi_site_survey", "host"): {
        "disclosure": "advanced",
        "tooltip": "Router host for live site survey.",
        "verification_note": "fake mode uses SYNTH fixtures; live requires full tuple.",
    },
    ("wifi_site_survey", "radio"): {
        "disclosure": "simple",
        "tooltip": "WifiMaster0 or WifiMaster1 radio.",
        "verification_note": (
            "fake mode: SYNTH-SSID-* fixtures (wifi_site_survey_routes.py ~68–95)."
        ),
    },
    ("wifi_site_survey", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential ref for live path.",
        "verification_note": "read-only site survey session.",
    },
    ("wifi_site_survey", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "Registered router_id for live tuple indirection.",
        "verification_note": "optional store indirection.",
    },
    ("wifi_site_survey", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Local bind address for SSH.",
        "verification_note": "optional live param.",
    },
    ("wifi_site_survey", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 SSH host key pin.",
        "verification_note": "Gate A preflight on live path.",
    },
    ("wifi_site_survey", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username for live site survey.",
        "verification_note": "live tuple field.",
    },
    # --- wifi_observed ---
    ("wifi_observed", "allow_insecure_http"): {
        "disclosure": "advanced",
        "tooltip": "Allow insecure HTTP for live path.",
        "verification_note": (
            "fake transport fixture readbacks (wifi_observed_routes.py ~72–115); "
            "non-certifying."
        ),
    },
    ("wifi_observed", "ap_ids"): {
        "disclosure": "simple",
        "tooltip": "List of AP IDs to observe.",
        "verification_note": "read-only observed-state; allowlist validated.",
    },
    ("wifi_observed", "credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Legacy alias for router_credential_ref_id.",
        "verification_note": "read-only observed-state.",
    },
    ("wifi_observed", "desired"): {
        "disclosure": "advanced",
        "tooltip": "Optional desired intent for drift compare.",
        "verification_note": "nested desired.* fields; read-only compare.",
    },
    ("wifi_observed", "desired.band"): {
        "disclosure": "advanced",
        "tooltip": "Desired Wi‑Fi band for drift compare.",
        "verification_note": "nested desired field; read-only.",
    },
    ("wifi_observed", "desired.enabled"): {
        "disclosure": "advanced",
        "tooltip": "Desired AP enabled flag for drift compare.",
        "verification_note": "nested desired field; read-only.",
    },
    ("wifi_observed", "desired.ssid"): {
        "disclosure": "advanced",
        "tooltip": "Desired SSID for drift compare.",
        "verification_note": "nested desired field; read-only.",
    },
    ("wifi_observed", "desired.wpa_mode"): {
        "disclosure": "advanced",
        "tooltip": "Desired WPA mode for drift compare.",
        "verification_note": "nested desired field; read-only.",
    },
    ("wifi_observed", "desired_ap_id"): {
        "disclosure": "advanced",
        "tooltip": "Target AP for desired intent.",
        "verification_note": "required when desired supplied.",
    },
    ("wifi_observed", "host"): {
        "disclosure": "advanced",
        "tooltip": "Router host for live observed-state.",
        "verification_note": "fake fixture or live read session.",
    },
    ("wifi_observed", "router_credential_ref_id"): {
        "disclosure": "advanced",
        "tooltip": "Sealed SSH credential ref.",
        "verification_note": "read-only observed-state.",
    },
    ("wifi_observed", "router_id"): {
        "disclosure": "advanced",
        "tooltip": "Registered router_id for live tuple.",
        "verification_note": "optional store indirection.",
    },
    ("wifi_observed", "source_address"): {
        "disclosure": "advanced",
        "tooltip": "Local bind address for SSH.",
        "verification_note": "optional live param.",
    },
    ("wifi_observed", "ssh_host_key_sha256"): {
        "disclosure": "advanced",
        "tooltip": "SHA256 SSH host key pin.",
        "verification_note": "Gate A preflight on live path.",
    },
    ("wifi_observed", "username"): {
        "disclosure": "advanced",
        "tooltip": "SSH username for live observed-state.",
        "verification_note": "live tuple field.",
    },
    # --- credentials (manual) ---
    ("credentials", "kind"): {
        "disclosure": "advanced",
        "tooltip": "Credential kind (default RouterManagementPassword).",
        "verification_note": "PutCredentialBody; vault sealed, metadata only in list.",
    },
    ("credentials", "secret"): {
        "disclosure": "simple",
        "tooltip": "Secret value intake for put/rotate (write-only).",
        "verification_note": (
            "Значение не сохраняется в manifest и не отображается; "
            "sealed в vault (PutCredentialBody / RotateCredentialBody)."
        ),
    },
    # --- commissioning (manual) ---
    ("commissioning", "mode"): {
        "disclosure": "advanced",
        "tooltip": "Adapter mode override (default host.adapter_mode).",
        "verification_note": "read-only MVP commissioning; zero router writes.",
    },
    ("commissioning", "router_id"): {
        "disclosure": "simple",
        "tooltip": "Router ID для commissioning run.",
        "verification_note": "read-only MVP commissioning; zero router writes.",
    },
    # --- keendns ---
    ("keendns", "components_raw"): {
        "disclosure": "advanced",
        "tooltip": (
            "Опциональный сырой вывод components для offline-classify статуса KeenDNS. "
            "Не для обычного заполнения оператором; simple mode скрывает."
        ),
        "verification_note": (
            "documentation_sourced_unconfirmed: только status/preview, маршрута apply нет; "
            "грамматика не device-certified; внешняя cloud-запись требует T4 Human Gate."
        ),
    },
    ("keendns", "ndns_show_raw"): {
        "disclosure": "advanced",
        "tooltip": (
            "Опциональный сырой вывод ndns show для offline-classify статуса. "
            "Не для обычного заполнения оператором; simple mode скрывает."
        ),
        "verification_note": (
            "documentation_sourced_unconfirmed: только status/preview, маршрута apply нет; "
            "грамматика не device-certified; внешняя cloud-запись требует T4 Human Gate."
        ),
    },
    ("keendns", "get_booked_raw"): {
        "disclosure": "advanced",
        "tooltip": (
            "Опциональный сырой вывод get booked для offline-classify статуса. "
            "Не для обычного заполнения оператором; simple mode скрывает."
        ),
        "verification_note": (
            "documentation_sourced_unconfirmed: только status/preview, маршрута apply нет; "
            "грамматика не device-certified; внешняя cloud-запись требует T4 Human Gate."
        ),
    },
    ("keendns", "intent_kind"): {
        "disclosure": "simple",
        "tooltip": "Намерение preview: book (зарегистрировать имя) или drop (освободить).",
        "verification_note": (
            "documentation_sourced_unconfirmed: sealed preview compile only; "
            "маршрута apply нет по построению; dispatch в облако недоступен без Human Gate; "
            "грамматика не device-certified."
        ),
    },
    ("keendns", "name"): {
        "disclosure": "simple",
        "tooltip": "Имя KeenDNS/CrazeDNS записи (1–64 символа).",
        "verification_note": (
            "documentation_sourced_unconfirmed: preview-only; "
            "грамматика из документации, не device-verified."
        ),
    },
    ("keendns", "domain"): {
        "disclosure": "simple",
        "tooltip": "Домен KeenDNS/CrazeDNS (1–64 символа).",
        "verification_note": (
            "documentation_sourced_unconfirmed: preview-only; "
            "грамматика из документации, не device-verified."
        ),
    },
    ("keendns", "mode"): {
        "disclosure": "simple",
        "tooltip": (
            "Режим регистрации: auto, cloud или direct. "
            "Обязателен при intent_kind=book; при drop должен быть опущен (422 иначе)."
        ),
        "verification_note": (
            "documentation_sourced_unconfirmed: preview-only; "
            "cloud/direct подразумевают внешнюю запись — apply route отсутствует, Human Gate; "
            "грамматика из документации, не device-verified."
        ),
    },
}


class FamilySpec(TypedDict):
    title: str
    models: tuple[type[BaseModel], ...]
    routes: dict[str, str]
    verification_status: str | None


class ManualFieldSpec(TypedDict):
    name: str
    type: str
    required: bool
    default: Any
    enum: NotRequired[list[str] | None]
    constraints: NotRequired[dict[str, int]]
    body_operation_by_value: NotRequired[dict[str, str]]
    route_key_by_value: NotRequired[dict[str, str]]
    required_when: NotRequired[dict[str, list[str]]]
    value_schema: NotRequired[str]


RCI_SEALED_UI_OPERATIONS: tuple[str, ...] = (
    "fail_safe_arm",
    "fail_safe_disarm",
    "interface_up",
    "interface_down",
    "configuration_save",
    "reboot",
)

RCI_SEALED_BODY_OPERATION_BY_VALUE: dict[str, str] = {
    "fail_safe_arm": "arm_timer_reboot_60",
    "fail_safe_disarm": "disarm_timer",
    "interface_up": "interface_up",
    "interface_down": "interface_down",
    "configuration_save": "configuration_save",
    "reboot": "reboot",
}

RCI_SEALED_ROUTE_KEY_BY_VALUE: dict[str, str] = {
    "fail_safe_arm": "fail_safe_arm",
    "fail_safe_disarm": "fail_safe_disarm",
    "interface_up": "interface",
    "interface_down": "interface",
    "configuration_save": "system_save",
    "reboot": "system_reboot",
}


# Manual-dict request bodies — no pydantic reflection; sentinel-tested in tests.
MANUAL_FIELD_SPECS: dict[str, list[ManualFieldSpec]] = {
    "commissioning": [
        {"name": "router_id", "type": "string", "required": True, "default": None},
        {"name": "mode", "type": "string", "required": False, "default": None},
    ],
    "rci_sealed": [
        {
            "name": "operation",
            "type": "enum",
            "required": False,
            "default": "fail_safe_arm",
            "enum": list(RCI_SEALED_UI_OPERATIONS),
            "body_operation_by_value": dict(RCI_SEALED_BODY_OPERATION_BY_VALUE),
            "route_key_by_value": dict(RCI_SEALED_ROUTE_KEY_BY_VALUE),
        },
        {
            "name": "interface_id",
            "type": "string",
            "required": False,
            "default": None,
            "constraints": {"min_length": 1, "max_length": 64},
            "required_when": {"operation": ["interface_up", "interface_down"]},
        },
    ],
}

# Manual overlay on pydantic families (legacy dict PUT bodies parsed in routes).
MANUAL_FIELD_OVERLAY: dict[str, list[ManualFieldSpec]] = {
    "desired_revision": [
        {
            "name": "based_on_observation_id",
            "type": "string",
            "required": True,
            "default": None,
        },
        {"name": "assignments", "type": "array", "required": False, "default": None},
        {"name": "reason", "type": "string", "required": False, "default": None},
    ],
    "keendns": [
        {
            "name": "mode",
            "type": "enum",
            "required": False,
            "default": None,
            "enum": ["auto", "cloud", "direct"],
            "required_when": {"intent_kind": ["book"]},
        },
    ],
}


FAMILY_SPECS: dict[str, FamilySpec] = {
    "wifi_ap": {
        "title": "Wi‑Fi точка доступа",
        "models": (WifiPreviewBody, WifiApplyBody, WifiTeardownBody),
        "routes": {
            "apply": f"{API_PREFIX}/wifi/apply",
            "preview": f"{API_PREFIX}/wifi/preview",
            "teardown": f"{API_PREFIX}/wifi/teardown",
        },
        "verification_status": "device_verified_wpa2",
    },
    "wifi_station": {
        "title": "Wi‑Fi станция (WISP)",
        "models": (WifiStationPreviewBody, WifiStationApplyBody, WifiStationTeardownBody),
        "routes": {
            "apply": f"{API_PREFIX}/wifi/station/apply",
            "preview": f"{API_PREFIX}/wifi/station/preview",
            "teardown": f"{API_PREFIX}/wifi/station/teardown",
        },
        "verification_status": "device_accepted_grammar",
    },
    "wireguard": {
        "title": "WireGuard / AmneziaWG",
        "models": (
            WireguardPreviewBody,
            WireguardApplyBody,
            WireguardTeardownBody,
            WireguardObserveBody,
        ),
        "routes": {
            "apply": f"{API_PREFIX}/wireguard/apply",
            "preview": f"{API_PREFIX}/wireguard/preview",
            "teardown": f"{API_PREFIX}/wireguard/teardown",
            "observe": f"{API_PREFIX}/wireguard/observe",
        },
        "verification_status": None,
    },
    "vlan": {
        "title": "VLAN",
        "models": (VlanPreviewBody,),
        "routes": {"preview": f"{API_PREFIX}/vlan/preview"},
        "verification_status": "offline_unverified",
    },
    "dhcp": {
        "title": "DHCP",
        "models": (DhcpPreviewBody,),
        "routes": {"preview": f"{API_PREFIX}/dhcp/preview"},
        "verification_status": "offline_unverified",
    },
    "dns": {
        "title": "DNS",
        "models": (DnsPreviewBody,),
        "routes": {"preview": f"{API_PREFIX}/dns/preview"},
        "verification_status": "offline_unverified",
    },
    "firewall": {
        "title": "Firewall",
        "models": (FirewallPreviewBody,),
        "routes": {"preview": f"{API_PREFIX}/firewall/preview"},
        "verification_status": "offline_unverified",
    },
    "vpn_policy_routing": {
        "title": "VPN policy routing",
        "models": (VpnPolicyPreviewBody,),
        "routes": {"preview": f"{API_PREFIX}/vpn/policy-routing/preview"},
        "verification_status": "help_verified_grammar_unapplied",
    },
    "wizard_draft": {
        "title": "Wizard draft router",
        "models": (WizardDraftRouterBody,),
        "routes": {"create": f"{API_PREFIX}/lab/wizard-draft-router"},
        "verification_status": "lab_draft_enroll",
    },
    "bootstrap_discovery": {
        "title": "Bootstrap discovery",
        "models": (BootstrapDiscoveryBody,),
        "routes": {"discover": f"{API_PREFIX}/lab/bootstrap-discovery"},
        "verification_status": "non_certifying_readonly",
    },
    "router_discovery": {
        "title": "Router discovery",
        "models": (RouterDiscoveryBody,),
        "routes": {"discover": f"{API_PREFIX}/lab/router-discovery"},
        "verification_status": "non_certifying_readonly",
    },
    "connection_health": {
        "title": "Connection health",
        "models": (ConnectionHealthBody,),
        "routes": {"assess": f"{API_PREFIX}/lab/connection-health"},
        "verification_status": "non_certifying_readonly",
    },
    "ssh_host_key": {
        "title": "SSH host key pin",
        "models": (SshHostKeyLearnBody, SshHostKeyConfirmBody),
        "routes": {
            "learn": f"{API_PREFIX}/routers/{{router_id}}/ssh-host-key/learn",
            "confirm": f"{API_PREFIX}/routers/{{router_id}}/ssh-host-key/confirm",
        },
        "verification_status": "tofu_pin",
    },
    "connection_context": {
        "title": "Connection context",
        "models": (ManagementUsernameBody,),
        "routes": {
            "management_username": (
                f"{API_PREFIX}/routers/{{router_id}}/management-username"
            ),
        },
        "verification_status": "server_side_username_store",
    },
    "enroll": {
        "title": "Router enroll",
        "models": (EnrollRouterBody,),
        "routes": {"enroll": f"{API_PREFIX}/routers"},
        "verification_status": "gate_a_gated_live",
    },
    "change_plan": {
        "title": "Change plan",
        "models": (CreatePlanBody, ConfirmPlanBody),
        "routes": {
            "create": f"{API_PREFIX}/routers/{{router_id}}/plans",
            "confirm": f"{API_PREFIX}/routers/{{router_id}}/plans/{{plan_id}}/confirm",
        },
        "verification_status": "sqlite_queue_no_live_router",
    },
    "deployment": {
        "title": "Deployment revision",
        "models": (CreateDeploymentRevisionBody,),
        "routes": {
            "create": f"{API_PREFIX}/routers/{{router_id}}/deployment-revisions",
        },
        "verification_status": "sqlite_only",
    },
    "desired_revision": {
        "title": "Desired revision",
        "models": (CreateDesiredRevisionBody,),
        "routes": {
            "create": f"{API_PREFIX}/routers/{{router_id}}/desired-revisions",
            "put": f"{API_PREFIX}/routers/{{router_id}}/desired-revision",
        },
        "verification_status": "sqlite_only",
    },
    "vpn_profile": {
        "title": "VPN profile",
        "models": (
            VpnProfileParsePreviewBody,
            VpnProfileImportBody,
            VpnProfileActivateBody,
            VpnProfileDeactivateBody,
        ),
        "routes": {
            "parse_preview": f"{API_PREFIX}/vpn-profiles/parse-preview",
            "import": f"{API_PREFIX}/vpn-profiles/import",
            "activate": f"{API_PREFIX}/vpn-profiles/{{profile_id}}/activate",
            "deactivate": f"{API_PREFIX}/vpn-profiles/deactivate",
        },
        "verification_status": "parse_preview_and_import",
    },
    "vpn_catalog": {
        "title": "VPN catalog",
        "models": (VpnCatalogStatusBody, VpnCatalogRemoveBody),
        "routes": {
            "catalog_status": f"{API_PREFIX}/vpn-profiles/catalog-status",
            "remove": f"{API_PREFIX}/vpn-profiles/{{profile_id}}/remove",
        },
        "verification_status": "catalog_status_and_remove",
    },
    "internet_status": {
        "title": "Internet status",
        "models": (InternetStatusObserveBody,),
        "routes": {
            "observe": f"{API_PREFIX}/internet-status/observe",
        },
        "verification_status": "read_only_observe",
    },
    "standing_network_preferences": {
        "title": "Standing network preferences",
        "models": (PutStandingNetworkPreferencesBody,),
        "routes": {
            "put": f"{API_PREFIX}/standing-network-preferences",
        },
        "verification_status": "host_persisted_defaults",
    },
    "remembered_uplink": {
        "title": "Remembered uplink",
        "models": (PutRememberedUplinkBody,),
        "routes": {
            "put": f"{API_PREFIX}/remembered-uplink",
        },
        "verification_status": "host_persisted_uplink_watchdog",
    },
    "traffic_discovery": {
        "title": "Traffic discovery",
        "models": (RecordObservationBody, CreateProposalBody),
        "routes": {
            "observation": f"{API_PREFIX}/traffic/observations",
            "proposal": f"{API_PREFIX}/traffic/proposals",
        },
        "verification_status": "proposals_only",
    },
    "rci_sealed": {
        "title": "Sealed RCI mutations",
        "models": (),
        "routes": {
            "fail_safe_arm": f"{API_PREFIX}/routers/{{router_id}}/rci/fail-safe/arm",
            "fail_safe_disarm": f"{API_PREFIX}/routers/{{router_id}}/rci/fail-safe/disarm",
            "interface": f"{API_PREFIX}/routers/{{router_id}}/rci/interface",
            "system_save": (
                f"{API_PREFIX}/routers/{{router_id}}/rci/system/configuration-save"
            ),
            "system_reboot": f"{API_PREFIX}/routers/{{router_id}}/rci/system/reboot",
        },
        "verification_status": "fake_rci_transport",
    },
    "wifi_site_survey": {
        "title": "Wi‑Fi site survey",
        "models": (WifiSiteSurveyBody,),
        "routes": {"survey": f"{API_PREFIX}/wifi/site-survey"},
        "verification_status": "read_only_fake_or_live",
    },
    "wifi_observed": {
        "title": "Wi‑Fi observed state",
        "models": (WifiObservedStateBody,),
        "routes": {"observed": f"{API_PREFIX}/wifi/observed-state"},
        "verification_status": "read_only_non_certifying",
    },
    "credentials": {
        "title": "Router credentials",
        "models": (PutCredentialBody, RotateCredentialBody),
        "routes": {
            "put": f"{API_PREFIX}/routers/{{router_id}}/credentials",
            "rotate": (
                f"{API_PREFIX}/routers/{{router_id}}/credentials/"
                f"{{credential_ref_id}}/rotate"
            ),
        },
        "verification_status": "vault_sealed",
    },
    "commissioning": {
        "title": "Commissioning",
        "models": (),
        "routes": {
            "create": f"{API_PREFIX}/sites/{{site_id}}/commissioning-runs",
        },
        "verification_status": "readonly_mvp",
    },
    "keendns": {
        "title": "KeenDNS / CrazeDNS (preview)",
        "models": (KeenDnsStatusBody, KeenDnsPreviewBody),
        "routes": {
            "status": f"{API_PREFIX}/keendns/status",
            "preview": f"{API_PREFIX}/keendns/preview",
        },
        "verification_status": "documentation_sourced_unconfirmed",
    },
}


# Live FastAPI body routes must appear in FAMILY_SPECS.routes or BODY_ROUTE_EXEMPTIONS.
# Reviewed 2026-08-01: exemptions remain ops/auth/out-of-scope surfaces only — not silent
# inheritance for operator field families (keendns and peers belong in FAMILY_SPECS).
BODY_ROUTE_EXEMPTIONS: dict[str, str] = {
    "/login": "Hub auth form; not operator UI field-manifest family",
    f"{API_PREFIX}/routers/{{router_id}}/preflight": (
        "Gate-A ops preflight; optional body; not operator field family in this cycle"
    ),
    f"{API_PREFIX}/sites/{{site_id}}/event-presets": (
        "Event-preset surface not in ui-field-manifest scope yet"
    ),
    f"{API_PREFIX}/event-presets/{{preset_id}}/revisions": (
        "Event-preset surface not in ui-field-manifest scope yet"
    ),
    f"{API_PREFIX}/event-presets/{{preset_id}}/publish": (
        "Event-preset surface not in ui-field-manifest scope yet"
    ),
    f"{API_PREFIX}/event-presets/{{preset_id}}/publications": (
        "Event-preset surface not in ui-field-manifest scope yet"
    ),
    f"{API_PREFIX}/lab/host-http-probe": (
        "Host-side lab probe; preset ref ids only; not operator field family"
    ),
    f"{API_PREFIX}/lab/host-tls-probe": (
        "Host-side lab probe; preset ref ids only; not operator field family"
    ),
    f"{API_PREFIX}/lab/host-internet-probe": (
        "Host-side lab probe; fixed targets profile; not operator field family"
    ),
    f"{API_PREFIX}/entry-pages": (
        "Entry page catalog create; audience only; not operator field-manifest family"
    ),
    f"{API_PREFIX}/entry-pages/{{page_id}}/draft": (
        "Entry page draft document; canonical schema validated server-side"
    ),
    f"{API_PREFIX}/entry-pages/{{page_id}}/publish": (
        "Entry page publish pointer swap; revision id only"
    ),
    f"{API_PREFIX}/entry-pages/{{page_id}}/unpublish": (
        "Entry page unpublish; empty body"
    ),
    f"{API_PREFIX}/entry-pages/{{page_id}}/self-check": (
        "Entry page in-process self-check; empty body"
    ),
}

BODY_ROUTE_GUARD_DECISION_TABLE: tuple[dict[str, str], ...] = (
    {
        "option": "A_extend_FAMILY_SPECS_only",
        "verdict": "rejected",
        "why": "Closes new families but leaves silent new-route hole (AC-3)",
    },
    {
        "option": "B_walk_create_app_APIRoute_body_field",
        "verdict": "chosen",
        "why": (
            "SSOT is live mounted app routes; fail if body route path not in "
            "union(FAMILY_SPECS.routes) and not in explicit BODY_ROUTE_EXEMPTIONS"
        ),
    },
    {
        "option": "C_openapi_requestBody_paths",
        "verdict": "rejected_as_primary",
        "why": "OpenAPI can lag route modules; secondary only",
    },
    {
        "option": "D_ast_regex_scan_route_modules",
        "verdict": "rejected",
        "why": "Brittle; not actual mounted routes; misses dynamic includes",
    },
    {
        "option": "E_import_star_routes_modules",
        "verdict": "rejected",
        "why": "Module inventory can drift from create_app include_router list",
    },
)

BODY_ROUTE_GUARD_RESIDUALS: tuple[str, ...] = (
    "Handlers using await request.json() without body_field (standing-network-preferences PUT, "
    "remembered-uplink PUT) — typed models in FAMILY_SPECS; walk cannot see body_field",
    "Routes without request body (GET/DELETE/empty POST)",
    "Intentionally exempted BODY_ROUTE_EXEMPTIONS (must be non-silent, with reason string)",
    "Nested opaque dict[str,Any] internals (existing residual)",
    "Unknown extras when handler lacks extra=forbid (existing residual; routes not owned)",
)


def _join_mounted_path(prefix: str, path: str) -> str:
    if not prefix:
        return path
    if path.startswith("/"):
        combined = prefix.rstrip("/") + path
    else:
        combined = prefix.rstrip("/") + "/" + path
    while "//" in combined:
        combined = combined.replace("//", "/")
    return combined


def _walk_body_route_paths(routes: list[Any], *, prefix: str = "") -> set[str]:
    from fastapi.routing import APIRoute
    from starlette.routing import Mount

    paths: set[str] = set()
    for route in routes:
        if isinstance(route, APIRoute):
            if route.body_field is not None:
                paths.add(route.path if not prefix else _join_mounted_path(prefix, route.path))
        elif isinstance(route, Mount):
            mount_prefix = _join_mounted_path(prefix, route.path)
            paths.update(_walk_body_route_paths(route.routes, prefix=mount_prefix))
    return paths


def collect_live_body_route_paths() -> frozenset[str]:
    from router_control_host.app import create_app

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "ui-manifest-route-coverage.sqlite3"
        app = create_app(db_path=db_path, enable_worker=False, skip_gate_a_load=True)
        try:
            return frozenset(_walk_body_route_paths(app.routes))
        finally:
            app.state.host.runtime.store._conn.close()


def family_spec_route_paths() -> frozenset[str]:
    paths: set[str] = set()
    for spec in FAMILY_SPECS.values():
        paths.update(spec["routes"].values())
    return frozenset(paths)


def assert_body_route_coverage() -> None:
    live_paths = collect_live_body_route_paths()
    allowed = family_spec_route_paths() | frozenset(BODY_ROUTE_EXEMPTIONS.keys())
    uncovered = sorted(live_paths - allowed)
    if uncovered:
        raise SystemExit(
            "body route paths not in FAMILY_SPECS.routes and not BODY_ROUTE_EXEMPTIONS: "
            + ", ".join(uncovered)
        )


def _is_opaque_dict(annotation: Any) -> bool:
    """True for dict[str, Any] — dynamic nested keys must not be invented."""
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is not dict:
        return False
    args = get_args(annotation)
    if len(args) != 2:
        return False
    key_ann, val_ann = args
    if key_ann is not str:
        return False
    val_ann = _unwrap_annotated(val_ann)
    return val_ann is Any


def _is_scalar_list(annotation: Any) -> bool:
    """True for list[str|int|float|bool] — safe-by-construction, no dotted children."""
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is not list:
        return False
    args = get_args(annotation)
    if len(args) != 1:
        return False
    item = _strip_optional(args[0])
    if item in (str, int, float, bool):
        return True
    return getattr(item, "__name__", "") == "StrictInt"


def _unwrap_annotated(annotation: Any) -> Any:
    origin = get_origin(annotation)
    if origin is Annotated:
        args = get_args(annotation)
        if args:
            return _unwrap_annotated(args[0])
    return annotation


def _strip_optional(annotation: Any) -> Any:
    annotation = _unwrap_annotated(annotation)
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _is_basemodel_subtype(annotation: Any) -> bool:
    annotation = _unwrap_annotated(annotation)
    try:
        return isinstance(annotation, type) and issubclass(annotation, BaseModel)
    except TypeError:
        return False


def _list_item_basemodel(annotation: Any) -> type[BaseModel] | None:
    """Return a single list item BaseModel, or None when item is a union or non-model."""
    models = _list_element_models(annotation)
    if len(models) == 1:
        return models[0]
    return None


def _list_element_models(annotation: Any) -> list[type[BaseModel]]:
    """Extract BaseModel item types from list[...] (including list[A | B])."""
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is not list:
        return []
    args = get_args(annotation)
    if len(args) != 1:
        return []
    return _models_from_annotation(args[0])


def _models_from_annotation(annotation: Any) -> list[type[BaseModel]]:
    """All BaseModel types directly reachable from an annotation."""
    annotation = _strip_optional(annotation)
    if _is_basemodel_subtype(annotation):
        return [annotation]
    dict_model = _dict_value_model(annotation)
    if dict_model is not None:
        return [dict_model]
    return _basemodel_arms_from_annotation(annotation)


def _fail_unhandled_list_element(element_annotation: Any) -> None:
    """Fail-closed when list element looks like nested models but walk cannot proceed."""
    element_annotation = _strip_optional(element_annotation)
    origin = get_origin(element_annotation)
    if origin is Union or origin is types.UnionType:
        args = [arg for arg in get_args(element_annotation) if arg is not type(None)]
        if any(_is_basemodel_subtype(arg) for arg in args):
            return
    if _is_basemodel_subtype(element_annotation):
        return
    if origin is list:
        inner_args = get_args(element_annotation)
        if inner_args and _models_from_annotation(inner_args[0]):
            raise SystemExit(
                "list element annotation contains nested BaseModel shapes the walker "
                "cannot flatten; extend _child_models_from_annotation"
            )


def _enum_values(annotation: Any) -> list[str] | None:
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is Literal:
        values = get_args(annotation)
        return [str(v) for v in values]
    if _is_basemodel_subtype(annotation):
        return None
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return [str(member.value) for member in annotation]
    return None


def _field_type_name(annotation: Any) -> str:
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is Literal:
        return "enum"
    if origin is list:
        return "array"
    if origin is dict:
        return "object"
    if origin is Union:
        return "object"
    if _is_basemodel_subtype(annotation):
        return "object"
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return "enum"
    if annotation in (int,) or getattr(annotation, "__name__", "") == "StrictInt":
        return "integer"
    if annotation is float:
        return "number"
    if annotation is bool:
        return "boolean"
    if annotation is str:
        return "string"
    name = getattr(annotation, "__name__", "")
    if name == "StrictInt":
        return "integer"
    return "string"


def _extract_constraints(field_info: FieldInfo) -> dict[str, int]:
    constraints: dict[str, int] = {}
    for item in field_info.metadata:
        min_length = getattr(item, "min_length", None)
        if min_length is not None:
            constraints["min_length"] = int(min_length)
        max_length = getattr(item, "max_length", None)
        if max_length is not None:
            constraints["max_length"] = int(max_length)
        ge = getattr(item, "ge", None)
        if ge is not None:
            constraints["ge"] = int(ge) if isinstance(ge, (int, bool)) else int(ge)
        le = getattr(item, "le", None)
        if le is not None:
            constraints["le"] = int(le) if isinstance(le, (int, bool)) else int(le)
    return constraints


def _serialize_default(value: Any) -> Any:
    if value is PydanticUndefined:
        return None
    if isinstance(value, Enum):
        return value.value
    return value


def _find_field_info(models: tuple[type[BaseModel], ...], field_name: str) -> FieldInfo:
    for model in models:
        if field_name in model.model_fields:
            return model.model_fields[field_name]
    raise KeyError(field_name)


def _reflect_field(
    family_id: str,
    field_name: str,
    field_info: FieldInfo,
) -> dict[str, Any]:
    curated = CURATED_META.get((family_id, field_name))
    if curated is None:
        raise SystemExit(
            f"missing CURATED_META for {family_id}.{field_name}; "
            "add disclosure/tooltip/verification_note before exporting"
        )

    enum_values = _enum_values(field_info.annotation)
    if "." in field_name:
        output_name = field_name
    else:
        output_name = _manifest_wire_name(field_info, field_name)
    field_entry: dict[str, Any] = {
        "name": output_name,
        "type": _field_type_name(field_info.annotation),
        "required": field_info.is_required(),
        "default": _serialize_default(field_info.default),
        "constraints": _extract_constraints(field_info),
        "disclosure": curated["disclosure"],
        "tooltip": curated["tooltip"],
        "verification_note": curated["verification_note"],
    }
    reject_http_code = curated.get("reject_http_code")
    if reject_http_code is not None:
        field_entry["reject_http_code"] = reject_http_code
    if enum_values is not None:
        field_entry["enum"] = enum_values
    else:
        field_entry["enum"] = None
    if _is_opaque_dict(field_info.annotation):
        field_entry["value_schema"] = "opaque_object"
    return field_entry


def _union_field_names(models: tuple[type[BaseModel], ...]) -> list[str]:
    names: set[str] = set()
    for model in models:
        names.update(model.model_fields.keys())
    return sorted(names)


def _manifest_wire_name(field_info: FieldInfo, python_name: str) -> str:
    alias = field_info.alias
    if isinstance(alias, str) and alias:
        return alias
    validation_alias = field_info.validation_alias
    if isinstance(validation_alias, str) and validation_alias:
        return validation_alias
    if isinstance(validation_alias, AliasChoices):
        string_choices = [
            choice for choice in validation_alias.choices if isinstance(choice, str) and choice
        ]
        if len(string_choices) > 1:
            raise SystemExit(
                f"AliasChoices with multiple string wire names unsupported for field "
                f"{python_name!r}; found {string_choices!r} — export fails closed to prevent "
                "silent alias drop"
            )
        if len(string_choices) == 1:
            return string_choices[0]
        raise SystemExit(
            f"non-string validation_alias choices unsupported for field {python_name!r}; "
            "AliasChoices must include at least one string wire name"
        )
    if validation_alias is not None:
        raise SystemExit(
            f"non-string validation_alias unsupported for field {python_name!r}: "
            f"{type(validation_alias).__name__}"
        )
    return python_name


def _union_arms(annotation: Any) -> list[Any]:
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        return [arg for arg in get_args(annotation) if arg is not type(None)]
    return [annotation]


def _basemodel_arms_from_annotation(annotation: Any) -> list[type[BaseModel]]:
    arms: list[type[BaseModel]] = []
    for arm in _union_arms(annotation):
        if _is_basemodel_subtype(arm):
            arms.append(arm)
    return arms


def _dict_value_model(annotation: Any) -> type[BaseModel] | None:
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is dict:
        args = get_args(annotation)
        if len(args) == 2 and _is_basemodel_subtype(args[1]):
            return args[1]
    return None


def _child_models_from_annotation(annotation: Any) -> list[type[BaseModel]]:
    annotation = _strip_optional(annotation)
    origin = get_origin(annotation)
    if origin is list:
        args = get_args(annotation)
        if len(args) == 1:
            element_models = _models_from_annotation(args[0])
            if element_models:
                return element_models
            _fail_unhandled_list_element(args[0])
            return []
    return _models_from_annotation(annotation)


def _discover_dotted_names_from_model(
    model: type[BaseModel],
    prefix: str,
    *,
    model_ancestry: tuple[type[BaseModel], ...],
    out: set[str],
) -> None:
    if model in model_ancestry:
        return
    next_ancestry = model_ancestry + (model,)
    for python_name, field_info in model.model_fields.items():
        wire_name = _manifest_wire_name(field_info, python_name)
        dotted = f"{prefix}.{wire_name}"
        out.add(dotted)
        _discover_dotted_names_from_annotation(
            field_info.annotation,
            dotted,
            model_ancestry=next_ancestry,
            out=out,
        )


def _discover_dotted_names_from_annotation(
    annotation: Any,
    prefix: str,
    *,
    model_ancestry: tuple[type[BaseModel], ...],
    out: set[str],
) -> None:
    for child_model in _child_models_from_annotation(annotation):
        _discover_dotted_names_from_model(
            child_model, prefix, model_ancestry=model_ancestry, out=out
        )


def _find_field_in_model(model: type[BaseModel], segment: str) -> FieldInfo | None:
    for python_name, field_info in model.model_fields.items():
        wire_name = _manifest_wire_name(field_info, python_name)
        if segment in (wire_name, python_name):
            return field_info
    return None


def _find_field_in_annotation(annotation: Any, segment: str) -> FieldInfo | None:
    annotation = _strip_optional(annotation)
    for model in _basemodel_arms_from_annotation(annotation):
        found = _find_field_in_model(model, segment)
        if found is not None:
            return found
    for item_model in _list_element_models(annotation):
        found = _find_field_in_model(item_model, segment)
        if found is not None:
            return found
    dict_model = _dict_value_model(annotation)
    if dict_model is not None:
        return _find_field_in_model(dict_model, segment)
    return None


def _nested_dotted_field_names(models: tuple[type[BaseModel], ...]) -> list[str]:
    nested: set[str] = set()
    for field_name in _union_field_names(models):
        field_info = _find_field_info(models, field_name)
        wire_prefix = _manifest_wire_name(field_info, field_name)
        _discover_dotted_names_from_annotation(
            field_info.annotation,
            wire_prefix,
            model_ancestry=(),
            out=nested,
        )
    return sorted(nested)


def _all_manifest_field_names(
    family_id: str,
    models: tuple[type[BaseModel], ...],
) -> list[str]:
    names: set[str] = set(_union_field_names(models)) if models else set()
    if models:
        names.update(_nested_dotted_field_names(models))
    for manual in MANUAL_FIELD_SPECS.get(family_id, []):
        names.add(manual["name"])
    for manual in MANUAL_FIELD_OVERLAY.get(family_id, []):
        names.add(manual["name"])
    return sorted(names)


def _find_field_info_for_manifest(
    models: tuple[type[BaseModel], ...],
    field_name: str,
) -> FieldInfo:
    if "." not in field_name:
        return _find_field_info(models, field_name)
    parts = field_name.split(".")
    parent_info: FieldInfo | None = None
    for model in models:
        parent_info = _find_field_in_model(model, parts[0])
        if parent_info is not None:
            break
    if parent_info is None:
        raise KeyError(field_name)
    current_annotation = parent_info.annotation
    for segment in parts[1:]:
        field_info = _find_field_in_annotation(current_annotation, segment)
        if field_info is None:
            raise KeyError(field_name)
        if segment == parts[-1]:
            return field_info
        current_annotation = field_info.annotation
    raise KeyError(field_name)


def _find_manual_spec(family_id: str, field_name: str) -> ManualFieldSpec | None:
    for spec in MANUAL_FIELD_SPECS.get(family_id, []):
        if spec["name"] == field_name:
            return spec
    for spec in MANUAL_FIELD_OVERLAY.get(family_id, []):
        if spec["name"] == field_name:
            return spec
    return None


def _reflect_manual_field(family_id: str, spec: ManualFieldSpec) -> dict[str, Any]:
    field_name = spec["name"]
    curated = CURATED_META.get((family_id, field_name))
    if curated is None:
        raise SystemExit(
            f"missing CURATED_META for {family_id}.{field_name}; "
            "add disclosure/tooltip/verification_note before exporting"
        )
    field_entry: dict[str, Any] = {
        "name": field_name,
        "type": spec["type"],
        "required": spec["required"],
        "default": spec.get("default"),
        "constraints": spec.get("constraints", {}),
        "disclosure": curated["disclosure"],
        "tooltip": curated["tooltip"],
        "verification_note": curated["verification_note"],
        "enum": spec.get("enum"),
    }
    reject_http_code = curated.get("reject_http_code")
    if reject_http_code is not None:
        field_entry["reject_http_code"] = reject_http_code
    if "enum" not in field_entry:
        field_entry["enum"] = None
    body_operation_by_value = spec.get("body_operation_by_value")
    if body_operation_by_value is not None:
        field_entry["body_operation_by_value"] = body_operation_by_value
    route_key_by_value = spec.get("route_key_by_value")
    if route_key_by_value is not None:
        field_entry["route_key_by_value"] = route_key_by_value
    required_when = spec.get("required_when")
    if required_when is not None:
        field_entry["required_when"] = required_when
    value_schema = spec.get("value_schema")
    if value_schema is not None:
        field_entry["value_schema"] = value_schema
    return field_entry


def build_manifest(*, skip_route_coverage: bool = False) -> dict[str, Any]:
    if not skip_route_coverage:
        assert_body_route_coverage()
    families: dict[str, Any] = {}
    for family_id in sorted(FAMILY_SPECS.keys()):
        spec = FAMILY_SPECS[family_id]
        fields: list[dict[str, Any]] = []
        for field_name in _all_manifest_field_names(family_id, spec["models"]):
            manual = _find_manual_spec(family_id, field_name)
            if manual is not None:
                fields.append(_reflect_manual_field(family_id, manual))
                continue
            field_info = _find_field_info_for_manifest(spec["models"], field_name)
            fields.append(_reflect_field(family_id, field_name, field_info))
        families[family_id] = {
            "title": spec["title"],
            "routes": dict(sorted(spec["routes"].items())),
            "verification_status": spec["verification_status"],
            "fields": fields,
        }
    return {
        "schema_version": 1,
        "generated_by": "scripts/export-ui-field-manifest.py",
        "families": families,
    }


def serialize_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def main() -> int:
    manifest = build_manifest()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(serialize_manifest(manifest), encoding="utf-8", newline="\n")
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
