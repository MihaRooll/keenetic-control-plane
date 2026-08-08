"""Typed OpenAPI response models for apply/teardown/preview and observe routes."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from router_control.application.apply_types import (
    ApplyOverallStatus,
    ApplyRollbackOutcome,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


TunnelVerificationStatus = Literal[
    "tunnel_no_peer",
    "tunnel_never_handshaked",
    "tunnel_healthy",
    "tunnel_unverified",
]

UplinkVerificationStatus = Literal[
    "uplink_dispatched_unverified",
    "uplink_associated_no_global",
    "uplink_verified_bounded",
    "uplink_failed",
]

PlannedUplinkVerificationLevel = Literal[
    "planned_uplink_verified_bounded",
]

ConfigurationVerificationStatus = Literal[
    "device_accepted_configuration",
]

InterfaceVerificationStatus = Literal[
    "interface_present_up",
    "interface_present_down",
    "interface_not_up",
    "interface_id_mismatch",
    "interface_absent",
    "interface_still_present",
]

InterfaceAddressVerificationStatus = Literal[
    "interface_address_not_configured",
    "address_configured_unverified",
    "address_readback_confirmed",
]

OnAirVerificationStatus = Literal[
    "on_air_verified",
    "on_air_admin_only",
    "on_air_unverified",
    "on_air_still_broadcasting",
]

OVERALL_HTTP_SEMANTICS = (
    "Terminal business outcome of a completed apply/teardown run. "
    "Routes return HTTP 200 when dispatch finished and this body is returned — "
    "clients MUST inspect overall (not HTTP status alone) for success vs failure."
)

VerdictSignalCode = Literal[
    "link",
    "connected",
    "state",
    "txbytes",
    "rxbytes",
    "broadcast",
    "peer_public_key",
    "peer_last_handshake",
    "peer_online",
    "peer_rxbytes",
    "peer_txbytes",
    "peer_enabled",
    "interface_readable",
    "interface_state",
    "interface_up",
    "associated_ssid_field_present",
    "associated_ssid_matches_intent",
    "internet_status",
    "gateway_status",
    "dns_status",
    "admin_up",
    "on_air_signal",
]

VerdictMissingSignalCode = Literal[
    "readback",
    "peer_public_key",
    "peer_last_handshake",
    "peer_online",
    "peer_rxbytes",
    "associated_ssid_field",
    "associated_ssid",
    "ssid_intent_match",
    "internet_status",
    "gateway_status",
    "dns_status",
    "internet_affirmative",
    "link",
    "broadcast",
    "on_air_signal",
    "positive_handshake",
    "positive_online",
    "positive_rxbytes",
    "uplink_settle_performed",
]

VerdictRejectionReason = Literal[
    "interface_state_not_evidence",
    "interface_up_not_evidence",
    "peer_enabled_not_evidence",
    "peer_txbytes_alone_not_evidence",
    "link_not_evidence",
    "connected_not_evidence",
    "connected_with_link_down",
    "state_up_with_link_down",
    "txbytes_without_rxbytes",
    "link_broadcast_conflict",
    "auth_type_not_evidence",
]


class VerdictSignalReadingResponse(_StrictModel):
    signal: VerdictSignalCode
    value: str | int | bool | None


class VerdictRejectedSignalResponse(_StrictModel):
    signal: VerdictSignalCode
    reason: VerdictRejectionReason


class VerdictExplanationResponse(_StrictModel):
    signals_read: list[VerdictSignalReadingResponse]
    signals_missing: list[VerdictMissingSignalCode]
    signals_rejected: list[VerdictRejectedSignalResponse]


class _ObservedMapping(_StrictModel):
    model_config = ConfigDict(extra="allow")


# --- WireGuard ---


class WireguardApplyStepResponse(_StrictModel):
    op: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None


class ApplyRollbackUncoveredOpResponse(_StrictModel):
    op: str
    reason: str


class WireguardApplyRollbackResponse(_StrictModel):
    attempted: bool
    ops: list[str]
    outcome: ApplyRollbackOutcome
    steps: list[WireguardApplyStepResponse] | None = None
    uncovered_ops: list[ApplyRollbackUncoveredOpResponse] | None = None


class WireguardApplyVerificationResponse(_StrictModel):
    id_ok: bool
    up_ok: bool
    observed: dict[str, Any]


class WireguardApplyResponse(_StrictModel):
    overall: ApplyOverallStatus = Field(description=OVERALL_HTTP_SEMANTICS)
    wg_id: str
    steps: list[WireguardApplyStepResponse]
    errors: list[str]
    rollback_errors: list[str] = []
    logs: list[str]
    tunnel_verification_status: TunnelVerificationStatus
    verdict_explanation: VerdictExplanationResponse
    configuration_verification_status: ConfigurationVerificationStatus | None = None
    interface_verification_status: InterfaceVerificationStatus | None = None
    interface_address_verification_status: InterfaceAddressVerificationStatus | None = None
    verification_status: WireguardPlanVerificationStatus | None = None
    verification_notes: list[str] | None = None
    verification: WireguardApplyVerificationResponse | None = None
    backup_basename: str | None = None
    backup_content_sha256: str | None = None
    rollback: WireguardApplyRollbackResponse | None = None


class WireguardSealedOpPreview(_StrictModel):
    operation: str
    wg_id: str
    asc_args: str | None = None
    credential_ref_id: str | None = None
    peer_public_key: str | None = None
    peer_endpoint: str | None = None
    peer_allow_ips: str | None = None
    peer_keepalive_interval: int | None = None
    peer_rci_shape: str | None = None
    notes: list[str] | None = None


class WireguardPreviewResponse(_StrictModel):
    wg_id: str
    verification_status: WireguardPlanVerificationStatus
    notes: list[str]
    apply_ops: list[WireguardSealedOpPreview]
    teardown_ops: list[WireguardSealedOpPreview]


class WireguardObserveResponse(_StrictModel):
    wg_id: str
    tunnel_verification_status: TunnelVerificationStatus
    verdict_explanation: VerdictExplanationResponse
    interface_readable: bool


# --- Wi-Fi AP ---


class WifiApplyStepResponse(_StrictModel):
    op: str
    operation: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None
    error_category: WifiApRciErrorCategoryLiteral | None = None
    router_message: str | None = None
    command_redacted: str | None = None


class WifiApplySkippedOpResponse(_StrictModel):
    op: str
    reason: str


class WifiApplyRollbackStepResponse(_StrictModel):
    op: str
    operation: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None
    error_category: WifiApRciErrorCategoryLiteral | None = None
    router_message: str | None = None
    command_redacted: str | None = None


class WifiApplyRollbackResponse(_StrictModel):
    attempted: bool
    ops: list[str]
    outcome: ApplyRollbackOutcome
    steps: list[WifiApplyRollbackStepResponse] | None = None
    uncovered_ops: list[ApplyRollbackUncoveredOpResponse] | None = None


class WifiApplyVerificationResponse(_StrictModel):
    ssid_ok: bool
    encryption_ok: bool
    admin_up_ok: bool
    on_air_ok: bool | None = None
    observed: dict[str, Any]


class WifiApplyResponse(_StrictModel):
    overall: ApplyOverallStatus = Field(description=OVERALL_HTTP_SEMANTICS)
    ap_id: str
    on_air_verification_status: OnAirVerificationStatus
    verdict_explanation: VerdictExplanationResponse
    steps: list[WifiApplyStepResponse]
    errors: list[str]
    rollback_errors: list[str] = []
    logs: list[str]
    verification: WifiApplyVerificationResponse | None = None
    backup_basename: str | None = None
    backup_content_sha256: str | None = None
    rollback: WifiApplyRollbackResponse | None = None
    skipped_ops: list[WifiApplySkippedOpResponse] | None = None


class WifiSealedOpPreview(_StrictModel):
    operation: str
    ap_id: str
    ssid: str | None = None
    credential_ref_id: str | None = None
    notes: list[str] | None = None


class WifiPreviewResponse(_StrictModel):
    ap_id: str
    verification_status: WifiPreviewVerificationStatus
    notes: list[str]
    apply_ops: list[WifiSealedOpPreview]
    teardown_ops: list[WifiSealedOpPreview]


# --- Wi-Fi station ---


class WifiStationApplyStepResponse(_StrictModel):
    op: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None


class WifiStationApplyRollbackResponse(_StrictModel):
    attempted: bool
    ops: list[str]
    outcome: ApplyRollbackOutcome
    steps: list[WifiStationApplyStepResponse] | None = None
    uncovered_ops: list[ApplyRollbackUncoveredOpResponse] | None = None


class WifiStationApplyResponse(_StrictModel):
    overall: ApplyOverallStatus = Field(description=OVERALL_HTTP_SEMANTICS)
    station_id: str
    verification_status: GrammarVerificationStatus
    grammar_verification_status: GrammarVerificationStatus
    uplink_verification_status: UplinkVerificationStatus
    verdict_explanation: VerdictExplanationResponse
    notes: list[str]
    steps: list[WifiStationApplyStepResponse]
    errors: list[str]
    rollback_errors: list[str] = []
    logs: list[str]
    backup_basename: str | None = None
    backup_content_sha256: str | None = None
    rollback: WifiStationApplyRollbackResponse | None = None
    uplink_readback: dict[str, Any] | None = None
    uplink_settle_seconds: float | None = None


class WifiStationSealedOpPreview(_StrictModel):
    operation: str
    station_id: str
    ssid: str | None = None
    credential_ref_id: str | None = None
    bssid: str | None = None
    priority: int | None = None
    standby_timeout_seconds: int | None = None
    notes: list[str] | None = None


class WifiStationPreviewResponse(_StrictModel):
    station_id: str
    verification_status: GrammarVerificationStatus
    grammar_verification_status: GrammarVerificationStatus
    planned_uplink_verification_level: PlannedUplinkVerificationLevel
    readback_rule: str
    notes: list[str]
    apply_ops: list[WifiStationSealedOpPreview]
    teardown_ops: list[WifiStationSealedOpPreview]


# --- Wi-Fi observed state ---


class ObservedWifiApStateResponse(_StrictModel):
    ap_id: str
    band: str
    ssid: str | None = None
    enabled_or_up: bool | None = None
    link_up: bool | None = None
    device_connected: bool | None = None
    wpa_mode: str
    encryption_raw: Any | None = None
    key_configured: bool | None = None
    readable: bool


class WifiObservedStateResponse(_StrictModel):
    access_points: list[ObservedWifiApStateResponse]
    certification_eligible: bool
    transport_security: str
    https_check: str
    offline_verified_only: bool
    comparisons: dict[str, dict[str, str]] | None = None


# --- Wi-Fi site survey ---


class WifiSiteSurveyResponse(_StrictModel):
    radio: str
    command: str
    networks: list[dict[str, Any]]
    network_count: int
    per_network_security_present: bool
    findings: list[str]
    skipped_row_count: int
    certification_eligible: bool
    transport_security: str
    offline_verified_only: bool


# --- Internet status observe ---


InternetStatusReadStatusLiteral = Literal["ok", "failed", "unsupported"]


class InternetStatusObserveResponse(_StrictModel):
    internet: bool | None
    reliable: bool | None
    gateway_accessible: bool | None
    dns_accessible: bool | None
    captive_accessible: bool | None
    gateway_interface: str | None
    gateway_ssid: str | None
    checked_at: str | None
    read_status: InternetStatusReadStatusLiteral


# --- Bootstrap discovery ---


class BootstrapComponentChangeSideEffects(_StrictModel):
    firmware_rebuild: bool
    automatic_reboot: bool
    management_downtime: bool
    firmware_version_changes: bool | None = None


IdentityStateLiteral = Literal["known_match", "known_mismatch", "unknown"]
CandidateOriginLiteral = Literal["default_gateway", "known_endpoint", "local_subnet_gateway"]
ConnectionHealthStatusLiteral = Literal["green", "yellow", "red"]


class RouterDiscoveryBounds(_StrictModel):
    sources: list[str]
    subnet_scan: bool
    free_form_hosts: bool
    credential_stuffing: bool
    description: str


class RouterDiscoveryCandidate(_StrictModel):
    host: str
    port: int
    source_address: str | None = None
    source_address_class: str | None = None
    candidate_origin: CandidateOriginLiteral
    router_id: str | None = None
    route_if_index: int | None = None
    route_label: str | None = None
    identity_state: IdentityStateLiteral
    credentials_required: bool
    writes_allowed: bool
    reason_code: str
    facts: dict[str, Any] | None = None


class RouterDiscoveryProbedHost(_StrictModel):
    host: str
    port: int
    source_address: str | None = None


class RouterDiscoveryExcludedCandidate(_StrictModel):
    host: str
    port: int | None = None
    candidate_origin: CandidateOriginLiteral | None = None
    reason_code: str


RouteTableSourceNameLiteral = Literal["default_gateway", "local_subnet_gateway"]
RouteTableSourceStatusLiteral = Literal["ok", "empty", "failed"]
RouteTableSourceReasonCodeLiteral = Literal[
    "timeout", "os_error", "unicode_decode", "json_decode", "nonzero_exit"
]


class RouterDiscoverySourceDiagnostic(_StrictModel):
    source: RouteTableSourceNameLiteral
    status: RouteTableSourceStatusLiteral
    reason_code: RouteTableSourceReasonCodeLiteral | None = None


class RouterDiscoveryResponse(_StrictModel):
    candidates: list[RouterDiscoveryCandidate]
    excluded_candidates: list[RouterDiscoveryExcludedCandidate] = []
    bounds: RouterDiscoveryBounds
    certification_eligible: bool
    probed_hosts: list[RouterDiscoveryProbedHost]
    source_diagnostics: list[RouterDiscoverySourceDiagnostic] = []
    degraded_sources: list[RouteTableSourceNameLiteral] = []


class ConnectionHealthFactsResponse(_StrictModel):
    reachable: bool | None
    host_key_match: bool | None
    tuple_match: bool | None
    credentials_present: bool | None
    evidence_fresh: bool | None


class ConnectionHealthResponse(_StrictModel):
    status: ConnectionHealthStatusLiteral
    reason_code: str
    facts: ConnectionHealthFactsResponse
    writes_allowed: bool
    certification_eligible: bool
    host: str | None = None
    port: int | None = None
    router_id: str | None = None
    source_address: str | None = None


class BootstrapDiscoveryResponse(_StrictModel):
    certification_eligible: bool
    transport_security: str
    https_check: str
    ssh_component_installed: bool | None
    ssh_access_enabled: bool | None
    wifi_access_points: list[dict[str, Any]]
    findings: list[str]
    component_change_side_effects: BootstrapComponentChangeSideEffects
    management_http: dict[str, Any] | None = None
    model: str | None = None
    firmware_version: str | None = None
    firmware_digest: str | None = None
    fingerprint_digest: str | None = None
    component_set_digest: str | None = None
    sandbox: str | None = None
    update_channel: str | None = None
    channel_firmware_version: str | None = None
    component_change_would_upgrade_firmware: bool | None = None
    component_change_crosses_major_version: bool | None = None
    update_channel_is_stable: bool | None = None
    components_inventory: dict[str, Any] | None = None
    ssh_component_determination: dict[str, Any] | None = None


# --- RCI typed mutations ---


class RciMutationLinks(_StrictModel):
    operation: str
    job: str


class RciMutationResponse(_StrictModel):
    operation_id: str
    job_id: str
    status: str
    result: dict[str, Any]
    links: RciMutationLinks


# --- Network family preview ---


OfflineVerificationStatus = Literal["offline_unverified"]

# Compile-time grammar/plan verification labels (preview + apply plan passthrough).
# NOTE: `verification_status` is overloaded across families — see module comment below.

GrammarVerificationStatus = Literal["device_accepted_grammar"]

WifiPreviewVerificationStatus = Literal["device_verified_wpa2"]

WireguardPlanVerificationStatus = Literal[
    "device_verified_asc9",
    "pending_live_verification",
    "unsupported_pending_verification",
    "unsupported",
]

VpnPolicyPreviewVerificationStatus = Literal["help_verified_grammar_unapplied"]

# Wi-Fi station apply duplicates grammar on `verification_status` (legacy axis); prefer
# `grammar_verification_status` for compile-time grammar and `uplink_verification_status`
# for runtime observe — split deferred (see API_CONTRACT §13.2.1 table footnote).

WifiApRciErrorCategoryLiteral = Literal[
    "unsupported_grammar",
    "rejected_by_router",
    "auth_or_permission",
    "resource_not_found",
    "transport_or_timeout",
    "unknown",
]


class VlanSealedOpPreview(_StrictModel):
    operation: str
    bridge_id: str | None = None
    zone_id: str | None = None
    vlan_id: int | None = None
    ipv4_cidr: str | None = None
    ipv4_gateway: str | None = None
    ipv4_mask: str | None = None
    security_level: str | None = None
    notes: list[str] | None = None


class VlanPreviewResponse(_StrictModel):
    bridge_id: str
    zone_id: str
    vlan_id: int
    ipv4_cidr: str
    ipv4_gateway: str
    verification_status: OfflineVerificationStatus
    notes: list[str]
    apply_ops: list[VlanSealedOpPreview]
    teardown_ops: list[VlanSealedOpPreview]


class DhcpSealedOpPreview(_StrictModel):
    operation: str
    zone_id: str | None = None
    pool_start: str | None = None
    pool_end: str | None = None
    lease_seconds: int | None = None
    mac_address: str | None = None
    ipv4_address: str | None = None
    notes: list[str] | None = None


class DhcpReservationPreview(_StrictModel):
    mac_address: str
    ipv4_address: str


class DhcpPreviewResponse(_StrictModel):
    zone_id: str
    pool_start: str
    pool_end: str
    lease_seconds: int
    reservations: list[DhcpReservationPreview]
    verification_status: OfflineVerificationStatus
    notes: list[str]
    apply_ops: list[DhcpSealedOpPreview]
    teardown_ops: list[DhcpSealedOpPreview]


class DnsSealedOpPreview(_StrictModel):
    operation: str
    zone_id: str | None = None
    local_fqdn: str | None = None
    upstream_resolver: str | None = None
    notes: list[str] | None = None


class DnsPreviewResponse(_StrictModel):
    zone_id: str
    local_fqdn: str
    upstream_resolvers: list[str]
    verification_status: OfflineVerificationStatus
    notes: list[str]
    apply_ops: list[DnsSealedOpPreview]
    teardown_ops: list[DnsSealedOpPreview]


class FirewallSealedOpPreview(_StrictModel):
    operation: str
    zone_id: str | None = None
    action: str | None = None
    destination_family: str | None = None
    ordinal: int | None = None
    notes: list[str] | None = None


class FirewallRulePreview(_StrictModel):
    action: str
    destination_family: str
    ordinal: int


class FirewallPreviewResponse(_StrictModel):
    zone_id: str
    rules: list[FirewallRulePreview]
    verification_status: OfflineVerificationStatus
    notes: list[str]
    apply_ops: list[FirewallSealedOpPreview]
    teardown_ops: list[FirewallSealedOpPreview]


# --- VPN policy-routing preview ---


class VpnPolicySealedOpPreview(_StrictModel):
    operation: str
    policy_name: str | None = None
    interface_id: str | None = None
    name_server_address: str | None = None
    name_server_domain: str | None = None
    name_server_on_interface: str | None = None
    global_auto: bool | None = None
    global_order: int | None = None
    global_priority: int | None = None
    notes: list[str] | None = None


class VpnPolicyPreviewResponse(_StrictModel):
    policy_name: str
    vpn_interface: str
    verification_status: VpnPolicyPreviewVerificationStatus
    unknowns: list[str]
    notes: list[str]
    apply_ops: list[VpnPolicySealedOpPreview]
    teardown_ops: list[VpnPolicySealedOpPreview]


# --- KeenDNS/CrazeDNS read-only status + preview ---


KeenDnsFeatureAvailability = Literal["unavailable", "disabled", "unknown"]
KeenDnsNameReservation = Literal["reserved", "not_reserved", "unknown"]
KeenDnsAccessMode = Literal["auto", "cloud", "direct", "unknown"]
KeenDnsPreviewVerificationStatus = Literal["documentation_sourced_unconfirmed"]


class KeenDnsStatusResponse(_StrictModel):
    feature_availability: KeenDnsFeatureAvailability
    name_reservation: KeenDnsNameReservation
    access_mode: KeenDnsAccessMode
    notes: list[str]


class KeenDnsObserveResponse(_StrictModel):
    default_fqdn: str | None = None
    ssl_valid: bool | None = None
    booked_name: str | None = None
    booked_domain: str | None = None
    booked_fqdn: str | None = None
    access_mode: KeenDnsAccessMode
    name_reservation: KeenDnsNameReservation
    notes: list[str]
    certification_eligible: Literal[False]


class KeenDnsSealedOpPreview(_StrictModel):
    operation: str
    command_text: str
    name: str | None = None
    domain: str | None = None
    mode: str | None = None
    notes: list[str] | None = None


class KeenDnsPreviewResponse(_StrictModel):
    intent_kind: str
    name: str
    domain: str
    mode: str | None = None
    verification_status: KeenDnsPreviewVerificationStatus
    notes: list[str]
    preview_ops: list[KeenDnsSealedOpPreview]


class KeenDnsApplyStepResponse(_StrictModel):
    op: str
    ok: bool
    command_redacted: str | None = None
    status_ident: str | None = None
    error: str | None = None


class KeenDnsApplyResponse(_StrictModel):
    overall: ApplyOverallStatus
    intent_kind: str
    name: str
    domain: str
    mode: str | None = None
    verification_status: KeenDnsPreviewVerificationStatus
    notes: list[str]
    steps: list[KeenDnsApplyStepResponse]
    errors: list[str]
    logs: list[str]
    backup_basename: str | None = None
    backup_content_sha256: str | None = None


HostProbeCheckedFrom = Literal["operator_host"]
HostTlsAggregateStatus = Literal["ok", "warning", "unknown", "failed"]


class HostHttpProbeResponse(_StrictModel):
    checked_from: HostProbeCheckedFrom
    reachable: bool | None
    http_status_class: str | None
    latency_ms: int | None
    reason_code: str
    target_host: str | None = None
    scheme: str | None = None
    redirect_followed: Literal[False]
    writes_allowed: Literal[False]
    certification_eligible: Literal[False]
    notes: list[str]


class HostTlsProbeResponse(_StrictModel):
    checked_from: HostProbeCheckedFrom
    reachable: bool | None
    cert_trusted: bool | None
    hostname_match: bool | None
    not_expired: bool | None
    aggregate_status: HostTlsAggregateStatus
    not_after: str | None = None
    issuer_summary: str | None = None
    chain_inspected: Literal[False]
    reason_code: str
    target_host: str | None = None
    writes_allowed: Literal[False]
    certification_eligible: Literal[False]
    notes: list[str]


class HostInternetProbeResponse(_StrictModel):
    checked_from: HostProbeCheckedFrom
    dns_ok: bool | None
    tcp_ok: bool | None
    internet_reachable: bool | None
    reason_code: str
    source_bound: Literal[False]
    writes_allowed: Literal[False]
    certification_eligible: Literal[False]
    notes: list[str]
