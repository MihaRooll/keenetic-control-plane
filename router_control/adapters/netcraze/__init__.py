"""Netcraze read-only Gate A adapter package."""

from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter, build_router_identity
from router_control.adapters.netcraze.awg_certification import (
    CertificationRunner,
    build_certification_evidence,
)
from router_control.adapters.netcraze.awg_hardware import (
    AwgHardwareBoundary,
    CommandShapeUnknown,
    TypedOperation,
)
from router_control.adapters.netcraze.awg_profile import (
    AwgProfileError,
    ParsedAwgProfile,
    parse_awg_profile_path,
)
from router_control.adapters.netcraze.capability_families import (
    CapabilityFamily,
    FamilyCatalog,
    FamilyCertificationState,
    TupleBinding,
)
from router_control.adapters.netcraze.certification import (
    GateACertification,
    GateACertificationError,
    load_gate_a_certification,
)
from router_control.adapters.netcraze.certification_framework import (
    CertificationPlanner,
)
from router_control.adapters.netcraze.certification_framework import (
    CertificationRunner as FamilyCertificationRunner,
)
from router_control.adapters.netcraze.codec import OperationCodec, TypedIntent
from router_control.adapters.netcraze.evidence_manifest import (
    EvidenceManifest,
    ProvenanceTier,
    load_evidence_manifest,
)
from router_control.adapters.netcraze.fail_safe_certification import (
    FailSafeDiscoveryRunner,
    FailSafeTrialAuthorization,
    load_fail_safe_authorization,
)
from router_control.adapters.netcraze.fail_safe_hardware import (
    FailSafeHardwareBoundary,
    FailSafeTypedOperation,
)
from router_control.adapters.netcraze.gate_bc import (
    GateBCAuthorization,
    GateBCError,
    load_gate_bc_authorization,
)
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_REGISTERED_OPERATIONS,
    OperationSpec,
    RegisteredOperation,
)
from router_control.adapters.netcraze.read_discovery import (
    ReadDiscoveryCatalog,
    gate_a_allowlist_unchanged,
    load_read_discovery_catalog,
)
from router_control.adapters.netcraze.route_topology_probe import (
    PARSER_VERSION as DEFAULT_ROUTE_PARSER_VERSION,
)
from router_control.adapters.netcraze.route_topology_probe import (
    DefaultRouteClassification,
    build_default_route_artifact,
    correlate_with_topology_artifact,
)
from router_control.adapters.netcraze.shape_registry import (
    CertifiedOperationRegistry,
    FamilyShapeRegistry,
    OperationPromotionRegistry,
    ShapePromotionState,
    ShapeRegistryError,
)
from router_control.adapters.netcraze.ssh_cli_discovery import (
    CONTRACT_ID as SSH_CLI_DISCOVERY_CONTRACT_ID,
)
from router_control.adapters.netcraze.ssh_cli_discovery import (
    SshCliDiscoveryAuthorization,
    SshCliDiscoveryRunner,
    load_ssh_cli_discovery_authorization,
)
from router_control.adapters.netcraze.topology_probe import (
    PARSER_VERSION,
    TopologyClassification,
    build_topology_artifact,
    classify_topology,
    parse_topology_interfaces,
)
from router_control.adapters.netcraze.transport import NetcrazeTransport, SshTunnelNetcrazeTransport
from router_control.adapters.netcraze.typed_executor import SharedTypedOperationExecutor

__all__ = [
    "AwgHardwareBoundary",
    "AwgProfileError",
    "CapabilityFamily",
    "CertificationPlanner",
    "CertificationRunner",
    "CertifiedOperationRegistry",
    "CommandShapeUnknown",
    "EvidenceManifest",
    "FailSafeDiscoveryRunner",
    "FailSafeHardwareBoundary",
    "FailSafeTrialAuthorization",
    "FailSafeTypedOperation",
    "FamilyCatalog",
    "FamilyCertificationRunner",
    "FamilyCertificationState",
    "FamilyShapeRegistry",
    "GateACertification",
    "GateACertificationError",
    "GateBCAuthorization",
    "GateBCError",
    "NetcrazeReadOnlyAdapter",
    "NetcrazeTransport",
    "ParsedAwgProfile",
    "ProvenanceTier",
    "ReadDiscoveryCatalog",
    "OperationCodec",
    "OperationPromotionRegistry",
    "OperationSpec",
    "RegisteredOperation",
    "ShapePromotionState",
    "ShapeRegistryError",
    "SharedTypedOperationExecutor",
    "SSH_CLI_DISCOVERY_CONTRACT_ID",
    "SshCliDiscoveryAuthorization",
    "SshCliDiscoveryRunner",
    "SYNTHETIC_REGISTERED_OPERATIONS",
    "TypedIntent",
    "SshTunnelNetcrazeTransport",
    "TupleBinding",
    "TypedOperation",
    "build_certification_evidence",
    "build_router_identity",
    "load_evidence_manifest",
    "load_fail_safe_authorization",
    "load_gate_a_certification",
    "load_gate_bc_authorization",
    "DefaultRouteClassification",
    "DEFAULT_ROUTE_PARSER_VERSION",
    "TopologyClassification",
    "build_default_route_artifact",
    "build_topology_artifact",
    "classify_topology",
    "correlate_with_topology_artifact",
    "gate_a_allowlist_unchanged",
    "load_read_discovery_catalog",
    "load_ssh_cli_discovery_authorization",
    "parse_topology_interfaces",
    "PARSER_VERSION",
    "parse_awg_profile_path",
]
