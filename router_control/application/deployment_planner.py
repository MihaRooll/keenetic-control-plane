"""P2 immutable deployment planner — offline/fake only."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from router_control.domain.enums import ExecutionTarget, IntentKind, OwnershipAction
from router_control.domain.errors import DeploymentPreconditionFailed
from router_control.domain.event_preset import ValidationStatus
from router_control.domain.network_intents import (
    EventPresetDocument as ParsedDocument,
)
from router_control.domain.network_intents import (
    TopologyBinding,
    TopologyGatewayBinding,
    digest_canonical,
    gateway_for_cidr,
    parse_event_preset_document,
)
from router_control.persistence.store import PersistenceStore
from router_control.ports.clock import ClockPort

PUBLICATION_SCHEMA_DIGEST = "sha256:p2-publication-schema-v1"
DEFAULT_REQUIRED_FAMILIES = ("fail_safe", "lan_zones", "wifi", "dhcp", "dns", "firewall")


@dataclass
class DeploymentPlannerService:
    store: PersistenceStore
    clock: ClockPort
    gate_c_closed: bool = True

    def build_topology_binding(self, document: ParsedDocument) -> TopologyBinding:
        gateways = tuple(
            TopologyGatewayBinding(
                zone_id=zone.zone_id.value,
                ipv4_gateway=gateway_for_cidr(zone.ipv4_cidr),
            )
            for zone in document.zones
        )
        return TopologyBinding(gateways=gateways, ports=(), radios=())

    def compile_typed_plan_items(
        self,
        document: ParsedDocument,
        *,
        topology: TopologyBinding,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        ordinal = 0
        for zone in document.zones:
            gateway = next(
                (g.ipv4_gateway for g in topology.gateways if g.zone_id == zone.zone_id.value),
                gateway_for_cidr(zone.ipv4_cidr),
            )
            vlan_intent = {
                "zone_id": zone.zone_id.value,
                "vlan_id": zone.vlan_id,
                "ipv4_cidr": zone.ipv4_cidr,
                "ipv4_gateway": gateway,
            }
            items.append(
                self._item(
                    ordinal,
                    IntentKind.VLAN.value,
                    vlan_intent,
                    OwnershipAction.CREATE,
                )
            )
            ordinal += 1
            dhcp_intent = zone.dhcp.to_canonical()
            dhcp_intent["zone_id"] = zone.zone_id.value
            items.append(
                self._item(
                    ordinal,
                    IntentKind.DHCP.value,
                    dhcp_intent,
                    OwnershipAction.CREATE,
                )
            )
            ordinal += 1
            dns_intent = zone.dns.to_canonical()
            dns_intent["zone_id"] = zone.zone_id.value
            items.append(
                self._item(
                    ordinal,
                    IntentKind.DNS.value,
                    dns_intent,
                    OwnershipAction.CREATE,
                )
            )
            ordinal += 1
            if zone.wifi is not None:
                wifi_intent = zone.wifi.to_canonical()
                wifi_intent["zone_id"] = zone.zone_id.value
                items.append(
                    self._item(
                        ordinal,
                        IntentKind.WIFI.value,
                        wifi_intent,
                        OwnershipAction.CREATE,
                    )
                )
                ordinal += 1
            fw_intent = zone.firewall.to_canonical()
            fw_intent["zone_id"] = zone.zone_id.value
            items.append(
                self._item(
                    ordinal,
                    IntentKind.FIREWALL.value,
                    fw_intent,
                    OwnershipAction.CREATE,
                )
            )
            ordinal += 1
        return items

    @staticmethod
    def _item(
        ordinal: int,
        intent_kind: str,
        intent: dict[str, Any],
        ownership_action: OwnershipAction,
    ) -> dict[str, Any]:
        intent_digest = digest_canonical(
            "change_plan", {"intent_kind": intent_kind, "intent": intent}
        )
        return {
            "ordinal": ordinal,
            "intent_kind": intent_kind,
            "intent_json": intent,
            "intent_digest": intent_digest,
            "ownership_action": ownership_action.value,
        }

    def build_canonical_desired(
        self,
        *,
        document: ParsedDocument,
        topology: TopologyBinding,
        published_preset_id: str,
        deployment_revision_id: str,
    ) -> tuple[dict[str, Any], str]:
        payload = {
            "published_preset_id": published_preset_id,
            "deployment_revision_id": deployment_revision_id,
            "topology": topology.to_canonical(),
            "zones": [z.to_canonical() for z in document.zones],
            "uplink": document.uplink.to_canonical(),
            "local_order_url": document.local_order_url,
        }
        digest = digest_canonical("desired", payload)
        return payload, digest

    def build_change_plan_digest_payload(
        self,
        *,
        router_id: str,
        deployment_revision_id: str,
        deployment_digest: str,
        desired_revision_id: str,
        desired_digest: str,
        observation_id: str,
        observation_state_digest: str,
        observation_resource_version: str,
        execution_target: str,
        family_cert_snapshots: list[dict[str, Any]],
        items: list[dict[str, Any]],
        risk_class: str,
        requires_backup: bool,
        requires_fail_safe: bool,
        expires_at: str,
        adopt_acknowledged: bool,
    ) -> dict[str, Any]:
        ordered_items = sorted(items, key=lambda i: int(i["ordinal"]))
        return {
            "router_id": router_id,
            "deployment_revision_id": deployment_revision_id,
            "deployment_digest": deployment_digest,
            "desired_revision_id": desired_revision_id,
            "desired_digest": desired_digest,
            "observation_id": observation_id,
            "observation_state_digest": observation_state_digest,
            "observation_resource_version": observation_resource_version,
            "execution_target": execution_target,
            "family_cert_snapshots": family_cert_snapshots,
            "items": [
                {
                    "ordinal": item["ordinal"],
                    "intent_kind": item["intent_kind"],
                    "intent_digest": item["intent_digest"],
                    "ownership_action": item.get("ownership_action"),
                    "preconditions": item.get("preconditions", []),
                    "postconditions": item.get("postconditions", []),
                }
                for item in ordered_items
            ],
            "risk_class": risk_class,
            "requires_backup": requires_backup,
            "requires_fail_safe": requires_fail_safe,
            "expires_at": expires_at,
            "adopt_acknowledged": adopt_acknowledged,
        }

    def compute_change_plan_digest(self, payload: dict[str, Any]) -> str:
        return digest_canonical("change_plan", payload)

    def publication_digests(
        self,
        *,
        canonical_document: dict[str, Any],
        validation_status: ValidationStatus,
    ) -> tuple[str, str, str]:
        doc_digest = digest_canonical("publication", canonical_document)
        schema_digest = PUBLICATION_SCHEMA_DIGEST
        validation_digest = digest_canonical(
            "publication",
            {"validation_status": validation_status.value},
        )
        return doc_digest, schema_digest, validation_digest

    def deployment_readiness(
        self,
        *,
        router_id: str,
        deployment_revision_id: str,
        execution_target: ExecutionTarget,
    ) -> dict[str, Any]:
        deployment = self.store.get_deployment_revision(deployment_revision_id)
        if deployment is None or str(deployment["router_id"]) != router_id:
            raise DeploymentPreconditionFailed("deployment revision not found")
        families = json.loads(str(deployment["required_families_json"]))
        cert_rows = self.store.list_active_family_certifications(router_id)
        cert_by_family = {str(r["family"]): r for r in cert_rows}
        blockers: list[dict[str, Any]] = []
        now_iso = self.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        for family in families:
            row = cert_by_family.get(family)
            if row is None:
                blockers.append({"family": family, "code": "cert_missing"})
                continue
            if row["valid_until"] < now_iso:
                blockers.append({"family": family, "code": "cert_expired"})
        if execution_target == ExecutionTarget.PRODUCTION:
            for gate in ("gate_d", "m6"):
                if gate not in {str(r["family"]) for r in cert_rows}:
                    blockers.append({"family": gate, "code": "production_gate_missing"})
        if self.gate_c_closed:
            blockers.append({"family": "gate_c", "code": "gate_c_closed"})
        write_ready = not blockers and execution_target == ExecutionTarget.LAB
        return {
            "deployment_revision_id": deployment_revision_id,
            "router_id": router_id,
            "execution_target": execution_target.value,
            "write_ready": write_ready,
            "blockers": blockers,
            "required_families": families,
        }

    def document_from_published(
        self,
        published_preset_id: str,
    ) -> tuple[ParsedDocument, ValidationStatus]:
        row = self.store.get_published_preset(published_preset_id)
        if row is None:
            raise DeploymentPreconditionFailed("published preset not found")
        revision = self.store.get_event_preset_revision(str(row["source_revision_id"]))
        if revision is None:
            raise DeploymentPreconditionFailed("source revision missing")
        doc = parse_event_preset_document(self.store.revision_canonical_json(revision))
        status = ValidationStatus(str(revision["validation_status"]))
        return doc, status

    def lineage_for_publication(
        self,
        *,
        preset_id: str,
        revision_id: str,
        revision_number: int,
        published_at: datetime,
        actor_id: str | None,
    ) -> dict[str, Any]:
        return {
            "preset_id": preset_id,
            "revision_id": revision_id,
            "revision_number": revision_number,
            "published_at": published_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor_id": actor_id or "hub_admin",
        }
