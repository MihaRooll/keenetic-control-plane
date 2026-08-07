import { pathToFileURL } from 'url';

const mod = await import("file:///C:/Users/katko/Desktop/Programms/keenetic-control-plane/router_control_host/web/hub/features/_adv_mut_remove_rule_1.js");
const groups = mod.groupDiscoveryCandidates([{"host": "192.168.2.1", "port": 22, "candidate_origin": "known_endpoint", "identity_state": "known_match", "reason_code": "probe_tuple_match", "router_id": "router-proven"}, {"host": "192.168.2.1", "port": 443, "candidate_origin": "known_endpoint", "identity_state": "unknown", "reason_code": "enrollment_draft_model_unknown", "router_id": "router-draft"}, {"host": "192.168.2.1", "port": 443, "candidate_origin": "local_subnet_gateway", "identity_state": "unknown", "reason_code": "unenrolled_host"}]);
console.log(JSON.stringify(groups));
