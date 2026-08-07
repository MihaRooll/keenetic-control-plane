import { pathToFileURL } from 'url';

const mod = await import("file:///C:/Users/katko/Desktop/Programms/keenetic-control-plane/router_control_host/web/hub/features/_adv_mut_remove_rule_1.js");
const groups = mod.groupDiscoveryCandidates([{"host": "192.168.2.1", "port": 22, "candidate_origin": "known_endpoint", "identity_state": "unknown", "reason_code": "enrollment_draft_model_unknown", "router_id": "draft-1"}, {"host": "192.168.2.1", "port": 443, "candidate_origin": "known_endpoint", "identity_state": "unknown", "reason_code": "enrollment_draft_model_unknown", "router_id": "draft-2"}, {"host": "192.168.2.1", "port": 443, "candidate_origin": "known_endpoint", "identity_state": "unknown", "reason_code": "enrollment_draft_model_unknown", "router_id": "draft-3"}]);
console.log(JSON.stringify(groups));
