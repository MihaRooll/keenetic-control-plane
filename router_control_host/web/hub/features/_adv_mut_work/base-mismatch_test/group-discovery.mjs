import { pathToFileURL } from 'url';

const mod = await import("file:///C:/Users/katko/Desktop/Programms/keenetic-control-plane/router_control_host/web/hub/features/connection-flow.js");
const groups = mod.groupDiscoveryCandidates([{"host": "192.168.2.1", "port": 22, "candidate_origin": "known_endpoint", "identity_state": "known_mismatch", "reason_code": "probe_tuple_mismatch", "router_id": "router-mismatch"}, {"host": "192.168.2.1", "port": 443, "candidate_origin": "known_endpoint", "identity_state": "known_match", "reason_code": "enrollment_match_identity_unverified", "router_id": "router-unverified"}]);
console.log(JSON.stringify(groups));
