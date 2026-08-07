import { pathToFileURL } from 'url';

const mod = await import("file:///C:/Users/katko/Desktop/Programms/keenetic-control-plane/router_control_host/web/hub/features/connection-flow.js");
const groups = mod.groupDiscoveryCandidates([{"host": "192.168.2.1", "port": 22, "candidate_origin": "known_endpoint", "identity_state": "known_match", "reason_code": "totally_made_up_reason", "router_id": "r1"}]);
console.log(JSON.stringify(groups));
