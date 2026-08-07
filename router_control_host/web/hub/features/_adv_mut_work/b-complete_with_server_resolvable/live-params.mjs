const mod = await import("file:///C:/Users/katko/Desktop/Programms/keenetic-control-plane/router_control_host/web/hub/features/live-connection-params.js");
const snapshot = {"routerId": "router-lab-1", "routerHost": "10.0.0.1", "siteId": "site-1", "hostKeyConfirmed": true, "eventPresetId": null, "eventPresetName": null, "wifiLive": {"host": "10.0.0.1", "username": null, "credentialRefId": "cred-ref-1", "sshHostKeySha256": null}, "wifiRoles": {"staffApId": null, "guestApId": null}, "sourceAddress": "192.168.2.144"};
console.log(JSON.stringify(mod.buildLiveConnectionParams(snapshot)));
