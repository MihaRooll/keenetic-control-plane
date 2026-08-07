"""One-off red/green driver for G-3 ensureWifiCredentialRef revoke block."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "router_control_host" / "web" / "hub" / "features" / "wifi-ap-model.js"

_DRIVER_SCRIPT = """
const input = JSON.parse(await new Response(process.stdin).text());
const mod = await import(input.modUri);
let putCount = 0;
let revokeCount = 0;
globalThis.fetch = async (url, init = {}) => {
  const method = String(init.method || 'GET').toUpperCase();
  if (method === 'PUT' && String(url).includes('/credentials')) {
    putCount += 1;
    return {
      ok: true,
      status: 201,
      headers: { get: () => 'application/json' },
      json: async () => ({ credential_ref_id: `cred-ref-${putCount}` }),
      text: async () => '{}',
    };
  }
  if (method === 'POST' && String(url).includes('/revoke')) {
    revokeCount += 1;
    return {
      ok: true,
      status: 202,
      headers: { get: () => 'application/json' },
      json: async () => ({ status: 'Queued' }),
      text: async () => '{}',
    };
  }
  throw new Error('unexpected fetch');
};
let cache = null;
const base = { routerId: 'router-lab-1', apId: 'WifiMaster0/AccessPoint4', ssid: 'Staff-Lab' };
for (const secret of input.secrets) {
  const result = await mod.ensureWifiCredentialRef({ ...base, secret, cached: cache });
  cache = result.cache;
}
console.log(JSON.stringify({ putCount, revokeCount }));
"""


def _run(mod_uri: str, secrets: list[str]) -> dict[str, int]:
    node = shutil.which("node")
    if node is None:
        raise SystemExit("node required")
    proc = subprocess.run(
        [node, "--input-type=module", "-e", _DRIVER_SCRIPT],
        input=json.dumps({"modUri": mod_uri, "secrets": secrets}),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    return json.loads(proc.stdout.strip())


def main() -> int:
    node = shutil.which("node")
    if node is None:
        raise SystemExit("node required")
    secrets = ["edit-psk-aaaaaa", "edit-psk-bbbbbb", "edit-psk-cccccc"]
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        shutil.copytree(REPO / "router_control_host" / "web" / "hub" / "core", root / "core")
        shutil.copytree(
            REPO / "router_control_host" / "web" / "hub" / "features",
            root / "features",
        )
        broken_path = root / "features" / "wifi-ap-model.js"
        text = broken_path.read_text(encoding="utf-8")
        broken_path.write_text(
            re.sub(
                r"  if \(cached\?\.refId\) \{.*?\n  \}\n\n  const idempotencyKey",
                "  const idempotencyKey",
                text,
                count=1,
                flags=re.DOTALL,
            ),
            encoding="utf-8",
        )
        red = _run((root / "features" / "wifi-ap-model.js").as_uri(), secrets)
        green = _run(SRC.as_uri(), secrets)
        print("RED (broken, no supersede revoke):", json.dumps(red))
        print("GREEN (fixed model):", json.dumps(green))
        if red["revokeCount"] != 0:
            print("RED proof invalid: expected revokeCount=0", file=sys.stderr)
            return 1
        if green["revokeCount"] != 2:
            print("GREEN proof invalid: expected revokeCount=2", file=sys.stderr)
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
