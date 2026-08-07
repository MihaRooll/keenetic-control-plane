"""Start fake-mode host for Wi-Fi e2e, run roundtrip, stop tracked PID."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _wait_health(base_url: str, timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url.rstrip('/')}/login", timeout=2) as resp:
                if resp.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"host not healthy at {base_url}")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8792
    base_url = f"http://127.0.0.1:{port}"
    db_path = Path(tempfile.gettempdir()) / f"keenetic-e2e-{port}-{uuid.uuid4().hex}.sqlite3"
    if db_path.exists():
        db_path.unlink()
    env = os.environ.copy()
    env.update(
        {
            "RC_UNSAFE_DISABLE_AUTH": "1",
            "RC_STANDALONE_LOOPBACK_AUTH": "1",
            "RC_ADAPTER_MODE": "fake",
            "RC_ALLOW_FAKE_MUTATIONS": "1",
            "RC_PUBLIC_BASE_URL": base_url,
            "HUB_ADMIN_PASSWORD": "e2e-fake-hub-password",
            "ROUTER_CONTROL_DB_PATH": str(db_path),
        }
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "router_control_host.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(REPO),
        env=env,
    )
    print(f"E2E_HOST_PID={proc.pid}", flush=True)
    print(f"E2E_BASE_URL={base_url}", flush=True)
    try:
        _wait_health(base_url)
        driver = REPO / "tests" / "support" / "hub_wifi_fake_e2e.py"
        run = subprocess.run(
            [sys.executable, str(driver), base_url, "hub_admin"],
            cwd=str(REPO),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if run.stdout.strip():
            print(run.stdout.strip())
        if run.returncode != 0:
            if run.stderr.strip():
                print(run.stderr.strip(), file=sys.stderr)
            return run.returncode
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        print(f"KILLED_PID={proc.pid}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
