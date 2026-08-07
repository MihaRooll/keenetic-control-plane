"""Guard against pytest harnesses opening the operator's live SQLite database."""

from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from router_control.persistence.connection import resolve_db_path

_LIVE_DB_PATH = Path("data") / "router_control.sqlite3"
_LIVE_DB_URI = f"file:{_LIVE_DB_PATH.as_posix()}?mode=ro"


def _pick_ephemeral_port(host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _read_live_db_snapshot() -> tuple[int, float]:
    conn = sqlite3.connect(_LIVE_DB_URI, uri=True)
    try:
        row = conn.execute("PRAGMA user_version").fetchone()
        user_version = int(row[0]) if row else 0
    finally:
        conn.close()
    mtime = _LIVE_DB_PATH.stat().st_mtime
    return user_version, mtime


def test_resolve_db_path_guard(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ROUTER_CONTROL_DB_PATH", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "manual::probe")

    with pytest.raises(RuntimeError, match="PYTEST_CURRENT_TEST"):
        resolve_db_path(None)

    explicit = tmp_path / "x.sqlite3"
    assert resolve_db_path(explicit) == explicit

    override_path = tmp_path / "override.sqlite3"
    monkeypatch.setenv("ROUTER_CONTROL_DB_PATH", str(override_path))
    assert resolve_db_path(None) == override_path


def test_uvicorn_without_db_isolation_never_touches_live_db() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    before_version, before_mtime = _read_live_db_snapshot()

    port = _pick_ephemeral_port()
    public_base = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.pop("ROUTER_CONTROL_DB_PATH", None)

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
        cwd=str(repo_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10.0
        became_healthy = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            try:
                with httpx.Client(base_url=public_base, timeout=1.0) as client:
                    probe = client.get("/login")
                    if probe.status_code == 200:
                        became_healthy = True
                        break
            except Exception:  # noqa: BLE001 - startup polling
                pass
            time.sleep(0.1)

        assert not became_healthy, "uvicorn became healthy without db isolation"

        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)

        assert proc.returncode not in (0, None), (
            f"expected non-zero exit when db isolation is missing, got {proc.returncode}"
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass

    after_version, after_mtime = _read_live_db_snapshot()
    assert after_version == before_version
    assert after_mtime == before_mtime
