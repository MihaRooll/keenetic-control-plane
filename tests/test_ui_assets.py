"""UI packaged assets: content types, allowlist, packaging."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "ui-assets.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_stylesheet_content_type(authed_client) -> None:
    r = authed_client.get("/settings/router-control/assets/styles.css")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/css")
    assert "--color-primary" in r.text
    assert "@media (prefers-reduced-motion" in r.text


def test_app_js_content_type(authed_client) -> None:
    r = authed_client.get("/settings/router-control/assets/app.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "")
    assert 'const API = "/api/router-control/v1"' in r.text


def test_unknown_asset_404(authed_client) -> None:
    r = authed_client.get("/settings/router-control/assets/evil.js")
    assert r.status_code == 404


def test_html_single_stylesheet_link(authed_client) -> None:
    r = authed_client.get("/settings/router-control")
    assert r.status_code == 200
    links = re.findall(r'<link[^>]+rel=["\']stylesheet["\'][^>]*>', r.text, re.I)
    assert len(links) == 1
    assert "/settings/router-control/assets/styles.css" in links[0]


def test_html_absolute_asset_urls(authed_client) -> None:
    r = authed_client.get("/settings/router-control/")
    assert r.status_code == 200
    assert 'href="/settings/router-control/assets/styles.css"' in r.text
    assert 'src="/settings/router-control/assets/app.js"' in r.text
    assert 'href="assets/' not in r.text
    assert 'src="assets/' not in r.text


def test_app_js_node_syntax_check() -> None:
    import shutil
    import subprocess

    js_path = Path(__file__).resolve().parents[1] / "router_control_host" / "web" / "app.js"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    result = subprocess.run(
        [node, "--check", str(js_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_app_js_structural_balance() -> None:
    js_path = Path(__file__).resolve().parents[1] / "router_control_host" / "web" / "app.js"
    source = js_path.read_text(encoding="utf-8")
    assert source.count("{") == source.count("}")
    assert source.count("(") == source.count(")")
    assert source.count("[") == source.count("]")


def test_html_no_inline_style_block(authed_client) -> None:
    r = authed_client.get("/settings/router-control")
    assert "<style" not in r.text.lower()
    assert 'style="' not in r.text.lower()


def test_js_no_innerhtml_or_element_style() -> None:
    js_path = Path(__file__).resolve().parents[1] / "router_control_host" / "web" / "app.js"
    source = js_path.read_text(encoding="utf-8")
    assert "innerHTML" not in source
    assert "outerHTML" not in source
    assert ".style" not in source
    assert "eval(" not in source
    assert "new Function" not in source


def test_package_data_includes_web_files() -> None:
    root = resources.files("router_control_host").joinpath("web")
    names = {p.name for p in root.iterdir()}
    assert "index.html" in names
    assert "styles.css" in names
    assert "app.js" in names
    assert "login.html" in names
    assert "login.js" in names
    assert "login.css" in names
    assert "favicon.svg" in names


def test_theme_controls_in_html(authed_client) -> None:
    r = authed_client.get("/settings/router-control")
    assert 'id="theme-system"' in r.text
    assert 'aria-pressed' in r.text
    assert 'data-theme-value="dark"' in r.text


def test_landmarks_in_html(authed_client) -> None:
    r = authed_client.get("/settings/router-control")
    assert 'role="banner"' in r.text or "<header" in r.text
    assert 'role="main"' in r.text
    assert "sidebar-nav" in r.text
    assert 'aria-live="polite"' in r.text
