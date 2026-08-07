"""Статические проверки motion/progress API LOCAL HUB."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"


def test_motion_js_exports_apply_screen_enter() -> None:
    source = (HUB / "core" / "motion.js").read_text(encoding="utf-8")
    assert "export function applyScreenEnter" in source
    assert "hub-screen-enter" in source
    assert "requestAnimationFrame" in source


def test_states_exports_create_progress_panel() -> None:
    source = (HUB / "core" / "states.js").read_text(encoding="utf-8")
    assert "export function createProgressPanel" in source
    assert "hub-progress-panel" in source
    assert "panel.update" in source


def test_api_exports_in_flight_helpers() -> None:
    source = (HUB / "core" / "api.js").read_text(encoding="utf-8")
    assert "export function getInFlightCount" in source
    assert "export function subscribeInFlight" in source
    assert "beginInFlight" in source
    assert "endInFlight" in source


def test_shell_request_progress_markup() -> None:
    source = (HUB / "core" / "shell.js").read_text(encoding="utf-8")
    assert "hub-shell__request-progress" in source
    assert "subscribeInFlight" in source


def test_tokens_css_calm_motion_values() -> None:
    source = (HUB / "styles" / "tokens.css").read_text(encoding="utf-8")
    assert "--hub-duration-fast: 180ms;" in source
    assert "--hub-duration-normal: 280ms;" in source
    assert "--hub-duration-slow: 480ms;" in source
    assert "--hub-ease-standard: cubic-bezier(0.25, 0.1, 0.25, 1);" in source
    assert "--hub-ease-emphasis: cubic-bezier(0.22, 1, 0.36, 1);" in source


def test_tokens_css_reduced_motion_zeroes_durations() -> None:
    source = (HUB / "styles" / "tokens.css").read_text(encoding="utf-8")
    block_start = source.index("@media (prefers-reduced-motion: reduce)")
    block = source[block_start:]
    assert "--hub-duration-fast: 0ms;" in block
    assert "--hub-duration-normal: 0ms;" in block
    assert "--hub-duration-slow: 0ms;" in block


def test_shell_progress_bar_timing_literals() -> None:
    source = (HUB / "core" / "shell.js").read_text(encoding="utf-8")
    assert ", 280);" in source
    assert ", 300);" in source
    assert ", 220);" not in source
    assert ", 175);" not in source
    hide_settle_ms = 300
    fade_ms = 280
    assert hide_settle_ms >= fade_ms
