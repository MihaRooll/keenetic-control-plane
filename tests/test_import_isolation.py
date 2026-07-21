"""Import isolation and side-effect checks."""

from __future__ import annotations

import importlib
import sys


def test_import_has_no_side_effects() -> None:
    sys.modules.pop("router_control", None)
    module = importlib.import_module("router_control")
    assert module.__version__ == "0.1.0"
    assert hasattr(module, "RouterControlPort")
    assert hasattr(module, "FakeRouterAdapter")


def test_public_exports_documented() -> None:
    import router_control

    assert router_control.__all__
    for name in router_control.__all__:
        assert hasattr(router_control, name), f"missing export {name}"
