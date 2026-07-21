"""Host application state holder."""

from __future__ import annotations

from dataclasses import dataclass, field

from router_control.composition import OfflineRuntime


@dataclass
class HostState:
    runtime: OfflineRuntime
    feature_state: str = "Ready"
    allow_fake_mutations: bool = False
    site_id: str | None = None
    _bootstrapped: bool = field(default=False, repr=False)

    def ensure_default_site(self) -> str:
        if self.site_id:
            return self.site_id
        self.site_id = self.runtime.store.create_site(
            display_name="Offline Lab",
            timezone="UTC",
            now=self.runtime.clock.now(),
        )
        return self.site_id
