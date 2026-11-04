"""Settings, from the environment."""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from advisory_map.advisories import cvelist, osv

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_OVERRIDE_PREFIX = "FEED_REFRESH_"


def parse_duration(text: str) -> int:
    """Seconds in a duration such as 90s, 15m, 24h or 1d."""
    match = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if not match:
        raise ValueError(f"not a duration: {text!r} (e.g. 15m, 24h, 1d)")
    return int(match[1]) * _UNITS[match[2]]


def _required(env: Mapping[str, str], name: str) -> str:
    if not env.get(name):
        raise ValueError(f"{name} must be set")
    return env[name]


@dataclass(frozen=True)
class Settings:
    prometheus_url: str
    prometheus_ca_file: str | None
    # The software to match against CVE records and OSV packages: see docs/mapping.md.
    mapping_file: Path | None
    cvelist_url: str
    osv_url: str
    data_dir: Path
    listen_port: int
    match_interval: int
    feed_refresh: int
    # FEED_REFRESH_<FEED> overrides, by feed name.
    feed_refresh_overrides: Mapping[str, int]

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        return cls(
            prometheus_url=_required(env, "PROMETHEUS_URL").rstrip("/"),
            prometheus_ca_file=env.get("PROMETHEUS_CA_FILE") or None,
            mapping_file=Path(env["MAPPING_FILE"]) if env.get("MAPPING_FILE") else None,
            cvelist_url=env.get("CVELIST_URL") or cvelist.URL,
            osv_url=env.get("OSV_URL") or osv.URL,
            data_dir=Path(env.get("DATA_DIR", "/data")),
            listen_port=int(env.get("LISTEN_PORT", "8080")),
            match_interval=parse_duration(env.get("MATCH_INTERVAL", "15m")),
            feed_refresh=parse_duration(env.get("FEED_REFRESH", "24h")),
            feed_refresh_overrides={
                name.removeprefix(_OVERRIDE_PREFIX).lower(): parse_duration(value)
                for name, value in env.items()
                if name.startswith(_OVERRIDE_PREFIX)
            },
        )

    def refresh_interval(self, feed: str) -> int:
        return self.feed_refresh_overrides.get(feed, self.feed_refresh)
