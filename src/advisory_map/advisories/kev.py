"""CISA's Known Exploited Vulnerabilities: no versions, it flags matches by their CVE."""

import json
from pathlib import Path
from typing import NamedTuple

from advisory_map.advisories.feed import Download


class Exploited(NamedTuple):
    date_added: str
    ransomware: bool


class Kev(Download[dict[str, Exploited]]):
    name = "kev"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def parse(self, path: Path) -> dict[str, Exploited]:
        return {
            entry["cveID"]: Exploited(entry["dateAdded"], entry["knownRansomwareCampaignUse"] == "Known")
            for entry in json.loads(path.read_bytes())["vulnerabilities"]
        }

    def records(self) -> int:
        return len(self.data or {})
