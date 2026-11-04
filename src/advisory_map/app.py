"""Every match interval: what's installed, the feeds that are due, the findings."""

import logging
import time
from collections import Counter
from dataclasses import replace

from prometheus_client import REGISTRY, start_http_server

from advisory_map.advisories import cvelist, debian, osv
from advisory_map.advisories.cvelist import CveList
from advisory_map.advisories.debian import DebianTracker
from advisory_map.advisories.feed import Feed
from advisory_map.advisories.kev import Kev
from advisory_map.advisories.osv import Osv
from advisory_map.config import Settings
from advisory_map.findings import Finding, Severity
from advisory_map.inventory.debian import DebianHost, debian_hosts
from advisory_map.inventory.mapping import Installed, Mapping, find, load_mapping
from advisory_map.inventory.prometheus import PrometheusAPI
from advisory_map.metrics import Collector

log = logging.getLogger(__name__)


def _rated(finding: Finding, severities: dict[str, Severity]) -> Finding:
    """The severity of the most recently updated source that has one: the finding's own, or its CVE
    record's. Debian's urgencies carry no date, so a CVE record's CVSS severity takes their place."""
    found = severities.get(finding.cve)
    if found is None or found.updated <= finding.severity_updated:
        return finding
    return replace(finding, severity=found.level, severity_source="cve.org", severity_updated=found.updated)


class App:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.prometheus = PrometheusAPI(settings.prometheus_url, settings.prometheus_ca_file)
        self.mapping = load_mapping(settings.mapping_file) if settings.mapping_file else Mapping()
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.debian = DebianTracker(settings.data_dir)
        self.kev = Kev(settings.data_dir)
        self.cvelist = CveList(
            settings.data_dir, {item.product for item in self.mapping.software if item.product}, settings.cvelist_url
        )
        self.osv = Osv(
            settings.data_dir, {item.package for item in self.mapping.software if item.package}, settings.osv_url
        )
        self.feeds: tuple[Feed, ...] = (self.debian, self.kev, self.cvelist, self.osv)
        if unknown := settings.feed_refresh_overrides.keys() - {feed.name for feed in self.feeds}:
            raise ValueError(f"FEED_REFRESH_ for unknown feeds: {', '.join(sorted(unknown))}")
        self.hosts: list[DebianHost] = []
        self.software: list[Installed] = []
        self.unmapped_images: list[str] = []
        self.findings: list[Finding] = []
        # Ranges that couldn't be compared in the last match, by source and reason.
        self.unmatched: Counter[tuple[str, str]] = Counter()
        self.last_match_success: float | None = None

    def _match(self) -> tuple[list[Finding], Counter[tuple[str, str]]]:
        """Every source's findings, and the ranges that couldn't be compared by source and reason. Where OSV
        has records for a CVE in an installation's package, its ranges decide (they're per package
        version, CVE records often aren't), not the CVE record's."""
        unmatched = {"cve.org": Counter[str](), "osv": Counter[str]()}
        decided = {
            (item.kind, item.target, item.namespace, cve)
            for item in self.software
            for cve in osv.covered(item, self.osv.data)
        }
        findings = [
            *debian.match(self.hosts, self.debian.data or {}),
            *osv.match(self.software, self.osv.data, unmatched["osv"]),
            *(
                finding
                for finding in cvelist.match(self.software, self.cvelist.data, unmatched["cve.org"])
                if (finding.target_kind, finding.target, finding.namespace, finding.cve) not in decided
            ),
        ]
        return findings, Counter(
            {(source, reason): count for source, counts in unmatched.items() for reason, count in counts.items()}
        )

    def run_once(self, now: float) -> None:
        self.hosts = debian_hosts(self.prometheus)
        self.software, self.unmapped_images = find(self.prometheus, self.mapping)
        self.debian.use_releases(host.release for host in self.hosts)
        for feed in self.feeds:
            feed.update(now, self.settings.refresh_interval(feed.name))

        findings, self.unmatched = self._match()
        severities = self.cvelist.severities({finding.cve for finding in findings if finding.source != "cve.org"})
        self.findings = [_rated(finding, severities) for finding in findings]
        self.last_match_success = now

    def run(self) -> None:
        REGISTRY.register(Collector(self))
        start_http_server(self.settings.listen_port)
        while True:
            started = time.time()
            try:
                self.run_once(started)
            except Exception as error:
                log.warning("match failed, keeping the last findings: %s", error)
            time.sleep(max(0.0, started + self.settings.match_interval - time.time()))
