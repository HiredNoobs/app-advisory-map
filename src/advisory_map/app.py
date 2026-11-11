"""Every match interval: what's installed, the feeds that are due, the findings."""

import logging
import time
from collections import Counter
from dataclasses import replace

from prometheus_client import REGISTRY, start_http_server

from advisory_map.advisories import cvelist, debian, osv
from advisory_map.advisories.cvelist import CveList, Details
from advisory_map.advisories.cwe import Cwe
from advisory_map.advisories.debian import DebianTracker
from advisory_map.advisories.feed import Feed
from advisory_map.advisories.kev import Kev
from advisory_map.advisories.osv import Osv
from advisory_map.advisories.releases import Releases
from advisory_map.config import Settings
from advisory_map.findings import Finding
from advisory_map.inventory.debian import DebianHost, debian_hosts
from advisory_map.inventory.mapping import Installed, Mapping, find, load_mapping
from advisory_map.inventory.prometheus import PrometheusAPI
from advisory_map.metrics import Collector

log = logging.getLogger(__name__)

# An installation (kind, target, namespace) and a CVE.
type _Key = tuple[str, str, str, str]


def _key(item: Installed, cve: str) -> _Key:
    return item.kind, item.target, item.namespace, cve


def _finding_key(finding: Finding) -> _Key:
    return finding.target_kind, finding.target, finding.namespace, finding.cve


def _enriched(finding: Finding, record: Details | None) -> Finding:
    """The finding with what its CVE record adds: the weaknesses the record cites, if any, and its severity
    where the record updated it after the finding's source. Debian's urgencies carry no date, so a CVE
    record's CVSS severity takes their place."""
    if record is None:
        return finding
    if record.cwes:
        finding = replace(finding, cwes=record.cwes)
    found = record.severity
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
        self.cwe = Cwe(settings.data_dir)
        self.releases = Releases(settings.data_dir, {item.releases for item in self.mapping.software if item.releases})
        self.feeds: tuple[Feed, ...] = (self.debian, self.kev, self.cvelist, self.osv, self.cwe, self.releases)
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
        """Every source's findings, and the ranges that couldn't be compared by source and reason.

        Where OSV has records for a CVE in an installation's package, its ranges decide (they're per
        package version, CVE records often aren't), not the CVE record's. Unless every OSV record leaves
        a range open and the CVE record says where it ends: a range is left open when the fix isn't a
        version of the package (Grafana 13, Vault 2 as Go modules). Per installation, not per mapping
        entry: one installation can have an entry for each name its CVE records use.
        """
        unmatched = {"cve.org": Counter[str](), "osv": Counter[str]()}
        # Each (installation, CVE) OSV has records for: whether one of them says where it ends.
        in_osv: dict[_Key, bool] = {}
        bounded_in_cvelist: set[_Key] = set()
        for item in self.software:
            for cve, bounded in osv.covered(item, self.osv.data).items():
                in_osv[_key(item, cve)] = in_osv.get(_key(item, cve), False) or bounded
            bounded_in_cvelist.update(_key(item, cve) for cve in cvelist.bounded(item, self.cvelist.data))
        by_cvelist = {key for key, bounded in in_osv.items() if not bounded and key in bounded_in_cvelist}
        by_osv = in_osv.keys() - by_cvelist

        findings = [
            *debian.match(self.hosts, self.debian.data or {}),
            *(
                finding
                for finding in osv.match(self.software, self.osv.data, unmatched["osv"], self.releases.data)
                if _finding_key(finding) not in by_cvelist
            ),
            *(
                finding
                for finding in cvelist.match(self.software, self.cvelist.data, unmatched["cve.org"], self.releases.data)
                if _finding_key(finding) not in by_osv
            ),
        ]
        return findings, Counter(
            {(source, reason): count for source, counts in unmatched.items() for reason, count in counts.items()}
        )

    def _update_findings(self, now: float) -> None:
        findings, self.unmatched = self._match()
        records = self.cvelist.details({finding.cve for finding in findings})
        self.findings = [_enriched(finding, records.get(finding.cve)) for finding in findings]
        self.last_match_success = now

    def run_once(self, now: float) -> None:
        """Findings from the feeds' copies in use, then again once the feeds that are due refresh: a
        refresh can take minutes (a first fetch, a changed mapping), and the findings stay meanwhile."""
        self.hosts = debian_hosts(self.prometheus)
        self.software, self.unmapped_images = find(self.prometheus, self.mapping)
        self.debian.use_releases(host.release for host in self.hosts)
        for feed in self.feeds:
            if feed.data is None:
                feed.load()
        due = [feed for feed in self.feeds if feed.due(now, self.settings.refresh_interval(feed.name))]
        self._update_findings(now)
        for feed in due:
            feed.refresh(now)
        if due:
            self._update_findings(now)

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
