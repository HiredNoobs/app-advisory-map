"""The findings and the feeds' health, built at each scrape from the app's state.

Not a registry of gauges: a finding that's gone (fixed, or its target removed) is simply not
yielded any more, so its series goes stale.
"""

from collections import Counter
from collections.abc import Iterator
from typing import TYPE_CHECKING

from prometheus_client.core import GaugeMetricFamily, Metric
from prometheus_client.registry import Collector as _Collector

from advisory_map.advisories.kev import Exploited
from advisory_map.findings import LABELS

if TYPE_CHECKING:
    from advisory_map.app import App

_FINDING_LABELS = [*LABELS, "kev", "kev_date_added", "kev_ransomware"]


def _kev_labels(exploited: Exploited | None) -> list[str]:
    if exploited is None:
        return ["false", "", ""]
    return ["true", exploited.date_added, "true" if exploited.ransomware else "false"]


class Collector(_Collector):
    def __init__(self, app: "App") -> None:
        self.app = app

    def collect(self) -> Iterator[Metric]:
        app = self.app
        kev = app.kev.data or {}

        vulnerabilities = GaugeMetricFamily(
            "advisory_map_vulnerability_info", "A CVE that applies to something running.", labels=_FINDING_LABELS
        )
        for finding in app.findings:
            labels = [getattr(finding, label) for label in LABELS]
            vulnerabilities.add_metric([*labels, *_kev_labels(kev.get(finding.cve))], 1)
        yield vulnerabilities

        weaknesses = GaugeMetricFamily(
            "advisory_map_vulnerability_cwe_info",
            "A weakness (CWE) of a CVE that applies to something running, named as in MITRE's catalogue.",
            labels=["cve", "cwe", "cwe_name"],
        )
        names = app.cwe.data or {}
        for cve, cwe in sorted({(finding.cve, cwe) for finding in app.findings for cwe in finding.cwes}):
            weaknesses.add_metric([cve, cwe, names.get(cwe, "")], 1)
        yield weaknesses

        packages = GaugeMetricFamily(
            "advisory_map_inventory_packages",
            "Packages (or mapped software) known per target; 0 where versions are missing (no dpkg textfile).",
            labels=["target_kind", "target"],
        )
        for host in app.hosts:
            packages.add_metric(["debian-package", host.instance], len(host.packages))
        for (kind, target), count in Counter((item.kind, item.target) for item in app.software).items():
            packages.add_metric([kind, target], count)
        yield packages

        unmapped = GaugeMetricFamily(
            "advisory_map_unmapped_image_info", "A running image no mapping entry covers.", labels=["image"]
        )
        for image in app.unmapped_images:
            unmapped.add_metric([image], 1)
        yield unmapped

        unmatched = GaugeMetricFamily(
            "advisory_map_unmatched_records",
            "Advisories skipped in the last match: their versions couldn't be compared.",
            labels=["source", "reason"],
        )
        for (source, reason), count in app.unmatched.items():
            unmatched.add_metric([source, reason], count)
        yield unmatched

        success = GaugeMetricFamily(
            "advisory_map_feed_last_success_timestamp_seconds", "When the feed last refreshed.", labels=["feed"]
        )
        attempt = GaugeMetricFamily(
            "advisory_map_feed_last_attempt_timestamp_seconds", "When the feed was last fetched.", labels=["feed"]
        )
        records = GaugeMetricFamily("advisory_map_feed_records", "Records in the feed's copy in use.", labels=["feed"])
        for feed in app.feeds:
            if feed.meta.last_success is not None:
                success.add_metric([feed.name], feed.meta.last_success)
            if feed.last_attempt is not None:
                attempt.add_metric([feed.name], feed.last_attempt)
            records.add_metric([feed.name], feed.records())
        yield from (success, attempt, records)

        if app.last_match_success is not None:
            yield GaugeMetricFamily(
                "advisory_map_match_last_success_timestamp_seconds",
                "When versions were last matched against the feeds.",
                value=app.last_match_success,
            )
