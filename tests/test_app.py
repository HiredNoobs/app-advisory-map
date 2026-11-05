from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import KEV, TRACKER, FakeHttp, Origin, osv_archive, record, response
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from advisory_map.advisories.debian import DebianTracker
from advisory_map.advisories.feed import Feed
from advisory_map.advisories.kev import Kev
from advisory_map.app import App
from advisory_map.common import http
from advisory_map.config import Settings
from advisory_map.metrics import Collector

PROMETHEUS_URL = "http://prometheus:9090"
OSV_URL = "http://osv"


class FakePrometheus:
    """host-1 with openssl at a given version, host-2 without the dpkg textfile; Vault on host-2."""

    def __init__(self) -> None:
        self.openssl = "3.5.4-1~deb13u1"

    def series(self, query: str) -> list[dict[str, Any]]:
        if query == "vault_build_info":
            return [{"metric": {"instance": "host-2", "version": "v2.1.2"}}]
        if query == "kube_pod_container_info":
            return [{"metric": {"image": image}} for image in ("hashicorp/vault:2.1.2", "redis:8.2@sha256:ab")]
        if query == 'node_os_info{id="debian"}':
            return [
                {"metric": {"instance": host, "id": "debian", "version_codename": "trixie"}}
                for host in ("host-1", "host-2")
            ]
        assert query == "dpkg_package_info"
        return [
            {"metric": {"instance": "host-1", "package": package, "source": "openssl", "source_version": self.openssl}}
            for package in ("libssl3t64", "openssl")
        ]

    def __call__(self, url: str) -> http.Response:
        query = parse_qs(urlparse(url).query)["query"][0]
        return response({"status": "success", "data": {"resultType": "vector", "result": self.series(query)}})


@pytest.fixture
def prometheus(fake_http: FakeHttp) -> FakePrometheus:
    fake = FakePrometheus()
    fake_http.routes.update({PROMETHEUS_URL: fake, DebianTracker.url: response(TRACKER), Kev.url: response(KEV)})
    return fake


@pytest.fixture
def env(tmp_path: Path, prometheus: FakePrometheus, origin: Origin) -> dict[str, str]:
    origin.commit()
    return {
        "PROMETHEUS_URL": PROMETHEUS_URL,
        "DATA_DIR": str(tmp_path / "data"),
        "CVELIST_URL": origin.url,
        "OSV_URL": OSV_URL,
    }


@pytest.fixture
def app(env: dict[str, str]) -> App:
    return App(Settings.from_env(env))


def scrape(app: App) -> dict[str, list[tuple[dict[str, str], float]]]:
    """Each metric's samples, as /metrics serves them."""
    registry = CollectorRegistry()
    registry.register(Collector(app))
    return {
        family.name: [(sample.labels, sample.value) for sample in family.samples]
        for family in text_string_to_metric_families(generate_latest(registry).decode())
    }


def test_run_once(app: App) -> None:
    app.run_once(1000)
    metrics = scrape(app)
    assert sorted(metrics["advisory_map_vulnerability_info"], key=lambda sample: sample[0]["cve"]) == [
        (
            {
                "cve": "CVE-2026-0001",
                "severity": "high",
                "severity_source": "debian",
                "source": "debian",
                "target_kind": "debian-package",
                "target": "host-1",
                "namespace": "",
                "package": "openssl",
                "installed_version": "3.5.4-1~deb13u1",
                "fixed_version": "3.5.4-1~deb13u2",
                "status": "fix-available",
                "kev": "true",
                "kev_date_added": "2026-10-30",
                "kev_ransomware": "true",
            },
            1.0,
        ),
        (
            {
                "cve": "CVE-2026-0002",
                "severity": "low",
                "severity_source": "debian",
                "source": "debian",
                "target_kind": "debian-package",
                "target": "host-1",
                "namespace": "",
                "package": "openssl",
                "installed_version": "3.5.4-1~deb13u1",
                "fixed_version": "",
                "status": "no-dsa",
                "kev": "false",
                "kev_date_added": "",
                "kev_ransomware": "",
            },
            1.0,
        ),
    ]
    assert ({"target_kind": "debian-package", "target": "host-2"}, 0.0) in metrics["advisory_map_inventory_packages"]
    assert ({"feed": "debian"}, 5.0) in metrics["advisory_map_feed_records"]
    assert metrics["advisory_map_feed_last_success_timestamp_seconds"] == [
        ({"feed": "debian"}, 1000),
        ({"feed": "kev"}, 1000),
        ({"feed": "cvelist"}, 1000),
        ({"feed": "osv"}, 1000),
    ]
    assert metrics["advisory_map_match_last_success_timestamp_seconds"] == [({}, 1000)]


def test_feeds_refresh_only_when_due(app: App, fake_http: FakeHttp) -> None:
    app.run_once(1000)
    app.run_once(1900)
    assert [url for url, _ in fake_http.requests if not url.startswith(PROMETHEUS_URL)] == [DebianTracker.url, Kev.url]


def test_restart_uses_the_copy_on_disk(app: App, fake_http: FakeHttp) -> None:
    app.run_once(1000)
    fake_http.routes[DebianTracker.url] = fake_http.routes[Kev.url] = OSError("offline")
    restarted = App(app.settings)
    restarted.run_once(1000 + 2 * 86400)
    assert len(restarted.findings) == 2
    assert restarted.kev.meta.last_success == 1000


def test_findings_stay_while_the_feeds_refresh(app: App, monkeypatch: pytest.MonkeyPatch) -> None:
    app.run_once(1000)
    restarted = App(app.settings)
    during: list[int] = []
    monkeypatch.setattr(Feed, "refresh", lambda feed, now: during.append(len(restarted.findings)))
    restarted.run_once(1000 + 2 * 86400)
    # Each feed was due: the findings from the copies on disk were there while it refreshed.
    assert during == [2, 2, 2, 2]


def test_fixed_finding_disappears(app: App, prometheus: FakePrometheus) -> None:
    app.run_once(1000)
    prometheus.openssl = "3.5.4-1~deb13u2"
    app.run_once(1900)
    assert [labels["cve"] for labels, _ in scrape(app)["advisory_map_vulnerability_info"]] == ["CVE-2026-0002"]


def test_cve_records(env: dict[str, str], origin: Origin, tmp_path: Path) -> None:
    mapping = tmp_path / "mapping.toml"
    mapping.write_text('[[software]]\nquery = "vault_build_info"\nvendor = "HashiCorp"\nproduct = "Vault"\n')
    origin.commit(
        # Its CVSS severity, dated, replaces Debian's urgency.
        record("CVE-2026-0001", product="openssl", cna_cvss={"cvssV3_1": {"baseSeverity": "CRITICAL"}}),
        record("CVE-2026-0100", [{"version": "0", "lessThan": "2.1.3", "status": "affected"}]),
        record("CVE-2026-0101", [{"version": "abc", "versionType": "git", "status": "affected"}]),
    )
    app = App(Settings.from_env({**env, "MAPPING_FILE": str(mapping)}))
    app.run_once(1000)
    metrics = scrape(app)
    found = {labels["cve"]: labels for labels, _ in metrics["advisory_map_vulnerability_info"]}
    assert (found["CVE-2026-0001"]["severity"], found["CVE-2026-0001"]["severity_source"]) == ("critical", "cve.org")
    assert found["CVE-2026-0100"] | {"kev": "false"} == {
        "cve": "CVE-2026-0100",
        "severity": "unknown",
        "severity_source": "cve.org",
        "source": "cve.org",
        "target_kind": "software",
        "target": "host-2",
        "namespace": "",
        "package": "hashicorp/vault",
        "installed_version": "v2.1.2",
        "fixed_version": "2.1.3",
        "status": "fix-available",
        "kev": "false",
        "kev_date_added": "",
        "kev_ransomware": "",
    }
    assert ({"target_kind": "software", "target": "host-2"}, 1.0) in metrics["advisory_map_inventory_packages"]
    assert metrics["advisory_map_unmatched_records"] == [({"source": "cve.org", "reason": "git"}, 1.0)]
    assert ({"feed": "cvelist"}, 2.0) in metrics["advisory_map_feed_records"]


def osv_record(cve: str, fixed: str, **fields: Any) -> dict[str, Any]:
    """GitHub's record of a CVE in Vault; without a fix, its range is left open."""
    events = [{"introduced": "0"}, *([{"fixed": fixed}] if fixed else [])]
    return {
        "id": cve.replace("CVE", "GHSA"),
        "modified": "2026-11-01T00:00:00Z",
        "aliases": [cve],
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "github.com/hashicorp/vault"},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
        **fields,
    }


def test_osv_and_unmapped_images(env: dict[str, str], origin: Origin, fake_http: FakeHttp, tmp_path: Path) -> None:
    mapping = tmp_path / "mapping.toml"
    mapping.write_text("""
[images]
query = "kube_pod_container_info"

[[software]]
query = "vault_build_info"
vendor = "HashiCorp"
product = "Vault"
ecosystem = "Go"
package = "github.com/hashicorp/vault"
images = "^hashicorp/vault:"
""")
    upto = [{"version": "0", "lessThan": "2.2.0", "status": "affected"}]
    origin.commit(
        # OSV has records for these two: its ranges decide.
        record("CVE-2026-0100", upto),
        record("CVE-2026-0101", upto, cna_cvss={"cvssV3_1": {"baseSeverity": "CRITICAL"}}),
        record("CVE-2026-0102", upto),
    )
    fake_http.routes[f"{OSV_URL}/Go/modified_id.csv"] = response(b"2026-11-01T00:00:00Z,GHSA-2026-0100\n")
    fake_http.routes[f"{OSV_URL}/Go/all.zip"] = response(
        osv_archive(
            # Fixed before the installed version.
            osv_record("CVE-2026-0100", "2.1.0"),
            # GitHub's level was updated after the CVE record's.
            osv_record("CVE-2026-0101", "2.1.4", database_specific={"severity": "HIGH"}),
        )
    )
    app = App(Settings.from_env({**env, "MAPPING_FILE": str(mapping)}))
    app.run_once(1000)
    metrics = scrape(app)
    found = {
        labels["cve"]: (labels["source"], labels["severity"], labels["fixed_version"])
        for labels, _ in metrics["advisory_map_vulnerability_info"]
        if labels["target"] == "host-2"
    }
    assert found == {
        "CVE-2026-0101": ("osv", "high", "2.1.4"),
        "CVE-2026-0102": ("cve.org", "unknown", "2.2.0"),
    }
    assert metrics["advisory_map_unmapped_image_info"] == [({"image": "redis:8.2"}, 1.0)]
    assert ({"feed": "osv"}, 2.0) in metrics["advisory_map_feed_records"]


def test_bounded_cve_records_decide_over_open_osv_ranges(
    env: dict[str, str], origin: Origin, fake_http: FakeHttp, tmp_path: Path
) -> None:
    # Two entries for one installation, one per product name: the bound counts for the installation.
    mapping = tmp_path / "mapping.toml"
    mapping.write_text("""
[[software]]
query = "vault_build_info"
vendor = "HashiCorp"
product = "Vault"
ecosystem = "Go"
package = "github.com/hashicorp/vault"

[[software]]
query = "vault_build_info"
vendor = "HashiCorp"
product = "Vault Enterprise"
""")
    origin.commit(
        # Fixed before the installed version (v2.1.2).
        record(
            "CVE-2026-0103", [{"version": "0", "lessThan": "2.1.0", "status": "affected"}], product="Vault Enterprise"
        ),
        # Fixed in a later one.
        record("CVE-2026-0104", [{"version": "0", "lessThan": "2.2.0", "status": "affected"}]),
        # Open as well: OSV's finding stands.
        record("CVE-2026-0105", [{"version": "2.0.0", "lessThan": "*", "status": "affected"}]),
    )
    fake_http.routes[f"{OSV_URL}/Go/modified_id.csv"] = response(b"2026-11-01T00:00:00Z,GHSA-2026-0103\n")
    fake_http.routes[f"{OSV_URL}/Go/all.zip"] = response(
        osv_archive(*(osv_record(f"CVE-2026-010{n}", "") for n in range(3, 7)))
    )
    app = App(Settings.from_env({**env, "MAPPING_FILE": str(mapping)}))
    app.run_once(1000)
    found = {
        labels["cve"]: (labels["source"], labels["status"], labels["fixed_version"])
        for labels, _ in scrape(app)["advisory_map_vulnerability_info"]
        if labels["target"] == "host-2"
    }
    assert found == {
        "CVE-2026-0104": ("cve.org", "fix-available", "2.2.0"),
        "CVE-2026-0105": ("osv", "open", ""),
        # No CVE record.
        "CVE-2026-0106": ("osv", "open", ""),
    }


def test_unknown_feed_override(env: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="nvd"):
        App(Settings.from_env({**env, "FEED_REFRESH_NVD": "1h"}))
