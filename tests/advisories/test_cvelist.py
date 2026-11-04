import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

import pytest
from conftest import Origin, record

from advisory_map.advisories.cvelist import (
    Advisory,
    CveList,
    Index,
    match,
    record_path,
    severity,
)
from advisory_map.findings import Severity
from advisory_map.inventory.mapping import Installed, Product

VAULT = Product("hashicorp", "vault")
CONSUL = Product("hashicorp", "consul")
DAY = 86400


def cvss(version: str, **fields: Any) -> dict[str, Any]:
    return {version: {"version": "x", **fields}}


def affected(upper: str) -> list[dict[str, Any]]:
    return [{"version": "0", "lessThan": upper, "status": "affected", "versionType": "semver"}]


def no_scan(*args: object) -> NoReturn:
    pytest.fail("every record was read again")


def git(repo: Path, *args: str) -> set[str]:
    return set(
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.split()
    )


@pytest.fixture
def feed(tmp_path: Path, origin: Origin) -> CveList:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return CveList(data_dir, {VAULT}, origin.url)


def delta_log(origin: Origin, *cves: str) -> None:
    """The repository's change log beside the records: not a record, though it names the product."""
    (origin.path / "cves").mkdir(exist_ok=True)
    (origin.path / "cves" / "deltaLog.json").write_text(json.dumps([{"new": cves, "product": "vault"}]))


def test_record_path() -> None:
    assert record_path("CVE-2026-12345") == "cves/2026/12xxx/CVE-2026-12345.json"
    assert record_path("CVE-2026-0001") == "cves/2026/0xxx/CVE-2026-0001.json"


def test_scan_indexes_the_mapped_products(feed: CveList, origin: Origin) -> None:
    delta_log(origin, "CVE-2026-0001")
    commit = origin.commit(
        record("CVE-2026-0001", affected("2.1.3"), cna_cvss=cvss("cvssV3_1", baseSeverity="HIGH")),
        record("CVE-2026-0002", affected("1.0"), product="Consul"),
        record("CVE-2026-0003", affected("2.0"), state="REJECTED"),
    )
    feed.update(1000, DAY)
    assert feed.data == Index(
        commit,
        frozenset({VAULT}),
        {
            VAULT: {
                "CVE-2026-0001": Advisory(
                    Severity("high", "2026-01-01T00:00:00.000Z"),
                    ({"versions": affected("2.1.3"), "defaultStatus": None},),
                )
            }
        },
    )
    assert feed.records() == 1
    assert feed.meta.last_success == 1000


def test_refresh_reads_only_the_changed_records(feed: CveList, origin: Origin, monkeypatch: pytest.MonkeyPatch) -> None:
    old = origin.commit(record("CVE-2026-0001", affected("2.1.3")), record("CVE-2026-0002", affected("2.1.4")))
    feed.update(1000, DAY)

    monkeypatch.setattr(CveList, "_scan", no_scan)
    delta_log(origin, "CVE-2026-0003")
    commit = origin.commit(record("CVE-2026-0003", affected("2.2.0")), remove=["CVE-2026-0002"])
    feed.update(1000 + DAY, DAY)

    assert feed.meta.last_success == 1000 + DAY
    assert feed.data is not None and feed.data.commit == commit
    assert sorted(feed.data.advisories[VAULT]) == ["CVE-2026-0001", "CVE-2026-0003"]
    # Only the head's objects are kept: the old commit is pruned, with the record only it had.
    kept = git(feed.repo, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
    assert kept == git(feed.repo, "rev-list", "--objects", "--no-object-names", commit)
    assert old not in kept


def test_refresh_without_changes(feed: CveList, origin: Origin, monkeypatch: pytest.MonkeyPatch) -> None:
    origin.commit(record("CVE-2026-0001", affected("2.1.3")))
    feed.update(1000, DAY)
    monkeypatch.setattr(CveList, "_scan", no_scan)
    monkeypatch.setattr(CveList, "_delta", no_scan)
    feed.update(1000 + DAY, DAY)
    assert feed.meta.last_success == 1000 + DAY
    assert feed.records() == 1


def test_restart_uses_the_index(feed: CveList, origin: Origin, monkeypatch: pytest.MonkeyPatch) -> None:
    origin.commit(record("CVE-2026-0001", affected("2.1.3")))
    feed.update(1000, DAY)
    restarted = CveList(feed.data_dir, {VAULT}, origin.url)
    monkeypatch.setattr(CveList, "_scan", no_scan)
    restarted.update(2000, DAY)
    assert restarted.data == feed.data
    assert restarted.meta.last_success == 1000


def test_changed_products_read_every_record(feed: CveList, origin: Origin) -> None:
    origin.commit(
        record("CVE-2026-0001", affected("2.1.3")), record("CVE-2026-0002", affected("1.0"), product="consul")
    )
    feed.update(1000, DAY)
    restarted = CveList(feed.data_dir, {VAULT, CONSUL}, origin.url)
    restarted.update(2000, DAY)
    assert restarted.data is not None
    assert {product: sorted(cves) for product, cves in restarted.data.advisories.items()} == {
        VAULT: ["CVE-2026-0001"],
        CONSUL: ["CVE-2026-0002"],
    }


def test_failed_fetch_keeps_the_index(feed: CveList, origin: Origin) -> None:
    origin.commit(record("CVE-2026-0001", affected("2.1.3")))
    feed.update(1000, DAY)
    feed.url = (origin.path.parent / "missing").as_uri()
    feed.update(1000 + DAY, DAY)
    assert feed.records() == 1
    assert (feed.meta.last_success, feed.last_attempt) == (1000, 1000 + DAY)


@pytest.mark.parametrize(
    "item, expected",
    [
        # The ADP updated its metrics after the CNA.
        (
            record(
                "CVE-2026-0001",
                cna_cvss=cvss("cvssV3_1", baseSeverity="MEDIUM"),
                adp_cvss=cvss("cvssV3_1", baseSeverity="CRITICAL"),
            ),
            Severity("critical", "2026-06-01T00:00:00.000Z"),
        ),
        # The newest CVSS version a container has.
        (
            record(
                "CVE-2026-0001", cna_cvss={**cvss("cvssV2_0", baseScore=9.0), **cvss("cvssV4_0", baseSeverity="LOW")}
            ),
            Severity("low", "2026-01-01T00:00:00.000Z"),
        ),
        # CVSS v2 has no severity in the record, only a score.
        (
            record("CVE-2026-0001", cna_cvss=cvss("cvssV2_0", baseScore=5.0)),
            Severity("medium", "2026-01-01T00:00:00.000Z"),
        ),
        (record("CVE-2026-0001"), None),
    ],
)
def test_severity(item: dict[str, Any], expected: Severity | None) -> None:
    assert severity(item) == expected


def test_severities(feed: CveList, origin: Origin) -> None:
    origin.commit(
        record("CVE-2026-0001", cna_cvss=cvss("cvssV3_1", baseSeverity="HIGH"), product="openssl"),
        record("CVE-2026-0002", product="openssl"),
    )
    assert feed.severities({"CVE-2026-0001"}) == {}
    feed.update(1000, DAY)
    assert feed.severities({"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-9999", "TEMP-0000000-ABCDEF"}) == {
        "CVE-2026-0001": Severity("high", "2026-01-01T00:00:00.000Z")
    }


def test_match() -> None:
    by_default = {"versions": affected("1.9"), "defaultStatus": "affected"}
    index = Index(
        "commit",
        frozenset({VAULT}),
        {
            VAULT: {
                "CVE-2026-0001": Advisory(Severity("high", ""), ({"versions": affected("2.1.3")},)),
                "CVE-2026-0002": Advisory(None, ({"versions": affected("2.0.0")},)),
                "CVE-2026-0003": Advisory(None, ({"versions": [{"version": "2.1.2", "status": "affected"}]},)),
                "CVE-2026-0004": Advisory(
                    None, ({"versions": [{"version": "abc", "versionType": "git", "status": "affected"}]},)
                ),
                # The CNA lists the version, an ADP the range with its fix.
                "CVE-2026-0005": Advisory(
                    None,
                    ({"versions": [{"version": "2.1.2", "status": "affected"}]}, {"versions": affected("2.1.5")}),
                ),
                # Affected by default, though only older releases are listed.
                "CVE-2026-0006": Advisory(None, (by_default,)),
                # ...and an ADP's range confirms it.
                "CVE-2026-0007": Advisory(None, (by_default, {"versions": affected("2.1.4")})),
            }
        },
    )
    unmatched: Counter[str] = Counter()
    vault = Installed("software", "vault/vault-0/vault", "vault", VAULT, None, "2.1.2")
    findings = list(match([vault], index, unmatched))
    assert [(f.cve, f.severity, f.fixed_version, f.status) for f in findings] == [
        ("CVE-2026-0001", "high", "2.1.3", "fix-available"),
        ("CVE-2026-0003", "unknown", "", "open"),
        ("CVE-2026-0005", "unknown", "2.1.5", "fix-available"),
        ("CVE-2026-0006", "unknown", "", "unconfirmed"),
        ("CVE-2026-0007", "unknown", "2.1.4", "fix-available"),
    ]
    assert (findings[0].target, findings[0].namespace, findings[0].package) == (
        "vault/vault-0/vault",
        "vault",
        "hashicorp/vault",
    )
    assert unmatched == Counter({"git": 1})
    assert list(match([vault], None, unmatched)) == []
