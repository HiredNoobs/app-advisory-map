import urllib.error
from collections import Counter
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeHttp, osv_archive, response

from advisory_map.advisories import releases
from advisory_map.advisories.osv import Index, Osv, covered, match
from advisory_map.findings import Severity
from advisory_map.inventory.mapping import Installed, Package, ReleaseSource

URL = "http://osv"
VAULT = Package("Go", "github.com/hashicorp/vault")
CONSUL = Package("Go", "github.com/hashicorp/consul")
DAY = 86400
RELEASES = ReleaseSource("git", "https://github.com/hashicorp/vault")
PUBLISHED = releases.Index(frozenset({RELEASES}), {RELEASES: ("v2.1.2", "v2.1.3", "v2.1.4", "v2.1.5", "v2.2.0")})


def record(
    osv_id: str,
    fixed: str = "1.2.3",
    package: Package = VAULT,
    aliases: tuple[str, ...] = (),
    severity: str | None = None,
    modified: str = "2026-11-01T00:00:00Z",
    cwes: tuple[str, ...] = (),
    **fields: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": osv_id,
        "modified": modified,
        "aliases": list(aliases),
        "affected": [
            {
                "package": {"ecosystem": package.ecosystem, "name": package.name},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, *([{"fixed": fixed}] if fixed else [])]}],
            }
        ],
        **fields,
    }
    if severity or cwes:
        item["database_specific"] = {"severity": severity, "cwe_ids": list(cwes)}
    return item


def changes(*lines: tuple[str, str]) -> bytes:
    """modified_id.csv: newest first."""
    return "".join(f"{modified},{osv_id}\n" for modified, osv_id in lines).encode()


def not_found(url: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 404, "Not Found", Message(), None)


@pytest.fixture
def feed(tmp_path: Path, fake_http: FakeHttp) -> Osv:
    fake_http.routes[f"{URL}/Go/modified_id.csv"] = response(changes(("2026-11-01T00:00:00Z", "GHSA-0001")))
    fake_http.routes[f"{URL}/Go/all.zip"] = response(
        osv_archive(
            record("GHSA-0001", aliases=("CVE-2026-0001",), severity="HIGH", cwes=("CWE-79", "NVD-CWE-noinfo")),
            record("GHSA-0002", package=CONSUL),
            record("GHSA-0003", withdrawn="2026-10-01T00:00:00Z"),
        )
    )
    return Osv(tmp_path, {VAULT}, URL)


def ids(feed: Osv) -> list[str]:
    assert feed.data is not None
    return sorted(feed.data.advisories.get(VAULT, {}))


def test_full_read(feed: Osv) -> None:
    feed.update(1000, DAY)
    assert feed.data is not None and feed.data.cursors == {"Go": "2026-11-01T00:00:00Z"}
    assert {package: list(ids) for package, ids in feed.data.advisories.items()} == {VAULT: ["GHSA-0001"]}
    advisory = feed.data.advisories[VAULT]["GHSA-0001"]
    assert (advisory.key, advisory.severity, advisory.cwes) == (
        "CVE-2026-0001",
        Severity("high", "2026-11-01T00:00:00Z"),
        ("CWE-79",),
    )
    assert advisory.bounded
    assert feed.records() == 1
    # The archive is read from disk, then deleted.
    assert sorted(path.name for path in feed.data_dir.iterdir()) == ["osv-index.json", "osv.meta.json"]


def test_delta_reads_only_the_changed_records(feed: Osv, fake_http: FakeHttp) -> None:
    feed.update(1000, DAY)
    fake_http.routes = {
        f"{URL}/Go/modified_id.csv": response(
            changes(
                ("2026-11-03T00:00:00Z", "GHSA-0004"),
                ("2026-11-02T00:00:00Z", "GHSA-0001"),
                ("2026-11-02T00:00:00Z", "GHSA-0005"),
                # The day before the last pass's newest: read again.
                ("2026-10-31T12:00:00Z", "GHSA-0006"),
                ("2026-10-30T00:00:00Z", "GHSA-0007"),
            )
        ),
        f"{URL}/Go/GHSA-0004.json": response(record("GHSA-0004", fixed="1.3.0")),
        f"{URL}/Go/GHSA-0001.json": response(record("GHSA-0001", withdrawn="2026-11-02T00:00:00Z")),
        f"{URL}/Go/GHSA-0005.json": not_found(f"{URL}/Go/GHSA-0005.json"),
        f"{URL}/Go/GHSA-0006.json": response(record("GHSA-0006", package=CONSUL)),
    }
    fake_http.requests.clear()
    feed.update(1000 + DAY, DAY)
    assert feed.meta.last_success == 1000 + DAY
    assert ids(feed) == ["GHSA-0004"]
    assert feed.data is not None and feed.data.cursors == {"Go": "2026-11-03T00:00:00Z"}
    assert sorted(url.rsplit("/", 1)[1] for url, _ in fake_http.requests) == [
        "GHSA-0001.json",
        "GHSA-0004.json",
        "GHSA-0005.json",
        "GHSA-0006.json",
        "modified_id.csv",
    ]


def test_failed_delta_keeps_the_index(feed: Osv, fake_http: FakeHttp) -> None:
    feed.update(1000, DAY)
    fake_http.routes = {
        f"{URL}/Go/modified_id.csv": response(changes(("2026-11-02T00:00:00Z", "GHSA-0004"))),
        f"{URL}/Go/GHSA-0004.json": OSError("offline"),
    }
    feed.update(1000 + DAY, DAY)
    assert ids(feed) == ["GHSA-0001"]
    assert feed.data is not None and feed.data.cursors == {"Go": "2026-11-01T00:00:00Z"}
    assert feed.meta.last_success == 1000


def test_restart_uses_the_index(feed: Osv, fake_http: FakeHttp) -> None:
    feed.update(1000, DAY)
    fake_http.requests.clear()
    restarted = Osv(feed.data_dir, {VAULT}, URL)
    restarted.update(2000, DAY)
    assert restarted.data == feed.data
    assert fake_http.requests == []


def test_changed_packages_read_everything(feed: Osv) -> None:
    feed.update(1000, DAY)
    restarted = Osv(feed.data_dir, {VAULT, CONSUL}, URL)
    # Until then, the records of the packages still mapped.
    restarted.load()
    assert restarted.data is not None and list(restarted.data.advisories) == [VAULT]
    assert restarted.due(1000, DAY)
    restarted.update(1000, DAY)
    assert not restarted.due(1000, DAY)
    assert restarted.data is not None
    assert {package: sorted(ids) for package, ids in restarted.data.advisories.items()} == {
        VAULT: ["GHSA-0001"],
        CONSUL: ["GHSA-0002"],
    }


def test_without_packages(tmp_path: Path, fake_http: FakeHttp) -> None:
    feed = Osv(tmp_path, (), URL)
    feed.update(1000, DAY)
    assert (feed.records(), fake_http.requests) == (0, [])


def index(fake_http: FakeHttp, tmp_path: Path, *records: dict[str, Any]) -> Index:
    """What a full read of these records indexes."""
    fake_http.routes[f"{URL}/Go/modified_id.csv"] = response(changes())
    fake_http.routes[f"{URL}/Go/all.zip"] = response(osv_archive(*records))
    feed = Osv(tmp_path, {VAULT}, URL)
    feed.refresh(1000)
    assert feed.data is not None
    return feed.data


INSTALLED = Installed("software", "vault/vault-0/vault", "vault", None, VAULT, "v2.1.2", RELEASES)


@pytest.fixture
def found(fake_http: FakeHttp, tmp_path: Path) -> Index:
    return index(
        fake_http,
        tmp_path,
        # GitHub's and the Go team's records of one vulnerability: one finding, with the CWEs of both.
        record(
            "GHSA-0001",
            fixed="",
            aliases=("CVE-2026-0001", "GO-2026-0001"),
            severity="MODERATE",
            cwes=("CWE-770", "CWE-400"),
        ),
        record("GO-2026-0001", fixed="2.1.5", aliases=("CVE-2026-0001", "GHSA-0001"), cwes=("CWE-400",)),
        # Neither has a CVE: the GitHub advisory names the finding.
        record("GO-2026-0002", fixed="2.2.0", aliases=("GHSA-0002",)),
        record("GHSA-0003", fixed="2.0.0"),
        {
            **record("GO-2026-0004"),
            "affected": [{"package": {"ecosystem": "Go", "name": VAULT.name}, "ranges": [{"type": "GIT"}]}],
        },
        # The last affected version, rather than the first fixed one.
        {
            **record("GHSA-0008"),
            "affected": [
                {
                    "package": {"ecosystem": "Go", "name": VAULT.name},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "2.1.3"}]}],
                }
            ],
        },
        # Fixed in a version not released yet.
        record("GHSA-0009", fixed="2.3.0"),
    )


def test_match(found: Index) -> None:
    findings = sorted(match([INSTALLED], found, Counter(), PUBLISHED), key=lambda finding: finding.cve)
    # Each fix is the first release no deciding record includes: never a version not released yet.
    assert [(f.cve, f.severity, f.fixed_version, f.status, f.cwes) for f in findings] == [
        ("CVE-2026-0001", "medium", "2.1.5", "fix-available", ("CWE-400", "CWE-770")),
        ("GHSA-0002", "unknown", "2.2.0", "fix-available", ()),
        ("GHSA-0008", "unknown", "2.1.4", "fix-available", ()),
        ("GHSA-0009", "unknown", "", "open", ()),
    ]
    assert (findings[0].source, findings[0].package, findings[0].severity_updated) == (
        "osv",
        VAULT.name,
        "2026-11-01T00:00:00Z",
    )


def test_match_without_releases(found: Index) -> None:
    # Nothing to check against: none is known to be fixed.
    assert {f.status for f in match([INSTALLED], found, Counter())} == {"open"}


def test_match_counts_the_ranges_it_cant_compare(found: Index) -> None:
    unmatched: Counter[str] = Counter()
    list(match([INSTALLED], found, unmatched, PUBLISHED))
    assert unmatched == Counter({"git": 1})


def test_match_without_an_index() -> None:
    assert list(match([INSTALLED], None, Counter())) == []


def test_covered(found: Index) -> None:
    assert covered(INSTALLED, found) == {
        "CVE-2026-0001": True,
        "GHSA-0002": True,
        "GHSA-0003": True,
        "GO-2026-0004": False,
        "GHSA-0008": True,
        "GHSA-0009": True,
    }


def test_fingerprint_follows_the_affected_ranges(fake_http: FakeHttp, tmp_path: Path) -> None:
    def fingerprint(*records: dict[str, Any]) -> str:
        [finding] = match([INSTALLED], index(fake_http, tmp_path, *records), Counter())
        return finding.fingerprint

    first = fingerprint(record("GHSA-0001", fixed="2.1.5"), record("GO-2026-0001", aliases=("GHSA-0001",)))
    assert first
    assert fingerprint(record("GO-2026-0001", aliases=("GHSA-0001",)), record("GHSA-0001", fixed="2.1.5")) == first
    assert fingerprint(record("GHSA-0001", fixed="2.1.6"), record("GO-2026-0001", aliases=("GHSA-0001",))) != first
    assert (
        fingerprint(
            record("GHSA-0001", fixed="2.1.5", modified="2027-01-01T00:00:00Z"),
            record("GO-2026-0001", aliases=("GHSA-0001",)),
        )
        == first
    )


def test_bounded_records_decide(fake_http: FakeHttp, tmp_path: Path) -> None:
    found = index(
        fake_http,
        tmp_path,
        # The Go database's range is left open, GitHub's ends before the installed version: not affected.
        record("GHSA-0005", fixed="2.0.0", aliases=("CVE-2026-0005", "GO-2026-0005"), severity="HIGH"),
        record("GO-2026-0005", fixed="", aliases=("CVE-2026-0005", "GHSA-0005")),
        # Only open ranges: they decide.
        record("GO-2026-0006", fixed="", aliases=("CVE-2026-0006",)),
        # An entry per range, one left open: it includes every later release, whatever the others say.
        {
            **record("GHSA-0007", aliases=("CVE-2026-0007",)),
            "affected": [*record("x")["affected"], *record("x", fixed="")["affected"]],
        },
    )
    vault = Installed("software", "vault/vault-0/vault", "vault", None, VAULT, "v2.1.2")
    assert [(f.cve, f.status) for f in match([vault], found, Counter())] == [
        ("CVE-2026-0006", "open"),
        ("CVE-2026-0007", "open"),
    ]
    assert covered(vault, found) == {"CVE-2026-0005": True, "CVE-2026-0006": False, "CVE-2026-0007": False}
