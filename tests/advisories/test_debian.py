import json
from pathlib import Path

from conftest import TRACKER

from advisory_map.advisories.debian import DebianTracker, Entry, Tracker, match
from advisory_map.inventory.debian import DebianHost


def reduced(tmp_path: Path, *releases: str) -> Tracker:
    """TRACKER as the feed keeps it, for these releases."""
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps(TRACKER))
    feed = DebianTracker(tmp_path)
    feed.releases = frozenset(releases)
    return feed.parse(path)


def test_parse_keeps_only_the_releases_in_use(tmp_path: Path) -> None:
    tracker = reduced(tmp_path, "trixie")
    assert tracker.keys() == {"trixie"}
    assert tracker["trixie"]["openssl"]["CVE-2026-0001"] == Entry("resolved", "3.5.4-1~deb13u2", "high")


def test_parse_statuses(tmp_path: Path) -> None:
    trixie = reduced(tmp_path, "trixie")["trixie"]
    assert trixie["openssl"]["CVE-2026-0002"] == Entry("no-dsa", "", "low")
    assert trixie["curl"]["CVE-2026-0003"] == Entry("postponed", "", "medium")
    assert trixie["curl"]["CVE-2026-0004"] == Entry("undetermined", "", "unknown")


def test_parse_drops_releases_never_affected(tmp_path: Path) -> None:
    assert reduced(tmp_path, "bookworm") == {"bookworm": {}}


def test_use_releases_reloads_from_disk(tmp_path: Path) -> None:
    (tmp_path / "debian.json").write_text(json.dumps(TRACKER))
    feed = DebianTracker(tmp_path)
    feed.use_releases(["trixie"])
    assert feed.data is not None and "openssl" in feed.data["trixie"]
    assert feed.records() == 5


def test_match(tmp_path: Path) -> None:
    tracker = reduced(tmp_path, "trixie")
    host = DebianHost("vm-1", "trixie", frozenset({("openssl", "3.5.4-1~deb13u1"), ("curl", "8.14.1-2")}))
    found = {(f.cve, f.status, f.fixed_version) for f in match([host], tracker)}
    assert found == {
        # ~deb13u1 sorts before ~deb13u2.
        ("CVE-2026-0001", "fix-available", "3.5.4-1~deb13u2"),
        ("CVE-2026-0002", "no-dsa", ""),
        ("CVE-2026-0003", "postponed", ""),
        ("CVE-2026-0004", "undetermined", ""),
    }


def test_match_with_the_fix_installed(tmp_path: Path) -> None:
    tracker = reduced(tmp_path, "trixie")
    host = DebianHost("vm-1", "trixie", frozenset({("openssl", "3.5.4-1~deb13u2")}))
    assert [f.cve for f in match([host], tracker)] == ["CVE-2026-0002"]


def test_match_other_release(tmp_path: Path) -> None:
    tracker = reduced(tmp_path, "trixie")
    host = DebianHost("vm-1", "forky", frozenset({("openssl", "1.0")}))
    assert list(match([host], tracker)) == []
