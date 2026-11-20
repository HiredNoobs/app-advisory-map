import json
from datetime import UTC, datetime
from pathlib import Path

from advisory_map.advisories.kev import Exploited
from advisory_map.findings import Finding
from advisory_map.vex.expiry import Fingerprints, expired
from advisory_map.vex.openvex import Statement, product


def finding(fingerprint: str = "aaaa", cve: str = "CVE-1") -> Finding:
    return Finding(
        cve, "high", "osv", "osv", "container", "ns/app", "ns", "pkg", "1.0", "", "open", fingerprint=fingerprint
    )


def verdict(day: int = 10, cve: str = "CVE-1") -> Statement:
    return Statement(
        cve, (), (product(),), "not_affected", "component_not_present", "", "", datetime(2026, 11, day, tzinfo=UTC), "a"
    )


def test_expires_when_its_vulnerability_changes(tmp_path: Path) -> None:
    fingerprints = Fingerprints(tmp_path / ".fingerprints.json")
    statement = verdict()
    fingerprints.record([(statement, finding("aaaa"))], [statement])
    assert not expired(statement, finding("aaaa"), fingerprints.data, {})
    assert expired(statement, finding("bbbb"), fingerprints.data, {})
    # Without a fingerprint now (its record not read), nothing to compare.
    assert not expired(statement, finding(""), fingerprints.data, {})


def test_a_new_statement_starts_again(tmp_path: Path) -> None:
    fingerprints = Fingerprints(tmp_path / ".fingerprints.json")
    old, new = verdict(10), verdict(11)
    fingerprints.record([(old, finding("aaaa"))], [old])
    fingerprints.record([(new, finding("bbbb"))], [old, new])
    assert expired(old, finding("bbbb"), fingerprints.data, {})
    assert not expired(new, finding("bbbb"), fingerprints.data, {})


def test_expires_when_exploited_since() -> None:
    statement = verdict(10)
    assert expired(statement, finding(), {}, {"CVE-1": Exploited("2026-11-11", False)})
    # Known when it was made.
    assert not expired(statement, finding(), {}, {"CVE-1": Exploited("2026-11-10", False)})
    assert not expired(statement, finding(), {}, {"CVE-2": Exploited("2026-11-11", False)})


def test_record_keeps_the_first_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / ".fingerprints.json"
    statement = verdict()
    fingerprints = Fingerprints(path)
    fingerprints.record([(statement, finding(""))], [statement])
    assert fingerprints.data == {}
    fingerprints.record([(statement, finding("aaaa"))], [statement])
    fingerprints.record([(statement, finding("bbbb"))], [statement])
    assert Fingerprints(path).data == fingerprints.data
    assert list(fingerprints.data.values()) == [{"CVE-1": "aaaa"}]


def test_record_forgets_statements_that_are_gone(tmp_path: Path) -> None:
    path = tmp_path / ".fingerprints.json"
    statement = verdict()
    fingerprints = Fingerprints(path)
    fingerprints.record([(statement, finding("aaaa"))], [statement])
    fingerprints.record([], [])
    assert Fingerprints(path).data == {}


def test_an_unreadable_file_starts_again(tmp_path: Path) -> None:
    path = tmp_path / ".fingerprints.json"
    path.write_text("{")
    assert Fingerprints(path).data == {}
    for content in (["not", "a", "mapping"], {"statement": ["not", "a", "mapping"]}, {"statement": {"CVE-1": 1}}):
        path.write_text(json.dumps(content))
        assert Fingerprints(path).data == {}
