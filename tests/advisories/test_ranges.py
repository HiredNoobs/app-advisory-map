from typing import Any

import pytest

from advisory_map.advisories.ranges import (
    Range,
    Unmatched,
    comparable,
    osv_bounded,
    osv_status,
    status,
    to_range,
)


@pytest.mark.parametrize(
    "older, newer",
    [
        ("1.2.3-rc.1", "1.2.3"),
        ("1.2.3", "1.2.10"),
        ("v1.9.0", "1.10.0"),
        ("1.21.2", "v1.21.3"),
        ("2.0.0-alpha", "2.0.0-beta"),
        ("1.0", "1.0.1"),
    ],
)
def test_order(older: str, newer: str) -> None:
    assert comparable(older) < comparable(newer)


def test_build_metadata_is_ignored() -> None:
    assert comparable("1.2.3+build.5") == comparable("1.2.3")


@pytest.mark.parametrize("version", ["", "n/a", "latest", "1.0 beta", "commit abc"])
def test_unparsable(version: str) -> None:
    with pytest.raises(Unmatched, match="unparsable"):
        comparable(version)


@pytest.mark.parametrize(
    "entry, expected",
    [
        ({"version": "0", "lessThan": "1.2.3", "status": "affected"}, Range(None, True, "1.2.3", False)),
        ({"version": "1.0.0", "lessThanOrEqual": "1.4", "status": "affected"}, Range("1.0.0", True, "1.4", True)),
        ({"version": "1.0", "lessThanOrEqual": "*", "status": "affected"}, Range("1.0", True, None, True)),
        ({"version": "n/a", "lessThan": "2", "status": "affected"}, Range(None, True, "2", False)),
        ({"version": "1.4.2", "status": "affected"}, Range("1.4.2", True, "1.4.2", True)),
        ({"version": "*", "status": "affected"}, Range(None, True, None, True)),
        # GitHub's records.
        ({"version": ">= 1.0.0, < 1.2.3", "status": "affected"}, Range("1.0.0", True, "1.2.3", False)),
        ({"version": "< 2.0", "status": "affected"}, Range(None, True, "2.0", False)),
        ({"version": "> 1.0, <= 1.5", "status": "affected"}, Range("1.0", False, "1.5", True)),
    ],
)
def test_to_range(entry: dict[str, str], expected: Range) -> None:
    assert to_range(entry) == expected


@pytest.mark.parametrize(
    "entry, reason",
    [
        ({"version": "abc123", "versionType": "git", "status": "affected"}, "git"),
        ({"version": "n/a", "status": "affected"}, "unspecified"),
        ({"version": "<< 1", "status": "affected"}, "unparsable"),
    ],
)
def test_to_range_unmatched(entry: dict[str, str], reason: str) -> None:
    with pytest.raises(Unmatched, match=reason):
        to_range(entry)


AFFECTED = {
    "versions": [
        {"version": "1.20.0", "lessThan": "1.20.5", "status": "affected"},
        {"version": "1.21.0", "lessThan": "1.21.2", "status": "affected"},
        {"version": "1.21.1", "status": "unaffected"},
    ],
    "defaultStatus": "unaffected",
}


@pytest.mark.parametrize(
    "version, expected",
    [
        ("1.20.4", ("affected", "1.20.5")),
        ("1.20.5", ("unaffected", "")),
        ("v1.21.0", ("affected", "1.21.2")),
        ("1.22.0", ("unaffected", "")),
        ("1.19.9", ("unaffected", "")),
    ],
)
def test_status(version: str, expected: tuple[str, str]) -> None:
    assert status(AFFECTED, version) == expected


def test_status_without_a_default() -> None:
    assert status({"versions": []}, "1.0") == ("unknown", "")


def test_status_affected_by_default() -> None:
    fixed_in_2 = {
        "versions": [{"version": "2.0", "lessThan": "*", "status": "unaffected"}],
        "defaultStatus": "affected",
    }
    assert status(fixed_in_2, "1.9") == ("affected", "")
    assert status(fixed_in_2, "2.1") == ("unaffected", "")
    assert status({"versions": [], "defaultStatus": "affected"}, "1.0") == ("affected", "")


def test_status_affected_by_default_beside_affected_versions() -> None:
    listed = {
        "versions": [{"version": "1.13.0", "lessThanOrEqual": "1.13.4", "status": "affected"}],
        "defaultStatus": "affected",
    }
    assert status(listed, "1.13.2") == ("affected", "")
    assert status(listed, "1.15.0") == ("unconfirmed", "")


def osv(*events: dict[str, str], kind: str = "SEMVER", versions: list[str] | None = None) -> dict[str, Any]:
    return {"ranges": [{"type": kind, "events": list(events)}], "versions": versions or []}


# Fixed in 1.2.5, then reintroduced in 1.3.0 and fixed again in 1.3.1 (events out of order, as records have them).
TWICE = osv({"introduced": "1.3.0"}, {"fixed": "1.3.1"}, {"introduced": "0"}, {"fixed": "1.2.5"})


@pytest.mark.parametrize(
    "entry, version, expected",
    [
        (TWICE, "1.2.0", (True, "1.2.5")),
        (TWICE, "v1.2.5", (False, "")),
        (TWICE, "1.2.7", (False, "")),
        (TWICE, "1.3.0", (True, "1.3.1")),
        (TWICE, "1.3.1", (False, "")),
        (osv({"introduced": "1.0"}, {"last_affected": "1.4"}), "1.4", (True, "")),
        (osv({"introduced": "1.0"}, {"last_affected": "1.4"}), "1.4.1", (False, "")),
        (osv({"introduced": "1.0"}, {"last_affected": "1.4"}), "0.9", (False, "")),
        (osv({"introduced": "0"}, {"fixed": "1.2.0"}), "1.2.0-rc.1", (True, "1.2.0")),
        # Go's ECOSYSTEM ranges are semver.
        (osv({"introduced": "0"}, {"fixed": "0.36.0"}, kind="ECOSYSTEM"), "v0.35.0", (True, "0.36.0")),
    ],
)
def test_osv_status(entry: dict[str, Any], version: str, expected: tuple[bool, str]) -> None:
    assert osv_status(entry, version, "Go") == expected


def test_osv_status_unordered_ecosystem() -> None:
    # PyPI's ordering (PEP 440) isn't dpkg's: the record's list of affected versions decides.
    entry = osv({"introduced": "0"}, {"fixed": "0.31.0"}, kind="ECOSYSTEM", versions=["0.30.0", "0.30.0rc1"])
    assert osv_status(entry, "0.30.0rc1", "PyPI") == (True, "0.31.0")
    assert osv_status(entry, "0.31.0", "PyPI") == (False, "")
    with pytest.raises(Unmatched, match="ecosystem"):
        osv_status(osv({"introduced": "0"}, {"fixed": "0.31.0"}, kind="ECOSYSTEM"), "0.30.0", "PyPI")


def test_osv_status_git() -> None:
    git = osv({"introduced": "0"}, {"fixed": "8f2e9c1"}, kind="GIT")
    with pytest.raises(Unmatched, match="git"):
        osv_status(git, "1.0", "Go")
    assert osv_status({**git, "versions": ["1.0"]}, "1.0", "Go") == (True, "")


@pytest.mark.parametrize(
    "entry, expected",
    [
        (TWICE, True),
        (osv({"introduced": "1.0"}, {"last_affected": "1.4"}), True),
        (osv({"introduced": "0"}, versions=["1.0"]), True),
        (osv({"introduced": "0"}), False),
        ({}, False),
    ],
)
def test_osv_bounded(entry: dict[str, Any], expected: bool) -> None:
    assert osv_bounded(entry) is expected
