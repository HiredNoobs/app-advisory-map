from typing import Any

import pytest

from advisory_map.advisories.ranges import (
    Range,
    Unmatched,
    bounded,
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
        (
            {"version": "Open source RabbitMQ: >= 3.12.7, < 3.12.11", "status": "affected"},
            Range("3.12.7", True, "3.12.11", False),
        ),
        # Free text.
        ({"version": "before 1.6.8", "status": "affected"}, Range(None, True, "1.6.8", False)),
        ({"version": "Prior to v1.13.9", "status": "affected"}, Range(None, True, "v1.13.9", False)),
        ({"version": "3.2.x prior to 3.2.4", "status": "affected"}, Range("3.2", True, "3.2.4", False)),
        ({"version": "kubelet 1.6 earlier than 1.6.9", "status": "affected"}, Range("1.6", True, "1.6.9", False)),
        ({"version": "2.4.1 and earlier", "status": "affected"}, Range(None, True, "2.4.1", True)),
        ({"version": "2.4.1 or below", "status": "affected"}, Range(None, True, "2.4.1", True)),
        ({"version": "v1.28.0 - v1.28.8", "status": "affected"}, Range("v1.28.0", True, "v1.28.8", True)),
        ({"version": "from 1.0 through 2.0", "status": "affected"}, Range("1.0", True, "2.0", True)),
        # A free-text version beside an upper bound starts the range; a product's name starts from the first.
        (
            {"version": "kubelet v1.22.0 - v1.22.13", "lessThan": "v1.22.14", "status": "affected"},
            Range("v1.22.0", True, "v1.22.14", False),
        ),
        ({"version": "longhorn", "lessThan": "1.1.3", "status": "affected"}, Range(None, True, "1.1.3", False)),
        # A JSON escape left in the record's text.
        (
            {"version": "11.0.0", "lessThan": "11.0.5\\+security-01", "status": "affected"},
            Range("11.0.0", True, "11.0.5+security-01", False),
        ),
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


@pytest.mark.parametrize(
    "entry",
    [
        {"version": "1.24.0", "lessThanOrEqual": "<=", "status": "affected"},
        {"version": "1.8", "lessThan": "v1.8*", "status": "affected"},
        {"version": "1.5", "lessThan": "unspecified", "status": "affected"},
        {"version": "next of 1.23.1", "status": "unknown"},
    ],
)
def test_status_unparsable(entry: dict[str, str]) -> None:
    with pytest.raises(Unmatched, match="unparsable"):
        status({"versions": [entry]}, "1.30.0")


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
        (osv({"introduced": "0"}, {"fixed": "8f2e9c1"}, kind="GIT"), True),
        ({"versions": ["1.0"]}, True),
        (osv({"introduced": "0"}), False),
        # Fixed in a pseudo-version, reintroduced from a release on: the last event, in version order.
        (osv({"introduced": "0.0.1-test"}, {"introduced": "0"}, {"fixed": "0.0.0-20250521211231-abc"}), False),
        # A list of versions doesn't end a range that's left open.
        (osv({"introduced": "0"}, versions=["1.0"]), False),
        ({"ranges": [*TWICE["ranges"], *osv({"introduced": "2.0"})["ranges"]]}, False),
        ({}, False),
    ],
)
def test_osv_bounded(entry: dict[str, Any], expected: bool) -> None:
    assert osv_bounded(entry) is expected


@pytest.mark.parametrize(
    "versions, default, expected",
    [
        ([{"version": "0", "lessThan": "2.1.3", "status": "affected"}], None, True),
        ([{"version": "2.0", "lessThanOrEqual": "2.1.2", "status": "affected"}], "unaffected", True),
        ([{"version": "2.1.2", "status": "affected"}], None, True),
        ([{"version": ">= 1.0, < 2.0", "status": "affected"}], None, True),
        ([{"version": "2.0", "lessThan": "*", "status": "affected"}], None, False),
        ([{"version": ">= 1.0", "status": "affected"}], None, False),
        # Affected by default: the listed range doesn't end it, an unaffected one from a release does.
        ([{"version": "0", "lessThan": "1.9", "status": "affected"}], "affected", False),
        ([{"version": "2.1.3", "lessThan": "*", "status": "unaffected"}], "affected", True),
        ([{"version": "0", "lessThan": "1.3.0", "status": "unaffected"}], "affected", False),
        ([{"version": "n/a", "status": "affected"}], None, False),
        ([], "affected", False),
    ],
)
def test_bounded(versions: list[dict[str, str]], default: str | None, expected: bool) -> None:
    assert bounded({"versions": versions, "defaultStatus": default}) is expected
