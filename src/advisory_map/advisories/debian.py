"""Debian's security tracker: each source package's CVEs per release, with the version that fixed them."""

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, NamedTuple

from debian.debian_support import Version

from advisory_map.advisories.feed import Download
from advisory_map.common import jsonstream
from advisory_map.findings import Finding
from advisory_map.inventory.debian import DebianHost

# Most of the tracker's urgencies are "not yet assigned".
_SEVERITIES = {"not yet assigned": "unknown"}


class Entry(NamedTuple):
    # resolved, or why there's no fix: open, no-dsa, postponed, ignored, undetermined.
    status: str
    # Empty unless resolved.
    fixed_version: str
    severity: str


# release -> source package -> CVE -> entry
type Tracker = dict[str, dict[str, dict[str, Entry]]]


def _entry(state: dict[str, Any]) -> Entry | None:
    """One release's state of a CVE, None where the release was never affected."""
    status, fixed = state["status"], state.get("fixed_version", "")
    if status == "resolved" and fixed == "0":
        return None
    if status == "open" and "nodsa" in state:
        status = state.get("nodsa_reason") or "no-dsa"
    urgency = state["urgency"].rstrip("*")
    return Entry(status, fixed, _SEVERITIES.get(urgency, urgency))


class DebianTracker(Download[Tracker]):
    """Only the releases in use are kept, read a CVE at a time: the whole tracker is ~90 MB, ~450 MB as Python
    objects."""

    name = "debian"
    url = "https://security-tracker.debian.org/tracker/data/json"

    def __init__(self, data_dir: Path) -> None:
        super().__init__(data_dir)
        self.releases: frozenset[str] = frozenset()

    def use_releases(self, releases: Iterable[str]) -> None:
        """Keep these releases' entries, reloading the copy on disk when they change."""
        releases = frozenset(releases)
        if releases != self.releases:
            self.releases = releases
            self.load()

    def parse(self, path: Path) -> Tracker:
        reduced: Tracker = {release: {} for release in self.releases}
        advisories = 0
        with path.open(encoding="utf-8") as file:
            # A CVE at a time: a source package can be large (linux is over a third of the tracker).
            for (source, cve), advisory in jsonstream.members(file, depth=2):
                advisories += 1
                for release, state in advisory["releases"].items():
                    if release in reduced and (entry := _entry(state)):
                        reduced[release].setdefault(source, {})[cve] = entry
        if not advisories:
            raise ValueError("the tracker is empty")
        return reduced

    def records(self) -> int:
        return sum(len(cves) for sources in (self.data or {}).values() for cves in sources.values())


def _status(entry: Entry, installed: str) -> str | None:
    """The finding's status, None where the installed version has the fix."""
    if entry.status != "resolved":
        return entry.status
    if Version(installed) < Version(entry.fixed_version):
        return "fix-available"
    return None


def match(hosts: Iterable[DebianHost], tracker: Tracker) -> Iterator[Finding]:
    for host in hosts:
        sources = tracker.get(host.release, {})
        for source, installed in host.packages:
            for cve, entry in sources.get(source, {}).items():
                if status := _status(entry, installed):
                    yield Finding(
                        cve=cve,
                        severity=entry.severity,
                        severity_source="debian",
                        source="debian",
                        target_kind="debian-package",
                        target=host.instance,
                        namespace="",
                        package=source,
                        installed_version=installed,
                        fixed_version=entry.fixed_version,
                        status=status,
                    )
