"""OSV's advisories (osv.dev), from its bulk exports: each mapped ecosystem's all.zip once, then the records
that changed, which its modified_id.csv lists newest first. Only the mapped packages' advisories are kept.

What's fetched never depends on what's installed: every record that changed is read, so nothing about
the inventory is sent.
"""

import json
import logging
import urllib.error
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import quote

from advisory_map.advisories import ranges
from advisory_map.advisories.feed import Feed, write_atomic
from advisory_map.common import http
from advisory_map.findings import Finding, Severity, cwe_ids
from advisory_map.inventory.mapping import Installed, Package

log = logging.getLogger(__name__)

URL = "https://osv-vulnerabilities.storage.googleapis.com"
# GitHub's levels, as the other sources name them.
_SEVERITIES = {"moderate": "medium"}


class Advisory(NamedTuple):
    # The CVE it's for, else its GitHub advisory, else its own ID: records for one vulnerability
    # (GitHub's, the Go team's, ...) share it.
    key: str
    # GitHub's level, dated by the record's last modification.
    severity: Severity | None
    # The record's affected entries for the package.
    affected: tuple[dict[str, Any], ...]
    # The weaknesses (CWE IDs) the record cites in its database_specific, as GitHub's do.
    cwes: tuple[str, ...]

    @property
    def bounded(self) -> bool:
        """Whether the record says where its affected versions end: one entry left open includes every
        later release."""
        return all(map(ranges.osv_bounded, self.affected))


# package -> OSV ID -> advisory
type Advisories = dict[Package, dict[str, Advisory]]


@dataclass(frozen=True)
class Index:
    packages: frozenset[Package]
    # ecosystem -> the newest modification its last pass read
    cursors: dict[str, str]
    advisories: Advisories

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "packages": sorted(self.packages),
                "cursors": self.cursors,
                "advisories": [
                    [*package, osv_id, *advisory]
                    for package, advisories in self.advisories.items()
                    for osv_id, advisory in advisories.items()
                ],
            }
        ).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> "Index":
        index = json.loads(raw)
        advisories: Advisories = {}
        for ecosystem, name, osv_id, key, severity, affected, cwes in index["advisories"]:
            advisories.setdefault(Package(ecosystem, name), {})[osv_id] = Advisory(
                key, Severity(*severity) if severity else None, tuple(affected), tuple(cwes)
            )
        return cls(frozenset(Package(*p) for p in index["packages"]), index["cursors"], advisories)


def _key(record: dict[str, Any]) -> str:
    ids = [record["id"], *record.get("aliases", [])]
    for prefix in ("CVE-", "GHSA-"):
        if found := sorted(i for i in ids if i.startswith(prefix)):
            return found[0]
    return str(record["id"])


def _severity(record: dict[str, Any]) -> Severity | None:
    level = record.get("database_specific", {}).get("severity")
    if not isinstance(level, str):
        return None
    level = level.lower()
    return Severity(_SEVERITIES.get(level, level), record.get("modified", ""))


class Osv(Feed[Index]):
    name = "osv"

    def __init__(self, data_dir: Path, packages: Iterable[Package] = (), url: str = URL) -> None:
        super().__init__(data_dir)
        self.url = url.rstrip("/")
        self.packages = frozenset(packages)
        self.index_path = data_dir / "osv-index.json"
        # Bytes that a record of a mapped package must contain: cheap to look for before parsing it.
        self._needles = [json.dumps(package.name).encode() for package in self.packages]

    def records(self) -> int:
        return sum(len(advisories) for advisories in self.data.advisories.values()) if self.data else 0

    def _load(self) -> Index:
        index = Index.from_json(self.index_path.read_bytes())
        # Indexed for other packages, it's partial: those still mapped until a refresh.
        return replace(index, advisories={p: ids for p, ids in index.advisories.items() if p in self.packages})

    def _partial(self) -> bool:
        return self.data is not None and self.data.packages != self.packages

    def _fetch(self) -> None:
        cursors: dict[str, str] = {}
        advisories: Advisories = {}
        for ecosystem in sorted({package.ecosystem for package in self.packages}):
            if self.data is None or self._partial() or not self.data.cursors.get(ecosystem):
                cursors[ecosystem], found = self._full(ecosystem)
            else:
                current = {p: a for p, a in self.data.advisories.items() if p.ecosystem == ecosystem}
                cursors[ecosystem], found = self._delta(ecosystem, current, self.data.cursors[ecosystem])
            advisories |= found
        self.data = Index(self.packages, cursors, advisories)
        write_atomic(self.index_path, self.data.to_json())
        log.info("feed %s: %d records of mapped packages", self.name, self.records())

    def _ecosystem_url(self, ecosystem: str, file: str) -> str:
        return f"{self.url}/{quote(ecosystem)}/{quote(file)}"

    def _changes(self, ecosystem: str) -> Iterator[tuple[str, str]]:
        """(modified, OSV ID) of the ecosystem's records, newest first."""
        with http.lines(self._ecosystem_url(ecosystem, "modified_id.csv")) as lines:
            for line in lines:
                modified, _, osv_id = line.decode().strip().partition(",")
                yield modified, osv_id

    def _full(self, ecosystem: str) -> tuple[str, Advisories]:
        """Every record, from the ecosystem's all.zip, read a record at a time from disk."""
        # The newest change before the download: the archive has everything up to it.
        cursor = next(self._changes(ecosystem), ("", ""))[0]
        advisories: Advisories = {}
        download = self.data_dir / ".osv-all.zip.tmp"
        try:
            http.get(self._ecosystem_url(ecosystem, "all.zip"), dest=download)
            with zipfile.ZipFile(download) as archive:
                for member in archive.infolist():
                    self._add(advisories, archive.read(member))
        finally:
            download.unlink(missing_ok=True)
        return cursor, advisories

    def _delta(self, ecosystem: str, current: Advisories, cursor: str) -> tuple[str, Advisories]:
        """The index with the records changed since the day before the last pass read again: an export can
        list a record after others modified later than it."""
        since = (date.fromisoformat(cursor[:10]) - timedelta(days=1)).isoformat()
        changed: dict[str, str] = {}
        for modified, osv_id in self._changes(ecosystem):
            if modified[:10] < since:
                break
            changed.setdefault(osv_id, modified)
        advisories = {
            package: {osv_id: advisory for osv_id, advisory in by_id.items() if osv_id not in changed}
            for package, by_id in current.items()
        }
        for osv_id in changed:
            try:
                raw = http.get(self._ecosystem_url(ecosystem, f"{osv_id}.json")).body
            except urllib.error.HTTPError as error:
                if error.code == 404:  # deleted
                    continue
                raise
            self._add(advisories, raw)
        return max([cursor, *changed.values()]), advisories

    def _add(self, advisories: Advisories, raw: bytes) -> None:
        if not any(needle in raw for needle in self._needles):
            return
        record = json.loads(raw)
        if record.get("withdrawn"):
            return
        affected: dict[Package, list[dict[str, Any]]] = {}
        for entry in record.get("affected", []):
            named = entry.get("package", {})
            package = Package(named.get("ecosystem", ""), named.get("name", ""))
            if package in self.packages:
                affected.setdefault(package, []).append(
                    {"ranges": entry.get("ranges", []), "versions": entry.get("versions", [])}
                )
        cwes = cwe_ids(record.get("database_specific", {}).get("cwe_ids", []))
        for package, entries in affected.items():
            advisories.setdefault(package, {})[record["id"]] = Advisory(
                _key(record), _severity(record), tuple(entries), cwes
            )


def covered(item: Installed, index: Index | None) -> dict[str, bool]:
    """The CVEs (and advisory IDs) OSV has records for in the installation's package, and whether one of
    them says where the affected versions end."""
    found: dict[str, bool] = {}
    if index is None or item.package is None:
        return found
    for advisory in index.advisories.get(item.package, {}).values():
        found[advisory.key] = found.get(advisory.key, False) or advisory.bounded
    return found


def _merged(verdicts: Iterable[tuple[bool, str]]) -> tuple[bool, str]:
    """Whether any verdict includes the version, and the first fix among those that do."""
    fixes = [fix for found, fix in verdicts if found]
    return bool(fixes), next(filter(None, fixes), "")


def _status(advisory: Advisory, version: str, ecosystem: str, unmatched: Counter[str]) -> tuple[bool, str]:
    """Whether the record includes the version, and the fix if known."""
    try:
        return _merged(ranges.osv_status(entry, version, ecosystem) for entry in advisory.affected)
    except ranges.Unmatched as reason:
        unmatched[str(reason)] += 1
        return False, ""


def match(installed: Iterable[Installed], index: Index | None, unmatched: Counter[str]) -> Iterator[Finding]:
    """A finding per vulnerability that includes an installation's version, its records merged; ranges
    that can't be compared are counted in unmatched by reason.

    Where a vulnerability has records that say where its affected versions end, they decide over those
    that leave a range open: a range is left open when the fix isn't a version of the package, as for
    Grafana 13 or Vault 2 as Go modules, while another record may name the release that fixed it.
    """
    if index is None:
        return
    for item in installed:
        if item.package is None:
            continue
        ecosystem = item.package.ecosystem
        vulnerabilities: dict[str, list[Advisory]] = {}
        for advisory in index.advisories.get(item.package, {}).values():
            vulnerabilities.setdefault(advisory.key, []).append(advisory)
        for key, records in vulnerabilities.items():
            deciding = [record for record in records if record.bounded] or records
            found, fixed = _merged(_status(record, item.version, ecosystem, unmatched) for record in deciding)
            if not found:
                continue
            severity = max(
                (record.severity for record in records if record.severity),
                key=lambda severity: severity.updated,
                default=Severity("unknown", ""),
            )
            yield Finding(
                cve=key,
                severity=severity.level,
                severity_source="osv",
                source="osv",
                target_kind=item.kind,
                target=item.target,
                namespace=item.namespace,
                package=item.package.name,
                installed_version=item.version,
                fixed_version=fixed,
                status="fix-available" if fixed else "open",
                severity_updated=severity.updated,
                cwes=cwe_ids(cwe for record in records for cwe in record.cwes),
            )
