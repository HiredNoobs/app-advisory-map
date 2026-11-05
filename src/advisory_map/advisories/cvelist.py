"""CVE.org's CVE List (github.com/CVEProject/cvelistV5): every CVE record, kept as a head-only bare git clone.

Two uses: the CVSS severity of any CVE, read from git by its ID when a finding needs it; and the CVEs of
the mapped products, from an index of just their records that each refresh updates from the files that
changed. Nothing holds all ~420k records at once.
"""

import json
import logging
import re
import subprocess
import threading
from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, NamedTuple

from advisory_map.advisories import ranges
from advisory_map.advisories.feed import Feed, write_atomic
from advisory_map.findings import Finding, Severity
from advisory_map.inventory.mapping import Installed, Product

log = logging.getLogger(__name__)

URL = "https://github.com/CVEProject/cvelistV5.git"
_BRANCH = "main"
# git maps whole pack files into memory and caches delta bases. Capped, reading every record of the
# ~340 MB pack peaks ~120 MB instead of ~450 MB, and the daily repack ~170 MB instead of ~570 MB. No
# automatic gc or maintenance: the feed repacks itself, and a detached `git maintenance` would never be
# reaped by the app, which is PID 1 in a container.
_GIT_CONFIG = [
    argument
    for setting in (
        "core.packedGitWindowSize=16m",
        "core.packedGitLimit=64m",
        "core.deltaBaseCacheLimit=16m",
        "pack.threads=1",
        "pack.windowMemory=32m",
        "gc.auto=0",
        "maintenance.auto=false",
    )
    for argument in ("-c", setting)
]
_RECORD = re.compile(r"CVE-\d+-\d+\.json")
# Newest first: the first a record's metrics have wins.
_CVSS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


class Advisory(NamedTuple):
    # Dated by when its provider (the CNA, or an ADP such as CISA's) last updated it.
    severity: Severity | None
    # The record's affected entries for the product.
    affected: tuple[dict[str, Any], ...]

    @property
    def bounded(self) -> bool:
        """Whether the record says where its affected versions end: the CNA's entry, or an ADP's that
        adds the bound."""
        return any(map(ranges.bounded, self.affected))


@dataclass(frozen=True)
class Index:
    commit: str
    products: frozenset[Product]
    # product -> CVE -> advisory
    advisories: dict[Product, dict[str, Advisory]]

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "commit": self.commit,
                "products": sorted(self.products),
                "advisories": [
                    [*product, cve, advisory.severity, advisory.affected]
                    for product, cves in self.advisories.items()
                    for cve, advisory in cves.items()
                ],
            }
        ).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> "Index":
        index = json.loads(raw)
        advisories: dict[Product, dict[str, Advisory]] = defaultdict(dict)
        for vendor, product, cve, severity, affected in index["advisories"]:
            advisories[Product(vendor, product)][cve] = Advisory(
                Severity(*severity) if severity else None, tuple(affected)
            )
        return cls(index["commit"], frozenset(Product(*p) for p in index["products"]), dict(advisories))


def record_path(cve: str) -> str:
    """Where a CVE's record is: cves/2026/12xxx/CVE-2026-12345.json."""
    _, year, number = cve.split("-")
    return f"cves/{year}/{number[:-3]}xxx/{cve}.json"


def _is_record(path: str) -> bool:
    """A CVE record, not one of the repository's other files (cves/deltaLog.json is ~40 MB)."""
    return _RECORD.fullmatch(path.rpartition("/")[2]) is not None


def _cvss_level(metrics: list[dict[str, Any]]) -> str | None:
    for version in _CVSS:
        for metric in metrics:
            if cvss := metric.get(version):
                if level := cvss.get("baseSeverity"):
                    return str(level).lower()
                if (score := cvss.get("baseScore")) is not None:
                    return "low" if score < 4 else "medium" if score < 7 else "high"
    return None


def _containers(record: dict[str, Any]) -> list[dict[str, Any]]:
    containers = record.get("containers", {})
    return [containers.get("cna", {}), *containers.get("adp", [])]


def severity(record: dict[str, Any]) -> Severity | None:
    """The CVSS severity of whichever container (the CNA's, an ADP's) updated one most recently."""
    found = None
    for container in _containers(record):
        if level := _cvss_level(container.get("metrics", [])):
            updated = container.get("providerMetadata", {}).get("dateUpdated", "")
            if found is None or updated > found.updated:
                found = Severity(level, updated)
    return found


class _Git:
    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def _command(self, *args: str) -> list[str]:
        return ["git", "-C", str(self.repo), *_GIT_CONFIG, *args]

    def __call__(self, *args: str) -> str:
        result = subprocess.run(self._command(*args), capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"git {args[0]}: {result.stderr.strip()}")
        return result.stdout

    def cat(self, names: Iterable[str]) -> Iterator[bytes | None]:
        """Each object's content (None where it's missing), in order. names are read on a thread while the
        contents stream back, so neither side is held whole."""
        with subprocess.Popen(
            self._command("cat-file", "--batch"), stdin=subprocess.PIPE, stdout=subprocess.PIPE
        ) as process:
            stdin, stdout = process.stdin, process.stdout
            assert stdin is not None and stdout is not None

            def write() -> None:
                try:
                    for name in names:
                        stdin.write(f"{name}\n".encode())
                except BrokenPipeError:
                    pass
                finally:
                    stdin.close()

            threading.Thread(target=write, daemon=True).start()
            while header := stdout.readline():
                fields = header.split()
                if len(fields) != 3:  # "<name> missing" (or ambiguous)
                    yield None
                    continue
                content = stdout.read(int(fields[2]))
                stdout.read(1)
                yield content

    def tree(self, commit: str, prefix: str) -> Iterator[tuple[str, str]]:
        """The path and ID of each file under prefix, streamed from ls-tree."""
        with subprocess.Popen(
            self._command("ls-tree", "-r", "-z", commit, "--", prefix), stdout=subprocess.PIPE
        ) as process:
            assert process.stdout is not None
            for entry in _split(process.stdout, b"\0"):
                info, _, path = entry.partition(b"\t")
                yield path.decode(), info.split()[2].decode()
        if process.returncode:
            raise RuntimeError(f"git ls-tree exited {process.returncode}")


def _split(stream: IO[bytes], separator: bytes) -> Iterator[bytes]:
    rest = b""
    while chunk := stream.read(1 << 16):
        *parts, rest = (rest + chunk).split(separator)
        yield from parts
    if rest:
        yield rest


class CveList(Feed[Index]):
    name = "cvelist"

    def __init__(self, data_dir: Path, products: Iterable[Product] = (), url: str = URL) -> None:
        super().__init__(data_dir)
        self.url = url
        self.products = frozenset(products)
        self.repo = data_dir / "cvelist.git"
        self.index_path = data_dir / "cvelist-index.json"
        self.git = _Git(self.repo)
        # CVE -> its severity, at data's commit.
        self._severities: dict[str, Severity | None] = {}
        # Bytes that a record of a mapped product must contain: cheap to look for before parsing it.
        self._needles = [json.dumps(product.product).encode() for product in self.products]

    def records(self) -> int:
        return sum(len(cves) for cves in self.data.advisories.values()) if self.data else 0

    def _load(self) -> Index | None:
        index = Index.from_json(self.index_path.read_bytes())
        # Indexed for other products: a refresh reads every record again.
        return index if index.products == self.products else None

    def _rev(self, ref: str) -> str | None:
        try:
            return self.git("rev-parse", "--verify", "--quiet", ref).strip() or None
        except RuntimeError:
            return None

    def _fetch(self) -> None:
        if not (self.repo / "HEAD").exists():
            self.repo.mkdir(parents=True, exist_ok=True)
            self.git("init", "--quiet", "--bare")
        old = self._rev(f"refs/heads/{_BRANCH}")
        self.git("fetch", "--quiet", "--depth", "1", self.url, _BRANCH)
        new = self.git("rev-parse", "FETCH_HEAD").strip()

        if self.data is None or old is None or self.data.commit != old:
            advisories = self._scan(new)
        elif new != old:
            advisories = self._delta(self.data.advisories, old, new)
        else:
            advisories = self.data.advisories
        index = Index(new, self.products, advisories)
        write_atomic(self.index_path, index.to_json())
        self.git("update-ref", f"refs/heads/{_BRANCH}", new)
        if self.data is None or self.data.commit != new:
            self._severities.clear()
        self.data = index
        if old not in (None, new):
            # Only the head's objects stay: the old commit goes, and the records only it had.
            self.git("reflog", "expire", "--expire=now", "--all")
            self.git("gc", "--quiet", "--prune=now")
        log.info("feed %s: at %s, %d records of mapped products", self.name, new[:12], self.records())

    def _mentions_products(self, raw: bytes) -> bool:
        lowered = raw.lower()
        return any(needle in lowered for needle in self._needles)

    def _add(self, advisories: dict[Product, dict[str, Advisory]], record: dict[str, Any]) -> None:
        if record.get("cveMetadata", {}).get("state") != "PUBLISHED":
            return
        affected: dict[Product, list[dict[str, Any]]] = defaultdict(list)
        for container in _containers(record):
            for entry in container.get("affected", []):
                product = Product(str(entry.get("vendor", "")).lower(), str(entry.get("product", "")).lower())
                if product in self.products:
                    affected[product].append(
                        {"versions": entry.get("versions", []), "defaultStatus": entry.get("defaultStatus")}
                    )
        cve = record["cveMetadata"]["cveId"]
        for product, entries in affected.items():
            advisories.setdefault(product, {})[cve] = Advisory(severity(record), tuple(entries))

    def _read(
        self, advisories: dict[Product, dict[str, Advisory]], names: Iterable[str]
    ) -> dict[Product, dict[str, Advisory]]:
        """advisories with these records added: only those mentioning a mapped product are parsed."""
        if self.products:
            for raw in self.git.cat(names):
                if raw and self._mentions_products(raw):
                    self._add(advisories, json.loads(raw))
        return advisories

    def _scan(self, commit: str) -> dict[Product, dict[str, Advisory]]:
        """Every record read again: the first refresh, or after the mapping's products change."""
        return self._read({}, (blob for path, blob in self.git.tree(commit, "cves") if _is_record(path)))

    def _delta(
        self, current: dict[Product, dict[str, Advisory]], old: str, new: str
    ) -> dict[Product, dict[str, Advisory]]:
        """The index with the records changed between two commits read again."""
        # Without rename detection, which lists a deleted record that resembles an added one under the new name only.
        diff = self.git("diff", "--name-only", "--no-renames", "-z", old, new, "--", "cves")
        paths = [path for path in diff.split("\0") if _is_record(path)]
        changed = {Path(path).stem for path in paths}
        kept = {
            product: {cve: advisory for cve, advisory in cves.items() if cve not in changed}
            for product, cves in current.items()
        }
        return self._read(kept, (f"{new}:{path}" for path in paths))

    def severities(self, cves: Collection[str]) -> dict[str, Severity]:
        """The CVSS severities of these CVEs, where their records have one."""
        if self.data is None:
            return {}
        wanted = sorted({cve for cve in cves if cve.startswith("CVE-")} - self._severities.keys())
        try:
            for cve, raw in zip(wanted, self.git.cat(f"{self.data.commit}:{record_path(cve)}" for cve in wanted)):
                self._severities[cve] = severity(json.loads(raw)) if raw else None
        except Exception as error:
            log.warning("feed %s: severities not read: %s", self.name, error)
        return {cve: level for cve in cves if (level := self._severities.get(cve))}


def bounded(item: Installed, index: Index | None) -> set[str]:
    """The CVEs whose record for the installation's product says where its affected versions end."""
    if index is None or item.product is None:
        return set()
    return {cve for cve, advisory in index.advisories.get(item.product, {}).items() if advisory.bounded}


def match(installed: Iterable[Installed], index: Index | None, unmatched: Counter[str]) -> Iterator[Finding]:
    """The CVEs whose affected versions include an installation's; ranges that can't be compared are
    counted in unmatched by reason."""
    if index is None:
        return
    for item in installed:
        if item.product is None:
            continue
        for cve, advisory in index.advisories.get(item.product, {}).items():
            try:
                verdicts = [ranges.status(affected, item.version) for affected in advisory.affected]
            except ranges.Unmatched as reason:
                unmatched[str(reason)] += 1
                continue
            statuses = {verdict for verdict, _ in verdicts}
            if "affected" in statuses:
                # The CNA's and ADPs' entries can differ: the first that names a fix.
                fixed = next((fix for verdict, fix in verdicts if verdict == "affected" and fix), "")
                status = "fix-available" if fixed else "open"
            elif "unconfirmed" in statuses:
                fixed, status = "", "unconfirmed"
            else:
                continue
            severity = advisory.severity or Severity("unknown", "")
            yield Finding(
                cve=cve,
                severity=severity.level,
                severity_source="cve.org",
                source="cve.org",
                target_kind=item.kind,
                target=item.target,
                namespace=item.namespace,
                package="/".join(item.product),
                installed_version=item.version,
                fixed_version=fixed,
                status=status,
                severity_updated=severity.updated,
            )
