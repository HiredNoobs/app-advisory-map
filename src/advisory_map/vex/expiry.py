"""When a verdict no longer holds: what it was made on has changed. Its vulnerability's advisories say
something new of how or where it's exploited (the finding's fingerprint differs from the one it had
when the verdict first applied), or it's been known to be exploited since (CISA's KEV)."""

import json
import logging
from collections.abc import Iterable, Mapping
from datetime import date
from pathlib import Path

from advisory_map.advisories.feed import write_atomic
from advisory_map.advisories.kev import Exploited
from advisory_map.findings import Finding, digest
from advisory_map.vex.openvex import Statement

log = logging.getLogger(__name__)

# Statement key -> CVE -> the finding's fingerprint when the statement first applied to it.
type Seen = Mapping[str, Mapping[str, str]]


def key(statement: Statement) -> str:
    """A statement, however many documents are read before it."""
    return digest([statement.author, statement.vulnerability, statement.timestamp.isoformat(), statement.products])


def expired(statement: Statement, finding: Finding, seen: Seen, kev: Mapping[str, Exploited]) -> bool:
    first = seen.get(key(statement), {}).get(finding.cve)
    if first and finding.fingerprint and first != finding.fingerprint:
        return True
    exploited = kev.get(finding.cve)
    return exploited is not None and date.fromisoformat(exploited.date_added) > statement.timestamp.date()


class Fingerprints:
    """The fingerprints the findings had when each statement first applied to them, kept in a file of the
    app's own (VEX_DIR/.fingerprints.json: its name starts with a dot, so it isn't read as a document)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, dict[str, str]] = {}
        try:
            loaded = json.loads(path.read_bytes())
            if not isinstance(loaded, dict) or not all(
                isinstance(seen, dict) and all(isinstance(value, str) for value in seen.values())
                for seen in loaded.values()
            ):
                raise ValueError("not an object of objects of fingerprints")
            self.data = loaded
        except FileNotFoundError:
            pass
        except ValueError as error:
            log.warning("%s doesn't load, starting again: %s", path, error)

    def record(self, applying: Iterable[tuple[Statement, Finding]], statements: Iterable[Statement]) -> None:
        """The fingerprints of findings statements apply to for the first time; statements no longer read
        are forgotten. Written only when that changes anything."""
        current = {key(statement) for statement in statements}
        data = {statement: seen.copy() for statement, seen in self.data.items() if statement in current}
        for statement, finding in applying:
            if finding.fingerprint:
                data.setdefault(key(statement), {}).setdefault(finding.cve, finding.fingerprint)
        if data != self.data:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            write_atomic(self.path, json.dumps(data, indent=2).encode())
            # Swapped in whole: scrapes read it meanwhile.
            self.data = data
