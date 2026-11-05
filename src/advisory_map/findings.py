"""A CVE that applies to something running."""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from typing import NamedTuple

_CWE = re.compile(r"CWE-\d+")


class Severity(NamedTuple):
    level: str
    # When its source last updated it: ISO 8601, so comparable as text; empty where the source has no date.
    updated: str


@dataclass(frozen=True)
class Finding:
    # The CVE, or the advisory's own ID where it has none.
    cve: str
    severity: str
    severity_source: str
    source: str
    # What kind of thing target is: debian-package (a host's packages), or a mapping entry's kind.
    target_kind: str
    # The host (its instance label), or the mapping entry's target labels.
    target: str
    namespace: str
    package: str
    installed_version: str
    # Empty without a fix.
    fixed_version: str
    # fix-available, or why there's none (open, unconfirmed, no-dsa, postponed, ignored, undetermined).
    status: str
    # When severity was last updated, to keep the newest source's: not a label.
    severity_updated: str = field(default="", metadata={"label": False})
    # The weaknesses (CWE IDs) it's an instance of: a metric of their own, not a label.
    cwes: tuple[str, ...] = field(default=(), metadata={"label": False})


# The fields served as labels.
LABELS = tuple(item.name for item in fields(Finding) if item.metadata.get("label", True))


def cwe_ids(values: Iterable[object]) -> tuple[str, ...]:
    """The CWE IDs among a record's values, once each."""
    return tuple(sorted({value for value in values if isinstance(value, str) and _CWE.fullmatch(value)}))
