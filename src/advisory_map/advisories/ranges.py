"""Whether a version is in an advisory's affected ranges: a CVE record's (CVE JSON 5 `versions`) or an
OSV record's (`ranges` and `versions`).

Versions are compared by dpkg's ordering (python-debian), after a semver-ish normalisation: a leading
"v" and "+build" metadata dropped, and "-" (a pre-release) as "~", which dpkg sorts before the release.
That orders 1.2.3-rc.1 < 1.2.3 < 1.2.10, as semver and most vendors do.
"""

import re
from contextlib import suppress
from typing import Any, NamedTuple

from debian.debian_support import Version

_CONSTRAINT = re.compile(r"\s*(<=|>=|<|>|=)?\s*([^\s,]+)\s*")
# A label before a version, ending in a colon: "Open source RabbitMQ: >= 3.12.7, < 3.12.11".
_LABEL = re.compile(r"^[^\d<>=:]+:\s*")
# Free-text ranges, as older records write them, and whether their upper bound is inclusive. Words
# naming the product may come first ("kubelet v1.22.0 - v1.22.13"); a lower bound's ".x" is dropped.
_LOWER, _UPPER = (rf"(?P<{bound}>v?\d[\w.~+-]*?)" for bound in ("lower", "upper"))
_FREE_TEXT = [
    (re.compile(rf"(?:[^\d<>=]*?\s)?{pattern}", re.IGNORECASE), upper_inclusive)
    for pattern, upper_inclusive in (
        # "before 1.6.8", "prior to 1.13.9", "3.2.x prior to 3.2.4"
        (rf"(?:{_LOWER}(?:\.x)?\s+)?(?:before|prior to|earlier than)\s+{_UPPER}", False),
        # "2.4.1 and earlier", "2.4.1 or below"
        (rf"{_UPPER}\s+(?:and|or)\s+(?:earlier|prior|below)", True),
        # "v1.28.0 - v1.28.8", "from 1.0 through 2.0"
        (rf"(?:from\s+)?{_LOWER}\s+(?:-|–|to|through)\s+{_UPPER}", True),
    )
]
_UNSPECIFIED = {"", "n/a", "unspecified", "unknown"}
# A range's lower bound that means "from the first version".
_FROM_START = {"0", "*"} | _UNSPECIFIED
# OSV ecosystems whose versions that ordering suits (semver, or close). Other ecosystems' ECOSYSTEM ranges
# (PyPI's PEP 440, Maven's, ...) are matched through the record's list of affected versions instead.
_ORDERED_ECOSYSTEMS = {"Go", "npm", "crates.io", "Hex", "Pub", "NuGet"}


class Unmatched(Exception):
    """A version or range that can't be compared; the reason is counted, not guessed."""


def _bare(version: str) -> str:
    return re.sub(r"^v(?=\d)", "", version.strip())


def comparable(version: str) -> Version:
    normalised = _bare(version).split("+", 1)[0].replace("-", "~")
    try:
        if not normalised[:1].isdigit():
            raise ValueError(version)
        return Version(normalised)
    except ValueError:
        raise Unmatched("unparsable") from None


class Range(NamedTuple):
    lower: str | None
    lower_inclusive: bool
    upper: str | None
    upper_inclusive: bool

    def contains(self, version: Version) -> bool:
        if self.lower is not None:
            lower = comparable(self.lower)
            if version < lower or (version == lower and not self.lower_inclusive):
                return False
        if self.upper is not None:
            upper = comparable(self.upper)
            if version > upper or (version == upper and not self.upper_inclusive):
                return False
        return True


def _constraints(text: str) -> Range:
    """GitHub's form: ">= 1.0.0, < 1.2.3", "< 2.0", "= 1.4"."""
    lower, lower_inclusive, upper, upper_inclusive = None, True, None, True
    for part in text.split(","):
        match = _CONSTRAINT.fullmatch(part)
        if not match:
            raise Unmatched("unparsable")
        op, version = match[1] or "=", match[2]
        if op in (">", ">=", "="):
            lower, lower_inclusive = version, op != ">"
        if op in ("<", "<=", "="):
            upper, upper_inclusive = version, op != "<"
    return Range(lower, lower_inclusive, upper, upper_inclusive)


def _free_text(text: str) -> Range | None:
    for pattern, upper_inclusive in _FREE_TEXT:
        if match := pattern.fullmatch(text):
            return Range(match.groupdict().get("lower"), True, match["upper"], upper_inclusive)
    return None


def _text(value: object) -> str:
    """A version field without a label or the JSON escapes some records keep ("11.0.5\\+security-01")."""
    return _LABEL.sub("", str(value).replace("\\", "").strip())


def _start(version: str) -> str | None:
    """Where a range given an upper bound starts: its version (a release line's "10.4.x" as 10.4), or a
    free-text range's start. From the first version where it names none ("0", "n/a", the product's name)."""
    if version.lower() in _FROM_START or not any(char.isdigit() for char in version):
        return None
    found = _free_text(version)
    return found.lower if found else re.sub(r"\.x$", "", version, flags=re.IGNORECASE)


def to_range(entry: dict[str, Any]) -> Range:
    """One `versions` entry as a range: CVE JSON 5's bounds, GitHub's constraints or common free text."""
    if entry.get("versionType") == "git":
        raise Unmatched("git")
    version = _text(entry.get("version", ""))
    upper = entry.get("lessThan")
    upper_inclusive = upper is None
    if upper is None:
        upper = entry.get("lessThanOrEqual")
    if upper is not None:
        upper = _text(upper)
        return Range(_start(version), True, None if upper == "*" else upper, upper_inclusive)
    if version.lower() in _UNSPECIFIED:
        raise Unmatched("unspecified")
    if version == "*":
        return Range(None, True, None, True)
    if found := _free_text(version):
        return found
    if any(op in version for op in "<>="):
        return _constraints(version)
    return Range(version, True, version, True)


def status(affected: dict[str, Any], version: str) -> str:
    """The status (affected, unaffected, unconfirmed or unknown) one `affected` entry gives version.

    The first `versions` entry containing it decides, else the entry's defaultStatus. A default of
    affected beside only affected versions is unconfirmed: records list affected releases that way and
    leave every later release (fixed) affected too.
    """
    installed = comparable(version)
    entries = affected.get("versions", [])
    for entry in entries:
        bounds = to_range(entry)
        if bounds.contains(installed):
            return str(entry.get("status", "unknown"))
    default = affected.get("defaultStatus") or "unknown"
    if default == "affected" and entries and all(entry.get("status") == "affected" for entry in entries):
        return "unconfirmed"
    return str(default)


def bounded(affected: dict[str, Any]) -> bool:
    """Whether one `affected` entry says where its affected versions end: an affected range with an upper
    bound (a single version is one) unless later releases are affected by default, or an unaffected
    range from a release on."""
    affected_by_default = affected.get("defaultStatus") == "affected"

    def ends(entry: dict[str, Any]) -> bool:
        try:
            bounds = to_range(entry)
        except Unmatched:
            return False
        if entry.get("status") == "affected":
            return bounds.upper is not None and not affected_by_default
        return entry.get("status") == "unaffected" and bounds.lower is not None and bounds.upper is None

    return any(map(ends, affected.get("versions", [])))


def _osv_range(events: list[dict[str, str]], installed: Version) -> bool:
    """Whether a SEMVER or ECOSYSTEM range includes the version: OSV's evaluation, over the events in
    version order (introduced "0" first)."""
    ordered = sorted(
        ((comparable(value), kind) for event in events for kind, value in event.items() if kind != "limit"),
        key=lambda event: event[0],
    )
    affected = False
    for version, kind in ordered:
        if kind == "introduced" and installed >= version:
            affected = True
        elif (kind == "fixed" and installed >= version) or (kind == "last_affected" and installed > version):
            affected = False
    return affected


def _osv_ends(bounds: dict[str, Any]) -> bool:
    """Whether an OSV range's last event, in version order, ends it (a fix, a last affected version)
    rather than introducing every version after it. Events that can't be ordered (a GIT range's commits)
    are taken as listed."""
    events = [(kind, value) for event in bounds.get("events", []) for kind, value in event.items() if kind != "limit"]
    if bounds.get("type") != "GIT":
        with suppress(Unmatched):
            events.sort(key=lambda event: comparable(event[1]))
    return bool(events) and events[-1][0] != "introduced"


def osv_bounded(affected: dict[str, Any]) -> bool:
    """Whether one OSV `affected` entry says where its affected versions end: every range ends, or it
    has only a list of versions. One range left open includes every later release, whatever the others
    say."""
    found = affected.get("ranges", [])
    return all(map(_osv_ends, found)) if found else bool(affected.get("versions"))


def osv_status(affected: dict[str, Any], version: str, ecosystem: str) -> bool:
    """Whether one OSV `affected` entry includes version.

    Its ranges decide where they can be ordered (SEMVER, and ECOSYSTEM in the ecosystems above); its list
    of affected versions does for the rest. A range neither can decide (GIT, or an unordered ECOSYSTEM
    range without the list) is unmatched.
    """
    listed = affected.get("versions", [])
    found = _bare(version) in {_bare(item) for item in listed}
    for bounds in affected.get("ranges", []):
        kind = bounds.get("type", "")
        if kind == "SEMVER" or (kind == "ECOSYSTEM" and ecosystem in _ORDERED_ECOSYSTEMS):
            found = _osv_range(bounds.get("events", []), comparable(version)) or found
        elif not listed:
            raise Unmatched(kind.lower() or "unspecified")
    return found
