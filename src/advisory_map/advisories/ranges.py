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

    @property
    def fixed(self) -> str:
        """The first version past an exclusive upper bound: the fix."""
        return self.upper if self.upper is not None and not self.upper_inclusive else ""


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


def to_range(entry: dict[str, Any]) -> Range:
    """One `versions` entry as a range."""
    if entry.get("versionType") == "git":
        raise Unmatched("git")
    version = str(entry.get("version", "")).strip()
    upper = entry.get("lessThan")
    upper_inclusive = upper is None
    if upper is None:
        upper = entry.get("lessThanOrEqual")
    if upper is not None:
        lower = None if version.lower() in _FROM_START else version
        return Range(lower, True, None if upper == "*" else upper, upper_inclusive)
    if version.lower() in _UNSPECIFIED:
        raise Unmatched("unspecified")
    if version == "*":
        return Range(None, True, None, True)
    if any(op in version for op in "<>="):
        return _constraints(version)
    return Range(version, True, version, True)


def status(affected: dict[str, Any], version: str) -> tuple[str, str]:
    """The status (affected, unaffected, unconfirmed or unknown) one `affected` entry gives version, and
    the fix if known.

    The first `versions` entry containing it decides, else the entry's defaultStatus. A default of
    affected beside only affected versions is unconfirmed: records list affected releases that way and
    leave every later release (fixed) affected too.
    """
    installed = comparable(version)
    entries = affected.get("versions", [])
    for entry in entries:
        bounds = to_range(entry)
        if bounds.contains(installed):
            return entry.get("status", "unknown"), bounds.fixed
    default = affected.get("defaultStatus") or "unknown"
    if default == "affected" and entries and all(entry.get("status") == "affected" for entry in entries):
        return "unconfirmed", ""
    return default, ""


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


def _osv_range(events: list[dict[str, str]], installed: Version) -> tuple[bool, str]:
    """Whether a SEMVER or ECOSYSTEM range includes the version, and its fix: OSV's evaluation, over the
    events in version order (introduced "0" first)."""
    ordered = sorted(
        ((comparable(value), kind, value) for event in events for kind, value in event.items() if kind != "limit"),
        key=lambda event: event[0],
    )
    affected = False
    for version, kind, _ in ordered:
        if kind == "introduced" and installed >= version:
            affected = True
        elif (kind == "fixed" and installed >= version) or (kind == "last_affected" and installed > version):
            affected = False
    if not affected:
        return False, ""
    return True, next((value for version, kind, value in ordered if kind == "fixed" and version > installed), "")


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


def osv_status(affected: dict[str, Any], version: str, ecosystem: str) -> tuple[bool, str]:
    """Whether one OSV `affected` entry includes version, and the fix if known.

    Its ranges decide where they can be ordered (SEMVER, and ECOSYSTEM in the ecosystems above); its list
    of affected versions does for the rest. A range neither can decide (GIT, or an unordered ECOSYSTEM
    range without the list) is unmatched.
    """
    listed = affected.get("versions", [])
    found = _bare(version) in {_bare(item) for item in listed}
    fixes, unordered = [], []
    for bounds in affected.get("ranges", []):
        kind = bounds.get("type", "")
        if kind == "SEMVER" or (kind == "ECOSYSTEM" and ecosystem in _ORDERED_ECOSYSTEMS):
            in_range, fixed = _osv_range(bounds.get("events", []), comparable(version))
            found = found or in_range
            fixes.append(fixed)
        elif not listed:
            raise Unmatched(kind.lower() or "unspecified")
        elif kind == "ECOSYSTEM":  # a GIT range's fixes are commits, not versions
            unordered += [event["fixed"] for event in bounds.get("events", []) if "fixed" in event]
    if not found:
        return False, ""
    # Else an unordered range's fix, if there's just one: of several, which applies isn't known.
    return True, next(filter(None, fixes), unordered[0] if len(set(unordered)) == 1 else "")
