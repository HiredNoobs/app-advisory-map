"""Software outside a package manager, found in Prometheus by a mapping and matched as CVE List products
and/or OSV packages. The mapping's format is in docs/mapping.md."""

import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from advisory_map.inventory.prometheus import PrometheusAPI


class Product(NamedTuple):
    """A product as CVE records name it, lowercased: records differ in case."""

    vendor: str
    product: str


class Package(NamedTuple):
    """A package as OSV names it: an ecosystem as its exports do (Go, PyPI, npm, ...), and the name."""

    ecosystem: str
    name: str


# A release's tag: a plain version, not a pre-release, a variant, a floating or a build tag (1.2.3, v1.2.3;
# not 1.2.3-rc.1, 1.2.3-alpine, 1.2 or 9799770991).
DEFAULT_RELEASE_PATTERN = r"^v?(\d+\.\d+\.\d+)$"


class ReleaseSource(NamedTuple):
    """Where the published releases are listed, a git repository's tags (`git`, its URL) or an image's
    tags in its registry (`registry`, host/repository), and which tags are releases: those pattern
    matches, its first group (or its whole match, without groups) the version."""

    kind: str
    name: str
    pattern: str = DEFAULT_RELEASE_PATTERN


RELEASE_KINDS = ("git", "registry")


@dataclass(frozen=True)
class Software:
    query: str
    product: Product | None = None
    package: Package | None = None
    version_label: str = "version"
    version_regex: re.Pattern[str] | None = None
    target_labels: tuple[str, ...] = ("instance",)
    kind: str = "software"
    # Images it covers though its series don't name them (an app found by its chart's version).
    images: re.Pattern[str] | None = None
    # Where its releases are listed: its fixes are among them.
    releases: ReleaseSource | None = None


@dataclass(frozen=True)
class Mapping:
    software: tuple[Software, ...] = ()
    # Every running image, from this query's label: those no entry covers are reported.
    images_query: str | None = None
    image_label: str = "image"


@dataclass(frozen=True)
class Installed:
    kind: str
    target: str
    namespace: str
    product: Product | None
    package: Package | None
    version: str
    # Its entry's.
    releases: ReleaseSource | None = None


class Found(NamedTuple):
    installed: list[Installed]
    # Running images no entry covers.
    unmapped_images: list[str]


def _pair[T](entry: dict[str, Any], make: Callable[[str, str], T], first: str, second: str) -> T | None:
    """make(first, second) from the entry, None without either; one alone is an error."""
    if first not in entry and second not in entry:
        return None
    return make(entry[first], entry[second])


def _release_source(entry: dict[str, Any]) -> ReleaseSource | None:
    if "releases" not in entry:
        return None
    kind, _, name = entry["releases"].partition(":")
    if kind not in RELEASE_KINDS or not name:
        raise ValueError(f"releases must be git:<url> or registry:<host>/<repository>, not {entry['releases']!r}")
    return ReleaseSource(kind, name, re.compile(entry.get("release_regex", DEFAULT_RELEASE_PATTERN)).pattern)


def _software(entry: dict[str, Any]) -> Software:
    product = _pair(entry, lambda vendor, name: Product(vendor.lower(), name.lower()), "vendor", "product")
    package = _pair(entry, Package, "ecosystem", "package")
    if product is None and package is None:
        raise KeyError("vendor and product, or ecosystem and package")
    return Software(
        query=entry["query"],
        product=product,
        package=package,
        version_label=entry.get("version_label", "version"),
        version_regex=re.compile(entry["version_regex"]) if "version_regex" in entry else None,
        target_labels=tuple(entry.get("target_labels", ["instance"])),
        kind=entry.get("kind", "software"),
        images=re.compile(entry["images"]) if "images" in entry else None,
        releases=_release_source(entry),
    )


def load_mapping(path: Path) -> Mapping:
    with path.open("rb") as file:
        mapping = tomllib.load(file)
    software = []
    for number, entry in enumerate(mapping.get("software", []), 1):
        try:
            software.append(_software(entry))
        except (KeyError, TypeError, AttributeError, ValueError, re.error) as error:
            raise ValueError(f"{path}: [[software]] entry {number}: {error!r}") from error
    images = mapping.get("images", {})
    if images and "query" not in images:
        raise ValueError(f"{path}: [images] needs a query")
    return Mapping(tuple(software), images.get("query"), images.get("label", "image"))


def cut(regex: re.Pattern[str], text: str) -> str | None:
    """The version in text: regex's first group, or its whole match without groups. None if it doesn't match."""
    match = regex.search(text)
    if match is None:
        return None
    return match[1] if regex.groups else match[0]


def _version(software: Software, labels: dict[str, str]) -> str | None:
    version = labels.get(software.version_label)
    if version is None or software.version_regex is None:
        return version
    return cut(software.version_regex, version)


def _image(reference: str) -> str:
    """An image without its digest: the repository and tag are what a mapping covers."""
    return reference.partition("@")[0]


def find(prometheus: PrometheusAPI, mapping: Mapping) -> Found:
    """Every installation the mapping's queries find (series without a version are skipped), and the
    running images none of them covers."""
    installed = set()
    covered = set()
    for software in mapping.software:
        for series in prometheus.query(software.query):
            labels = series["metric"]
            if version := _version(software, labels):
                target = "/".join(labels.get(label, "") for label in software.target_labels)
                namespace = labels.get("namespace", "")
                installed.add(
                    Installed(
                        software.kind, target, namespace, software.product, software.package, version, software.releases
                    )
                )
                if image := labels.get(mapping.image_label):
                    covered.add(_image(image))
    unmapped = set()
    if mapping.images_query:
        for series in prometheus.query(mapping.images_query):
            image = _image(series["metric"].get(mapping.image_label, ""))
            if (
                image
                and image not in covered
                and not any(software.images and software.images.search(image) for software in mapping.software)
            ):
                unmapped.add(image)
    return Found(sorted(installed, key=lambda item: (item.kind, item.target, repr(item))), sorted(unmapped))
