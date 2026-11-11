"""The published releases of the mapped software: a git repository's tags, or an image's tags in its
registry. A finding's fix is the lowest release newer than the installed version that its advisory
doesn't include, so it's always a version that exists: an advisory's bounds only say where the affected
versions end, not that a release past them does.

Only the mapping's sources are looked up, by name, as a dependency updater does: never what's installed
or its versions.
"""

import json
import logging
import os
import re
import subprocess
import urllib.error
import urllib.parse
from bisect import bisect_right
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from operator import itemgetter
from pathlib import Path

from debian.debian_support import Version

from advisory_map.advisories import ranges
from advisory_map.advisories.feed import Feed, write_atomic
from advisory_map.common import http
from advisory_map.inventory.mapping import Installed, ReleaseSource, cut

log = logging.getLogger(__name__)

# Tags per registry request; registries page with a Link header past it.
_PAGE = 1000
# Docker Hub's names: the registry's host, and the namespace of its official images ("python").
_DOCKER_HUB = "registry-1.docker.io"
_AUTH_PARAMS = re.compile(r'(\w+)="([^"]*)"')
_NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')
# git asks for credentials when a repository is missing or private: a failure instead.
_GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
_GIT_TIMEOUT = 120


@dataclass(frozen=True)
class Index:
    sources: frozenset[ReleaseSource]
    # source -> its tags, as listed
    tags: dict[ReleaseSource, tuple[str, ...]]
    # (source, release regex) -> its releases, parsed once per index
    _releases: dict[tuple[ReleaseSource, re.Pattern[str]], list[tuple[Version, str]]] = field(
        init=False, default_factory=dict, compare=False, repr=False
    )

    def releases(self, source: ReleaseSource, regex: re.Pattern[str]) -> list[tuple[Version, str]]:
        """The source's releases, oldest first, each version as regex cuts it from a tag: one per version,
        however many of its tags name it (v1.2.3 and 1.2.3)."""
        key = (source, regex)
        if key not in self._releases:
            by_version: dict[Version, str] = {}
            for tag in self.tags.get(source, ()):
                if (version := cut(regex, tag)) is not None:
                    with suppress(ranges.Unmatched):
                        by_version.setdefault(ranges.comparable(version), version)
            self._releases[key] = sorted(by_version.items())
        return self._releases[key]

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "sources": sorted(self.sources),
                "tags": [[*source, tags] for source, tags in self.tags.items()],
            }
        ).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> "Index":
        index = json.loads(raw)
        return cls(
            frozenset(ReleaseSource(*source) for source in index["sources"]),
            {ReleaseSource(kind, name): tuple(tags) for kind, name, tags in index["tags"]},
        )


def git_tags(url: str) -> list[str]:
    """The repository's tags, from git's ref advertisement: one request, no API."""
    result = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", url],
        capture_output=True,
        text=True,
        env=_GIT_ENV,
        timeout=_GIT_TIMEOUT,
    )
    if result.returncode:
        raise RuntimeError(f"git ls-remote {url}: {result.stderr.strip()}")
    # Each line is "<sha>\trefs/tags/<tag>".
    return [line.partition("\t")[2].removeprefix("refs/tags/") for line in result.stdout.splitlines()]


def _registry_token(challenge: str) -> str:
    """An anonymous pull token from the registry's auth service, as its 401 challenge describes it."""
    scheme, _, params = challenge.partition(" ")
    if scheme.lower() != "bearer":
        raise RuntimeError(f"unsupported registry auth: {challenge!r}")
    fields = dict(_AUTH_PARAMS.findall(params))
    query = urllib.parse.urlencode({key: value for key, value in fields.items() if key in ("service", "scope")})
    body = json.loads(http.get(f"{fields['realm']}?{query}").body)
    return str(body.get("token") or body["access_token"])


def registry_tags(name: str) -> list[str]:
    """An image's tags (name: host/repository), from the registry API, anonymously."""
    host, _, repository = name.partition("/")
    if host == "docker.io":
        host = _DOCKER_HUB
        if "/" not in repository:
            repository = f"library/{repository}"
    base = f"https://{host}"
    url: str | None = f"{base}/v2/{repository}/tags/list?n={_PAGE}"
    headers: dict[str, str] = {}
    tags: list[str] = []
    while url:
        try:
            response = http.get(url, headers)
        except urllib.error.HTTPError as error:
            if error.code != 401 or headers:
                raise
            headers["Authorization"] = f"Bearer {_registry_token(error.headers.get('WWW-Authenticate', ''))}"
            continue
        tags += json.loads(response.body).get("tags") or []
        link = _NEXT_LINK.search(response.headers.get("Link", ""))
        url = urllib.parse.urljoin(base, link[1]) if link else None
    return tags


_LISTS: dict[str, Callable[[str], list[str]]] = {"git": git_tags, "registry": registry_tags}


class Releases(Feed[Index]):
    name = "releases"

    def __init__(self, data_dir: Path, sources: Iterable[ReleaseSource] = ()) -> None:
        super().__init__(data_dir)
        self.sources = frozenset(sources)
        self.path = data_dir / "releases.json"

    def records(self) -> int:
        return sum(len(tags) for tags in self.data.tags.values()) if self.data else 0

    def _load(self) -> Index:
        index = Index.from_json(self.path.read_bytes())
        # Listed for other sources, it's partial: those still mapped until a refresh.
        return replace(index, tags={source: tags for source, tags in index.tags.items() if source in self.sources})

    def _partial(self) -> bool:
        return self.data is not None and self.data.sources != self.sources

    def _fetch(self) -> None:
        tags = {source: tuple(_LISTS[source.kind](source.name)) for source in sorted(self.sources)}
        self.data = Index(self.sources, tags)
        write_atomic(self.path, self.data.to_json())
        log.info("feed %s: %d tags of %d sources", self.name, self.records(), len(self.sources))


def newer(item: Installed, index: Index | None) -> list[str]:
    """The installation's releases newer than its version, oldest first. Empty without a release source,
    or before its tags are known."""
    if index is None or item.releases is None:
        return []
    try:
        installed = ranges.comparable(item.version)
    except ranges.Unmatched:
        return []
    found = index.releases(item.releases, item.release_regex)
    return [version for _, version in found[bisect_right(found, installed, key=itemgetter(0)) :]]


def first_fix(releases: Iterable[str], affects: Callable[[str], bool]) -> str:
    """The first of releases the advisory doesn't affect, empty if it affects them all. A release whose
    status can't be compared isn't taken for a fix."""
    for version in releases:
        with suppress(ranges.Unmatched):
            if not affects(version):
                return version
    return ""
