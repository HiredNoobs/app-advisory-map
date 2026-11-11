import json
import subprocess
import urllib.error
from dataclasses import replace
from email.message import Message
from pathlib import Path

import pytest
from conftest import FakeHttp, response

from advisory_map.advisories.releases import (
    Index,
    Releases,
    first_fix,
    newer,
    registry_tags,
)
from advisory_map.common import http
from advisory_map.inventory.mapping import Installed, Package, ReleaseSource

DAY = 86400
REGISTRY = ReleaseSource("registry", "ghcr.io/hashicorp/vault")
ALPINE = REGISTRY._replace(pattern=r"^(\d+\.\d+\.\d+)-alpine$")
CONSUL = ReleaseSource("registry", "ghcr.io/hashicorp/consul")
VAULT = Package("Go", "github.com/hashicorp/vault")
TAGS = "https://ghcr.io/v2/hashicorp/vault/tags/list"
CHALLENGE = 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:hashicorp/vault:pull"'


def unauthorized(url: str, challenge: str) -> urllib.error.HTTPError:
    headers = Message()
    headers["WWW-Authenticate"] = challenge
    return urllib.error.HTTPError(url, 401, "Unauthorized", headers, None)


def tagged_repository(path: Path, *tags: str) -> str:
    """A git repository with these tags (the first annotated) on one commit; its file:// URL."""
    path.mkdir()

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(path), "-c", "user.name=test", "-c", "user.email=test@example.invalid", *args],
            check=True,
            capture_output=True,
        )

    git("init", "--quiet")
    git("commit", "--quiet", "--allow-empty", "--message", "release")
    git("tag", "--annotate", "--message", tags[0], tags[0])
    for tag in tags[1:]:
        git("tag", tag)
    return path.as_uri()


def test_git_tags(tmp_path: Path) -> None:
    source = ReleaseSource("git", tagged_repository(tmp_path / "talos", "v1.14.4", "v1.14.5", "v1.15.0-beta.0"))
    feed = Releases(tmp_path, {source})
    feed.update(1000, DAY)
    assert feed.data is not None
    # Its release tags; an annotated one once, not its peeled ^{} ref as well.
    assert sorted(feed.data.tags[source]) == ["v1.14.4", "v1.14.5"]


def test_a_repository_is_listed_once_and_only_releases_kept(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[TAGS] = response({"tags": ["2.1.2", "2.1.2-alpine", "2.1", "9799770991", "sha-8f2e9c1"]})
    feed = Releases(tmp_path, {REGISTRY, ALPINE})
    feed.update(1000, DAY)
    assert feed.data is not None and feed.data.tags == {REGISTRY: ("2.1.2",), ALPINE: ("2.1.2-alpine",)}
    assert len(fake_http.requests) == 1


def test_missing_git_repository_fails(tmp_path: Path) -> None:
    feed = Releases(tmp_path, {ReleaseSource("git", (tmp_path / "missing").as_uri())})
    feed.update(1000, DAY)
    assert (feed.data, feed.meta.last_success) == (None, None)


def test_registry_tags_with_a_token_and_pages(fake_http: FakeHttp) -> None:
    def tags(url: str) -> http.Response:
        if fake_http.requests[-1][1].get("Authorization") != "Bearer t0ken":
            raise unauthorized(url, CHALLENGE)
        if "last=" in url:
            return response({"name": "hashicorp/vault", "tags": ["2.1.3"]})
        return response(
            {"name": "hashicorp/vault", "tags": ["2.1.1", "2.1.2"]},
            Link='</v2/hashicorp/vault/tags/list?last=2.1.2&n=1000>; rel="next"',
        )

    fake_http.routes["https://ghcr.io/token"] = response({"token": "t0ken"})
    fake_http.routes[TAGS] = tags
    assert registry_tags(REGISTRY.name) == ["2.1.1", "2.1.2", "2.1.3"]
    assert [url for url, _ in fake_http.requests] == [
        f"{TAGS}?n=1000",
        "https://ghcr.io/token?service=ghcr.io&scope=repository%3Ahashicorp%2Fvault%3Apull",
        f"{TAGS}?n=1000",
        f"{TAGS}?last=2.1.2&n=1000",
    ]


def test_registry_refuses_the_token(fake_http: FakeHttp) -> None:
    def refused(url: str) -> http.Response:
        raise unauthorized(url, CHALLENGE)

    fake_http.routes["https://ghcr.io/token"] = response({"token": "t0ken"})
    fake_http.routes[TAGS] = refused
    with pytest.raises(urllib.error.HTTPError):
        registry_tags(REGISTRY.name)


@pytest.mark.parametrize(
    "name, url",
    [
        ("docker.io/python", "https://registry-1.docker.io/v2/library/python/tags/list"),
        ("docker.io/grafana/grafana", "https://registry-1.docker.io/v2/grafana/grafana/tags/list"),
        ("quay.io/jetstack/cert-manager-controller", "https://quay.io/v2/jetstack/cert-manager-controller/tags/list"),
    ],
)
def test_registry_names(fake_http: FakeHttp, name: str, url: str) -> None:
    fake_http.routes[url] = response({"tags": ["1.0"]})
    assert registry_tags(name) == ["1.0"]


def test_restart_uses_the_copy_on_disk(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[TAGS] = response({"tags": ["2.1.2"]})
    feed = Releases(tmp_path, {REGISTRY})
    feed.update(1000, DAY)
    fake_http.requests.clear()
    restarted = Releases(tmp_path, {REGISTRY})
    restarted.update(2000, DAY)
    assert (restarted.data, fake_http.requests) == (feed.data, [])


def test_reads_a_copy_without_patterns(tmp_path: Path) -> None:
    # Its sources have the default pattern; tags it didn't filter aren't releases all the same.
    kind, name, _ = REGISTRY
    copy = {"sources": [[kind, name]], "tags": [[kind, name, ["2.1.3", "99"]]]}
    (tmp_path / "releases.json").write_text(json.dumps(copy))
    feed = Releases(tmp_path, {REGISTRY})
    feed.load()
    assert feed.data is not None and feed.data.sources == {REGISTRY}
    assert newer(vault("2.1.2"), feed.data) == ["2.1.3"]


def test_changed_sources_are_listed_again(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[TAGS] = response({"tags": ["2.1.2"]})
    fake_http.routes["https://ghcr.io/v2/hashicorp/consul/tags/list"] = response({"tags": ["1.22.0"]})
    Releases(tmp_path, {REGISTRY}).update(1000, DAY)
    restarted = Releases(tmp_path, {REGISTRY, CONSUL})
    # Until then, the tags of the sources still mapped.
    restarted.load()
    assert restarted.data is not None and list(restarted.data.tags) == [REGISTRY]
    assert restarted.due(1000, DAY)
    restarted.update(1000, DAY)
    assert restarted.data is not None and restarted.data.tags == {REGISTRY: ("2.1.2",), CONSUL: ("1.22.0",)}


def vault(version: str, source: ReleaseSource | None = REGISTRY) -> Installed:
    return Installed("container", "vault/vault-0/vault", "vault", None, VAULT, version, source)


TAGGED = ("2.1.1", "v2.1.2", "2.1.3-rc.1", "2.1.3", "2.1.10", "v2.1.10", "2.2", "2.2.0-alpine", "2.2.0", "latest")
INDEX = Index(frozenset({REGISTRY, ALPINE}), {REGISTRY: TAGGED, ALPINE: TAGGED})


def test_newer() -> None:
    # Plain versions only, oldest first, once each, as their first tag names them less a leading v.
    assert newer(vault("2.1.2"), INDEX) == ["2.1.3", "2.1.10", "2.2.0"]
    assert newer(vault("2.1.3"), INDEX) == ["2.1.10", "2.2.0"]
    assert newer(vault("v2.2.0"), INDEX) == []
    assert newer(vault("2.1.2", ALPINE), INDEX) == ["2.2.0"]
    assert newer(vault("2.1.2", source=None), INDEX) == []
    assert newer(vault("2.1.2"), None) == []
    assert newer(vault("latest"), INDEX) == []


def test_parsed_releases_stay_with_their_index() -> None:
    parsed = Index(frozenset({REGISTRY}), {REGISTRY: ("2.1.3",)})
    assert newer(vault("2.1.2"), parsed) == ["2.1.3"]
    # Equal to an index not parsed yet; one made from it (new tags) parses its own.
    assert parsed == Index(frozenset({REGISTRY}), {REGISTRY: ("2.1.3",)})
    assert newer(vault("2.1.2"), replace(parsed, tags={REGISTRY: ("2.1.4",)})) == ["2.1.4"]


def test_first_fix() -> None:
    assert first_fix(["2.1.3", "2.1.10", "2.2.0"], lambda version: version != "2.2.0") == "2.2.0"
    assert first_fix(["2.1.3"], lambda version: True) == ""
    assert first_fix([], lambda version: False) == ""
