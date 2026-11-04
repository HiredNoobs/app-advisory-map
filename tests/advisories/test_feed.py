import json
from pathlib import Path

from conftest import KEV, FakeHttp, response

from advisory_map.advisories.kev import Exploited, Kev


def test_refresh_then_not_modified(tmp_path: Path, fake_http: FakeHttp) -> None:
    feed = Kev(tmp_path)
    fake_http.routes[feed.url] = response(KEV, ETag='"v1"', Last_Modified="Tue, 03 Nov 2026 20:00:24 GMT")
    feed.refresh(100)
    assert feed.data == {"CVE-2026-0001": Exploited("2026-10-30", True)}
    assert feed.meta.last_success == 100 and feed.meta.etag == '"v1"'

    fake_http.routes[feed.url] = response(None, status=304)
    feed.refresh(200)
    assert fake_http.requests[-1][1] == {
        "If-None-Match": '"v1"',
        "If-Modified-Since": "Tue, 03 Nov 2026 20:00:24 GMT",
    }
    assert feed.meta.last_success == 200
    assert feed.records() == 1


def test_failed_refresh_keeps_the_last_good_copy(tmp_path: Path, fake_http: FakeHttp) -> None:
    feed = Kev(tmp_path)
    fake_http.routes[feed.url] = response(KEV)
    feed.refresh(100)

    fake_http.routes[feed.url] = response({"unexpected": []})
    feed.refresh(200)
    fake_http.routes[feed.url] = OSError("connection refused")
    feed.refresh(300)

    assert feed.records() == 1
    assert json.loads(feed.path.read_text()) == KEV
    assert feed.meta.last_success == 100 and feed.last_attempt == 300


def test_load_from_disk(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[Kev.url] = response(KEV, ETag='"v1"')
    Kev(tmp_path).refresh(100)

    feed = Kev(tmp_path)
    feed.load()
    assert feed.records() == 1 and feed.meta.etag == '"v1"'
    assert not feed.due(now=100 + 3600, interval=86400)
    assert feed.due(now=100 + 86400, interval=86400)


def test_copy_without_its_meta_is_used_and_refreshed(tmp_path: Path) -> None:
    (tmp_path / "kev.json").write_text(json.dumps(KEV))
    feed = Kev(tmp_path)
    feed.load()
    assert feed.records() == 1 and feed.due(now=100, interval=86400)


def test_unloadable_copy_is_fetched_whole(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[Kev.url] = response(KEV, ETag='"v1"')
    Kev(tmp_path).refresh(100)
    (tmp_path / "kev.json").write_text("not json")

    feed = Kev(tmp_path)
    feed.load()
    assert feed.data is None and feed.due(now=200, interval=86400)
    feed.refresh(200)
    # Nothing to fall back on, so no conditional headers.
    assert fake_http.requests[-1][1] == {}
    assert feed.records() == 1
