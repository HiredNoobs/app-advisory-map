"""An advisory feed, kept on disk as its last good copy."""

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from advisory_map.common import http

log = logging.getLogger(__name__)


@dataclass
class Meta:
    """When the feed last succeeded, and what a download's next conditional GET needs."""

    etag: str | None = None
    last_modified: str | None = None
    last_success: float | None = None


def _tmp(path: Path) -> Path:
    """Where path's next version is written, to replace it whole (never a partial file)."""
    return path.with_name(f".{path.name}.tmp")


def write_atomic(path: Path, data: bytes) -> None:
    tmp = _tmp(path)
    tmp.write_bytes(data)
    os.replace(tmp, path)


class Feed[T]:
    """Refreshed when due; a refresh that fails keeps the last good copy, on disk and in data."""

    name: str

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.meta_path = data_dir / f"{self.name}.meta.json"
        self.data: T | None = None
        self.meta = Meta()
        self.last_attempt: float | None = None

    def records(self) -> int:
        """How many records data holds, for the feed's metrics."""
        raise NotImplementedError

    def _load(self) -> T | None:
        """The copy on disk: FileNotFoundError without one, None where it can't be used."""
        raise NotImplementedError

    def _fetch(self) -> None:
        """A new copy into data and on disk, or an exception leaving both as they were."""
        raise NotImplementedError

    def load(self) -> None:
        """The copy on disk, if there is one. One that doesn't load is fetched again."""
        try:
            self.data = self._load()
            # Without its meta (a crash between the two writes) it's used, and refreshed at once.
            self.meta = Meta(**json.loads(self.meta_path.read_bytes()))
        except FileNotFoundError:
            pass
        except Exception as error:
            log.warning("feed %s: the copy on disk doesn't load, fetching it again: %s", self.name, error)
            self.data = None

    def due(self, now: float, interval: int) -> bool:
        return self.data is None or self.meta.last_success is None or now - self.meta.last_success >= interval

    def update(self, now: float, interval: int) -> None:
        """The copy on disk until there's one in use, then a refresh whenever one is due."""
        if self.data is None:
            self.load()
        if self.due(now, interval):
            self.refresh(now)

    def refresh(self, now: float) -> None:
        self.last_attempt = now
        try:
            self._fetch()
        except Exception as error:
            log.warning("feed %s: refresh failed, keeping the last good copy: %s", self.name, error)
            return
        self.meta.last_success = now
        write_atomic(self.meta_path, json.dumps(asdict(self.meta)).encode())


class Download[T](Feed[T]):
    """A file downloaded with a conditional GET, parsed from disk (which validates it), then swapped in.

    Parsing from the file keeps large feeds out of memory: a feed can stream it and keep only what it needs.
    """

    url: str

    def __init__(self, data_dir: Path) -> None:
        super().__init__(data_dir)
        self.path = data_dir / f"{self.name}.json"

    def parse(self, path: Path) -> T:
        raise NotImplementedError

    def _load(self) -> T:
        return self.parse(self.path)

    def _fetch(self) -> None:
        headers = {}
        # Without a copy loaded, a 304 would leave nothing to use.
        if self.data is not None:
            if self.meta.etag:
                headers["If-None-Match"] = self.meta.etag
            if self.meta.last_modified:
                headers["If-Modified-Since"] = self.meta.last_modified
        download = _tmp(self.path)
        try:
            response = http.get(self.url, headers, dest=download)
            if response.status == 304:
                return
            data = self.parse(download)
            os.replace(download, self.path)
        finally:
            download.unlink(missing_ok=True)
        self.data = data
        self.meta.etag = response.headers.get("ETag")
        self.meta.last_modified = response.headers.get("Last-Modified")
        log.info("feed %s: updated, %d records", self.name, self.records())
