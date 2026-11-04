import gzip
import threading
import urllib.error
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from advisory_map.common import http

BODY = b'{"vulnerabilities": []}'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/missing":
            self.send_error(404)
        elif self.headers.get("If-None-Match") == '"v1"':
            self.send_response(304)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("ETag", '"v1"')
            gzipped = "gzip" in self.headers.get("Accept-Encoding", "")
            body = gzip.compress(BODY) if gzipped else BODY
            if gzipped:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_gzip_is_decompressed(server: str) -> None:
    response = http.get(f"{server}/feed")
    assert (response.status, response.body, response.headers["ETag"]) == (200, BODY, '"v1"')


def test_download_to_a_file(server: str, tmp_path: Path) -> None:
    dest = tmp_path / "feed.json"
    response = http.get(f"{server}/feed", dest=dest)
    assert (response.status, response.body, response.headers["ETag"]) == (200, b"", '"v1"')
    assert dest.read_bytes() == BODY


def test_not_modified(server: str) -> None:
    response = http.get(f"{server}/feed", {"If-None-Match": '"v1"'})
    assert (response.status, response.body) == (304, b"")


def test_errors_raise(server: str) -> None:
    with pytest.raises(urllib.error.HTTPError):
        http.get(f"{server}/missing")


def test_lines(server: str) -> None:
    # Not gzipped: no Accept-Encoding is sent.
    with http.lines(f"{server}/feed") as lines:
        assert list(lines) == [BODY]
    with pytest.raises(urllib.error.HTTPError):
        with http.lines(f"{server}/missing"):
            pass
