"""HTTP GETs, with conditional requests and gzip."""

import gzip
import shutil
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from email.message import Message
from pathlib import Path

USER_AGENT = "advisory-map"
TIMEOUT = 300


@dataclass(frozen=True)
class Response:
    status: int
    headers: Message
    # Empty when the body went to a file.
    body: bytes = b""


def get(
    url: str,
    headers: Mapping[str, str] | None = None,
    context: ssl.SSLContext | None = None,
    dest: Path | None = None,
) -> Response:
    """GET url, its body streamed into dest if given. A 304 (Not Modified) is returned like a 200, other
    errors raise."""
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip", **(headers or {})}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as response:
            body = gzip.GzipFile(fileobj=response) if response.headers.get("Content-Encoding") == "gzip" else response
            if dest is None:
                return Response(response.status, response.headers, body.read())
            with dest.open("wb") as file:
                shutil.copyfileobj(body, file)
            return Response(response.status, response.headers)
    except urllib.error.HTTPError as error:
        if error.code == 304:
            return Response(304, error.headers)
        raise


@contextmanager
def lines(url: str) -> Iterator[Iterator[bytes]]:
    """GET url's body a line at a time; leaving the block early closes the connection, the rest unread."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        yield iter(response)
