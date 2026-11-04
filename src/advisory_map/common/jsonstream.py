"""A JSON document's members one at a time, so a large document is never in memory whole."""

import json
from collections.abc import Iterator
from typing import Any, TextIO

_DECODER = json.JSONDecoder()
_WHITESPACE = " \t\n\r"
_CHUNK = 1 << 20


class _Reader:
    """A window on the file: read as values need it, dropped once they're decoded."""

    def __init__(self, file: TextIO) -> None:
        self.file = file
        self.buffer = ""
        self.pos = 0
        self.eof = False

    def _more(self) -> bool:
        # At least as much again as is held, so a value spanning many chunks is decoded again only a
        # logarithmic number of times.
        chunk = self.file.read(max(_CHUNK, len(self.buffer) - self.pos))
        self.buffer, self.pos = self.buffer[self.pos :] + chunk, 0
        self.eof = not chunk
        return bool(chunk)

    def peek(self) -> str:
        """The next non-whitespace character, left in place; empty at the end."""
        while True:
            while self.pos < len(self.buffer) and self.buffer[self.pos] in _WHITESPACE:
                self.pos += 1
            if self.pos < len(self.buffer) or not self._more():
                return self.buffer[self.pos : self.pos + 1]

    def token(self, expected: str) -> str:
        """The next non-whitespace character, which must be one of expected."""
        char = self.peek()
        if not char or char not in expected:
            raise ValueError(f"expected one of {expected!r}, found {char or 'the end'!r}")
        self.pos += 1
        return char

    def value(self) -> Any:
        self.peek()
        while True:
            try:
                value, end = _DECODER.raw_decode(self.buffer, self.pos)
            except json.JSONDecodeError:
                if self._more():
                    continue
                raise
            # Ending at the buffer's end, it may go on (a number's digits): decode it again with more.
            if end == len(self.buffer) and not self.eof and self._more():
                continue
            self.pos = end
            return value

    def members(self, depth: int, keys: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
        self.token("{")
        if self.peek() == "}":
            self.token("}")
            return
        while True:
            key = self.value()
            if not isinstance(key, str):
                raise ValueError(f"an object key must be a string, found {key!r}")
            self.token(":")
            if depth == 1:
                yield (*keys, key), self.value()
            else:
                yield from self.members(depth - 1, (*keys, key))
            if self.token(",}") == "}":
                return


def members(file: TextIO, depth: int = 1) -> Iterator[tuple[tuple[str, ...], Any]]:
    """The members of the JSON object in file, depth objects down, with the keys leading to each:
    depth 2 yields ((outer key, inner key), value) for every member of every object in the document.
    Each value is decoded whole by json, so memory is bounded by the largest value rather than the
    document."""
    yield from _Reader(file).members(depth)
