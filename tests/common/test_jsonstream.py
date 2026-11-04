import io
import json

import pytest

from advisory_map.common import jsonstream

DOCUMENT = {
    "openssl": {"CVE-1": {"releases": {"trixie": {"status": "open"}}}, "CVE-2": 1234567890},
    "empty": {},
    "zlib": {"CVE-3": [1, 2.5, -3e2, True, None, 'é ✓ "quoted" \\']},
}


@pytest.fixture(params=[1, 3, 7, 1 << 20], ids=lambda chunk: f"chunk {chunk}")
def chunk(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> int:
    """Tiny chunks put every token and value across chunk boundaries."""
    monkeypatch.setattr(jsonstream, "_CHUNK", request.param)
    return request.param


def members(text: str, depth: int = 1) -> list[tuple[tuple[str, ...], object]]:
    return list(jsonstream.members(io.StringIO(text), depth))


@pytest.mark.parametrize("indent", [None, 2])
def test_members(chunk: int, indent: int | None) -> None:
    text = json.dumps(DOCUMENT, indent=indent, ensure_ascii=False)
    assert members(text) == [((key,), value) for key, value in DOCUMENT.items()]


@pytest.mark.parametrize("indent", [None, 2])
def test_members_two_deep(chunk: int, indent: int | None) -> None:
    text = json.dumps(DOCUMENT, indent=indent, ensure_ascii=False)
    assert members(text, depth=2) == [
        (("openssl", "CVE-1"), DOCUMENT["openssl"]["CVE-1"]),
        (("openssl", "CVE-2"), 1234567890),
        (("zlib", "CVE-3"), DOCUMENT["zlib"]["CVE-3"]),
    ]


@pytest.mark.parametrize("text", ["{}", " \n{ \t}\n"])
def test_empty(chunk: int, text: str) -> None:
    assert members(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        '{"a": 1',
        '{"a": 1,',
        '{"a" 1}',
        '{"a": tru}',
        "{1: 2}",
        '{"a": 1 "b": 2}',
    ],
)
def test_invalid(chunk: int, text: str) -> None:
    with pytest.raises(ValueError):
        members(text)


def test_two_deep_needs_objects(chunk: int) -> None:
    with pytest.raises(ValueError):
        members('{"a": {"b": 1}, "c": [1]}', depth=2)
