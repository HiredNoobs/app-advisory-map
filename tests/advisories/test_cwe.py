from pathlib import Path

from conftest import CWES, FakeHttp, cwe_catalogue, response

from advisory_map.advisories.cwe import Cwe


def test_names(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[Cwe.url] = response(CWES)
    feed = Cwe(tmp_path)
    feed.refresh(100)
    assert feed.data == {
        "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-310": "Cryptographic Issues",
    }
    assert (tmp_path / "cwe.xml.zip").read_bytes() == CWES


def test_any_schema_version(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[Cwe.url] = response(
        cwe_catalogue(
            ("Category", "16", "Configuration"),
            ("View", "1000", "Research Concepts"),
            namespace="http://cwe.mitre.org/cwe-7",
        )
    )
    feed = Cwe(tmp_path)
    feed.refresh(100)
    assert feed.data == {"CWE-16": "Configuration", "CWE-1000": "Research Concepts"}


def test_a_catalogue_without_entries_keeps_the_last_good_copy(tmp_path: Path, fake_http: FakeHttp) -> None:
    fake_http.routes[Cwe.url] = response(CWES)
    feed = Cwe(tmp_path)
    feed.refresh(100)
    fake_http.routes[Cwe.url] = response(cwe_catalogue())
    feed.refresh(200)
    assert feed.records() == 2 and feed.meta.last_success == 100
    fake_http.routes[Cwe.url] = response(b"<html>maintenance</html>")
    feed.refresh(300)
    assert feed.records() == 2 and feed.meta.last_success == 100
