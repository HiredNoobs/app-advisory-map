import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from advisory_map.vex.openvex import Statement, Store, product

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def document(*statements: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/public/vex-1",
        "author": "Security Team",
        "timestamp": "2026-11-01T00:00:00Z",
        "version": 1,
        "statements": list(statements),
        **fields,
    }


def statement(**fields: Any) -> dict[str, Any]:
    return {
        "vulnerability": {"name": "CVE-2026-0001"},
        "products": [{"@id": product()}],
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        **fields,
    }


def write(directory: Path, name: str, content: Any) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content if isinstance(content, str) else json.dumps(content))


@pytest.mark.parametrize(
    "kind, target, expected",
    [
        (None, None, "advisory-map:installation"),
        ("container", None, "advisory-map:installation/container"),
        ("container", "web/frontend", "advisory-map:installation/container/web/frontend"),
        # A kind is one segment, a target's labels keep theirs.
        ("a/b", "host 1", "advisory-map:installation/a%2Fb/host%201"),
    ],
)
def test_product(kind: str | None, target: str | None, expected: str) -> None:
    assert product(kind, target) == expected


def test_target_needs_a_kind() -> None:
    with pytest.raises(ValueError):
        product(None, "host-1")


def test_statements(tmp_path: Path) -> None:
    write(
        tmp_path,
        "team.json",
        document(
            statement(),
            statement(
                vulnerability={"name": "GHSA-xxxx", "aliases": ["CVE-2026-0002"]},
                products=[{"@id": product("container", "ns/app")}, {"identifiers": {"purl": "pkg:golang/x"}}],
                status="affected",
                justification=None,
                action_statement="Upgrade",
                timestamp="2026-11-02T03:04:05.123456789+01:00",
            ),
        ),
    )
    assert Store(tmp_path).statements() == [
        Statement(
            vulnerability="CVE-2026-0001",
            aliases=(),
            products=(product(),),
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            impact_statement="",
            action_statement="",
            timestamp=datetime(2026, 11, 1, tzinfo=UTC),
            author="Security Team",
        ),
        Statement(
            vulnerability="GHSA-xxxx",
            aliases=("CVE-2026-0002",),
            products=(product("container", "ns/app"), "pkg:golang/x"),
            status="affected",
            justification="",
            impact_statement="",
            action_statement="Upgrade",
            timestamp=datetime(2026, 11, 2, 2, 4, 5, 123456, tzinfo=UTC),
            author="Security Team",
        ),
    ]


def test_names() -> None:
    item = Statement("CVE-1", ("GHSA-1", "CVE-1"), (), "fixed", "", "", "", NOW, "a")
    assert item.names == {"CVE-1", "GHSA-1"}


@pytest.mark.parametrize(
    "content, reason",
    [
        ("{", "not JSON"),
        ([], "not an object"),
        (document(statement(), **{"@context": "https://example.com"}), "@context"),
        ({k: v for k, v in document(statement()).items() if k != "author"}, "author"),
        (document(statement(), version="1"), "version"),
        (document(statement(), timestamp="yesterday"), "timestamp"),
        (document(statement(vulnerability={})), "vulnerability"),
        (document(statement(vulnerability={"name": "CVE-1", "aliases": "GHSA-1"})), "aliases"),
        (document(statement(products=[])), "products"),
        (document(statement(products=[{"hashes": {}}])), "products"),
        (document(statement(status="exploitable")), "status"),
        (document(statement(justification="trust me")), "justification"),
        (document(statement(justification=None)), "justification or an impact_statement"),
        (document(statement(status="affected", justification=None)), "action_statement"),
    ],
)
def test_invalid_documents_are_left_out(tmp_path: Path, content: Any, reason: str) -> None:
    write(tmp_path, "bad.json", content)
    write(tmp_path, "good.json", document(statement()))
    store = Store(tmp_path)
    assert [item.author for item in store.statements()] == ["Security Team"]
    assert list(store.invalid) == ["bad.json"]
    assert reason in store.invalid["bad.json"]


def test_impact_statement_instead_of_justification(tmp_path: Path) -> None:
    write(tmp_path, "team.json", document(statement(justification=None, impact_statement="No OIDC")))
    assert Store(tmp_path).statements()[0].impact_statement == "No OIDC"


def test_only_json_files(tmp_path: Path) -> None:
    write(tmp_path, "notes.txt", "not a document")
    write(tmp_path, ".team.json.tmp", "{")
    assert Store(tmp_path).statements() == []


def test_missing_directory(tmp_path: Path) -> None:
    store = Store(tmp_path / "missing")
    assert store.statements() == []
    assert store.invalid == {}


def test_reloads_changed_files(tmp_path: Path) -> None:
    write(tmp_path, "team.json", document(statement()))
    store = Store(tmp_path)
    assert len(store.statements()) == 1
    write(tmp_path, "team.json", document(statement(), statement(status="fixed", justification=None)))
    assert len(store.statements()) == 2
    (tmp_path / "team.json").unlink()
    assert store.statements() == []


def test_add_creates_the_authors_document(tmp_path: Path) -> None:
    store = Store(tmp_path / "vex")
    added = store.add(
        "Alice@Example.com",
        "CVE-2026-0001",
        product("container", "web/frontend"),
        "not_affected",
        NOW,
        justification="vulnerable_code_not_in_execute_path",
        impact_statement="The OIDC login is not configured",
    )
    path = store.document("Alice@Example.com")
    assert path == tmp_path / "vex" / "alice-example.com.json"
    written = json.loads(path.read_text())
    assert written["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert written["@id"].startswith("urn:uuid:")
    assert (written["author"], written["timestamp"], written["version"]) == ("Alice@Example.com", NOW.isoformat(), 1)
    assert written["statements"] == [
        {
            "vulnerability": {"name": "CVE-2026-0001"},
            "products": [{"@id": "advisory-map:installation/container/web/frontend"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": "The OIDC login is not configured",
            "timestamp": NOW.isoformat(),
        }
    ]
    assert store.statements() == [added]


def test_add_appends_and_versions(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.add("alice", "CVE-1", product(), "under_investigation", NOW)
    later = NOW.replace(hour=13)
    store.add("alice", "CVE-1", product(), "affected", later, action_statement="Upgrade")
    written = json.loads(store.document("alice").read_text())
    assert (written["version"], written["timestamp"], written["last_updated"]) == (
        2,
        NOW.isoformat(),
        later.isoformat(),
    )
    assert [item["status"] for item in written["statements"]] == ["under_investigation", "affected"]
    assert not list(tmp_path.glob(".*"))


def test_add_rejects_an_invalid_statement(tmp_path: Path) -> None:
    store = Store(tmp_path)
    with pytest.raises(ValueError, match="justification or an impact_statement"):
        store.add("alice", "CVE-1", product(), "not_affected", NOW)
    assert not list(tmp_path.iterdir())


def test_add_refuses_another_authors_document(tmp_path: Path) -> None:
    write(tmp_path, "alice.json", document(statement(), author="ALICE"))
    with pytest.raises(ValueError, match="ALICE"):
        Store(tmp_path).add("alice", "CVE-1", product(), "fixed", NOW)


def test_add_refuses_an_invalid_document(tmp_path: Path) -> None:
    write(tmp_path, "alice.json", "{")
    with pytest.raises(ValueError, match="not JSON"):
        Store(tmp_path).add("alice", "CVE-1", product(), "fixed", NOW)
    assert (tmp_path / "alice.json").read_text() == "{"
